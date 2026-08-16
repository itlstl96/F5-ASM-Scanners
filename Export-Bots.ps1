.\Export-Bots.ps1 -BigIPHost 192.168.100.144 -Port 443 -User admin

param (
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User
)

# ============================================================
# Password
# ============================================================

$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)


# ============================================================
# BIG-IP REST API settings
# ============================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# BIG-IP commonly uses self-signed certificates
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$BaseUrl = "https://$BigIPHost`:$Port"

$ProfilesUrl = "$BaseUrl/mgmt/tm/security/bot-defense/profile/"


# ============================================================
# Authentication
# ============================================================

$AuthString = "$User`:$PlainPassword"

$AuthHeader = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes($AuthString)
)


# ============================================================
# Function: Convert BIG-IP localhost URL
# ============================================================

function Convert-BigIPUrl {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $null
    }

    # BIG-IP commonly returns:
    # https://localhost/mgmt/...
    #
    # Replace localhost with the BIG-IP supplied on CLI.

    return ($Url -replace '^https?://localhost', $BaseUrl)
}


# ============================================================
# Function: GET BIG-IP REST API
# ============================================================

function Invoke-BigIPGet {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    try {

        $request = [System.Net.HttpWebRequest]::Create($Url)

        $request.Method = "GET"
        $request.Headers["Authorization"] = "Basic $AuthHeader"
        $request.Accept = "application/json"

        $response = $request.GetResponse()

        try {

            $stream = $response.GetResponseStream()

            $reader = New-Object System.IO.StreamReader($stream)

            $json = $reader.ReadToEnd()

            $reader.Close()

            if ([string]::IsNullOrWhiteSpace($json)) {
                return $null
            }

            return ($json | ConvertFrom-Json)
        }
        finally {
            $response.Close()
        }
    }
    catch {

        Write-Host ""
        Write-Host "ERROR calling BIG-IP API" -ForegroundColor Red
        Write-Host "URL: $Url"
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""

        return $null
    }
}


# ============================================================
# Function: Get complete collection
#
# BIG-IP REST API collections can be paginated.
# This function retrieves all items using $top / $skip.
# ============================================================

function Get-BigIPCollection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    $allItems = @()

    $pageSize = 1000
    $skip = 0

    while ($true) {

        # Remove existing query string
        $baseCollectionUrl = $Url -replace '\?.*$', ''

        $pageUrl = "$baseCollectionUrl`?`$top=$pageSize&`$skip=$skip"

        Write-Verbose "Getting collection page: $pageUrl"

        $data = Invoke-BigIPGet -Url $pageUrl

        if ($null -eq $data) {
            break
        }

        if ($data.items) {

            $pageItems = @($data.items)

            $allItems += $pageItems

            Write-Verbose "Retrieved $($pageItems.Count) items."

            if ($pageItems.Count -lt $pageSize) {
                break
            }

            $skip += $pageSize
        }
        else {
            break
        }
    }

    return $allItems
}


# ============================================================
# Function: Get class mitigation overrides
# ============================================================

function Get-ClassMitigations {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    $result = @{}

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $result
    }

    $Url = Convert-BigIPUrl -Url $Url

    $items = Get-BigIPCollection -Url $Url

    foreach ($item in $items) {

        if ([string]::IsNullOrWhiteSpace($item.name)) {
            continue
        }

        $action = $null

        if ($item.mitigation -and $item.mitigation.action) {
            $action = $item.mitigation.action
        }

        if ($null -ne $action) {
            $result[$item.name] = $action
        }
    }

    return $result
}


# ============================================================
# Function: Get profile class override reference
# ============================================================

function Get-ClassOverrideUrl {
    param (
        [Parameter(Mandatory=$true)]
        $Profile
    )

    if ($Profile.classOverridesReference) {

        return $Profile.classOverridesReference.link
    }

    return $null
}


# ============================================================
# Template fallback defaults
#
# These are used only if the inherited default profile does
# not expose a class override for a particular class.
#
# The API values are used where available.
# ============================================================

function Get-TemplateDefaults {
    param (
        [string]$Template
    )

    $defaults = @{}

    switch ($Template.ToLower()) {

        "balanced" {

            $defaults["Trusted Bot"] = "alarm"
            $defaults["Untrusted Bot"] = "alarm"
            $defaults["Suspicious Browser"] = "captcha"
            $defaults["Malicious Bot"] = "block"
            $defaults["Unknown"] = "rate-limit"

        }

        default {

            # We do NOT assume values for unknown templates.
            # The parent/default profile should provide them.

        }
    }

    return $defaults
}


# ============================================================
# Start
# ============================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "BIG-IP Bot Defense Export"
Write-Host "=============================================="
Write-Host ""
Write-Host "BIG-IP: $BigIPHost`:$Port"
Write-Host ""


# ============================================================
# Get Bot Defense profiles
# ============================================================

Write-Host "Retrieving Bot Defense profiles..."

$data = Invoke-BigIPGet -Url $ProfilesUrl

if ($null -eq $data) {

    Write-Host "ERROR: Unable to retrieve Bot Defense profiles." -ForegroundColor Red

    exit 1
}

if (-not $data.items) {

    Write-Host "No Bot Defense profiles found."

    exit 0
}

$profiles = @($data.items)

Write-Host "Profiles found: $($profiles.Count)"
Write-Host ""


# ============================================================
# CSV output
# ============================================================

$OutputFile = Join-Path `
    -Path (Get-Location) `
    -ChildPath "Bot_Defense_Profiles_Export.csv"

$results = @()


# ============================================================
# Process profiles
# ============================================================

foreach ($profile in $profiles) {

    Write-Host "----------------------------------------------"
    Write-Host "Processing profile: $($profile.name)"
    Write-Host "----------------------------------------------"


    # --------------------------------------------------------
    # Basic profile information
    # --------------------------------------------------------

    $profileName = if ($profile.name) {
        $profile.name
    }
    else {
        "N/A"
    }

    $enforcementMode = if ($profile.enforcementMode) {
        $profile.enforcementMode
    }
    else {
        "N/A"
    }

    $template = if ($profile.template) {
        $profile.template
    }
    else {
        "N/A"
    }

    $defaultsFrom = if ($profile.defaultsFrom) {
        $profile.defaultsFrom
    }
    else {
        "N/A"
    }


    Write-Host "Template: $template"
    Write-Host "Defaults From: $defaultsFrom"
    Write-Host "Enforcement Mode: $enforcementMode"


    # ========================================================
    # Build default mitigation settings
    # ========================================================

    $effectiveMitigation = @{}

    # --------------------------------------------------------
    # First: template fallback
    # --------------------------------------------------------

    $templateDefaults = Get-TemplateDefaults -Template $template

    foreach ($key in $templateDefaults.Keys) {

        $effectiveMitigation[$key] = $templateDefaults[$key]
    }


    # --------------------------------------------------------
    # Second: retrieve defaultsFrom profile
    # --------------------------------------------------------

    if ($profile.defaultsFromReference) {

        $defaultsUrl = Convert-BigIPUrl `
            -Url $profile.defaultsFromReference.link

        Write-Host "Getting default profile..."

        $defaultsProfile = Invoke-BigIPGet -Url $defaultsUrl

        if ($null -ne $defaultsProfile) {

            Write-Host "Default profile found: $($defaultsProfile.name)"


            # ------------------------------------------------
            # Get class overrides from default profile
            # ------------------------------------------------

            $defaultClassOverrideUrl = Get-ClassOverrideUrl `
                -Profile $defaultsProfile

            if ($defaultClassOverrideUrl) {

                Write-Host "Getting default class mitigation settings..."

                $defaultMitigations = Get-ClassMitigations `
                    -Url $defaultClassOverrideUrl

                foreach ($key in $defaultMitigations.Keys) {

                    $effectiveMitigation[$key] =
                        $defaultMitigations[$key]
                }
            }
        }
    }


    # ========================================================
    # Staged signatures
    # ========================================================

    $stagedSignatureCount = 0

    if ($profile.stagedSignaturesReference) {

        $stagedUrl = Convert-BigIPUrl `
            -Url $profile.stagedSignaturesReference.link

        Write-Host "Getting staged signatures..."

        $stagedSignatures = Get-BigIPCollection `
            -Url $stagedUrl

        $stagedSignatureCount = @($stagedSignatures).Count
    }
    elseif ($profile.selfLink) {

        # Fallback if stagedSignaturesReference doesn't exist

        $profileUrl = Convert-BigIPUrl `
            -Url $profile.selfLink

        $profileBaseUrl = $profileUrl -replace '\?.*$', ''

        $stagedUrl = "$profileBaseUrl/staged-signatures"

        Write-Host "Getting staged signatures..."

        $stagedSignatures = Get-BigIPCollection `
            -Url $stagedUrl

        $stagedSignatureCount = @($stagedSignatures).Count
    }

    Write-Host "Staged signatures: $stagedSignatureCount"


    # ========================================================
    # Profile-specific class overrides
    # ========================================================

    $profileOverrideUrl = Get-ClassOverrideUrl `
        -Profile $profile

    if ($profileOverrideUrl) {

        Write-Host "Getting profile class overrides..."

        $profileMitigations = Get-ClassMitigations `
            -Url $profileOverrideUrl

        # ----------------------------------------------------
        # Apply explicit profile overrides
        #
        # These take precedence over inherited/default values.
        # ----------------------------------------------------

        foreach ($key in $profileMitigations.Keys) {

            $effectiveMitigation[$key] =
                $profileMitigations[$key]

            Write-Host "Override: $key = $($profileMitigations[$key])"
        }
    }


    # ========================================================
    # Get final values
    # ========================================================

    $trustedBot = if ($effectiveMitigation.ContainsKey("Trusted Bot")) {
        $effectiveMitigation["Trusted Bot"]
    }
    else {
        "N/A"
    }

    $untrustedBot = if ($effectiveMitigation.ContainsKey("Untrusted Bot")) {
        $effectiveMitigation["Untrusted Bot"]
    }
    else {
        "N/A"
    }

    $suspiciousBrowser = if ($effectiveMitigation.ContainsKey("Suspicious Browser")) {
        $effectiveMitigation["Suspicious Browser"]
    }
    else {
        "N/A"
    }

    $maliciousBot = if ($effectiveMitigation.ContainsKey("Malicious Bot")) {
        $effectiveMitigation["Malicious Bot"]
    }
    else {
        "N/A"
    }

    $unknown = if ($effectiveMitigation.ContainsKey("Unknown")) {
        $effectiveMitigation["Unknown"]
    }
    else {
        "N/A"
    }


    # ========================================================
    # Console summary
    # ========================================================

    Write-Host ""
    Write-Host "Effective Mitigation Settings:"
    Write-Host "  Trusted Bot        : $trustedBot"
    Write-Host "  Untrusted Bot      : $untrustedBot"
    Write-Host "  Suspicious Browser : $suspiciousBrowser"
    Write-Host "  Malicious Bot      : $maliciousBot"
    Write-Host "  Unknown            : $unknown"
    Write-Host ""


    # ========================================================
    # Create CSV object
    # ========================================================

    $result = [PSCustomObject]@{

        Profile               = $profileName

        Template              = $template

        EnforcementMode       = $enforcementMode

        StagedSignatures      = $stagedSignatureCount

        "Trusted Bot"         = $trustedBot

        "Untrusted Bot"       = $untrustedBot

        "Suspicious Browser"  = $suspiciousBrowser

        "Malicious Bot"       = $maliciousBot

        "Unknown"             = $unknown
    }


    $results += $result
}


# ============================================================
# Export CSV
# ============================================================

Write-Host "=============================================="
Write-Host "Exporting CSV..."
Write-Host "=============================================="

$results | Export-Csv `
    -Path $OutputFile `
    -NoTypeInformation `
    -Encoding UTF8


# ============================================================
# Finished
# ============================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Bot Defense export completed."
Write-Host "=============================================="
Write-Host ""
Write-Host "Profiles exported : $($results.Count)"
Write-Host "Output file        : $OutputFile"
Write-Host ""
