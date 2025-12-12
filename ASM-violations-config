param (
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$true)]
    [string]$PolicyFile
)

# -----------------------------
# Secure password
# -----------------------------
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString
$BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# -----------------------------
# Networking / SSL
# -----------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$AuthHeader = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Plain"))

# -----------------------------
# Hard-coded exact-match violation list (human-readable descriptions)
# -----------------------------
$ViolationFilters = @(
    "Cookie not RFC-compliant",
    "Illegal cookie length",
    "Modified ASM cookie",
    "Illegal file type",
    "Failed to convert character",
    "Illegal HTTP status in response",
    "Request length exceeds defined buffer size",
    "Illegal header length",
    "Illegal host name",
    "Illegal method",
    "Illegal repeated header",
    "Illegal meta character in parameter name",
    "Illegal redirection attempt",
    "Access from disallowed User/Session/IP/Device ID",
    "Illegal URL"
)

# -----------------------------
# Load policies (policy file format: Name:ID per line)
# -----------------------------
$Policies = Get-Content $PolicyFile | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("-")) { return }

    if ($line.StartsWith("+")) { $line = $line.Substring(1) }

    if ($line -match "^(.*?):(.*)$") {
        [PSCustomObject]@{
            Name = $matches[1].Trim()
            ID   = $matches[2].Trim()
        }
    }
} | Where-Object { $_ -ne $null }

# -----------------------------
# Helper: Http GET and parse JSON (returns $null on failure)
# -----------------------------
function Invoke-GetJson {
    param(
        [Parameter(Mandatory=$true)][string]$Url
    )

    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = $AuthHeader
        $req.Accept = "application/json"
        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()
        Start-Sleep -Milliseconds 300  # small delay so we don't hammer the API
        return (ConvertFrom-Json $json)
    }
    catch {
        Write-Warning "Failed to GET $Url : $($_.Exception.Message)"
        return $null
    }
}

# -----------------------------
# Function: fetch policy-level violations (items array)
# -----------------------------
function Get-PolicyViolations {
    param([string]$PolicyID)
    $url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyID/blocking-settings/violations/"
    $json = Invoke-GetJson -Url $url
    if ($null -eq $json) { return @() }
    return ,$json.items | Where-Object { $_ -ne $null }
}

# -----------------------------
# Functions: fetch specific policy config endpoints
# Each returns parsed JSON or $null
# -----------------------------
function Get-HeaderSettings { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/header-settings/" }
function Get-FileTypes       { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/filetypes" }
function Get-CookieSettings  { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/cookie-settings" }
function Get-General        { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/general" }
function Get-HostNames      { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/host-names" }
function Get-Methods        { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/methods" }
function Get-Redirection    { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/redirection-protection" }
function Get-SessionTracking{ param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/session-tracking" }
function Get-CharacterSets  { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/character-sets" }

# -----------------------------
# Prepare CSV column headers (exact order requested)
# -----------------------------
$CsvColumns = @(
    "PolicyName",
    "PolicyID",

    "Cookie not RFC-compliant",
    "Illegal cookie length",
    "Cookie length configured",
    "Modified ASM cookie",
    "Illegal file type",
    "File types configured",
    "Failed to convert character",
    "Illegal HTTP status in response",
    "HTTP status configured",
    "Request length exceeds defined buffer size",
    "Illegal header length",
    "Header length configured",
    "Illegal host name",
    "Host names configured",
    "Illegal method",
    "Methods configured",
    "Illegal repeated header",
    "Illegal meta character in parameter name",
    "0x25 status in parameter name",
    "Illegal redirection attempt",
    "Redirection configuration",
    "Access from disallowed User/Session/IP/Device ID",
    "Session awareness config",
    "Illegal URL"
)

$CSVRows = @()

# -----------------------------
# Main loop: iterate policies and collect everything
# -----------------------------
foreach ($policy in $Policies) {
    Write-Host "Processing policy: $($policy.Name) ($($policy.ID))"

    # Initialize the row with defaults: violations False, config empty
    $row = [ordered]@{}
    foreach ($col in $CsvColumns) {
        if ($col -eq "PolicyName")   { $row[$col] = $policy.Name; continue }
        if ($col -eq "PolicyID")     { $row[$col] = $policy.ID; continue }

        switch ($col) {
            default { $row[$col] = $false } # by default boolean false for violation flags
        }
    }

    # For config columns that are not boolean, use empty string instead of $false
    $nonBoolConfigCols = @(
        "Cookie length configured",
        "File types configured",
        "HTTP status configured",
        "Header length configured",
        "Host names configured",
        "Methods configured",
        "Redirection configuration",
        "Session awareness config",
        "0x25 status in parameter name"
    )
    foreach ($c in $nonBoolConfigCols) { $row[$c] = "" }

    # -----------------------------
    # 1) Get violations (blocking states)
    # -----------------------------
    $violations = Get-PolicyViolations -PolicyID $policy.ID

    foreach ($v in $violations) {
        if (-not $v) { continue }

        # Use the friendly description for exact matching (case-insensitive)
        $desc = $null
        if ($v.PSObject.Properties.Name -contains "description") { $desc = $v.description.Trim() }

        if ($null -ne $desc) {
            foreach ($vf in $ViolationFilters) {
                if ($desc.ToLower() -eq $vf.ToLower()) {
                    # set boolean column to the blocking state
                    $colName = $vf
                    $row[$colName] = [bool]$v.block
                    break
                }
            }
        }
    }

    # -----------------------------
    # 2) Collect config endpoints (always, per Option A)
    # -----------------------------
    # Header settings
    $h = Get-HeaderSettings -policyID $policy.ID
    if ($null -ne $h -and $h.maximumHttpHeaderLength) {
        $row["Header length configured"] = $h.maximumHttpHeaderLength
    }

    # File types
    $ft = Get-FileTypes -policyID $policy.ID
    if ($null -ne $ft -and $ft.items) {
        $allowed = @()
        $disallowed = @()
        foreach ($it in $ft.items) {
            if ($it.name) {
                if ($it.allowed -eq $true) { $allowed += $it.name }
                elseif ($it.allowed -eq $false) { $disallowed += $it.name }
            }
        }
        $row["File types configured"] = "allowed=[" + ($allowed -join ",") + "]; disallowed=[" + ($disallowed -join ",") + "]"
    }

    # Cookie settings
    $ck = Get-CookieSettings -policyID $policy.ID
    if ($null -ne $ck -and $ck.maximumCookieHeaderLength) {
        $row["Cookie length configured"] = $ck.maximumCookieHeaderLength
    }

    # General (allowed response codes)
    $g = Get-General -policyID $policy.ID
    if ($null -ne $g -and $g.allowedResponseCodes) {
        # join array
        $row["HTTP status configured"] = ($g.allowedResponseCodes -join ",")
    }

    # Host names
    $hn = Get-HostNames -policyID $policy.ID
    if ($null -ne $hn -and $hn.items) {
        $hostnames = @()
        foreach ($it in $hn.items) {
            if ($it.name) { $hostnames += $it.name }
        }
        $row["Host names configured"] = ($hostnames -join ",")
    }

    # Methods
    $meth = Get-Methods -policyID $policy.ID
    if ($null -ne $meth -and $meth.items) {
        $methods = @()
        foreach ($it in $meth.items) {
            if ($it.name) { $methods += $it.name }
        }
        $row["Methods configured"] = ($methods -join ",")
    }

    # Redirection protection
    $rd = Get-Redirection -policyID $policy.ID
    if ($null -ne $rd) {
        if ($rd.redirectionProtectionEnabled -ne $null) {
            $row["Redirection configuration"] = "enabled=" + ($rd.redirectionProtectionEnabled -as [string])
        }
        if ($rd.redirectionDomains -ne $null) {
            $domains = @()
            foreach ($d in $rd.redirectionDomains) {
                if ($d.domainName) { $domains += $d.domainName }
            }
            if ($domains.Count -gt 0) {
                $row["Redirection configuration"] += "; domains=[" + ($domains -join ",") + "]"
            }
        }
    }

    # Session tracking / session awareness
    $st = Get-SessionTracking -policyID $policy.ID
    if ($null -ne $st) {
        $sessParts = @()
        # enableSessionAwareness
        if ($st.sessionTrackingConfiguration -and $st.sessionTrackingConfiguration.enableSessionAwareness -ne $null) {
            $sessParts += "enableSessionAwareness=" + ($st.sessionTrackingConfiguration.enableSessionAwareness -as [string])
            $row["Session awareness config"] = ($sessParts -join ";")
        }
        # violationDetectionPeriod
        if ($st.violationDetectionActions -and $st.violationDetectionActions.violationDetectionPeriod -ne $null) {
            $sessParts += "violationDetectionPeriod=" + ($st.violationDetectionActions.violationDetectionPeriod -as [string])
        }
        # blockAll properties (period, ipThreshold, urlBlockingMode)
        if ($st.blockAll) {
            if ($st.blockAll.period -ne $null) { $sessParts += "period=" + ($st.blockAll.period -as [string]) }
            if ($st.blockAll.ipThreshold -ne $null) { $sessParts += "ipThreshold=" + ($st.blockAll.ipThreshold -as [string]) }
            if ($st.blockAll.urlBlockingMode -ne $null) { $sessParts += "urlBlockingMode=" + ($st.blockAll.urlBlockingMode -as [string]) }
        }
        if ($sessParts.Count -gt 0) { $row["Session awareness config"] = ($sessParts -join "; ") }
    }

    # Character sets (parameter-name) -> find 0x25 metachar
    $cs = Get-CharacterSets -policyID $policy.ID
    if ($null -ne $cs) {
        # If the endpoint returns a single object with characterSetType, or collection, handle both
        $characterEntries = @()
        if ($cs.characterSetType -and ($cs.characterSetType -eq "parameter-name")) {
            $characterEntries += $cs
        }
        elseif ($cs.items) {
            foreach ($it in $cs.items) {
                if ($it.characterSetType -and $it.characterSetType -eq "parameter-name") { $characterEntries += $it }
            }
        }
        foreach ($ce in $characterEntries) {
            if ($ce.characterSet) {
                foreach ($m in $ce.characterSet) {
                    if ($m.metachar -and $m.metachar -eq "0x25") {
                        # isAllowed true/false
                        $row["0x25 status in parameter name"] = "allowed=" + ($m.isAllowed -as [string])
                    }
                }
            }
        }
        # If not found, keep empty string
    }

    # Ensure boolean columns are real booleans for CSV (leave configs as strings)
    foreach ($vf in $ViolationFilters) {
        $colName = $vf
        if ($row[$colName] -is [string]) {
            # already filled maybe as string (shouldn't normally happen), coerce
            if ($row[$colName].ToLower() -in @("true","false")) {
                $row[$colName] = [bool]::Parse($row[$colName])
            }
            else {
                $row[$colName] = [bool]$row[$colName]
            }
        } else {
            $row[$colName] = [bool]$row[$colName]
        }
    }

    # Add row to CSVRows
    $CSVRows += New-Object PSObject -Property $row
}

# -----------------------------
# Export CSV
# -----------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$policyBase = [System.IO.Path]::GetFileNameWithoutExtension($PolicyFile)
$csvFileName = "$timestamp-$policyBase.csv"

# Ensure consistent column order when exporting
$CSVRows | Select-Object $CsvColumns | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "CSV output written to: $csvFileName"
Write-Host "Done."
