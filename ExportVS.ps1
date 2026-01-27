param (
    [Parameter(Mandatory = $true)]
    [string]$BigIPHost,

    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$User
)

# Prompt for password securely
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString

# Convert secure password to plain text
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disable SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Base Virtual Server endpoint
$Url = "https://$BigIPHost`:$Port/mgmt/tm/ltm/virtual"

# Authorization header
$AuthString = "$User`:$PlainPassword"
$AuthHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthString))

$Headers = @{
    "Authorization" = "Basic $AuthHeader"
}

# -------------------------
# Helper functions
# -------------------------

function Invoke-BigIPGet {
    param (
        [string]$Url,
        [hashtable]$Headers
    )

    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "GET"
        foreach ($key in $Headers.Keys) {
            $request.Headers[$key] = $Headers[$key]
        }
        $request.Accept = "application/json"

        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()

        return $json | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Get-ProfileFullPath {
    param (
        $ProfilesData,
        [string]$ProfileName
    )

    $profile = $ProfilesData.items | Where-Object { $_.name -eq $ProfileName }
    if ($profile) {
        return $profile.fullPath
    }
    return ""
}

# -------------------------
# Get Virtual Servers
# -------------------------

$data = Invoke-BigIPGet -Url $Url -Headers $Headers

if (-not $data -or -not $data.items) {
    Write-Host "No virtual servers found or unable to connect."
    exit 1
}

# -------------------------
# Process Virtual Servers
# -------------------------

$csvData = foreach ($vs in $data.items) {

    # iRules
    $iRules = if ($vs.rules) {
        $vs.rules -join "; "
    } else {
        ""
    }

    # Destination parsing
    $destinationIP   = ""
    $destinationPort = ""

    if ($vs.destination) {
        $dest = $vs.destination -replace '^/[^/]+/', ''
        if ($dest -match '^(.*):(\d+)$') {
            $destinationIP   = $matches[1]
            $destinationPort = $matches[2]
        }
    }

    # Initialize profile values
    $httpProfile          = ""
    $tcpProfile           = ""
    $tcpAnalyticsProfile  = ""
    $httpAnalyticsProfile = ""
    $websocketProfile     = ""

    # Profiles lookup
    if ($vs.profilesReference -and $vs.profilesReference.link) {

        $profilesUrl = $vs.profilesReference.link `
            -replace "https://localhost", "https://$BigIPHost`:$Port"

        $profilesData = Invoke-BigIPGet -Url $profilesUrl -Headers $Headers

        if ($profilesData -and $profilesData.items) {
            $httpProfile          = Get-ProfileFullPath $profilesData "http"
            $tcpProfile           = Get-ProfileFullPath $profilesData "tcp"
            $tcpAnalyticsProfile  = Get-ProfileFullPath $profilesData "tcp-analytics"
            $httpAnalyticsProfile = Get-ProfileFullPath $profilesData "analytics"
            $websocketProfile     = Get-ProfileFullPath $profilesData "websocket"
        }
    }

    [PSCustomObject]@{
        name                 = $vs.name
        creationTime         = $vs.creationTime
        lastModifiedTime     = $vs.lastModifiedTime
        destinationIP        = $destinationIP
        destinationPort      = $destinationPort
        iRules               = $iRules
        httpProfile          = $httpProfile
        tcpProfile           = $tcpProfile
        tcpAnalyticsProfile  = $tcpAnalyticsProfile
        httpAnalyticsProfile = $httpAnalyticsProfile
        websocketProfile     = $websocketProfile
        connectionLimit      = $vs.connectionLimit
        rateLimit            = $vs.rateLimit
        flowEvictionPolicy   = $vs.flowEvictionPolicy
    }
}

# -------------------------
# Export CSV
# -------------------------

$OutputFile = Join-Path (Get-Location) "Virtual_Servers_Export.csv"

$csvData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host "Virtual servers exported to $OutputFile"
