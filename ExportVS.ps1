param (
    [Parameter(Mandatory = $true)]
    [string]$BigIPHost,

    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$User
)

# -------------------------
# Authentication
# -------------------------

$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$BaseUrl = "https://$BigIPHost`:$Port"
$VSUrl   = "$BaseUrl/mgmt/tm/ltm/virtual"

$AuthHeader = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("$User`:$PlainPassword")
)

$Headers = @{ Authorization = "Basic $AuthHeader" }

# -------------------------
# Profile lists
# -------------------------

$HttpProfiles = @("custom-http","http","http-explicit","http-transparent")
$TcpProfiles = @(
    "apm-forwarding-client-tcp","apm-forwarding-server-tcp","f5-tcp-lan",
    "f5-tcp-mobile","f5-tcp-progressive","f5-tcp-wan","mptcp-mobile-optimized",
    "splitsession-default-tcp","tcp","tcp-lan-optimized"
)
$WebsocketProfiles = @("websocket")
$HttpAnalyticsProfiles = @("analytics")
$TcpAnalyticsProfiles = @("tcp-analytics")

# -------------------------
# Helper functions
# -------------------------

function Invoke-BigIPGet {
    param ($Url)

    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = $Headers.Authorization
        $req.Accept = "application/json"

        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $reader.ReadToEnd() | ConvertFrom-Json
    }
    catch {
        $null
    }
}

function Get-ProfileByList {
    param (
        $ProfilesData,
        [string[]]$PossibleNames
    )

    foreach ($name in $PossibleNames) {
        $match = $ProfilesData.items | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if ($match) { return $match.fullPath }
    }
    return ""
}

# -------------------------
# Get Virtual Servers
# -------------------------

$data = Invoke-BigIPGet $VSUrl
if (-not $data.items) {
    Write-Host "No virtual servers found."
    exit 1
}

# -------------------------
# Process Virtual Servers
# -------------------------

$csvData = foreach ($vs in $data.items) {

    # iRules
    $iRules = if ($vs.rules) { $vs.rules -join "; " } else { "" }

    # Destination parsing
    $destinationIP = ""
    $destinationPort = ""

    if ($vs.destination) {
        $dest = $vs.destination -replace '^/[^/]+/', ''
        if ($dest -match '^(.*):(\d+)$') {
            $destinationIP   = $matches[1]
            $destinationPort = $matches[2]
        }
    }

    # Profiles
    $httpProfile          = ""
    $tcpProfile           = ""
    $tcpAnalyticsProfile  = ""
    $httpAnalyticsProfile = ""
    $websocketProfile     = ""

    if ($vs.profilesReference.link) {

        $profilesUrl = $vs.profilesReference.link -replace "https://localhost", $BaseUrl
        $profiles = Invoke-BigIPGet $profilesUrl

        if ($profiles.items) {
            $httpProfile          = Get-ProfileByList $profiles $HttpProfiles
            $tcpProfile           = Get-ProfileByList $profiles $TcpProfiles
            $tcpAnalyticsProfile  = Get-ProfileByList $profiles $TcpAnalyticsProfiles
            $httpAnalyticsProfile = Get-ProfileByList $profiles $HttpAnalyticsProfiles
            $websocketProfile     = Get-ProfileByList $profiles $WebsocketProfiles
        }
    }

    [PSCustomObject]@{
        name                 = $vs.name
        destinationIP        = $destinationIP
        destinationPort      = $destinationPort
        iRules               = $iRules
        httpAnalyticsProfile = $httpAnalyticsProfile
        httpProfile          = $httpProfile
        tcpProfile           = $tcpProfile
        tcpAnalyticsProfile  = $tcpAnalyticsProfile
        websocketProfile     = $websocketProfile
        connectionLimit      = $vs.connectionLimit
        rateLimit            = $vs.rateLimit
        flowEvictionPolicy   = $vs.flowEvictionPolicy
    }
}

# -------------------------
# Export CSV
# -------------------------

$csvData | Export-Csv "Virtual_Servers_Export.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Export completed successfully."
