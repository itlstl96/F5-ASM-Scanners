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
# Generic GET
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

# -------------------------
# Get nodes for a VS via its pool
# -------------------------
function Get-NodesFromVS {
    param ($vs)

    if (-not $vs.poolReference -or -not $vs.poolReference.link) { return @() }

    $poolUrl = $vs.poolReference.link -replace "https://localhost", $BaseUrl
    $poolObj = Invoke-BigIPGet $poolUrl
    if (-not $poolObj) { return @() }

    if (-not $poolObj.membersReference -or -not $poolObj.membersReference.link) { return @() }
    $membersUrl = $poolObj.membersReference.link -replace "https://localhost", $BaseUrl
    $membersObj = Invoke-BigIPGet $membersUrl
    if (-not $membersObj.items) { return @() }

    return $membersObj.items
}

# -------------------------
# Get ASM policies
# -------------------------
$asmData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/asm/policies/"
$asmPolicies = @{}
foreach ($p in $asmData.items) { $asmPolicies[$p.name] = $p.fullPath }

# -------------------------
# Get DOS profiles
# -------------------------
$dosData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/security/dos/profile"
$dosProfiles = @{}
foreach ($d in $dosData.items) { $dosProfiles[$d.name] = $d.fullPath }

# -------------------------
# Get VS list
# -------------------------
$data = Invoke-BigIPGet $VSUrl
if (-not $data.items) {
    Write-Host "No virtual servers found."
    exit 1
}

# -------------------------
# Process each VS
# -------------------------
$csvData = foreach ($vs in $data.items) {

    # Parse VS IP and port from destination
    $vsIP = ""
    $vsPort = ""
    if ($vs.destination) {
        $dest = $vs.destination -replace '^/[^/]+/', ''
        if ($dest -match '^(.*):(\d+)$') {
            $vsIP = $matches[1]
            $vsPort = $matches[2]
        }
    }

    # Parse tags from description
    $vsImportance = ""
    $ipPublic = ""
    $itOwner = ""
    $businessOwner = ""

    if ($vs.description) {
        if ($vs.description -match '\[utilizare\]:\[(.*?)\]') { $vsImportance = $matches[1] }
        if ($vs.description -match '\[ip_public\]:\[(.*?)\]') { $ipPublic = $matches[1] }
        if ($vs.description -match '\[it_owner\]:\[(.*?)\]') { $itOwner = $matches[1] }
        if ($vs.description -match '\[business_owner\]:\[(.*?)\]') { $businessOwner = $matches[1] }
    }

    # Get pool members
    $members = Get-NodesFromVS $vs
    if (-not $members) { $members = @(@{address=""; name=""}) } # handle VS with no members

    # Get profiles attached to VS
    $vsProfilesData = Invoke-BigIPGet ($BaseUrl + "/mgmt/tm/ltm/virtual/~$($vs.partition)~$($vs.name)/profiles/")
    $asmList = @()
    $dosList = @()
    if ($vsProfilesData.items) {
        foreach ($p in $vsProfilesData.items) {
            $nameNormalized = $p.name -replace '^ASM_', ''
            if ($asmPolicies.ContainsKey($nameNormalized)) { $asmList += $nameNormalized }
            elseif ($dosProfiles.ContainsKey($p.name)) { $dosList += $p.name }
        }
    }

    # Check if LTM policy exists
    $policiesData = Invoke-BigIPGet ($BaseUrl + "/mgmt/tm/ltm/virtual/~$($vs.partition)~$($vs.name)/policies/")
    if ($policiesData.items) {
        foreach ($pol in $policiesData.items) {
            # Skip default ASM policies starting with asm_auto_l7_
            if ($pol.name -notmatch '^asm_auto_l7_') {
                # Crawl rules of LTM policy
                $rulesData = Invoke-BigIPGet ($BaseUrl + "/mgmt/tm/ltm/policy/$($pol.name)/rules")
                if ($rulesData.items) {
                    foreach ($r in $rulesData.items) {
                        $actionsData = Invoke-BigIPGet ($r.actionsReference.link -replace "https://localhost", $BaseUrl)
                        if ($actionsData.items) {
                            foreach ($a in $actionsData.items) {
                                # ASM policy attached via LTM
                                if ($a.asm -eq $true -and $a.policy) {
                                    $asmName = ($a.policy -split '/')[-1]
                                    if (-not $asmList.Contains($asmName)) { $asmList += $asmName }
                                }
                                # DOS policy attached via LTM
                                if ($a.dos -eq $true -and $a.policy) {
                                    $dosName = ($a.policy -split '/')[-1]
                                    if (-not $dosList.Contains($dosName)) { $dosList += $dosName }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    $asmList = ($asmList | Sort-Object -Unique | Where-Object { $_ -ne "websecurity" }) -join ';'
    $dosList = ($dosList | Sort-Object -Unique) -join ';'

    foreach ($m in $members) {
        $nodeIP = $m.address
        $nodePort = ""
        if ($m.name -match ':(\d+)$') { $nodePort = $matches[1] }

        [PSCustomObject]@{
            VS_Importance = $vsImportance
            It_owner      = $itOwner
            Business_owner= $businessOwner
            VS_Name       = $vs.name
            IP_Public     = $ipPublic
            VS_IP         = $vsIP
            VS_Port       = $vsPort
            Node_IP       = $nodeIP
            Node_Port     = $nodePort
            ASM_Policies  = $asmList
            DOS_Policies  = $dosList
        }
    }
}

# -------------------------
# Export CSV
# -------------------------
$csvData | Export-Csv "BIGIP_VS_Nodes.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Export completed: BIGIP_VS_Nodes.csv"
