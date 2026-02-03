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
# ASM policies to exclude from hostname extraction
# -------------------------
$ExcludedAsmHostnamePolicies = @(
    "Copie3",
    "PolicyZ"
)

# -------------------------
# Custom VS Importance order
# -------------------------
$importanceOrder = @("Critic","Important","Mediu","Non-Prod")

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
# Get ASM policies (name -> id)
# -------------------------
$asmData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/asm/policies/"
$asmPolicies = @{}
foreach ($p in $asmData.items) {
    $asmPolicies[$p.name] = $p.id
}

# -------------------------
# Cache ASM host-names
# -------------------------
$asmHostCache = @{}

function Get-AsmHostNames {
    param ($PolicyName)

    if ($asmHostCache.ContainsKey($PolicyName)) {
        return $asmHostCache[$PolicyName]
    }

    if (-not $asmPolicies.ContainsKey($PolicyName)) {
        $asmHostCache[$PolicyName] = @()
        return @()
    }

    $policyId = $asmPolicies[$PolicyName]
    $hostsData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/asm/policies/$policyId/host-names"

    $hosts = @()
    if ($hostsData.items) {
        foreach ($h in $hostsData.items) {
            if ($h.name) {
                $hosts += $h.name
            }
        }
    }

    $asmHostCache[$PolicyName] = $hosts
    return $hosts
}

# -------------------------
# Get L7 DoS profiles
# -------------------------
$dosData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/security/dos/profile"
$dosProfiles = @{}
foreach ($d in $dosData.items) {
    $dosProfiles[$d.name] = $d.fullPath
}

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

    # VS IP / port
    $vsIP = ""
    $vsPort = ""
    if ($vs.destination) {
        $dest = $vs.destination -replace '^/[^/]+/', ''
        if ($dest -match '^(.*):(\d+)$') {
            $vsIP = $matches[1]
            $vsPort = $matches[2]
        }
    }

    # Description tags
    $vsImportance = ""
    $ipPublic = ""
    $itOwner = ""
    $businessOwner = ""
    $waap = ""

    if ($vs.description) {
        if ($vs.description -match '\[utilizare\]:\[(.*?)\]') { $vsImportance = $matches[1] }
        if ($vs.description -match '\[ip_public\]:\[(.*?)\]') { $ipPublic = $matches[1] }
        if ($vs.description -match '\[it_owner\]:\[(.*?)\]') { $itOwner = $matches[1] }
        if ($vs.description -match '\[business_owner\]:\[(.*?)\]') { $businessOwner = $matches[1] }
        if ($vs.description -match '\[waap\]:\[(.*?)\]') { $waap = $matches[1] }
    }

    # Pool members
    $members = Get-NodesFromVS $vs
    if (-not $members) {
        $members = @(@{ address=""; name="" })
    }

    # ASM / DoS detection
    $asmList = @()
    $dosList = @()

    $vsProfilesData = Invoke-BigIPGet (
        "$BaseUrl/mgmt/tm/ltm/virtual/~$($vs.partition)~$($vs.name)/profiles/"
    )

    if ($vsProfilesData.items) {
        foreach ($p in $vsProfilesData.items) {
            $asmName = $p.name -replace '^ASM_', ''
            if ($asmPolicies.ContainsKey($asmName)) {
                $asmList += $asmName
            }
            elseif ($dosProfiles.ContainsKey($p.name)) {
                $dosList += $p.name
            }
        }
    }

    $policiesData = Invoke-BigIPGet (
        "$BaseUrl/mgmt/tm/ltm/virtual/~$($vs.partition)~$($vs.name)/policies/"
    )

    if ($policiesData.items) {
        foreach ($pol in $policiesData.items) {

            if ($pol.name -match '^asm_auto_l7_') { continue }

            $policyPath = "~$($pol.partition)~$($pol.name)"
            $rulesData = Invoke-BigIPGet "$BaseUrl/mgmt/tm/ltm/policy/$policyPath/rules"

            foreach ($r in $rulesData.items) {
                $actionsData = Invoke-BigIPGet (
                    $r.actionsReference.link -replace "https://localhost", $BaseUrl
                )

                foreach ($a in $actionsData.items) {

                    if (($a.asm -eq $true -or $a.asm -eq "true") -and $a.policy) {
                        $asmList += ($a.policy -split '/')[-1]
                    }

                    if (($a.l7dos -eq $true -or $a.l7dos -eq "true") -and $a.fromProfile) {
                        $dosList += ($a.fromProfile -split '/')[-1]
                    }
                }
            }
        }
    }

    $asmList = ($asmList | Sort-Object -Unique | Where-Object { $_ -ne "websecurity" })
    $dosList = ($dosList | Sort-Object -Unique)

    # ASM host-names (excluding shared policies)
    $hostNames = @()
    foreach ($asm in $asmList) {
        if ($ExcludedAsmHostnamePolicies -contains $asm) { continue }
        $hostNames += Get-AsmHostNames $asm
    }

    $asmListOut  = $asmList -join ';'
    $dosListOut  = $dosList -join ';'
    $hostsOut    = ($hostNames | Sort-Object -Unique) -join ';'

    foreach ($m in $members) {
        $nodeIP = $m.address
        $nodePort = ""
        if ($m.name -match ':(\d+)$') {
            $nodePort = $matches[1]
        }

        [PSCustomObject]@{
            VS_Importance         = $vsImportance
            It_owner              = $itOwner
            Business_owner        = $businessOwner
            WAAP                  = $waap
            ASM_Allowed_Hostnames = $hostsOut
            VS_Name               = $vs.name
            IP_Public             = $ipPublic
            VS_IP                 = $vsIP
            VS_Port               = $vsPort
            Node_IP               = $nodeIP
            Node_Port             = $nodePort
            ASM_Policies          = $asmListOut
            DOS_Policies          = $dosListOut
        }
    }
}

# -------------------------
# Sort CSV by VS_Importance order before export
# -------------------------
$csvData | Sort-Object @{Expression={ [array]::IndexOf($importanceOrder,$_."VS_Importance") }; Ascending=$true} |
    Export-Csv "BIGIP_VS_Nodes.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Export completed: BIGIP_VS_Nodes.csv"
