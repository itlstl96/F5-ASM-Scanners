param (
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$true)]
    [string]$InputFile
)

# -----------------------------
# Prompt for password securely
# -----------------------------
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# -----------------------------
# Configure networking
# -----------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Prepare basic auth header
$AuthString = "$User`:$PlainPassword"
$AuthHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthString))

# -----------------------------
# Read policy IDs from file
# -----------------------------
$Policies = Get-Content -Path $InputFile | ForEach-Object {
    $_ = $_.Trim()
    if ($_ -eq "") { return }
    if ($_ -match "^(.*)\s*:\s*(.*)$") {
        [PSCustomObject]@{
            PolicyName = $matches[1].Trim()
            PolicyHash = $matches[2].Trim()
        }
    } else {
        [PSCustomObject]@{
            PolicyName = $_
            PolicyHash = $_
        }
    }
}

# -----------------------------
# Function to get policy name
# -----------------------------
function Get-PolicyName {
    param([string]$PolicyHash)

    $Url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyHash"
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = "GET"
    $request.Headers["Authorization"] = "Basic $AuthHeader"
    $request.Accept = "application/json"

    try {
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $json = $reader.ReadToEnd()
        $reader.Close()

        $data = $json | ConvertFrom-Json
        return $data.name
    } catch {
        return $PolicyHash
    }
}

# -----------------------------
# Function to get signatures for a policy
# -----------------------------
function Get-PolicySignatures {
    param([string]$PolicyHash)

    $Url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyHash/signatures"
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = "GET"
    $request.Headers["Authorization"] = "Basic $AuthHeader"
    $request.Accept = "application/json"

    try {
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $json = $reader.ReadToEnd()
        $reader.Close()

        $data = $json | ConvertFrom-Json
        return $data.items
    } catch {
        Write-Warning "Failed to get signatures for policy $PolicyHash': $_"
        return @()
    }
}

# -----------------------------
# Output table header
# -----------------------------
Write-Host ""
Write-Host "=============================="
Write-Host ("{0,-25} {1,6} {2,6} {3,8} {4,8} {5,6}" -f "Policy Name","ALARM","BLOCK","STAGING","ENABLED","TOTAL")
Write-Host ("=" * 65)

# -----------------------------
# Process each policy
# -----------------------------
foreach ($Policy in $Policies) {
    $PolicyName = Get-PolicyName -PolicyHash $Policy.PolicyHash
    $Signatures = Get-PolicySignatures -PolicyHash $Policy.PolicyHash

    $Counts = @{
        alarm         = ($Signatures | Where-Object { $_.alarm -eq $true }).Count
        block         = ($Signatures | Where-Object { $_.block -eq $true }).Count
        performStaging= ($Signatures | Where-Object { $_.performStaging -eq $true }).Count
        enabled       = ($Signatures | Where-Object { $_.enabled -eq $true }).Count
        total         = $Signatures.Count
    }

    # Print row
    Write-Host ("{0,-25} {1,6} {2,6} {3,8} {4,8} {5,6}" -f `
        $PolicyName, $Counts.alarm, $Counts.block, $Counts.performStaging, $Counts.enabled, $Counts.total)
}
