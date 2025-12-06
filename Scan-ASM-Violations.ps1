param (
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$true)]
    [string]$PolicyFile,

    [Parameter(Mandatory=$true)]
    [string]$ViolationsFile
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
# Load policies
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
}

# -----------------------------
# Load violation descriptions
# -----------------------------
$ViolationFilters = Get-Content $ViolationsFile | Where-Object { $_.Trim() -ne "" }

# -----------------------------
# Function: Get ASM Violations
# -----------------------------
function Get-PolicyViolations {
    param([string]$PolicyID)

    $url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyID/blocking-settings/violations/"
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = "GET"
    $req.Headers["Authorization"] = $AuthHeader
    $req.Accept = "application/json"

    try {
        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()

        Start-Sleep -Seconds 1   ### ADDED: 1s delay after every BIG-IP query

        return (ConvertFrom-Json $json).items
    }
    catch {
        Write-Warning "❌ Failed to fetch violations for policy $PolicyID"
        return @()
    }
}

# -----------------------------
# Live header before loop  ### ADDED
# -----------------------------
Write-Host ""
Write-Host ("{0,-25} | {1,-50} | {2,5} | {3,5} | {4,5}" -f `
    "Policy","Violation Description","Block","Alarm","Learn")
Write-Host ("-" * 105)

# -----------------------------
# Scan and LIVE output
# -----------------------------
$Results = @()

foreach ($policy in $Policies) {
    $violations = Get-PolicyViolations -PolicyID $policy.ID

    foreach ($v in $violations) {
        $desc = $v.description.Trim()

        foreach ($vf in $ViolationFilters) {
            if ($desc.ToLower().Contains($vf.ToLower())) {

                $row = [PSCustomObject]@{
                    Policy      = $policy.Name
                    Description = $desc
                    Block       = $v.block
                    Alarm       = $v.alarm
                    Learn       = $v.learn
                }

                $Results += $row

                # ------- LIVE PRINT --------  ### ADDED
                Write-Host ("{0,-25} | {1,-50} | {2,5} | {3,5} | {4,5}" -f `
                    $row.Policy, $row.Description, $row.Block, $row.Alarm, $row.Learn)

                break
            }
        }
    }
}

# -----------------------------
# Final summary
# -----------------------------
Write-Host ""
Write-Host "Scan complete. Total results: $($Results.Count)"
