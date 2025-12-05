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
# Read input policies from file
# -----------------------------
$Policies = Get-Content -Path $InputFile | ForEach-Object {
    if ($_ -match "^(.*)\s*:\s*(.*)$") {
        [PSCustomObject]@{
            PolicyName = $matches[1].Trim()
            PolicyHash = $matches[2].Trim()
        }
    }
}

# -----------------------------
# Entity types to query
# -----------------------------
$EntityTypes = @("parameters","urls","cookies","headers","json-profiles")

# -----------------------------
# Function to get entities per policy and entity type
# -----------------------------
function Get-Entities {
    param (
        [string]$PolicyHash,
        [string]$EntityType,
        [string]$PolicyName
    )

    $Url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyHash/$EntityType"

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

        # Confirmation message
        Write-Host "$PolicyName - $EntityType - ok"

        # 1-second delay after request
        Start-Sleep -Seconds 1

        return $data.items
    } catch {
        Write-Warning "Failed to retrieve $EntityType for policy $PolicyHash`: $_"
        # Still wait 1 second to avoid flooding BIG-IP
        Start-Sleep -Seconds 1
        return @()
    }
}

# -----------------------------
# Collect data
# -----------------------------
$Rows = @()

foreach ($Policy in $Policies) {
    Write-Host "`n⏳ Querying policy: $($Policy.PolicyName) ($($Policy.PolicyHash))"

    foreach ($EntityType in $EntityTypes) {
        $Items = Get-Entities -PolicyHash $Policy.PolicyHash -EntityType $EntityType -PolicyName $Policy.PolicyName

        foreach ($Item in $Items) {

            # Determine attack signature check
            $CheckSignatures = if ($EntityType -eq "headers") { $Item.checkSignatures } else { $Item.attackSignaturesCheck }

            # Capitalize first letter of EntityType
            $CleanEntityType = ($EntityType -replace "-", " ")
            $CleanEntityType = $CleanEntityType.Substring(0,1).ToUpper() + $CleanEntityType.Substring(1)

            $Row = [PSCustomObject]@{
                SecurityPolicy        = $Policy.PolicyName
                EntityType            = $CleanEntityType
                EntityName            = $Item.name
                AttackSignaturesCheck = $CheckSignatures
                Staged                = $Item.performStaging
                Sensitive             = if ($Item.sensitiveParameter) { $Item.sensitiveParameter } else { $Item.sensitiveCookie }
                SignatureOverrides    = ($Item.signatureOverrides | ForEach-Object { "$($_.signatureReference.signatureId) - $($_.signatureReference.name)" }) -join "`n"
            }

            $Rows += $Row
        }
    }
}

# -----------------------------
# Output table and export
# -----------------------------
$Rows | Format-Table -AutoSize

$ExportFile = Join-Path -Path (Get-Location) -ChildPath "ASM_Entities_Export.csv"
$Rows | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "`nAll entities exported to $ExportFile"
