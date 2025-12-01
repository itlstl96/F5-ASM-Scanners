<#
.SYNOPSIS
    Scan F5 ASM/WAF Entity Configs

.DESCRIPTION
    Queries a BIG-IP device for ASM entity configurations from enabled security policies
    and exports results to CSV.

.AUTHOR
    PGV
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$true)]
    [string]$PolicyFile,

    [int]$Port = 8443
)

# -----------------------------
# Banner
# -----------------------------
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "        ⚠  F5 - ASM ENTITIES SCANNER  (CLI MODE)" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Author: PGV`n" -ForegroundColor Green

# -----------------------------
# Prompt for password securely
# -----------------------------
$Password = Read-Host -AsSecureString "🔐 Enter password for user '$User'"
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# -----------------------------
# Config
# -----------------------------
$CsvOutputFile = "ASM_Entities_Report.csv"
$BaseUrl = "https://$BigIPHost`:$Port/mgmt/tm"
$Headers = @{ "Content-Type" = "application/json" }
$Rows = @()

# -----------------------------
# Read policies
# -----------------------------
if (-not (Test-Path $PolicyFile)) {
    Write-Error "❌ Policy file '$PolicyFile' not found."
    exit 1
}

$Policies = @()
Get-Content $PolicyFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and $line -notmatch "^\(-\)") {
        if ($line -match "^\(\+\)") { $line = $line.Substring(3) }
        $parts = $line.Split(":", 2)
        if ($parts.Count -eq 2) {
            $Policies += [PSCustomObject]@{ PolicyHash = $parts[1]; PolicyName = $parts[0] }
        }
    }
}

if ($Policies.Count -eq 0) {
    Write-Warning "⚠ No enabled policies found."
    exit 0
}

Write-Host "`n🚀 Starting scan of $($Policies.Count) enabled policies...`n"

# -----------------------------
# Helper: query entities
# -----------------------------
function Get-Entities {
    param(
        [string]$PolicyHash,
        [string]$EntityType
    )
    $Url = "$BaseUrl/asm/policies/$PolicyHash/$EntityType"
    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers `
            -Credential (New-Object System.Management.Automation.PSCredential($User, $Password)) `
            -SkipCertificateCheck
        Start-Sleep -Milliseconds 500
        Write-Host "   ✅ $EntityType retrieved successfully"
        return $Response.items
    } catch {
        Write-Warning ("   ❌ Failed to query {0}: {1}" -f $EntityType, $_.Exception.Message)
        return @()
    }
}


# -----------------------------
# Entity types to query
# -----------------------------
$EntityTypes = @("parameters","urls","cookies","headers","json-profiles")

# -----------------------------
# Collect data
# -----------------------------
foreach ($Policy in $Policies) {
    Write-Host "`n⏳ Querying policy: $($Policy.PolicyName) ($($Policy.PolicyHash))"

    foreach ($EntityType in $EntityTypes) {
        $Items = Get-Entities -PolicyHash $Policy.PolicyHash -EntityType $EntityType
        foreach ($Item in $Items) {
            $CheckSignatures = if ($EntityType -eq "headers") { $Item.checkSignatures } else { $Item.attackSignaturesCheck }

            $Row = [PSCustomObject]@{
                "SecurityPolicy"        = $Policy.PolicyName
                "EntityType"            = ($EntityType -replace "-", " ") -replace "\b\w", { $_.Value.ToUpper() }
                "EntityName"            = $Item.name
                "AttackSignaturesCheck" = $CheckSignatures
                "Staged"                = $Item.performStaging
                "Sensitive"             = if ($Item.sensitiveParameter) { $Item.sensitiveParameter } else { $Item.sensitiveCookie }
                "SignatureOverrides"    = ($Item.signatureOverrides | ForEach-Object { "$($_.signatureReference.signatureId) - $($_.signatureReference.name)" }) -join "`n"
            }

            $Rows += $Row
        }
    }
}

# -----------------------------
# Export CSV
# -----------------------------
try {
    $Rows | Export-Csv -Path $CsvOutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n📁 CSV report saved as $CsvOutputFile" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to export CSV: $_"
    exit 1
}

Write-Host "`n✅ Scan complete. Total policies scanned: $($Policies.Count)"
