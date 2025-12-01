<#
.SYNOPSIS
    Export F5 ASM/WAF Security Policies

.DESCRIPTION
    Queries a BIG-IP device for ASM security policies and saves them
    to a local file in the format: PolicyName:PolicyID

.AUTHOR
    PGV
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [int]$Port = 8443
)

# -----------------------------
# Banner
# -----------------------------
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "        ⚠  F5 - ASM POLICIES LISTER  (CLI MODE)" -ForegroundColor Cyan
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
$OutputFile = "ASM_security_policies.txt"
$BaseUrl = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies"

# Create a WebSession
$Headers = @{
    "Content-Type" = "application/json"
}

# -----------------------------
# Fetch policies
# -----------------------------
try {
    $Response = Invoke-RestMethod -Uri $BaseUrl -Method Get -Headers $Headers -Credential (New-Object System.Management.Automation.PSCredential($User, $Password)) -SkipCertificateCheck
} catch {
    Write-Error "❌ Connection error while fetching policies: $_"
    exit 1
}

if (-not $Response.items) {
    Write-Warning "⚠ No policies found or request failed."
    exit 0
}

# -----------------------------
# Print and save policies
# -----------------------------
Write-Host "`n📌 Found $($Response.items.Count) security policies`n"

$Response.items | ForEach-Object {
    $PolicyName = $_.name
    $PolicyID   = $_.id
    Write-Host "$PolicyName : $PolicyID"
} 

# Write to file
try {
    $Response.items | ForEach-Object {
        "$($_.name):$($_.id)" | Out-File -FilePath $OutputFile -Encoding utf8 -Append
    }

    Write-Host "`n✅ Policies saved to $OutputFile" -ForegroundColor Green
} catch {
    Write-Error "❌ Error writing file: $_"
    exit 1
}
