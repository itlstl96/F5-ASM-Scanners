#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory=$true)][string]$BigIPHost,
    [Parameter(Mandatory=$true)][string]$User,
    [int]$Port = 8443,
    [Parameter(Mandatory=$true)][string]$PolicyFile,
    [Parameter(Mandatory=$true)][string]$ViolationsFile
)

# -----------------------------
# Banner
# -----------------------------
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "        F5 - ASM - Violations Scanner (CLI MODE)" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Author: PGV`n"

# -----------------------------
# Password prompt (hidden)
# -----------------------------
$SecurePassword = Read-Host -AsSecureString "🔐 Enter password for user '$User'"
$Credential = New-Object System.Management.Automation.PSCredential($User, $SecurePassword)

$HttpsRequestCount = 0
$Headers = @{ "Content-Type" = "application/json" }

# -----------------------------
# Load policies file
# -----------------------------
if (!(Test-Path $PolicyFile)) {
    Write-Error "❌ Policy file not found: $PolicyFile"
    exit 1
}

$Policies = @()
Get-Content $PolicyFile | ForEach-Object {
    $line = $_.Trim()
    if (!$line -or !$line.Contains(":")) { return }
    $parts = $line.Split(":",2)
    $Policies += ,@($parts[0].Trim(), $parts[1].Trim())
}

# -----------------------------
# Load violation descriptions
# -----------------------------
if (!(Test-Path $ViolationsFile)) {
    Write-Error "❌ Violation list file not found: $ViolationsFile"
    exit 1
}

$ViolationList = @()
Get-Content $ViolationsFile | ForEach-Object {
    $v = $_.Trim()
    if ($v) { $ViolationList += $v }
}

# -----------------------------
# Query violations from BIG-IP
# -----------------------------
function Get-Violations {
    param([string]$PolicyHash)

    $Url = "https://${BigIPHost}:${Port}/mgmt/tm/asm/policies/${PolicyHash}/blocking-settings/violations/"
    try {
        $Resp = Invoke-RestMethod -Uri $Url -Method Get -Headers $Headers -Credential $Credential -SkipCertificateCheck -TimeoutSec 15
        $script:HttpsRequestCount++
        Write-Host "✅ Request OK → $PolicyHash"
        return $Resp.items
    } catch {
        Write-Warning "❌ Error fetching violations for policy ${PolicyHash}: $($_.Exception.Message)"
        return @()
    } finally {
        Start-Sleep 1  # ⏱ 1 second delay between each request
    }
}

# -----------------------------
# Collect results
# -----------------------------
$Rows = @()

foreach ($p in $Policies) {
    $PolicyName = $p[0]
    $PolicyHash = $p[1]

    Write-Host "`n⏳ Scanning policy: $PolicyName ($PolicyHash)"

    $Violations = Get-Violations -PolicyHash $PolicyHash

    foreach ($v in $Violations) {
        $Desc = $v.description.Trim()

        foreach ($item in $ViolationList) {
            if ($Desc.ToLower().Contains($item.ToLower())) {
                $Rows += ,@(
                    $PolicyName,
                    $Desc,
                    ($v.block ? "true" : "false"),
                    ($v.alarm ? "true" : "false"),
                    ($v.learn ? "true" : "false")
                )
                break
            }
        }
    }
}

# -----------------------------
# Export results to CSV (overwrite each run)
# -----------------------------
$CsvFile = "ASM_violation_scan_results.csv"

$OutRows = @()
$OutRows += "Policy,Violation Description,Block,Alarm,Learn"

foreach ($row in $Rows) {
    $OutRows += "$($row[0]),`"$($row[1])`",$($row[2]),$($row[3]),$($row[4])"
}

$OutRows | Out-File -FilePath $CsvFile -Encoding utf8 -Force

Write-Host "`n📁 CSV results exported to $CsvFile" -ForegroundColor Green

# -----------------------------
# Print aligned table to CLI
# -----------------------------
if (!$Rows) {
    Write-Host "`n⚠ No matching violations found."
} else {

    $HeadersRow = @("Policy", "Violation Description", "Block", "Alarm", "Learn")

    $ColWidths = @(0,0,0,0,0)
    for ($i = 0; $i -lt 5; $i++) {
        $max = ($Rows | ForEach-Object { 
            if ($null -ne $_[$i]) { $_[$i].Length } else { 0 }
        } | Measure-Object -Maximum).Maximum
        $ColWidths[$i] = [Math]::Max($max, $HeadersRow[$i].Length)
    }

    $HeaderLine = ""
    for ($i = 0; $i -lt 5; $i++) {
        $HeaderLine += $HeadersRow[$i].PadRight($ColWidths[$i])
        if ($i -lt 4) { $HeaderLine += " | " }
    }

    Write-Host "`n📊 Scan Results:`n"
    Write-Host $HeaderLine

    Write-Host (("-" * $ColWidths[0]) + "-+-" +
               ("-" * $ColWidths[1]) + "-+-" +
               ("-" * $ColWidths[2]) + "-+-" +
               ("-" * $ColWidths[3]) + "-+-" +
               ("-" * $ColWidths[4]))

    $Rows | ForEach-Object {
        $line = ""
        for ($i = 0; $i -lt 5; $i++) {
            if ($null -ne $_[$i]) {
                $line += $_[$i].PadRight($ColWidths[$i])
            } else {
                $line += "".PadRight($ColWidths[$i])
            }
            if ($i -lt 4) { $line += " | " }
        }
        Write-Host $line
    }
}

# -----------------------------
# HTTPS stats
# -----------------------------
Write-Host "`n🔎 Scan complete!" -ForegroundColor Green
Write-Host "🌐 Total HTTPS requests made to BIG-IP: $($script:HttpsRequestCount)" -ForegroundColor Yellow
