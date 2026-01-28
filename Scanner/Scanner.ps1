# ================= BigIP Scanner Menu =================

function Show-Menu {
    Clear-Host
    Write-Host "================= BigIP Scanner Menu =================" -ForegroundColor Cyan
    Write-Host "1. Scan ASM Entities"
    Write-Host "2. Scan ASM Signature Sets"
    Write-Host "3. Scan ASM Signatures"
    Write-Host "4. Scan ASM Sub Violations"
    Write-Host "5. Scan ASM Violations"
    Write-Host "6. Scan DOS Config"
    Write-Host "0. Exit"
    Write-Host "======================================================"
}

$ScriptMap = @{
    "1" = "Scan-ASM-Entities.ps1"
    "2" = "Scan-ASM-Signature-Sets.ps1"
    "3" = "Scan-ASM-Signatures.ps1"
    "4" = "Scan-ASM-Sub-Violations.ps1"
    "5" = "Scan-ASM-Violations.ps1"
    "6" = "Scan-DOS-config.ps1"
}

# -----------------------------
# Ask user for BigIP credentials ONCE
# -----------------------------
$BigIPHost = Read-Host "Enter BigIP Host"
$Port      = Read-Host "Enter Port (e.g., 443 or 8443)"
$User      = Read-Host "Enter Username"

# Convert Port safely
try {
    $Port = [int]$Port
}
catch {
    Write-Host "`nInvalid port number. Exiting..." -ForegroundColor Red
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Enter your choice"

    if ($choice -eq "0") {
        Write-Host "`nExiting..." -ForegroundColor Yellow
        break
    }

    if (-not $ScriptMap.ContainsKey($choice)) {
        Write-Host "`nInvalid selection. Try again." -ForegroundColor Red
        Start-Sleep 1
        continue
    }

    $ScriptName = $ScriptMap[$choice]
    $ScriptPath = Join-Path $PSScriptRoot $ScriptName

    if (-not (Test-Path $ScriptPath)) {
        Write-Host "`nScript not found: $ScriptName" -ForegroundColor Red
        Read-Host "`nPress ENTER to return to menu"
        continue
    }

    # -----------------------------
    # Prompt only for InputFile
    # -----------------------------
    $InputFile = Read-Host "Enter Input File (file name or full path)"

    # If InputFile is relative, assume same folder
    if (-not (Test-Path $InputFile)) {
        $InputFile = Join-Path $PSScriptRoot $InputFile
    }

    if (-not (Test-Path $InputFile)) {
        Write-Host "`nInput file not found: $InputFile" -ForegroundColor Red
        Read-Host "`nPress ENTER to return to menu"
        continue
    }

    # -----------------------------
    # Execute selected script
    # -----------------------------
    Write-Host "`nRunning $ScriptName ...`n" -ForegroundColor Green

    try {
        & $ScriptPath `
            -BigIPHost $BigIPHost `
            -Port $Port `
            -User $User `
            -InputFile $InputFile
    }
    catch {
        Write-Host "Error executing ${ScriptName}: $_" -ForegroundColor Red
    }

    Read-Host "`nPress ENTER to return to menu"

} while ($true)
