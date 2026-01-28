param (
    [Parameter(Mandatory = $true)]
    [string]$BigIPHost,

    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$user
)

function Show-Menu {
    Clear-Host
    Write-Host "============================================"
    Write-Host "============================================"
    Write-Host "====         BIG-IP Export Menu         ===="
    Write-Host "====                        author: PGV ===="
    Write-Host "============================================"
    Write-Host "============================================"
    Write-Host "1. Export ASM policies"
    Write-Host "2. Export DOS policies"
    Write-Host "3. Export Virtual Server details"
    Write-Host "Q. Quit"
    Write-Host ""
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1, 2, 3, Q)"

    switch ($choice.ToUpper()) {

        "1" {
            Write-Host "`nRunning ExportASM.ps1...`n"
            & ".\ExportASM.ps1" `
                -BigIPHost $BigIPHost `
                -Port $Port `
                -user $user

            Read-Host "`nPress ENTER to return to menu"
        }

        "2" {
            Write-Host "`nRunning ExportDOS.ps1...`n"
            & ".\ExportDOS.ps1" `
                -BigIPHost $BigIPHost `
                -Port $Port `
                -user $user

            Read-Host "`nPress ENTER to return to menu"
        }

        "3" {
            Write-Host "`nRunning ExportVS.ps1...`n"
            & ".\ExportVS.ps1" `
                -BigIPHost $BigIPHost `
                -Port $Port `
                -user $user

            Read-Host "`nPress ENTER to return to menu"
        }

        "Q" {
            Write-Host "`nExiting..."
        }

        default {
            Write-Host "`nInvalid selection. Try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }

} while ($choice.ToUpper() -ne "Q")
