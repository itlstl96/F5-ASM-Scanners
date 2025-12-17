param (
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$false)]
    [string]$OutputCsv = "L7_DOS_Profiles_Report.csv"
)

# Prompt for password securely
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString

# Convert secure password → plain text
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# TLS + ignore SSL certs
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Prepare Basic Auth header
$AuthString = "$User`:$PlainPassword"
$AuthHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthString))

$Results = @()

# Read input file
$InputLines = Get-Content $InputFile
$total = $InputLines.Count
$counter = 0

foreach ($line in $InputLines) {

    if ($line -match "AppURL:\s+(https://.+?)/application") {

        $counter++
        $BasePath = $matches[1]

        # Build URLs
        $ProfileUrl     = "https://$BigIPHost`:$Port$($BasePath -replace '^https://localhost')"
        $ApplicationUrl = "$ProfileUrl/application"

        try {
            # ----------------------
            # Get profile info
            # ----------------------
            $reqProfile = [System.Net.HttpWebRequest]::Create($ProfileUrl)
            $reqProfile.Method = "GET"
            $reqProfile.Headers["Authorization"] = "Basic $AuthHeader"
            $reqProfile.Accept = "application/json"

            $respProfile = $reqProfile.GetResponse()
            $jsonProfile = (New-Object IO.StreamReader($respProfile.GetResponseStream())).ReadToEnd()
            $profile = $jsonProfile | ConvertFrom-Json

            $whitelistPath = if ($profile.httpWhitelist) { $profile.httpWhitelist } else { "N/A" }

            Start-Sleep -Seconds 1  # Delay after request

            # ----------------------
            # Get application info
            # ----------------------
            $reqApp = [System.Net.HttpWebRequest]::Create($ApplicationUrl)
            $reqApp.Method = "GET"
            $reqApp.Headers["Authorization"] = "Basic $AuthHeader"
            $reqApp.Accept = "application/json"

            $respApp = $reqApp.GetResponse()
            $jsonApp = (New-Object IO.StreamReader($respApp.GetResponseStream())).ReadToEnd()
            $appData = $jsonApp | ConvertFrom-Json

            Start-Sleep -Seconds 1  # Delay after request

            # TPS-based
            $tps = $null
            if ($appData.items -and $appData.items[0].tpsBased) {
                $tps = $appData.items[0].tpsBased
            }

            # Heavy URLs (line break for CSV)
            $heavyUrls = "N/A"
            if ($appData.items -and $appData.items[0].heavyUrls -and $appData.items[0].heavyUrls.includeList) {
                $heavyUrls = ($appData.items[0].heavyUrls.includeList | ForEach-Object {
                    "$($_.url) ($($_.threshold))"
                }) -join "`n"
            }

            # Build result object
            $Results += [PSCustomObject]@{
                ProfileName          = $profile.name
                FullPath             = $profile.fullPath

                HttpWhitelistEnabled = [bool]$profile.httpWhitelist
                HttpWhitelist        = $whitelistPath

                TpsMode              = if ($tps) { $tps.mode } else { "N/A" }
                UrlMinAutoTps        = if ($tps) { $tps.urlMinimumAutoTps } else { "N/A" }
                UrlMaxAutoTps        = if ($tps) { $tps.urlMaximumAutoTps } else { "N/A" }
                IpMinAutoTps         = if ($tps) { $tps.ipMinimumAutoTps } else { "N/A" }
                IpMaxAutoTps         = if ($tps) { $tps.ipMaximumAutoTps } else { "N/A" }
                UrlEnableHeavy       = if ($tps) { $tps.urlEnableHeavy } else { "N/A" }

                HeavyUrls            = $heavyUrls
            }

            Write-Host "[$counter/$total] $($profile.fullPath) ... OK" -ForegroundColor Green
        }
        catch {
            $Results += [PSCustomObject]@{
                ProfileName          = "ERROR"
                FullPath             = $ProfileUrl
                HttpWhitelistEnabled = $false
                HttpWhitelist        = "Query Failed"
                TpsMode              = "ERROR"
                UrlMinAutoTps        = "ERROR"
                UrlMaxAutoTps        = "ERROR"
                IpMinAutoTps         = "ERROR"
                IpMaxAutoTps         = "ERROR"
                UrlEnableHeavy       = "ERROR"
                HeavyUrls            = "ERROR"
            }

            Write-Host "[$counter/$total] $ProfileUrl ... FAILED" -ForegroundColor Red
        }
    }
}

# ----------------------
# Export to CSV
# ----------------------
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV exported to $OutputCsv" -ForegroundColor Green
