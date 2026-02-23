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
# Read input policies
# Format: PolicyName : PolicyHash
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
# Function to retrieve URLs
# -----------------------------
function Get-PolicyUrls {
    param (
        [string]$PolicyHash,
        [string]$PolicyName
    )

    $Url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyHash/urls"

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
        Write-Host "$PolicyName - URLs retrieved"
        Start-Sleep -Milliseconds 500
        return $data.items
    }
    catch {
        Write-Warning "Failed retrieving URLs for $PolicyName : $_"
        return @()
    }
}

# -----------------------------
# Collect data
# -----------------------------
$Rows = @()

foreach ($Policy in $Policies) {

    Write-Host "`nQuerying policy: $($Policy.PolicyName)"

    $Urls = Get-PolicyUrls -PolicyHash $Policy.PolicyHash -PolicyName $Policy.PolicyName

    foreach ($UrlItem in $Urls) {

        $UrlName  = $UrlItem.name
        $Method   = $UrlItem.method
        $Protocol = $UrlItem.protocol

        if (-not $UrlItem.urlContentProfiles) {
            $Rows += [PSCustomObject]@{
                SecurityPolicy = $Policy.PolicyName
                URL            = $UrlName
                Method         = $Method
                Protocol       = $Protocol
                HeaderOrder    = ""
                HeaderName     = ""
                HeaderValue    = ""
                Action         = ""
            }
            continue
        }

        # Normalize headerOrder (default = 0)
        $SortedProfiles = $UrlItem.urlContentProfiles | ForEach-Object {

            $orderValue = if ($_.headerOrder -eq "default") {
                0
            }
            else {
                [int]$_.headerOrder
            }

            $_ | Add-Member -NotePropertyName NumericOrder -NotePropertyValue $orderValue -PassThru
        } | Sort-Object NumericOrder

        foreach ($HeaderRule in $SortedProfiles) {

            $Rows += [PSCustomObject]@{
                SecurityPolicy = $Policy.PolicyName
                URL            = $UrlName
                Method         = $Method
                Protocol       = $Protocol
                HeaderOrder    = $HeaderRule.NumericOrder
                HeaderName     = $HeaderRule.headerName
                HeaderValue    = $HeaderRule.headerValue
                Action         = $HeaderRule.type
            }
        }
    }
}

# -----------------------------
# Export CSV
# -----------------------------
$DateStamp = (Get-Date).ToString("MMddyyyy")
$TimeStamp = (Get-Date).ToString("HHmm")
$InputListName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)

$ExportFileName = "$DateStamp-$InputListName-URLs-$TimeStamp.csv"
$ExportFile = Join-Path -Path (Get-Location) -ChildPath $ExportFileName

$Rows | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8

Write-Host "`nExport completed: $ExportFile"
