param (
    [Parameter(Mandatory=$true)]
    [string]$BigIPHost,

    [Parameter(Mandatory=$true)]
    [int]$Port,

    [Parameter(Mandatory=$true)]
    [string]$User
)

# Prompt for password securely
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString

# Convert secure password → plain text
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disable SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Virtual Server endpoint
$Url = "https://$BigIPHost`:$Port/mgmt/tm/ltm/virtual"

# Prepare HTTP request
$AuthString = "$User`:$PlainPassword"
$AuthHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthString))

$request = [System.Net.HttpWebRequest]::Create($Url)
$request.Method = "GET"
$request.Headers["Authorization"] = "Basic $AuthHeader"
$request.Accept = "application/json"

# Send request
try {
    $response = $request.GetResponse()
} catch {
    Write-Host "ERROR: Cannot connect to BIG-IP at $BigIPHost on port $Port"
    Write-Host $_.Exception.Message
    exit 1
}

# Read response
$reader = New-Object System.IO.StreamReader($response.GetResponseStream())
$json = $reader.ReadToEnd()
$reader.Close()

$data = $json | ConvertFrom-Json

# Output CSV path
$OutputFile = Join-Path (Get-Location) "Virtual_Servers_Export.csv"

if ($data.items) {

    $csvData = foreach ($vs in $data.items) {

        $securityProfiles = if ($vs.securityLogProfiles) {
            ($vs.securityLogProfiles -replace '^"|"$') -join "; "
        } else {
            ""
        }

        [PSCustomObject]@{
            name               = $vs.name
            creationTime       = $vs.creationTime
            lastModifiedTime   = $vs.lastModifiedTime
            destination        = $vs.destination
            securityLogProfiles= $securityProfiles
            connectionLimit    = $vs.connectionLimit
            rateLimit          = $vs.rateLimit
            flowEvictionPolicy = $vs.flowEvictionPolicy
        }
    }

    $csvData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Virtual servers exported to $OutputFile"
}
else {
    Write-Host "No virtual servers found."
}
