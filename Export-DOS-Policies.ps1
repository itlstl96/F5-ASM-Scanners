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

# DoS L7 Profile endpoint
$Url = "https://$BigIPHost`:$Port/mgmt/tm/security/dos/profile"

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
$stream = $response.GetResponseStream()
$reader = New-Object System.IO.StreamReader($stream)
$json = $reader.ReadToEnd()
$reader.Close()

# Convert JSON
$data = $json | ConvertFrom-Json

# Output file
$OutputFile = Join-Path -Path (Get-Location) -ChildPath "L7_DOS_Profiles_Export.txt"

if ($data.items) {
    $outputLines = @()

    foreach ($profile in $data.items) {
        $name       = $profile.name
        $partition  = $profile.partition
        $fullPath   = $profile.fullPath
        $selfLink   = $profile.selfLink
        $appLink    = if ($profile.applicationReference) {
            $profile.applicationReference.link
        } else {
            "N/A"
        }

        $line = "$fullPath | AppURL: $appLink"
        Write-Output $line
        $outputLines += $line
    }

    $outputLines | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "L7 DoS profiles exported to $OutputFile"
}
else {
    Write-Host "No L7 DoS profiles found."
    "No L7 DoS profiles found." | Out-File -FilePath $OutputFile -Encoding UTF8
}
