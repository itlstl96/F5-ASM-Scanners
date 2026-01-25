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

# Force TLS 1.2 for BIG-IP REST API
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disable SSL certificate validation (BIG-IP often uses self‑signed certs)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Build URL using input Port
$Url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies"

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

# Read response JSON
$stream = $response.GetResponseStream()
$reader = New-Object System.IO.StreamReader($stream)
$json = $reader.ReadToEnd()
$reader.Close()

# Convert to PowerShell object
$data = $json | ConvertFrom-Json

# Prepare output file path
$OutputFile = Join-Path -Path (Get-Location) -ChildPath "ASM_Policies_Export.txt"

# Output policies to console and file
if ($data.items) {
    $outputLines = @()
    foreach ($policy in $data.items) {
        $policyId = if ($policy.id) { $policy.id } else { "N/A" }
        $line = "$($policy.name) : $policyId"
        Write-Output $line          # console
        $outputLines += $line       # collect for file
    }
    # Save to text file
    $outputLines | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "Policies exported to $OutputFile"
} else {
    Write-Host "No policies found."
    "No policies found." | Out-File -FilePath $OutputFile -Encoding UTF8
}
