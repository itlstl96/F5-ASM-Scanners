param (
    [Parameter(Mandatory = $true)]
    [string]$BigIPHost,

    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$User
)

# -------------------------
# Authentication
# -------------------------

$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$BaseUrl = "https://$BigIPHost`:$Port"
$ClientSSLUrl = "$BaseUrl/mgmt/tm/ltm/profile/client-ssl"

$AuthHeader = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("$User`:$PlainPassword")
)

$Headers = @{ Authorization = "Basic $AuthHeader" }

# -------------------------
# Helper function
# -------------------------

function Invoke-BigIPGet {
    param ($Url)

    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = $Headers.Authorization
        $req.Accept = "application/json"

        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $reader.ReadToEnd() | ConvertFrom-Json
    }
    catch {
        Write-Host "Failed to query $Url"
        return $null
    }
}

# -------------------------
# Get Client SSL Profiles
# -------------------------

$data = Invoke-BigIPGet $ClientSSLUrl

if (-not $data.items) {
    Write-Host "No Client SSL profiles found."
    exit 1
}

# -------------------------
# Process Profiles
# -------------------------

$csvData = foreach ($profile in $data.items) {

    # Some profiles may use certKeyChain instead of direct cert/key fields
    $cert  = $profile.cert
    $key   = $profile.key
    $chain = $profile.chain

    if (-not $cert -and $profile.certKeyChain) {
        $cert  = $profile.certKeyChain[0].cert
        $key   = $profile.certKeyChain[0].key
        $chain = $profile.certKeyChain[0].chain
    }

    [PSCustomObject]@{
        name      = $profile.name
        cert      = $cert
        key       = $key
        chain     = $chain
        tmOptions = $profile.tmOptions
    }
}

# -------------------------
# Export CSV
# -------------------------

$csvPath = "Client_SSL_Profiles_Export.csv"
$csvData | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Export completed successfully."
Write-Host "File saved as $csvPath"
