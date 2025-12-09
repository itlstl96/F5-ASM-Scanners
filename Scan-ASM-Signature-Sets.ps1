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

# Authentication header
$AuthString = "$User`:$PlainPassword"
$AuthHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthString))

# Build dynamic CSV file name
$Now = Get-Date
$DatePart = $Now.ToString("MMddyyyy")
$TimePart = $Now.ToString("HHmm")
$InputFileName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
$OutputFile = Join-Path -Path (Get-Location) -ChildPath "$DatePart-$InputFileName-SignatureSets-$TimePart.csv"

# Read input file (PolicyName : PolicyID)
$PolicyList = @()
Get-Content $InputFile | ForEach-Object {
    if ($_ -match "^(.*)\s*:\s*(.*)$") {
        $PolicyList += [PSCustomObject]@{
            PolicyName = $matches[1].Trim()
            PolicyID   = $matches[2].Trim()
        }
    }
}

# Function to query ASM API
function Get-ASM {
    param (
        [string]$Url
    )
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = "Basic $AuthHeader"
        $req.Accept = "application/json"

        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()
        return ($json | ConvertFrom-Json)
    }
    catch {
        Write-Host "ERROR: Request failed for $Url"
        Write-Host $_.Exception.Message
        return $null
    }
}

# Collect all unique signature set names across all policies
$AllSignatureSets = @{}

foreach ($policy in $PolicyList) {
    $SigUrl = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$($policy.PolicyID)/signature-sets"
    $SigSets = Get-ASM -Url $SigUrl
    if ($SigSets -and $SigSets.items) {
        foreach ($sig in $SigSets.items) {
            $sigName = $sig.signatureSetReference.name
            if (-not $AllSignatureSets.ContainsKey($sigName)) {
                $AllSignatureSets[$sigName] = $true
            }
        }
    }
    Start-Sleep -Seconds 1  # 1-second delay between policies
}

$SigColumns = $AllSignatureSets.Keys | Sort-Object

# Prepare CSV data
$CsvData = @()

foreach ($policy in $PolicyList) {
    $SigUrl = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$($policy.PolicyID)/signature-sets"
    $SigSets = Get-ASM -Url $SigUrl

    $row = [ordered]@{}
    $row["PolicyName"] = $policy.PolicyName
    $row["PolicyID"]   = $policy.PolicyID

    foreach ($sigName in $SigColumns) {
        $exists = $false
        if ($SigSets -and $SigSets.items) {
            foreach ($sig in $SigSets.items) {
                if ($sig.signatureSetReference.name -eq $sigName -and $sig.block -eq $true) {
                    $exists = $true
                    break
                }
            }
        }
        $row[$sigName] = $exists
    }

    $CsvData += New-Object PSObject -Property $row

    # Live CLI confirmation
    Write-Host "$($policy.PolicyName) - OK"

    Start-Sleep -Seconds 1  # 1-second delay after each policy
}

# Export to CSV
$CsvData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "CSV exported to $OutputFile"
