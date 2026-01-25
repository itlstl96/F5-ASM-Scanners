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
# Secure password
# -----------------------------
$Password = Read-Host -Prompt "Enter password for $User" -AsSecureString
$BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# -----------------------------
# Networking / SSL
# -----------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$AuthHeader = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Plain"))

# -----------------------------
# Columns for CSV with Comments
# -----------------------------
$EvasionCols = @(
    "Trailing slash","Trailing dot","Semicolon path parameters","Bad unescape","Apache whitespace",
    "Bare byte decoding","IIS Unicode codepoints","IIS backslashes","%u decoding","Multiple decoding",
    "Directory traversals","Multiple slashes"
)

$HttpCols = @(
    "Check maximum number of cookies","Multiple host headers","Check maximum number of parameters",
    "Bad host header value","Check maximum number of headers","Unparsable request content",
    "High ASCII characters in headers","Null in request","Bad HTTP version","Content length should be a positive number",
    "Host header contains IP address","CRLF characters before request start","No Host header in HTTP/1.1 request",
    "Bad multipart parameters parsing","Bad multipart/form-data request parsing","Body in GET or HEAD requests",
    "Chunked request with Content-Length header","Several Content-Length headers","Header name with no header value",
    "POST request with Content-Length: 0"
)

# Create CSV columns: add a "Comments" column after each sub-violation
$CsvColumns = @("PolicyName","PolicyID")
foreach ($col in $EvasionCols + $HttpCols) {
    $CsvColumns += $col
    $CsvColumns += "${col} Comments"
}

$CSVRows = @()

# -----------------------------
# Load policies
# -----------------------------
$Policies = Get-Content $InputFile | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("-")) { return }

    if ($line.StartsWith("+")) { $line = $line.Substring(1) }

    if ($line -match "^(.*?):(.*)$") {
        [PSCustomObject]@{
            Name = $matches[1].Trim()
            ID   = $matches[2].Trim()
        }
    }
} | Where-Object { $_ -ne $null }

# -----------------------------
# Helper function: GET JSON
# -----------------------------
function Invoke-GetJson {
    param([string]$Url)
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = $AuthHeader
        $req.Accept = "application/json"
        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()
        Start-Sleep -Milliseconds 200
        return (ConvertFrom-Json $json)
    } catch {
        Write-Warning "Failed to GET $Url : $($_.Exception.Message)"
        return $null
    }
}

# -----------------------------
# Main loop: process policies
# -----------------------------
foreach ($policy in $Policies) {
    Write-Host "Processing policy: $($policy.Name) ($($policy.ID))"

    # Initialize CSV row
    $row = [ordered]@{}
    foreach ($col in $CsvColumns) {
        if ($col -eq "PolicyName") { $row[$col] = $policy.Name; continue }
        if ($col -eq "PolicyID")   { $row[$col] = $policy.ID; continue }
        # Default for sub-violations is false, comments are empty
        if ($col -like "*Comments") { $row[$col] = "" } else { $row[$col] = $false }
    }

    # -----------------------------
    # 1) Evasions
    # -----------------------------
    $evasionsUrl = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$($policy.ID)/blocking-settings/evasions"
    $evasionsJson = Invoke-GetJson -Url $evasionsUrl
    if ($evasionsJson -and $evasionsJson.items) {
        foreach ($item in $evasionsJson.items) {
            if ($item.description -and $EvasionCols -contains $item.description) {
                $row[$item.description] = [bool]$item.enabled
            }
        }
    }

    # -----------------------------
    # 2) HTTP protocols
    # -----------------------------
    $httpUrl = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$($policy.ID)/blocking-settings/http-protocols"
    $httpJson = Invoke-GetJson -Url $httpUrl
    if ($httpJson -and $httpJson.items) {
        foreach ($item in $httpJson.items) {
            if ($item.description -and $HttpCols -contains $item.description) {
                $row[$item.description] = [bool]$item.enabled
            }
        }
    }

    # Add row
    $CSVRows += New-Object PSObject -Property $row
}

# -----------------------------
# Export CSV
# -----------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$policyBase = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
$csvFileName = "$timestamp-$policyBase-subviolations.csv"

$CSVRows | Select-Object $CsvColumns | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "CSV output written to: $csvFileName"
Write-Host "Done."
