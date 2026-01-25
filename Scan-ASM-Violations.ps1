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
# Hard-coded exact-match violation list (human-readable descriptions)
# -----------------------------
$ViolationFilters = @(
    "Cookie not RFC-compliant",
    "Illegal cookie length",
    "Modified ASM cookie",
    "Illegal file type",
    "Failed to convert character",
    "Illegal HTTP status in response",
    "Request length exceeds defined buffer size",
    "Illegal header length",
    "Illegal host name",
    "Illegal method",
    "Illegal repeated header",
    "Illegal meta character in parameter name",
    "Illegal redirection attempt",
    "Access from disallowed User/Session/IP/Device ID",
    "Illegal URL"
)

# -----------------------------
# Load policies (policy file format: Name:ID per line)
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
# Helper: Http GET and parse JSON (returns $null on failure)
# -----------------------------
function Invoke-GetJson {
    param(
        [Parameter(Mandatory=$true)][string]$Url
    )

    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Headers["Authorization"] = $AuthHeader
        $req.Accept = "application/json"
        $resp = $req.GetResponse()
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $json = $reader.ReadToEnd()
        $reader.Close()
        Start-Sleep -Milliseconds 300  # small delay so we don't hammer the API
        return (ConvertFrom-Json $json)
    }
    catch {
        Write-Warning "Failed to GET $Url : $($_.Exception.Message)"
        return $null
    }
}

# -----------------------------
# Function: fetch policy-level violations (items array)
# -----------------------------
function Get-PolicyViolations {
    param([string]$PolicyID)
    $url = "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$PolicyID/blocking-settings/violations/"
    $json = Invoke-GetJson -Url $url
    if ($null -eq $json) { return @() }
    return ,$json.items | Where-Object { $_ -ne $null }
}

# -----------------------------
# Functions: fetch specific policy config endpoints
# Each returns parsed JSON or $null
# -----------------------------
function Get-HeaderSettings { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/header-settings/" }
function Get-FileTypes       { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/filetypes" }
function Get-CookieSettings  { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/cookie-settings" }
function Get-General        { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/general" }
function Get-HostNames      { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/host-names" }
function Get-Methods        { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/methods" }
function Get-Redirection    { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/redirection-protection" }
function Get-SessionTracking{ param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/session-tracking" }
function Get-CharacterSets  { param($policyID) return Invoke-GetJson -Url "https://$BigIPHost`:$Port/mgmt/tm/asm/policies/$policyID/character-sets" }

# -----------------------------
# Prepare CSV column headers (with unique comments)
# -----------------------------
$CsvColumns = @(
    "PolicyName",
    "PolicyID",

    "Cookie not RFC-compliant","Comments_Cookie",
    "Illegal cookie length","Cookie length configured","Comments_CookieLength",
    "Modified ASM cookie","Comments_ModifiedCookie",
    "Illegal file type","File types configured","Comments_FileType",
    "Failed to convert character","Comments_FailedConvert",
    "Illegal HTTP status in response","Comments_HTTPStatus",
    "HTTP status configured",
    "Request length exceeds defined buffer size","Comments_RequestLength",
    "Illegal header length","Header length configured","Comments_HeaderLength",
    "Illegal host name","Host names configured","Comments_HostName",
    "Illegal method","Methods configured","Comments_Methods",
    "Illegal repeated header","Comments_RepeatedHeader",
    "Illegal meta character in parameter name","0x25 status in parameter name","Comments_MetaChar",
    "Illegal redirection attempt","Redirection configuration","Comments_Redirection",
    "Access from disallowed User/Session/IP/Device ID","Session awareness config","Comments_Session",
    "Illegal URL","Comments_URL"
)

$CSVRows = @()

# -----------------------------
# Main loop: iterate policies and collect everything
# -----------------------------
foreach ($policy in $Policies) {
    Write-Host "Processing policy: $($policy.Name) ($($policy.ID))"

    # Initialize the row with defaults: violations False, configs empty
    $row = [ordered]@{}
    foreach ($col in $CsvColumns) {
        if ($col -eq "PolicyName") { $row[$col] = $policy.Name; continue }
        if ($col -eq "PolicyID")   { $row[$col] = $policy.ID; continue }

        if ($col -like "Comments*") {
            $row[$col] = ""  # empty string for manual comments
        }
        else {
            $row[$col] = $false  # default boolean for violation flags
        }
    }

    # Non-boolean config columns
    $nonBoolConfigCols = @(
        "Cookie length configured",
        "File types configured",
        "HTTP status configured",
        "Header length configured",
        "Host names configured",
        "Methods configured",
        "Redirection configuration",
        "Session awareness config",
        "0x25 status in parameter name"
    )
    foreach ($c in $nonBoolConfigCols) { $row[$c] = "" }

    # -----------------------------
    # 1) Get violations (blocking states)
    # -----------------------------
    $violations = Get-PolicyViolations -PolicyID $policy.ID

    foreach ($v in $violations) {
        if (-not $v) { continue }

        $desc = $null
        if ($v.PSObject.Properties.Name -contains "description") { $desc = $v.description.Trim() }

        if ($null -ne $desc) {
            foreach ($vf in $ViolationFilters) {
                if ($desc.ToLower() -eq $vf.ToLower()) {
                    $colName = $vf
                    $row[$colName] = [bool]$v.block
                    break
                }
            }
        }
    }

    # -----------------------------
    # 2) Collect config endpoints
    # -----------------------------
    $h = Get-HeaderSettings -policyID $policy.ID
    if ($null -ne $h -and $h.maximumHttpHeaderLength) { $row["Header length configured"] = $h.maximumHttpHeaderLength }

    $ft = Get-FileTypes -policyID $policy.ID
    if ($null -ne $ft -and $ft.items) {
        $allowed = @()
        $disallowed = @()
        foreach ($it in $ft.items) {
            if ($it.name) {
                if ($it.allowed -eq $true) { $allowed += $it.name }
                elseif ($it.allowed -eq $false) { $disallowed += $it.name }
            }
        }
        $row["File types configured"] = "allowed=[" + ($allowed -join ",") + "]; disallowed=[" + ($disallowed -join ",") + "]"
    }

    $ck = Get-CookieSettings -policyID $policy.ID
    if ($null -ne $ck -and $ck.maximumCookieHeaderLength) { $row["Cookie length configured"] = $ck.maximumCookieHeaderLength }

    $g = Get-General -policyID $policy.ID
    if ($null -ne $g -and $g.allowedResponseCodes) { $row["HTTP status configured"] = ($g.allowedResponseCodes -join ",") }

    $hn = Get-HostNames -policyID $policy.ID
    if ($null -ne $hn -and $hn.items) { $row["Host names configured"] = (($hn.items | ForEach-Object { $_.name }) -join ",") }

    $meth = Get-Methods -policyID $policy.ID
    if ($null -ne $meth -and $meth.items) { $row["Methods configured"] = (($meth.items | ForEach-Object { $_.name }) -join ",") }

    $rd = Get-Redirection -policyID $policy.ID
    if ($null -ne $rd) {
        if ($rd.redirectionProtectionEnabled -ne $null) { $row["Redirection configuration"] = "enabled=" + ($rd.redirectionProtectionEnabled -as [string]) }
        if ($rd.redirectionDomains -ne $null) {
            $domains = @()
            foreach ($d in $rd.redirectionDomains) { if ($d.domainName) { $domains += $d.domainName } }
            if ($domains.Count -gt 0) { $row["Redirection configuration"] += "; domains=[" + ($domains -join ",") + "]" }
        }
    }

    $st = Get-SessionTracking -policyID $policy.ID
    if ($null -ne $st) {
        $sessParts = @()
        if ($st.sessionTrackingConfiguration -and $st.sessionTrackingConfiguration.enableSessionAwareness -ne $null) {
            $sessParts += "enableSessionAwareness=" + ($st.sessionTrackingConfiguration.enableSessionAwareness -as [string])
        }
        if ($st.violationDetectionActions -and $st.violationDetectionActions.violationDetectionPeriod -ne $null) {
            $sessParts += "violationDetectionPeriod=" + ($st.violationDetectionActions.violationDetectionPeriod -as [string])
        }
        if ($st.blockAll) {
            if ($st.blockAll.period -ne $null) { $sessParts += "period=" + ($st.blockAll.period -as [string]) }
            if ($st.blockAll.ipThreshold -ne $null) { $sessParts += "ipThreshold=" + ($st.blockAll.ipThreshold -as [string]) }
            if ($st.blockAll.urlBlockingMode -ne $null) { $sessParts += "urlBlockingMode=" + ($st.blockAll.urlBlockingMode -as [string]) }
        }
        if ($sessParts.Count -gt 0) { $row["Session awareness config"] = ($sessParts -join "; ") }
    }

    $cs = Get-CharacterSets -policyID $policy.ID
    if ($null -ne $cs) {
        $characterEntries = @()
        if ($cs.characterSetType -and ($cs.characterSetType -eq "parameter-name")) { $characterEntries += $cs }
        elseif ($cs.items) { foreach ($it in $cs.items) { if ($it.characterSetType -eq "parameter-name") { $characterEntries += $it } } }

        foreach ($ce in $characterEntries) {
            if ($ce.characterSet) {
                foreach ($m in $ce.characterSet) {
                    if ($m.metachar -eq "0x25") { $row["0x25 status in parameter name"] = "allowed=" + ($m.isAllowed -as [string]) }
                }
            }
        }
    }

    foreach ($vf in $ViolationFilters) { $row[$vf] = [bool]$row[$vf] }

    $CSVRows += New-Object PSObject -Property $row
}

# -----------------------------
# Export CSV
# -----------------------------
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$policyBase = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
$csvFileName = "$timestamp-$policyBase.csv"

$CSVRows | Select-Object $CsvColumns | Export-Csv -Path $csvFileName -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "CSV output written to: $csvFileName"
Write-Host "Done."
