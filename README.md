.\Export-ASM-Policies.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin

.\Scan-ASM-Entities.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -InputFile ASM_Policies_Export.txt

.\Scan-ASM-Signatures.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -InputFile ASM_Policies_Export.txt


1. List ASM policies in format [security policy name] : [security policy id]

`pwsh ./Export-ASM-Policies.ps1 -BigIPHost 192.168.1.x -User admin`

```
================================================
        ⚠  F5 - ASM POLICIES LISTER  (CLI MODE)
================================================
Author: PGV

🔐 Enter password for user 'admin': **********

📌 Found 3 security policies

Copie2 : qiy21TOeRI2vyNMdxIgOfg
Copie1 : gvqBoTcOCf7q4zAuFozUEg
Default : KRFEmGtMyABlzWyLt3ow8A

✅ Policies saved to ASM_security_policies.txt
```


2. For the ASM policies extracted at 1. this will output in CSV file the following columns. The script has a delay embeded after eache query:

`pwsh ./Scan-ASM-Entities.ps1 -BigIPHost 192.168.1.x -User admin -PolicyFile ASM_security_policies.txt`

```
================================================
        ⚠  F5 - ASM ENTITIES SCANNER  (CLI MODE)
================================================
Author: PGV

🔐 Enter password for user 'admin': **********

🚀 Starting scan of 3 enabled policies...


⏳ Querying policy: Copie2 (qiy21TOeRI2vyNMdxIgOfg)
   ✅ parameters retrieved successfully
   ✅ urls retrieved successfully
   ✅ cookies retrieved successfully
   ✅ headers retrieved successfully
   ✅ json-profiles retrieved successfully

⏳ Querying policy: Copie1 (gvqBoTcOCf7q4zAuFozUEg)
   ✅ parameters retrieved successfully
   ✅ urls retrieved successfully
   ✅ cookies retrieved successfully
   ✅ headers retrieved successfully
   ✅ json-profiles retrieved successfully

⏳ Querying policy: Default (KRFEmGtMyABlzWyLt3ow8A)
   ✅ parameters retrieved successfully
   ✅ urls retrieved successfully
   ✅ cookies retrieved successfully
   ✅ headers retrieved successfully
   ✅ json-profiles retrieved successfully

📁 CSV report saved as ASM_Entities_Report.csv

✅ Scan complete. Total policies scanned: 3
```

With this output you can find if you have parameters in staging or without check attack signatures active. The following entities will be scanned: parameters, URLs, Cookies, Headers, JSON profiles

| Security Policy | Entity Type   | Entity Name      | Attack Signatures Check | Staged | Sensitive | Signature Overrides |
|-----------------|---------------|------------------|--------------------------|--------|-----------|----------------------|
| Copie2          | Parameters    | *                | True                     | True   | False     |                      |
| Copie2          | Urls          | /vvvvv           | True                     | True   |           | 200010211 - "%CommonProgramW6432%" access (Header) 200100093 - "%ALLUSERSPROFILE%" access (URI) |
| Copie2          | Urls          | *                | True                     | True   |           |                      |
| Copie2          | Urls          | *                | False                    | True   |           |                      |
| Copie2          | Cookies       | *                | True                     | True   |           |                      |
| Copie2          | Headers       | transfer-encoding| False                    | False  |           |                      |
| Copie2          | Headers       | authorization    | False                    | False  |           |                      |
| Copie2          | Headers       | cookie           | False                    | False  |           |                      |
| Copie2          | Headers       | *                | False                    | False  |           |                      |
| Copie2          | Headers       | referer          | False                    | False  |           |                      |
| Copie2          | Json Profiles | Default          | False                    | False  |           |                      |
| Copie1          | Parameters    | test             | False                    | False  | False     |                      |
| Copie1          | Parameters    | parametru2       | True                     | True   | False     | 200010210 - "%CommonProgramW6432%" access (Parameter) 200100092 - "%ALLUSERSPROFILE%" access (parameter) 200100096 - "%COMPUTERNAME%" access (parameter) 200100108 - "%CommonProgramFiles%" access (parameter) |
| Copie1          | Parameters    | parametru1       | False                    | False  | True      |                      |
| Copie1          | Parameters    | *                | True                     | True   | False     |                      |
| Copie1          | Urls          | /URL2            | True                     | False  |           | 200100092 - "%ALLUSERSPROFILE%" access (parameter) |
| Copie1          | Urls          | /abcd            | False                    | True   |           |                      |
| Copie1          | Urls          | *                | True                     | True   |           |                      |
| Copie1          | Urls          | *                | True                     | True   |           |                      |



3. Search all policies for specific violations.

`pwsh ./Scan-ASM-Violations.ps1 -BigIPHost 192.168.1.x -User admin -Port 8443 -PolicyFile ASM_security_policies.txt -ViolationsFile Violations-list.txt`
```
==================================================
        F5 - ASM - Violations Scanner (CLI MODE)
==================================================
Author: PGV

🔐 Enter password for user 'admin': **********

⏳ Scanning policy: Copie2 (qiy21TOeRI2vyNMdxIgOfg)
✅ Request OK → qiy21TOeRI2vyNMdxIgOfg

⏳ Scanning policy: Copie1 (gvqBoTcOCf7q4zAuFozUEg)
✅ Request OK → gvqBoTcOCf7q4zAuFozUEg

⏳ Scanning policy: Default (KRFEmGtMyABlzWyLt3ow8A)
✅ Request OK → KRFEmGtMyABlzWyLt3ow8A

📁 CSV results exported to ASM_violation_scan_results.csv

📊 Scan Results:

Policy  | Violation Description                    | Block | Alarm | Learn
--------+------------------------------------------+-------+-------+------
Copie2  | Modified ASM cookie                      | true  | true  | true 
Copie2  | Illegal meta character in parameter name | false | true  | false
Copie2  | Illegal host name                        | false | false | false
Copie1  | Modified ASM cookie                      | false | false | true 
Copie1  | Illegal meta character in parameter name | false | false | false
Copie1  | Illegal host name                        | true  | true  | false
Default | Illegal host name                        | false | false | false
Default | Modified ASM cookie                      | true  | true  | true 
Default | Illegal meta character in parameter name | false | false | false

🔎 Scan complete!
🌐 Total HTTPS requests made to BIG-IP: 3
```
































