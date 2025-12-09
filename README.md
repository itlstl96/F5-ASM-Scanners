The following repo requires admin/api access to BigIP in order to check for misconfigurations. 

The environment was PowerShell 5 with BigIP 17.1.5


Export-ASM-Policies.ps1 
--- 
1. Usage: This script will extract all the ASM policies into a text file that will be used in the future as an input list.
2. CLI command: `.\Export-ASM-Policies.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin`

Scan-ASM-Entities.ps1
---
1. Usage: This script will output parameters,URLs,headers,cookies,JSON profiles configured and with informations like staging, check attack signatures etc
2. CLI command: `.\Scan-ASM-Entities.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -InputFile ASM_Policies_Export.txt`
3. Output in CSV file, and also in CLI:

   
| Security Policy | Entity Type   | Entity Name      | Attack Signatures Check | Staged | Sensitive | Signature Overrides |
|-----------------|---------------|------------------|--------------------------|--------|-----------|----------------------|
| Copie2          | Parameters    | *                | True                     | True   | False     |                      |
| Copie2          | Urls          | /vvvvv           | True                     | True   |           | 200010211 - "%CommonProgramW6432%" access (Header) 200100093 - "%ALLUSERSPROFILE%" access (URI) |
| Copie2          | Urls          | *                | True                     | True   |           |                      |
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



Scan-ASM-Signatures.ps1
---
1. Usage: This will scan the ASM signatures and will output a statistic with enabled signatures, staged, blocking etc 
2. CLI command: `.\Scan-ASM-Signatures.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -InputFile ASM_Policies_Export.txt`
3. Output: This has only CLI output

| Policy Name | ALARM | BLOCK | STAGING | ENABLED | TOTAL |
|------------|-------|-------|---------|---------|-------|
| Copie2     | 9185  | 9185  | 9183    | 9185    | 9185  |
| Copie1     | 9185  | 9185  | 12      | 9185    | 9185  |
| Default    | 298   | 298   | 4       | 298     | 298   |


Scan-ASM-Violations.ps1
---
1. Usage: This will check for specific violation status on all the policies. Eg: Find if "Illegal host name" is in blocking mode on every policy or not.
2. CLI command: `.\Scan-ASM-Violations.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -PolicyFile ASM_Policies_Export.txt -ViolationsFile list.txt`
3. Output:

| Policy  | Violation Description                       | Block | Alarm | Learn |
|---------|--------------------------------------------|-------|-------|-------|
| Copie2  | Modified ASM cookie                         | True  | True  | True  |
| Copie2  | Illegal meta character in parameter name   | False | True  | False |
| Copie2  | Illegal host name                           | False | False | False |
| Copie1  | Modified ASM cookie                         | False | False | True  |
| Copie1  | Illegal meta character in parameter name   | False | False | False |
| Copie1  | Illegal host name                           | True  | True  | False |
| Default | Illegal host name                           | False | False | False |
| Default | Modified ASM cookie                         | True  | True  | True  |
| Default | Illegal meta character in parameter name   | False | False | False |



 .\Scan-ASM-Signature-Sets.ps1 -BigIPHost 192.168.1.220 -Port 8443 -User admin -InputFile ASM_Policies_Export.txt


