The following repo requires admin/api access to BigIP in order to check for misconfigurations. 

The environment was PowerShell 5 with BigIP 17.1.5

===Exporters===

Usually the exporters do not need an input list of any type. And will generate a list that can be used for scanners.

1. Export-SSL-client.ps1. This can be used to see all details and possible misconfigs of Client SSL.
	- Client SSL profile name
    - Certificate name
    - Certificate key
    - Certificate chain
    - Certificate tmOptions

2. ExportASM.ps1. This is exporting the full list and IDs for ASM profiles

3. ExportDOS.ps1. This is exporting the full list and IDs for DOS profiles

4. ExportVS.ps1
	- Virtual Server name / Port / IP
	- TCP connection limits / Eviction policies
	- Logging / Analytics profiles



===Scanners===


Scanners will require a list as input (ASM, DOS etc). Usually exported from exporter menu.

1. Scan-ASM-Entities.ps1. Used to check for staing entities where requests will not be blocked.
	- Parameters / URLs /Cookies
	- Signatures exceptions
	- Staging status


2. Scan-ASM-Signature-Sets.ps1
	- List of signatures settes applied to each ASM policy.

3. Scan-ASM-Signatures.ps1. Count of signatures on policies:
	- Alarm
	- Block
	- Staging
	- Enabled
	- Total

4. Scan-ASM-Sub-Violations.ps1. List subviolations (HTTP and Evasions) for each ASM policy.

5. Scan-ASM-Violations.ps1. List some usefull violations and their config for each ASM policy.

6. Scan-DOS-config.ps1
	- DOS profile name
	- Whitelisted IPs
	- Rate limits

7. URL-scanner.ps1. This can be used to check for misconfigured "do nothing" options.
	- URl list based on ASM policies
	- List of actions based on content type.
