# Check-SuspiciousActivity
A read-only PowerShell security diagnostic scanner for Windows.
`Check-SuspiciousActivity.ps1` analyzes a Windows system for common indicators of suspicious activity, persistence mechanisms, malware-related anomalies, and security configuration issues.
The scanner is designed for **diagnosis and investigation**. It does not remove, quarantine, terminate, or modify detected objects.
---
## Features
The scanner checks multiple Windows security areas, including:
- Running processes
- Process signatures
- SHA-256 file hashes
- Suspicious executable locations
- Registry persistence
- Run / RunOnce entries
- Active Setup entries
- COM / CLSID hijacking indicators
- Scheduled tasks
- Windows services
- WMI event subscriptions
- Network connections
- Listening ports
- Windows Firewall inbound rules
- Hosts file
- Proxy configuration
- DNS configuration
- Browser extensions
- Local administrator accounts
- Windows Defender status
- Windows Defender exclusions
- Windows Event Logs
- Suspicious command-line patterns
- Recently modified system files
- Shadow Copy information
- Drivers and other system indicators
The scanner also provides:
- MITRE ATT&CK technique mapping
- Risk scoring
- Finding deduplication
- IOC generation
- SHA-256 hashes
- VirusTotal lookup references
- Scanner self-exclusion
- Read-only AST validation
- Source coverage validation
- Source status reporting
- JSON reports
- HTML reports
- TXT reports
- IOC JSON reports
- Quality Gates for scan and report integrity
---
## Safety Model
This project is intentionally **read-only**.
The scanner does not:
- Delete files
- Quarantine files
- Kill processes
- Stop services
- Modify registry persistence
- Change firewall rules
- Change Windows Defender settings
- Remove scheduled tasks
- Modify system configuration
- Perform malware remediation
Detected items are reported for manual investigation.
The scanner may create its own output reports. This report generation is separate from modifying the Windows system being analyzed.
---
## Requirements
### Operating System
Supported target:
- Windows 10
- Windows 11
### PowerShell
The current release is runtime-validated on:
```text
Windows PowerShell 5.1
Desktop edition
```
PowerShell 7 / PowerShell Core has **not yet been runtime-validated**.
### Administrator privileges
Administrator privileges are recommended for maximum visibility and access to protected Windows security sources.
---
## Usage
Open **Windows PowerShell as Administrator**.
Temporarily allow script execution for the current PowerShell process:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Run the scanner:
```powershell
.\Check-SuspiciousActivity.ps1
```
The scanner performs a read-only diagnostic scan and generates timestamped reports.
---
## Output
The scanner generates structured reports containing information such as:
- Scan metadata
- System information
- Source status
- Findings
- Severity
- Confidence
- Risk score
- MITRE ATT&CK mappings
- Indicators of compromise
- SHA-256 hashes
- Quality Gate results
- Scan errors and informational events
Supported output formats include:
```text
TXT
HTML
JSON
IOC JSON
```
The JSON report is the primary machine-readable result and contains the structured scan data used for further analysis.
---
## Findings
Each finding may contain information such as:
```text
Category
Severity
Confidence
Risk Score
MITRE ATT&CK ID
MITRE ATT&CK Name
Recommendation
File Path
SHA-256
Process ID
Service Name
Task Name
Registry Path
IOC data
Timestamp
```
Findings should be interpreted using their complete evidence rather than a single indicator.
For example, an unsigned executable alone does not necessarily mean that the executable is malicious.
---
## Risk Score
The scanner calculates a risk score using multiple evidence categories.
The final score is validated against the underlying score components to detect calculation inconsistencies.
Risk levels are intended as analytical guidance:
```text
LOW
MEDIUM
HIGH
CRITICAL
```
A risk score is **not proof of malware infection**.
Individual findings should be reviewed using their:
- Severity
- Confidence
- Evidence
- File path
- Signature status
- SHA-256 hash
- Persistence mechanism
- MITRE ATT&CK mapping
- System context
---
## MITRE ATT&CK
Where applicable, findings are mapped to MITRE ATT&CK techniques.
Examples include:
```text
T1053.005  Scheduled Task/Job: Scheduled Task
T1543.003  Create or Modify System Process: Windows Service
T1546.003  Event Triggered Execution: WMI Event Subscription
T1546.015  Event Triggered Execution: Component Object Model Hijacking
T1547.014  Boot or Logon Autostart Execution: Active Setup
```
MITRE ATT&CK mappings provide investigation context and should not be interpreted as confirmation that a technique was used maliciously.
---
## Quality Gates
The scanner performs internal validation of the scan and generated reports.
Quality checks include:
- Read-only validation
- PowerShell compatibility
- Source coverage
- Required fields
- Finding deduplication
- IOC deduplication
- Self-exclusion
- Risk score consistency
- JSON round-trip validation
- HTML structure validation
- HTML escaping validation
- Source status validation
The overall quality status can be:
```text
PASS
PASS_WITH_WARNINGS
FAIL
```
---
## Read-Only Validation
The scanner includes an AST-based validation mechanism for detecting potentially destructive PowerShell commands in the scanner code.
The validation analyzes PowerShell syntax rather than simply searching for command names in strings or comments.
This helps distinguish actual executable commands from:
- Documentation
- Comments
- Report text
- Example strings
The scanner is designed to remain read-only while performing system diagnostics.
---
## Self-Exclusion
The scanner identifies its own running process and excludes it from process findings where applicable.
The self-exclusion mechanism uses runtime information such as:
- Scanner PID
- Scanner path
- Scanner command line
- Scanner SHA-256
The scan report records whether self-exclusion was successfully applied and verified.
---
## Coverage
The scanner reports the status of major diagnostic sources.
Example sources include:
```text
Processes
Services
Scheduled Tasks
WMI
Defender
Defender Preferences
Event Logs
Network
```
Source failures are reported separately from normal informational conditions.
The scanner distinguishes between:
- Successful sources
- Unavailable sources
- Disabled sources
- Permission errors
- Parsing errors
- Informational limitations
This prevents incomplete data from being silently presented as a complete scan.
---
## PowerShell Compatibility
### Tested
```text
Windows PowerShell 5.1
Desktop edition
```
### Not yet runtime-validated
```text
PowerShell 7 / PowerShell Core
```
The current release is intended for Windows PowerShell 5.1 until additional PowerShell 7 runtime testing is completed.
---
## Runtime Validation
Version `2.0.0` has been end-to-end tested on:
```text
Operating System:
Windows 11 Home
PowerShell:
Windows PowerShell 5.1.26100.9549
Edition:
Desktop
Execution:
Administrator
Runtime duration:
41.6 seconds
```
The validation run completed with:
```text
RealScanErrors = 0
OverallQualityStatus = PASS
```
Quality Gate results from the validation run:
```text
RiskScoreConsistencyStatus = PASS
PowerShellCompatibilityStatus = PASS
ReadOnlyStatus = PASS
RequiredFieldsStatus = PASS
IocJsonStatus = PASS
CoverageStatus = PASS
DuplicateIOCStatus = PASS
SelfExclusionStatus = PASS
DeduplicationStatus = PASS
SourceStatusGate = PASS
HtmlStructureStatus = PASS
JsonRoundTripStatus = PASS
DuplicateFindingStatus = PASS
HtmlEscapingStatus = PASS
```
---
## Example Scan Result
A scan can produce findings with different levels of confidence.
For example:
```text
Severity: LOW
Confidence: LOW
```
may indicate an item that requires manual review rather than confirmed malicious activity.
Likewise:
```text
Severity: MEDIUM
Confidence: LOW
```
should not automatically be interpreted as malware.
The scanner intentionally separates:
- Severity
- Confidence
- Evidence
- Context
- Risk score
to reduce false conclusions from individual indicators.
---
## Windows Application Packaging
Modern Windows applications may use AppX/MSIX package signing rather than traditional per-file Authenticode signatures.
As a result, an executable located under:
```text
C:\Program Files\WindowsApps\
```
may return an Authenticode result such as:
```text
NotSigned
```
without that result alone indicating malicious activity.
The scanner treats supported packaged Windows applications as contextual evidence rather than automatically classifying them as malicious based solely on a per-file Authenticode result.
---
## Limitations
This project is a **diagnostic security scanner**, not a replacement for:
- Microsoft Defender
- EDR products
- Antivirus software
- SIEM platforms
- Digital forensics suites
- Incident response tooling
A finding does not automatically mean that malware is present.
Likewise, the absence of findings does not prove that a system is completely clean.
Some legitimate Windows components and third-party applications may appear unusual because of:
- Application packaging
- System persistence mechanisms
- Scheduled tasks
- Software updaters
- User-installed applications
- Signature availability
- Security product behavior
- Windows configuration differences
Findings should therefore be reviewed in context.
---
## Recommended Investigation Workflow
When a finding requires investigation, review:
1. File path
2. Digital signature
3. Publisher
4. SHA-256 hash
5. Parent process
6. Command line
7. Persistence mechanism
8. Creation/modification time
9. Related Event Log entries
10. MITRE ATT&CK mapping
11. Other findings associated with the same object
For unknown files, the generated SHA-256 can be used for reputation analysis with services such as VirusTotal.
Do not automatically delete or modify an object solely because it appears in the report.
---
## Project Structure
```text
Check-SuspiciousActivity/
│
├── Check-SuspiciousActivity.ps1
├── README.md
├── LICENSE
├── CHANGELOG.md
└── .gitignore
```
---
## Version
Current release:
```text
v2.0.0
```
---
## Changelog
### v2.0.0
Initial public release of the current scanner architecture.
Major capabilities include:
- Read-only Windows security diagnostics
- MITRE ATT&CK mapping
- Risk scoring
- Finding deduplication
- IOC generation
- Self-exclusion
- AST-based read-only validation
- Source coverage validation
- Quality Gates
- JSON output
- HTML output
- TXT output
- IOC JSON output
- Windows PowerShell 5.1 runtime validation
---
## Security
If you discover a security issue in the scanner itself, please report it through the repository's issue or security reporting mechanisms rather than publicly posting sensitive details.
---
## Disclaimer
This project is provided for defensive security diagnostics, system administration, incident investigation, research, and educational purposes.
The scanner is read-only by design and does not perform remediation.
Always review findings and supporting evidence before taking any action on a system.
---
## License
This project is distributed under the license included in the repository.
See `LICENSE` for details.
