# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] - 2026-09-25

### Added

- Read-only Windows security diagnostic scanner.
- Process inspection and signature analysis.
- SHA-256 hashing for relevant files.
- Registry persistence checks.
- Active Setup inspection.
- COM / CLSID hijacking detection.
- Scheduled task analysis.
- Windows service analysis.
- WMI event subscription checks.
- Network connection inspection.
- Listening port analysis.
- Windows Firewall inbound rule inspection.
- Hosts file analysis.
- Proxy configuration checks.
- DNS configuration checks.
- Browser extension inspection.
- Local administrator account checks.
- Windows Defender status and preference checks.
- Windows Event Log analysis.
- Suspicious command-line pattern detection.
- Recently modified system file checks.
- Driver inspection.
- Shadow Copy information.
- MITRE ATT&CK technique mapping.
- Risk scoring.
- Finding deduplication.
- IOC generation.
- SHA-256 based investigation data.
- Scanner self-exclusion.
- AST-based read-only validation.
- Source coverage validation.
- Source status reporting.
- JSON report generation.
- HTML report generation.
- TXT report generation.
- IOC JSON report generation.
- Quality Gates for scan and report integrity.

### Validation

Version 2.0.0 was end-to-end runtime-tested on:

- Windows 11 Home
- Windows PowerShell 5.1.26100.9549
- Desktop edition
- Administrator execution

Validation result:

- `OverallQualityStatus = PASS`
- `RealScanErrors = 0`
- `ReadOnlyStatus = PASS`
- `CoverageStatus = PASS`
- `DuplicateFindingStatus = PASS`
- `DuplicateIOCStatus = PASS`
- `DeduplicationStatus = PASS`
- `SelfExclusionStatus = PASS`
- `RiskScoreConsistencyStatus = PASS`
- `IocJsonStatus = PASS`
- `JsonRoundTripStatus = PASS`
- `HtmlStructureStatus = PASS`
- `HtmlEscapingStatus = PASS`

### Notes

PowerShell 7 / PowerShell Core has not yet been runtime-validated.

The scanner is diagnostic and read-only. It does not perform malware removal, quarantine, process termination, service modification, registry modification, or other remediation actions.

[2.0.0]: https://github.com/hsynaze/Check-SuspiciousActivity/releases/tag/v2.0.0
