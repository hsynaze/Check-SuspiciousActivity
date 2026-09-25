<#
.SYNOPSIS
    Security diagnostic scanner for Windows with risk scoring and MITRE ATT&CK
    mapping. Covers persistence, process, network, driver, browser, Defender,
    event log, ransomware/cryptominer correlation, and IOC export.

.DESCRIPTION
    This is NOT an antivirus or EDR. It does not remove, quarantine, or block
    anything. It collects information, scores findings by severity/confidence,
    maps relevant findings to MITRE ATT&CK techniques, and exports a text
    report, an HTML dashboard, and JSON (full findings + a compact IOC file).

    LIMITATIONS (read this before trusting a clean result):
    - This is heuristic detection, not signature-based malware identification.
      A LOW/MEDIUM finding is a lead to investigate, not a verdict.
    - Per-process integrity level is not implemented (would require additional
      low-level token-inspection API calls beyond this script's scope).
    - Generic DLL search-order-hijacking detection is not implemented in full;
      real detection of that technique needs file-system access tracing
      (Procmon/ETW), which a static PowerShell script cannot do. A narrow
      heuristic is included instead (see Get-TempExecutableIndicators).
    - Event Log checks depend on audit policies most home PCs do not enable
      by default (e.g. process-creation auditing, PowerShell script-block
      logging). Empty results there often mean "not logged", not "clean".
    - Reverse DNS lookups are OFF by default (can be slow / hang on some
      networks) - enable via $Config.EnableReverseDns if you want them.

    RUNTIME VALIDATION STATUS:
    - Runtime-tested on Windows PowerShell 5.1 (Desktop edition): the script
      executes end to end and all quality gates report PASS on the tested
      host. Note that "tested" means it ran and self-validated there - it
      does not mean every detector has been exercised against real malware.
    - PowerShell 7 (Core edition) is NOT yet validated. The code avoids
      PowerShell 7-only syntax, but no PS 7 run has been performed, so
      PowerShellCompatibilityStatus reports NOT_TESTED when running there.

.NOTES
    Run as Administrator for full visibility.
#>

# =================================================================
# CONFIGURATION - change these without touching detection logic
# =================================================================
$Config = @{
    ScanDepth              = 2       # how many subfolder levels to recurse when scanning Temp/AppData/System32
    RecentDays             = 14      # "recently modified" window for files
    EventLogDays           = 7       # how far back to look in Event Logs
    EnableHashing          = $true   # compute SHA256 for flagged files (adds time)
    EnableNetworkAnalysis  = $true
    EnableEventLogAnalysis = $true
    EnableBrowserAnalysis  = $true
    EnableDriverAnalysis   = $true
    EnableReverseDns       = $false  # reverse DNS on external IPs - can be slow, off by default
    MaxFilesPerDirectory   = 200
    MaxRegistryKeysToScan  = 2000   # separate from MaxFilesPerDirectory - used for HKCU CLSID enumeration
    MaxEvents              = 300
    OutputDirectory        = $PSScriptRoot
}

$ErrorActionPreference = 'SilentlyContinue'
$script:ScanDate      = Get-Date
$script:StartTime     = $script:ScanDate
$script:ScannerVersion = "2.0"
$script:PowerShellVersion = $PSVersionTable.PSVersion.ToString()
$script:OSVersion = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { [System.Environment]::OSVersion.VersionString }
$script:IsAdministrator = try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $null }
$script:ScriptSHA256 = if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue)) {
    try { (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { "unavailable" }
} else { "unavailable (script path not resolvable, e.g. run via -Command)" }
$stamp                = "{0:yyyyMMdd_HHmmss}" -f $script:ScanDate
$reportPath            = Join-Path $Config.OutputDirectory ("SecurityReport_{0}.txt"  -f $stamp)
$htmlReportPath        = Join-Path $Config.OutputDirectory ("SecurityReport_{0}.html" -f $stamp)
$jsonReportPath        = Join-Path $Config.OutputDirectory ("SecurityReport_{0}.json" -f $stamp)
$iocReportPath         = Join-Path $Config.OutputDirectory ("SecurityReport_{0}_IOCs.json" -f $stamp)
$script:jsonReportPath = $jsonReportPath
$script:iocReportPath  = $iocReportPath

$report               = New-Object System.Collections.Generic.List[string]
$script:AllFindings   = New-Object System.Collections.Generic.List[object]
$script:FindingDedupKeys = @{}
# Every time Add-Finding detects a duplicate CANDIDATE (same PID +
# category-family + normalized command as an already-recorded finding) and
# merges it, the event is appended here. DuplicateFindingStatus validates
# the merge MECHANISM against these real events rather than guessing after
# the fact by grouping the finished findings.
$script:DuplicateMergeEvents = New-Object System.Collections.Generic.List[object]
$script:HighRiskPIDs  = New-Object System.Collections.Generic.List[int]
$flagCount            = 0
$script:findingIdCounter = 1

# ScanErrors: a LIST of scan events/errors encountered during the scan.
# The Code field distinguishes real failures from informational conditions.
# (access denied, log missing, WMI failure, hash failure, but also purely
# informational states such as a source not being present on this system).
# ScanCoverage: pure COUNTERS of how much was actually checked. These are
# kept separate on purpose - "0 findings because a directory was truncated
# by a configured limit" is a coverage fact, not an error; "0 findings
# because Get-CimInstance threw an access-denied exception" is a real
# error. Conflating the two (as a single flat counter hashtable did before)
# makes it impossible to tell which is which.
$script:ScanErrors = New-Object System.Collections.Generic.List[object]
# Code semantics: ERROR (a genuine unexpected failure), UNAVAILABLE (a data
# source simply wasn't there - e.g. Defender module absent, third-party AV
# in place - not a failure of the scanner), PERMISSION_DENIED (access
# denied on a specific path/key), PARSE_ERROR (structured data - XML/JSON -
# could not be parsed, with a text fallback still attempted), plus the
# informational codes listed below. Severity stays for backward-compatible
# display; Code is what call sites should branch on.
$script:AllowedScanErrorCodes = @(
    'ERROR',               # a genuine failure of the scan operation
    'UNAVAILABLE',         # data source simply not present on this system
    'PERMISSION_DENIED',   # access denied on a specific path/key/source
    'PARSE_ERROR',         # structured data could not be parsed at all
    'PARSE_WARNING',       # parsed, but some optional detail was lost
    'UNSUPPORTED_SOURCE',  # feature not available on this Windows version
    'TRUNCATED_BY_LIMIT'   # result capped by a configured limit, not an error
)
# Codes that represent an actual scan FAILURE (used for exit code / gating);
# everything else in the allowed list is informational.
$script:RealScanErrorCodes = @('ERROR', 'PERMISSION_DENIED', 'PARSE_ERROR')
$script:InformationalScanErrorCodes = @('UNAVAILABLE', 'PARSE_WARNING', 'UNSUPPORTED_SOURCE', 'TRUNCATED_BY_LIMIT')

function Add-ScanError($component, $message, $severity, $code = 'ERROR') {
    # Only a genuinely UNKNOWN code falls back to ERROR. Previously any code
    # outside a hardcoded four-item list was silently rewritten to ERROR,
    # which would have turned informational states such as TRUNCATED_BY_LIMIT
    # into apparent scan failures.
    if ($code -notin $script:AllowedScanErrorCodes) { $code = 'ERROR' }
    [void]$script:ScanErrors.Add([PSCustomObject]@{
        Component = $component
        Message   = $message
        Severity  = $severity
        Code      = $code
        Timestamp = (Get-Date).ToString('s')
    })
}

$script:ScanCoverage = @{
    FilesChecked              = 0
    DirectoriesChecked        = 0
    DirectoriesTruncated      = 0   # a directory hit its file/subdirectory cap - NOT an error, just a completeness note
    ProcessesChecked          = 0
    ServicesChecked           = 0
    DriversChecked            = 0
    ScheduledTasksChecked     = 0
    RegistryKeysChecked       = 0
    NetworkConnectionsChecked = 0
    WmiSubscriptionsChecked   = 0
    BrowserExtensionsChecked  = 0
    SignatureChecksPerformed  = 0
    SignatureUnavailable      = 0   # could not be verified either way - not an error, just inconclusive
    DefenderChecksPerformed   = 0
    EventLogsQueried          = 0
}

# SourceStatus tracks whether each source was successfully QUERIED, which is
# a different question from how many objects it returned. Zero network
# connections, zero WMI subscriptions or zero scheduled tasks are all
# perfectly normal RESULTS from a source that worked correctly - counting
# objects conflates "found nothing" with "never checked".
# Values:
#   OK                - queried successfully (regardless of object count)
#   ERROR             - the query itself failed
#   PERMISSION_DENIED - access denied specifically
#   UNAVAILABLE       - source genuinely not present on this system
#   NOT_TESTED        - never reached (a code path did not run)
#   DISABLED          - deliberately switched off via $Config by the user;
#                       not a technical failure; non-critical disabled
#                       sources do not lower CoverageStatus, while a
#                       disabled CriticalSource caps CoverageStatus at
#                       PARTIAL
$script:SourceStatus = @{
    Processes           = 'NOT_TESTED'
    Services            = 'NOT_TESTED'
    ScheduledTasks      = 'NOT_TESTED'
    Network             = 'NOT_TESTED'
    WMI                 = 'NOT_TESTED'
    Defender            = 'NOT_TESTED'
    DefenderPreferences = 'NOT_TESTED'
    EventLogs           = 'NOT_TESTED'
}
# Critical sources are required for a minimally valid host scan.
# Failure of a critical source results in CoverageStatus = FAIL.
# Non-critical source failures result in PARTIAL.
$script:CriticalSources = @(
    'Processes',
    'Services'
)
function Set-SourceStatus($sourceName, $status) {
    if ($script:SourceStatus.ContainsKey($sourceName)) { $script:SourceStatus[$sourceName] = $status }
}
$totalSections        = 28
$sectionIndex         = 0

# =================================================================
# MITRE ATT&CK CATALOG (Enterprise matrix, techniques used below)
# =================================================================
$MitreCatalog = @{
    'T1547.001' = 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    'T1053.005' = 'Scheduled Task/Job: Scheduled Task'
    'T1543.003' = 'Create or Modify System Process: Windows Service'
    'T1059'     = 'Command and Scripting Interpreter'
    'T1059.001' = 'Command and Scripting Interpreter: PowerShell'
    'T1059.003' = 'Command and Scripting Interpreter: Windows Command Shell'
    'T1218.005' = 'System Binary Proxy Execution: Mshta'
    'T1218.010' = 'System Binary Proxy Execution: Regsvr32'
    'T1218.011' = 'System Binary Proxy Execution: Rundll32'
    'T1218.007' = 'System Binary Proxy Execution: Msiexec'
    'T1197'     = 'BITS Jobs'
    'T1140'     = 'Deobfuscate/Decode Files or Information'
    'T1055'     = 'Process Injection'
    'T1547.004' = 'Boot or Logon Autostart Execution: Winlogon Helper DLL'
    'T1546.003' = 'Event Triggered Execution: WMI Event Subscription'
    'T1553.004' = 'Subvert Trust Controls: Install Root Certificate'
    'T1562.001' = 'Impair Defenses: Disable or Modify Tools'
    'T1562.004' = 'Impair Defenses: Disable or Modify System Firewall'
    'T1219'     = 'Remote Access Software'
    'T1546.012' = 'Event Triggered Execution: Image File Execution Options Injection'
    'T1546.009' = 'Event Triggered Execution: AppInit DLLs'
    'T1547.014' = 'Boot or Logon Autostart Execution: Active Setup'
    'T1547.006' = 'Boot or Logon Autostart Execution: Kernel Modules and Extensions'
    'T1546.015' = 'Event Triggered Execution: Component Object Model Hijacking'
    'T1546.008' = 'Event Triggered Execution: Accessibility Features'
    'T1574.001' = 'Hijack Execution Flow: DLL Search Order Hijacking'
    'T1036'     = 'Masquerading'
    'T1486'     = 'Data Encrypted for Impact (Ransomware)'
    'T1490'     = 'Inhibit System Recovery'
    'T1496'     = 'Resource Hijacking (Cryptomining)'
    'T1176'     = 'Browser Extensions'
    'T1105'     = 'Ingress Tool Transfer'
    'T1027'     = 'Obfuscated Files or Information'
    'T1112'     = 'Modify Registry'
    'T1021.001' = 'Remote Services: Remote Desktop Protocol'
    'T1546.013' = 'Event Triggered Execution: PowerShell Profile'
    'T1556'     = 'Modify Authentication Process'
    'T1070.004' = 'Indicator Removal: File Deletion'
    'T1601'     = 'Modify System Image'
}

$SeverityScore = @{ INFO = 0; LOW = 2; MEDIUM = 5; HIGH = 8; CRITICAL = 13 }
$ConfidenceMultiplier = @{ LOW = 0.5; MEDIUM = 0.75; HIGH = 1.0 }

# =================================================================
# CORE PRIMITIVES
# =================================================================
function Add-Section($title) {
    $script:sectionIndex++
    Write-Progress -Activity "Security diagnostic scan" -Status $title -PercentComplete ([math]::Min(100, ($script:sectionIndex / $script:totalSections) * 100))
    $report.Add("`n" + ("=" * 70))
    $report.Add($title)
    $report.Add("=" * 70)
}

function Add-Line($text) {
    $report.Add($text)
}

# Add-Finding is the single entry point for anything that should count
# toward the risk score, MITRE mapping, and IOC/JSON export. It also writes
# a human-readable line into the same $report used by the text/HTML log,
# so the existing narrative output keeps working unchanged.
# FindingKey: Group-Object on Text alone can miss real duplicates (two
# different underlying events rendering the same text) or be fooled by
# text that varies slightly for the same object. A stable key built from
# Category + MitreId + the best available object identifier (path/PID/task
# name/registry path/certificate thumbprint) tracks the actual OBJECT and
# SOURCE, not just the rendered message. Findings with none of those
# identifying fields fall back to Category+Text so unrelated narrative
# findings are never grouped together by accident.
# Returns the dedup key for a finding using EXACTLY the rule Add-Finding
# applies, or $null when Add-Finding would not deduplicate this finding at
# all. Keeping this in one place means the quality gate can never drift
# away from the mechanism it is validating.
#
# Add-Finding deduplicates ONLY findings that carry both PID_ and Command,
# keyed on PID + dedup-category-family + normalized Command. Everything
# else is intentionally left alone: several independent findings about the
# same file, registry key or service are each meant to stand on their own,
# and inventing a broader identity here purely to satisfy a quality gate
# would assert a canonical-record rule the scanner does not actually have.
function Get-FindingDedupKey($f) {
    $ioc = $f.IOC
    if (-not $ioc) { return $null }
    if (-not ($ioc.ContainsKey('PID_') -and $ioc['PID_'])) { return $null }
    if (-not ($ioc.ContainsKey('Command') -and $ioc['Command'])) { return $null }

    $dedupCategoryFamily = @{ 'LOLBin' = 'ProcessExecution'; 'CommandLine' = 'ProcessExecution'; 'Execution' = 'ProcessExecution' }
    $dedupCategory = $f.Category
    if ($dedupCategoryFamily.ContainsKey($f.Category)) { $dedupCategory = $dedupCategoryFamily[$f.Category] }

    $normalizedCmd = ($ioc['Command'].ToString().Trim().ToLower() -replace '\s+', ' ')
    return "{0}|{1}|{2}" -f $ioc['PID_'], $dedupCategory, $normalizedCmd
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)] [string]$Category,
        [Parameter(Mandatory = $true)] [string]$Text,
        [string]$Severity = 'LOW',
        [string]$Confidence = 'MEDIUM',
        [string]$MitreId = '',
        [string]$MitreConfidence = 'CONFIRMED',  # 'CONFIRMED', 'LIKELY', 'HEURISTIC', or 'CONTEXT_ONLY' - see individual call sites
        [string]$EvidenceType = 'DIRECT',        # 'DIRECT' (a directly observed fact), 'HEURISTIC' (an inference from a pattern), or 'CONTEXT' (background info, weak signal on its own) - independent of MitreConfidence, used for the ConfirmedScore/HeuristicScore/ContextScore breakdown
        [string]$Recommendation = '',
        [hashtable]$IOC = $null
    )
    if (-not $SeverityScore.ContainsKey($Severity)) { $Severity = 'LOW' }
    if (-not $ConfidenceMultiplier.ContainsKey($Confidence)) { $Confidence = 'MEDIUM' }
    if ($EvidenceType -notin @('DIRECT', 'HEURISTIC', 'CONTEXT')) { $EvidenceType = 'DIRECT' }

    # Self-exclusion: this scanner's own process (or the shell hosting it)
    # must never be scored as if it were malware. Overrides severity/
    # confidence/evidence AFTER the caller's own logic has run, so no
    # individual detector needs its own self-check. -NoProfile and
    # -ExecutionPolicy Bypass are exactly how this scanner itself is
    # launched - they are not treated as a strong indicator here either.
    if ($IOC -and $IOC.ContainsKey('PID_') -and $IOC['PID_'] -and $script:SelfExclusionPids -and $script:SelfExclusionPids.Contains([int]$IOC['PID_'])) {
        $Severity = 'INFO'; $Confidence = 'HIGH'; $EvidenceType = 'CONTEXT'; $MitreId = ''; $MitreConfidence = 'CONTEXT_ONLY'
        $Text = "$Text [SELF-EXCLUDED: this is the scanner's own process/host, not flagged as malware]"
    }

    # Dedup key comes from Get-FindingDedupKey - the SINGLE implementation
    # of this rule, shared with the DuplicateFindingStatus quality gate so
    # the gate can never validate a different rule than the one actually
    # applied here. It returns $null for findings this scanner does not
    # deduplicate (anything without both PID_ and Command).
    $dedupKey = Get-FindingDedupKey ([PSCustomObject]@{ Category = $Category; IOC = $IOC })

    if ($dedupKey -and $script:FindingDedupKeys.ContainsKey($dedupKey)) {
        $existingId = $script:FindingDedupKeys[$dedupKey]
        $existing = $script:AllFindings | Where-Object { $_.Id -eq $existingId } | Select-Object -First 1
        if ($existing) {
            # A duplicate CANDIDATE was detected: the incoming finding has
            # the same PID + category-family + normalized command as one
            # already recorded. Capture the pre-merge state so the quality
            # gate can verify afterwards that the merge behaved correctly
            # (no second finding, no second RiskScore contribution, the
            # original Id preserved).
            $preMergeSeverity   = $existing.Severity
            $preMergeConfidence = $existing.Confidence
            $preMergeRiskScore  = $existing.RiskScore
            $preMergeCount      = $script:AllFindings.Count

            # Merge: keep the higher severity/confidence seen so far, but do
            # NOT add a second RiskScore contribution or a second report line
            # for what is really the same underlying event.
            if ($SeverityScore[$Severity] -gt $SeverityScore[$existing.Severity]) { $existing.Severity = $Severity }
            if ($ConfidenceMultiplier[$Confidence] -gt $ConfidenceMultiplier[$existing.Confidence]) { $existing.Confidence = $Confidence }
            $existing.RiskScore = [math]::Round($SeverityScore[$existing.Severity] * $ConfidenceMultiplier[$existing.Confidence], 1)
            if ($MitreConfidence -eq 'CONFIRMED' -and $existing.MitreConfidence -eq 'HEURISTIC') { $existing.MitreConfidence = 'CONFIRMED' }
            $evidenceRank = @{ DIRECT = 2; HEURISTIC = 1; CONTEXT = 0 }
            if ($evidenceRank[$EvidenceType] -gt $evidenceRank[$existing.EvidenceType]) { $existing.EvidenceType = $EvidenceType }
            if ($existing.Recommendation -notmatch [regex]::Escape($Recommendation)) {
                $existing.Recommendation = "$($existing.Recommendation) | Also matched by $Category check: $Recommendation"
            }
            # Provenance: record every category that contributed, so a merge
            # never silently discards which detectors fired.
            if (-not $existing.PSObject.Properties['MergedFromCategories']) {
                Add-Member -InputObject $existing -NotePropertyName 'MergedFromCategories' -NotePropertyValue @($existing.Category) -Force
            }
            if ($existing.MergedFromCategories -notcontains $Category) {
                $existing.MergedFromCategories = @($existing.MergedFromCategories) + $Category
            }

            [void]$script:DuplicateMergeEvents.Add([PSCustomObject]@{
                DedupKey           = $dedupKey
                ExistingFindingId  = $existingId
                IncomingCategory   = $Category
                ExistingCategory   = $existing.Category
                PID_               = $IOC['PID_']
                Command            = $IOC['Command']
                PreMergeSeverity   = $preMergeSeverity
                PostMergeSeverity  = $existing.Severity
                PreMergeConfidence = $preMergeConfidence
                PostMergeConfidence = $existing.Confidence
                PreMergeRiskScore  = $preMergeRiskScore
                PostMergeRiskScore = $existing.RiskScore
                FindingsCountBefore = $preMergeCount
                FindingsCountAfter  = $script:AllFindings.Count
                Timestamp          = (Get-Date).ToString('s')
            })
            return $existing
        }
    }

    $script:flagCount++
    $marker = '[?]'
    if ($Severity -eq 'HIGH' -or $Severity -eq 'CRITICAL') { $marker = '[!]' }
    $report.Add("$marker $Text")
    if ($MitreId -and $MitreCatalog.ContainsKey($MitreId)) {
        $confNote = if ($MitreConfidence -eq 'HEURISTIC') { ' (heuristic mapping - inferred, not directly confirmed)' } else { '' }
        $report.Add("    MITRE ATT&CK: $MitreId - $($MitreCatalog[$MitreId])$confNote")
    }
    if ($Recommendation) {
        $report.Add("    Recommended action: $Recommendation")
    }

    $mitreName = ''
    if ($MitreId -and $MitreCatalog.ContainsKey($MitreId)) { $mitreName = $MitreCatalog[$MitreId] }
    $baseScore = $SeverityScore[$Severity]
    $mult = $ConfidenceMultiplier[$Confidence]
    $riskScore = [math]::Round($baseScore * $mult, 1)

    $finding = [PSCustomObject]@{
        Id             = $script:findingIdCounter
        Category       = $Category
        Text           = $Text
        Severity       = $Severity
        Confidence     = $Confidence
        RiskScore      = $riskScore
        MitreId        = $MitreId
        MitreName      = $mitreName
        MitreConfidence = if ($MitreId) { $MitreConfidence } else { '' }
        EvidenceType    = $EvidenceType
        Recommendation = $Recommendation
        IOC            = $IOC
        Timestamp      = (Get-Date).ToString('s')
    }
    if ($dedupKey) { $script:FindingDedupKeys[$dedupKey] = $script:findingIdCounter }
    $script:findingIdCounter++
    [void]$script:AllFindings.Add($finding)
    return $finding
}

function Add-Context($text) {
    # Purely informational line - config/state display, not a scored finding.
    $report.Add($text)
}

function HtmlEscape($text) {
    if ($null -eq $text) { return "" }
    $t = [string]$text
    $t = $t.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
    return $t
}

function Get-FileHashSafe($path) {
    if (-not $Config.EnableHashing) { return "" }
    if (-not $path) { return "" }
    if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { return "" }
    try {
        return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        Add-ScanError 'Get-FileHashSafe' "Failed to hash file: $path - $($_.Exception.Message)" 'LOW' 'ERROR'
        return ""
    }
}

function Get-SignatureSafe($path) {
    if (-not $path) { return $null }
    try {
        return Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    } catch {
        return $null
    }
}

# Signature verdict, used wherever "unsigned" was previously being conflated
# with "couldn't check the signature" or "chain not trusted" (a real logical
# bug: NotTrusted/UnknownError/Incompatible are NOT the same evidence as a
# confirmed hash-mismatch tamper, and a path that failed to resolve is not
# evidence of anything at all).
# Returns one of: Valid, NotSigned, Invalid, Untrusted, Unavailable
#   Valid       - signed and the signature validates
#   NotSigned   - confirmed no signature present at all
#   Invalid     - signature present but HASH MISMATCH - genuine tamper evidence
#   Untrusted   - signature present, hash matches, but the cert chain isn't
#                 trusted (e.g. self-issued/dev cert) - weaker signal than Invalid
#   Unavailable - could not determine at all (path unresolved, access denied,
#                 unsupported file format, or any other inconclusive error) -
#                 NOT evidence of tampering, must not be treated as such
# Correctly tests whether $path is inside $directory, as opposed to a plain
# $path.StartsWith($directory) check - which would incorrectly treat
# "C:\WindowsMalware\evil.exe" as being inside "C:\Windows" because the
# TEXT happens to start with the same characters. Fixed by normalizing both
# sides (resolving relative segments and trailing slashes) and comparing
# against $directory + a trailing directory separator, so only a real
# subdirectory/file boundary counts as a match.
function Test-PathUnderDirectory($path, $directory) {
    if (-not $path -or -not $directory) { return $false }
    try {
        $normPath = [System.IO.Path]::GetFullPath($path).TrimEnd('\')
        $normDir = [System.IO.Path]::GetFullPath($directory).TrimEnd('\')
    } catch {
        return $false
    }
    if ($normPath.Equals($normDir, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $normPath.StartsWith($normDir + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-SignatureVerdict($path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
        $script:ScanCoverage.SignatureUnavailable++
        return 'Unavailable'
    }
    $script:ScanCoverage.SignatureChecksPerformed++
    $sig = Get-SignatureSafe $path
    if (-not $sig) { $script:ScanCoverage.SignatureUnavailable++; return 'Unavailable' }
    switch ($sig.Status) {
        'Valid'        { return 'Valid' }
        'NotSigned'    { return 'NotSigned' }
        'HashMismatch' { return 'Invalid' }
        'NotTrusted'   { return 'Untrusted' }
        default        { $script:ScanCoverage.SignatureUnavailable++; return 'Unavailable' }  # NotSupportedFileFormat, Incompatible, UnknownError, etc.
    }
}

# Resolves a WMI CommandLineTemplate (or any raw command line) to a real,
# checkable executable path. The previous regex only matched an explicitly
# quoted/bare path ending in ".exe" and failed on: bare interpreter names
# without a path or extension ("powershell -enc ..."), cmd's "/c" launcher
# form, and unexpanded %ENV% variables (cmd.exe syntax, not auto-expanded by
# PowerShell/.NET path APIs).
function Resolve-CommandLineExecutable($cmdLine) {
    if (-not $cmdLine) { return $null }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($cmdLine)

    if ($expanded -match '^"([^"]+\.(exe|cmd|bat|ps1|vbs))"') { return $Matches[1] }
    if ($expanded -match '^(\S+\.(exe|cmd|bat|ps1|vbs))\b') { return $Matches[1] }

    if ($expanded -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\b') {
        $interpreter = $Matches[1].ToLower()
        $knownPaths = @{
            'powershell' = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            'cmd'        = "$env:SystemRoot\System32\cmd.exe"
            'wscript'    = "$env:SystemRoot\System32\wscript.exe"
            'cscript'    = "$env:SystemRoot\System32\cscript.exe"
            'mshta'      = "$env:SystemRoot\System32\mshta.exe"
            'rundll32'   = "$env:SystemRoot\System32\rundll32.exe"
            'regsvr32'   = "$env:SystemRoot\System32\regsvr32.exe"
        }
        if ($knownPaths.ContainsKey($interpreter)) { return $knownPaths[$interpreter] }
        if ($interpreter -eq 'pwsh') {
            $pwshCmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
            if ($pwshCmd) { return $pwshCmd.Source }
        }
    }
    # cmd /c "some.exe ..." - pull the inner executable out of the /c payload
    if ($expanded -match '/c\s+"?([^"\s]+\.(exe|cmd|bat))') { return $Matches[1] }

    return $null  # genuinely could not resolve - Get-SignatureVerdict will
                  # correctly report this as 'Unavailable', not 'NotSigned'
}

function Get-ProcessOwnerSafe($cimProc) {
    try {
        $ownerInfo = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -ErrorAction Stop
        if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) { return "$($ownerInfo.Domain)\$($ownerInfo.User)" }
    } catch {}
    return "Unknown"
}

# Classifies a remote IP so network findings can tell "genuinely external"
# apart from loopback/private/link-local/common-virtualization ranges.
# VMware, VirtualBox, Docker, WSL2, and most VPN clients all route through
# addresses that fall in these ranges - none of that is inherently
# malicious, and treating it as such is a common source of false positives.
# IsPrivateAddress and IsVirtualizationNetwork are independent flags: ALL of
# 172.16.0.0/12 and 192.168.0.0/16 are private (RFC 1918), but only the
# specific, well-documented DEFAULT subnets within them are also flagged as
# virtualization - the private/12 and /16 blocks are far too broad to
# attribute to virtualization software in general, most of that space is
# just ordinary home/office private networking.
function Get-AddressClassification($ipString) {
    $result = @{ IsLoopback = $false; IsPrivateAddress = $false; IsLinkLocal = $false; IsVirtualizationNetwork = $false; IsExternal = $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($ipString, [ref]$ip)) { return $result }

    if ([System.Net.IPAddress]::IsLoopback($ip)) { $result.IsLoopback = $true }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $ip.GetAddressBytes()
        if ($bytes[0] -eq 10) { $result.IsPrivateAddress = $true }
        elseif ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) {
            $result.IsPrivateAddress = $true
            # Only Docker Desktop's specific default bridge subnet
            # (172.17.0.0/16) is flagged as virtualization here - the rest of
            # 172.16.0.0/12 is ordinary RFC 1918 private space with no
            # reliable virtualization association.
            if ($bytes[1] -eq 17) { $result.IsVirtualizationNetwork = $true }
        }
        elseif ($bytes[0] -eq 192 -and $bytes[1] -eq 168) {
            $result.IsPrivateAddress = $true
            # VirtualBox host-only adapters default to 192.168.56.0/24 - this
            # specific /24 only, not the whole 192.168.0.0/16 block (which is
            # also where most home routers and VMware NAT setups live).
            if ($bytes[2] -eq 56) { $result.IsVirtualizationNetwork = $true }
        }
        elseif ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { $result.IsLinkLocal = $true }
    } else {
        $ipStr = $ip.ToString()
        # fe80::/10 covers fe80:: through febf:: - checking the first two
        # hex nibbles against 8/9/a/b after "fe" catches the full /10 range,
        # not just the literal "fe80:" prefix.
        if ($ipStr -match '^fe[89ab][0-9a-f]:') { $result.IsLinkLocal = $true }
        elseif ($ipStr -match '^f[cd][0-9a-f]{2}:') { $result.IsPrivateAddress = $true }  # IPv6 unique local (fc00::/7)
    }
    $result.IsExternal = -not ($result.IsLoopback -or $result.IsPrivateAddress -or $result.IsLinkLocal)
    return $result
}

function Add-HighRiskPid($pid_) {
    if ($pid_ -and (-not ($script:HighRiskPIDs -contains $pid_))) {
        [void]$script:HighRiskPIDs.Add($pid_)
    }
}

Write-Host "Running security diagnostic scan... this may take a few minutes." -ForegroundColor Cyan

# =================================================================
# SHARED SCAN CONTEXT (built once, reused by multiple functions to
# avoid repeating expensive queries - see Config item 21, performance)
# =================================================================
function Initialize-ScanContext {
    Add-Section "SCAN CONTEXT - building process/network snapshot"
    $script:CimProcesses = @()
    $script:ProcessById = @{}
    try {
        $script:CimProcesses = Get-CimInstance Win32_Process -ErrorAction Stop
        foreach ($p in $script:CimProcesses) { $script:ProcessById[[int]$p.ProcessId] = $p }
        Set-SourceStatus 'Processes' 'OK'
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        Set-SourceStatus 'Processes' $code
        Add-ScanError 'Initialize-ScanContext' "Get-CimInstance Win32_Process failed: $($_.Exception.Message)" 'HIGH' $code
    }

    # Both network queries are evaluated INDEPENDENTLY. Previously a
    # successful Established query set Network = OK, and a subsequent Listen
    # failure could not lower it again (the Listen branch only upgraded from
    # NOT_TESTED), so a genuinely broken Listen query was masked entirely.
    $script:TcpEstablished = @()
    $script:TcpListening = @()
    $networkEstablishedOk = $false
    $networkListenOk = $false
    $networkWorstCode = 'ERROR'

    try {
        $script:TcpEstablished = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
        $networkEstablishedOk = $true
    } catch {
        # An empty result is normal and would NOT throw; reaching here means
        # the query itself failed.
        $script:TcpEstablished = @()
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        $networkWorstCode = $code
        Add-ScanError 'Initialize-ScanContext' "Get-NetTCPConnection (Established) failed: $($_.Exception.Message)" 'MEDIUM' $code
    }

    try {
        $script:TcpListening = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $networkListenOk = $true
    } catch {
        $script:TcpListening = @()
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        if ($networkWorstCode -ne 'PERMISSION_DENIED') { $networkWorstCode = $code }
        Add-ScanError 'Initialize-ScanContext' "Get-NetTCPConnection (Listen) failed: $($_.Exception.Message)" 'MEDIUM' $code
    }

    if ($networkEstablishedOk -and $networkListenOk) {
        Set-SourceStatus 'Network' 'OK'
    } else {
        # Either or both halves failed - the network picture is incomplete
        # either way, so the source is not reported as OK.
        Set-SourceStatus 'Network' $networkWorstCode
        Add-Line ("Network source incomplete - Established query OK: {0}, Listen query OK: {1}" -f $networkEstablishedOk, $networkListenOk)
    }
    Add-Context ("Processes captured: {0}" -f (@($script:CimProcesses)).Count)
    Add-Context ("Established connections: {0}" -f (@($script:TcpEstablished)).Count)
    Add-Context ("Listening ports: {0}" -f (@($script:TcpListening)).Count)

    # Self-exclusion: the scanner's OWN process (and the shell that hosts it)
    # would otherwise show up as "powershell.exe -NoProfile -ExecutionPolicy
    # Bypass -File Check-SuspiciousActivity.ps1" and get flagged by the
    # command-line/LOLBin checks as if it were a suspicious script. Excluded
    # by: current PID, its immediate parent PID, and any process whose
    # command line references this script's own filename.
    $script:SelfExclusionPids = New-Object System.Collections.Generic.HashSet[int]
    [void]$script:SelfExclusionPids.Add($PID)
    if ($script:ProcessById.ContainsKey($PID) -and $script:ProcessById[$PID].ParentProcessId) {
        [void]$script:SelfExclusionPids.Add([int]$script:ProcessById[$PID].ParentProcessId)
    }
    $selfScriptName = if ($PSCommandPath) { [System.IO.Path]::GetFileName($PSCommandPath) } else { $null }
    if ($selfScriptName) {
        foreach ($p in $script:CimProcesses) {
            if ($p.CommandLine -and $p.CommandLine.ToLower().Contains($selfScriptName.ToLower())) {
                [void]$script:SelfExclusionPids.Add([int]$p.ProcessId)
            }
        }
    }
    $script:ScannerPid = $PID
    $script:ScannerPath = if ($PSCommandPath) { $PSCommandPath } else { $null }
    $script:ScannerHash = $script:ScriptSHA256  # already computed at script start
    $script:ScannerCommandLine = if ($script:ProcessById.ContainsKey($PID)) { $script:ProcessById[$PID].CommandLine } else { $null }
    $script:SelfExclusionImplemented = $true  # the mechanism itself exists in this script version
    $script:SelfExclusionApplied = $true
    $script:SelfExcludedProcessCount = $script:SelfExclusionPids.Count
    # Verification: did the scanner's own PID actually appear in the process
    # snapshot it excludes from? Absence can happen in rare timing cases and
    # is reported as context here, NOT recorded as a ScanError.
    $script:SelfExclusionVerification = if ($script:ProcessById.ContainsKey($PID)) { 'VERIFIED - own PID found in process snapshot and excluded' } else { 'UNVERIFIED - own PID not present in the process snapshot (not treated as an error)' }
    Add-Context ("Self-exclusion verification: {0}" -f $script:SelfExclusionVerification)
    Add-Context ("Self-exclusion PIDs (this scanner's own process/host, never scored as malware): {0}" -f (($script:SelfExclusionPids | Sort-Object) -join ', '))
}

function Test-ReadOnlyCompliance($scriptPath) {
    # The previous version searched the script's own TEXT for destructive
    # command names via regex - which meant it matched the very line that
    # DEFINES the regex pattern list (a string literal containing
    # "Remove-Item|Stop-Process|...") as if it were a real invocation,
    # guaranteeing ReadOnlyStatus = FAIL against this exact file every time.
    # AST parsing distinguishes an actual command invocation (a CommandAst
    # node) from the same text sitting inside a comment, a string literal,
    # or a regex pattern - those never produce a CommandAst for that name.
    $destructiveCommands = @('Remove-Item', 'Stop-Process', 'Stop-Service', 'Set-Service', 'Set-MpPreference',
                              'Disable-MpPreference', 'Set-NetFirewallRule', 'Disable-NetFirewallRule',
                              'Unregister-ScheduledTask', 'Remove-ItemProperty', 'Set-ItemProperty',
                              'New-ItemProperty', 'Set-ExecutionPolicy')
    $result = [PSCustomObject]@{ Status = 'NOT_TESTED'; Method = 'none'; Warnings = New-Object System.Collections.Generic.List[string] }

    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) {
        [void]$result.Warnings.Add('Script path not resolvable (e.g. run via -Command instead of -File) - cannot self-check, reporting NOT_TESTED rather than guessing.')
        return $result
    }

    try {
        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors -and $parseErrors.Count -gt 0) { throw "Parser reported $($parseErrors.Count) syntax error(s) while re-parsing own source." }

        $commandAsts = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
        $foundInvocations = New-Object System.Collections.Generic.List[string]
        foreach ($cmd in $commandAsts) {
            $cmdName = $cmd.GetCommandName()
            if ($cmdName -and ($destructiveCommands -contains $cmdName)) {
                [void]$foundInvocations.Add("$cmdName at line $($cmd.Extent.StartLineNumber)")
            }
        }
        $result.Method = 'AST'
        if ($foundInvocations.Count -gt 0) {
            $result.Status = 'FAIL'
            foreach ($fi in $foundInvocations) { [void]$result.Warnings.Add("Real command invocation found: $fi") }
        } else {
            $result.Status = 'PASS'
        }
        return $result
    } catch {
        # AST parsing itself failed (should not normally happen since this
        # script is already running, but the file on disk could differ from
        # what's executing, e.g. edited mid-run) - fall back to a regex scan
        # that explicitly SKIPS comment lines and lines that look like a
        # pattern-list string definition, so it doesn't repeat the original bug.
        [void]$result.Warnings.Add("AST-based check unavailable ($($_.Exception.Message)) - used regex fallback instead, which is less precise than AST.")
        try {
            $lines = Get-Content -LiteralPath $scriptPath
            $foundInvocations = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($line.TrimStart().StartsWith('#')) { continue }
                if ($line -match "=\s*@\(|=\s*'[^']*\|") { continue }  # a pattern/array definition line, not an invocation
                foreach ($cmd in $destructiveCommands) {
                    if ($line -match "(^|[;|(]\s*)$([regex]::Escape($cmd))\b" -and $line -notmatch "['""][^'""]*$([regex]::Escape($cmd))[^'""]*['""]") {
                        [void]$foundInvocations.Add("$cmd at line $($i + 1): $($line.Trim())")
                    }
                }
            }
            $result.Method = 'regex-fallback'
            if ($foundInvocations.Count -gt 0) {
                $result.Status = 'FAIL'
                foreach ($fi in $foundInvocations) { [void]$result.Warnings.Add("Possible invocation: $fi") }
            } else {
                $result.Status = 'PASS'
            }
        } catch {
            $result.Status = 'NOT_TESTED'
            $result.Method = 'none'
            [void]$result.Warnings.Add("Could not read own source at all: $($_.Exception.Message)")
        }
        return $result
    }
}

function Get-ParentPidSafe($pidToLookup) {
    if ($pidToLookup -and $script:ProcessById.ContainsKey([int]$pidToLookup)) {
        return $script:ProcessById[[int]$pidToLookup].ParentProcessId
    }
    return $null
}

function Get-ProcessAncestry($pidToTrace) {
    $chain = New-Object System.Collections.Generic.List[string]
    $current = $script:ProcessById[[int]$pidToTrace]
    $depth = 0
    while ($current -and $depth -lt 5) {
        [void]$chain.Add(("{0} (PID {1})" -f $current.Name, $current.ProcessId))
        $parentId = [int]$current.ParentProcessId
        if (-not $script:ProcessById.ContainsKey($parentId)) { break }
        $current = $script:ProcessById[$parentId]
        $depth++
    }
    $chain.Reverse()
    return ($chain -join ' -> ')
}

# =================================================================
# 1. SUSPICIOUS PROCESSES
# =================================================================
function Get-SuspiciousProcesses {
    Add-Section "SUSPICIOUS PROCESSES"
    $suspiciousPaths = @('\Temp\', '\AppData\Local\Temp\', '\Downloads\', '\Users\Public\', '\ProgramData\')
    $found = 0
    $processes = Get-Process | Where-Object { $_.Path } | Select-Object Name, Id, Path, StartTime, Company
    foreach ($p in $processes) {
        $script:ScanCoverage.ProcessesChecked++
        $isSuspiciousPath = $false
        foreach ($sp in $suspiciousPaths) {
            if ($p.Path -match [regex]::Escape($sp)) { $isSuspiciousPath = $true; break }
        }
        $verdict = Get-SignatureVerdict $p.Path
        # 'Unavailable' means we could not determine anything - it is NOT the
        # same evidence as a confirmed-unsigned or confirmed-tampered file and
        # must not drive severity on its own.
        $isConfirmedBad = ($verdict -eq 'NotSigned' -or $verdict -eq 'Invalid' -or $verdict -eq 'Untrusted')

        # Packaged Windows applications (AppX/MSIX under WindowsApps) are
        # signed at the PACKAGE level, not per-file with Authenticode, so
        # Get-AuthenticodeSignature legitimately reports NotSigned for many
        # of their executables - e.g. MicrosoftStartFeedProvider and
        # WhatsApp.Root in a real scan. That is a property of how MSIX
        # signing works, not evidence of anything.
        #
        # This is deliberately NOT a blanket whitelist:
        #   - the location alone never marks anything suspicious;
        #   - NotSigned inside WindowsApps is treated as weak/inconclusive
        #     and needs corroborating evidence before it raises risk;
        #   - Invalid (a signature present but failing hash validation) is
        #     still real tamper evidence and is NOT downgraded here;
        #   - executables outside WindowsApps are unaffected.
        $windowsAppsRoots = @()
        if ($env:ProgramFiles) { $windowsAppsRoots += (Join-Path $env:ProgramFiles 'WindowsApps') }
        if (${env:ProgramFiles(x86)}) { $windowsAppsRoots += (Join-Path ${env:ProgramFiles(x86)} 'WindowsApps') }
        $isPackagedApp = $false
        foreach ($war in $windowsAppsRoots) {
            if (Test-PathUnderDirectory $p.Path $war) { $isPackagedApp = $true; break }
        }
        # Only the "unsigned" verdicts are explained away by packaging.
        $packagedWeakSignal = ($isPackagedApp -and ($verdict -eq 'NotSigned' -or $verdict -eq 'Untrusted'))

        if ($isSuspiciousPath -or $isConfirmedBad) {
            $flags = @()
            if ($isSuspiciousPath) { $flags += "running from a suspicious folder" }
            if ($isConfirmedBad) { $flags += ("signature: {0}" -f $verdict) }
            elseif ($verdict -eq 'Unavailable') { $flags += "signature could not be verified" }
            if ($packagedWeakSignal) { $flags += "packaged Windows app (AppX/MSIX) - Authenticode result is inconclusive for this package type" }
            $hash = Get-FileHashSafe $p.Path
            $ancestry = Get-ProcessAncestry $p.Id

            # Baseline severity from the signature verdict alone.
            $sev = 'LOW'; $conf = 'LOW'
            if ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }

            # A suspicious path is corroborating evidence and escalates the
            # baseline - but only when the signature is ALSO confirmed bad.
            # A suspicious path alone with a Valid or Unavailable signature
            # stays at LOW, same as before this fix.
            if ($isSuspiciousPath -and $isConfirmedBad) {
                if ($verdict -eq 'Invalid') { $sev = 'CRITICAL'; $conf = 'HIGH' }
                else { $sev = 'MEDIUM'; $conf = 'MEDIUM' }
            }

            # Packaged app with only the weak unsigned signal and no other
            # corroboration: report as context, not as a risk contributor.
            $evidenceType = 'HEURISTIC'
            $mitreConf = 'CONTEXT_ONLY'
            if ($packagedWeakSignal -and -not $isSuspiciousPath) {
                $sev = 'INFO'; $conf = 'LOW'; $evidenceType = 'CONTEXT'
            }

            $ioc = @{ Path = $p.Path; SHA256 = $hash; Process = $p.Name; PID_ = $p.Id; ParentPID_ = (Get-ParentPidSafe $p.Id) }
            $recommendation = if ($packagedWeakSignal -and -not $isSuspiciousPath) {
                "Executables inside WindowsApps are package-signed (AppX/MSIX) rather than Authenticode-signed per file, so a NotSigned result here is expected and not by itself a reason for concern. Verify the package identity in Settings > Apps if the app is unfamiliar."
            } else {
                "Check the file path and publisher; if unfamiliar, upload the hash to VirusTotal before deciding."
            }
            $f = Add-Finding -Category 'Process' -Severity $sev -Confidence $conf -EvidenceType $evidenceType -MitreConfidence $mitreConf `
                -Text ("{0} (PID {1}) - {2}" -f $p.Name, $p.Id, ($flags -join '; ')) `
                -Recommendation $recommendation `
                -IOC $ioc
            Add-Line ("    Path: {0}" -f $p.Path)
            Add-Line ("    Company: {0}" -f $p.Company)
            if ($hash) {
                Add-Line ("    SHA256: {0}" -f $hash)
                Add-Line ("    Check at: https://www.virustotal.com/gui/file/{0}" -f $hash)
            }
            if ($ancestry) { Add-Line ("    Ancestry: {0}" -f $ancestry) }
            Add-Line ""
            $found++
            if ($sev -eq 'HIGH' -or $sev -eq 'CRITICAL') { Add-HighRiskPid $p.Id }
        }
    }
    if ($found -eq 0) { Add-Context "No processes matched the suspicious-path/confirmed-bad-signature heuristic." }
}

# =================================================================
# 2. PERSISTENCE INDICATORS (Registry Run Keys, Startup Folder, IFEO,
#    SilentProcessExit, Active Setup, Winlogon (Shell/Userinit/Notify),
#    ShellServiceObjectDelayLoad, AppInit_DLLs, PowerShell Profiles,
#    COM Hijacking)
# =================================================================
function Get-PersistenceIndicators {
    Add-Section "PERSISTENCE - AUTOSTART LOCATIONS"

    # --- Registry Run / RunOnce ---
    Add-Line "--- Registry Run / RunOnce keys ---"
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $script:RunKeysGlobal = $runKeys
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key
            $items.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                ForEach-Object {
                    Add-Line ("[{0}] {1} = {2}" -f $key, $_.Name, $_.Value)
                }
        }
    }

    # --- Startup folders (with signature check) ---
    Add-Line ""
    Add-Line "--- Startup folders ---"
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -File | ForEach-Object {
                if ($_.Extension -notmatch '\.(exe|dll|ps1|vbs|js|bat|cmd)$') {
                    Add-Line ("File: {0}" -f $_.FullName)
                    return
                }
                $verdict = Get-SignatureVerdict $_.FullName
                if ($verdict -eq 'Valid') {
                    Add-Line ("File: {0} (signed)" -f $_.FullName)
                    return
                }
                $sev = 'LOW'; $conf = 'LOW'
                if ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }
                elseif ($verdict -eq 'NotSigned') { $sev = 'MEDIUM'; $conf = 'MEDIUM' }
                elseif ($verdict -eq 'Untrusted') { $sev = 'MEDIUM'; $conf = 'LOW' }
                # 'Unavailable' (couldn't check at all) stays LOW/LOW - not evidence of anything.
                Add-Finding -Category 'Persistence' -Severity $sev -Confidence $conf -MitreId 'T1547.001' `
                    -Text ("Startup item with signature status '{0}': {1}" -f $verdict, $_.FullName) `
                    -Recommendation "Confirm you installed this yourself; if not, remove it and re-scan." `
                    -IOC @{ Path = $_.FullName; SHA256 = (Get-FileHashSafe $_.FullName) } | Out-Null
            }
        }
    }

    # --- IFEO Debugger hijacks (generic scan of all subkeys, not just accessibility bins) ---
    Add-Line ""
    Add-Line "--- Image File Execution Options (Debugger hijacks) ---"
    $accessibilityBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
    $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $ifeoFound = 0
    if (Test-Path $ifeoBase) {
        Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $ifeoFound++
                $targetName = $_.PSChildName.ToLower()
                if ($accessibilityBinaries -contains $targetName) {
                    Add-Finding -Category 'Persistence' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1546.008' `
                        -Text ("{0} has a Debugger override: {1} - classic Sticky Keys / RDP pre-auth backdoor" -f $_.PSChildName, $debugger) `
                        -Recommendation "Remove the Debugger value immediately; this allows SYSTEM-level access from the login screen without credentials." `
                        -IOC @{ RegistryKey = $_.PSPath; Command = $debugger } | Out-Null
                } else {
                    Add-Finding -Category 'Persistence' -Severity 'HIGH' -Confidence 'MEDIUM' -MitreId 'T1546.012' `
                        -Text ("{0} has an unexpected Debugger override: {1}" -f $_.PSChildName, $debugger) `
                        -Recommendation "IFEO Debugger values hijack execution of the named binary - verify this was intentionally configured (some debugging/compat tools use it legitimately)." `
                        -IOC @{ RegistryKey = $_.PSPath; Command = $debugger } | Out-Null
                }
            }
        }
    }
    if ($ifeoFound -eq 0) { Add-Context "No IFEO Debugger overrides found (normal)." }

    # --- SilentProcessExit (similar hijack mechanism to IFEO) ---
    Add-Line ""
    Add-Line "--- SilentProcessExit monitoring ---"
    $spePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    $speFound = 0
    if (Test-Path $spePath) {
        Get-ChildItem $spePath -ErrorAction SilentlyContinue | ForEach-Object {
            $monitor = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).MonitorProcess
            if ($monitor) {
                $speFound++
                Add-Finding -Category 'Persistence' -Severity 'MEDIUM' -Confidence 'MEDIUM' -MitreId 'T1546.012' `
                    -Text ("SilentProcessExit monitor set for {0}: {1}" -f $_.PSChildName, $monitor) `
                    -Recommendation "This mechanism silently launches a program whenever the named process exits - verify it is expected diagnostic tooling." `
                    -IOC @{ RegistryKey = $_.PSPath; Command = $monitor } | Out-Null
            }
        }
    }
    if ($speFound -eq 0) { Add-Context "No SilentProcessExit entries found (normal)." }

    # --- Active Setup ---
    Add-Line ""
    Add-Line "--- Active Setup (Installed Components) ---"
    $activeSetupPath = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
    if (Test-Path $activeSetupPath) {
        Get-ChildItem $activeSetupPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($props.StubPath) {
                $exePart = $props.StubPath -replace '^"?([^"]+\.exe)"?.*', '$1'
                $verdict = Get-SignatureVerdict $exePart
                if ($verdict -eq 'Valid') {
                    Add-Line ("StubPath: {0} (signed)" -f $props.StubPath)
                } else {
                    $sev = 'LOW'; $conf = 'LOW'
                    if ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }
                    elseif ($verdict -eq 'NotSigned') { $sev = 'MEDIUM'; $conf = 'LOW' }
                    elseif ($verdict -eq 'Untrusted') { $sev = 'MEDIUM'; $conf = 'LOW' }
                    Add-Finding -Category 'Persistence' -Severity $sev -Confidence $conf -MitreId 'T1547.014' `
                        -Text ("Active Setup StubPath (target signature: {0}): {1} = {2}" -f $verdict, $props.'(default)', $props.StubPath) `
                        -Recommendation "Active Setup runs once per user at logon - confirm this belongs to installed software you recognize." `
                        -IOC @{ RegistryKey = $_.PSPath; Command = $props.StubPath } | Out-Null
                }
            }
        }
    }

    # --- Winlogon (Shell / Userinit / Notify) ---
    Add-Line ""
    Add-Line "--- Winlogon Shell / Userinit / Notify ---"
    $winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
    if ($winlogon) {
        if ($winlogon.Shell -and $winlogon.Shell -ne 'explorer.exe') {
            Add-Finding -Category 'Persistence' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1547.004' `
                -Text ("Winlogon Shell is not the default explorer.exe: {0}" -f $winlogon.Shell) `
                -Recommendation "This runs instead of the normal desktop at every logon - investigate immediately." `
                -IOC @{ RegistryKey = $winlogonPath; Command = $winlogon.Shell } | Out-Null
        } else {
            Add-Line ("Shell: {0} (normal)" -f $winlogon.Shell)
        }
        if ($winlogon.Userinit -and $winlogon.Userinit -ne 'C:\Windows\system32\userinit.exe,') {
            Add-Finding -Category 'Persistence' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1547.004' `
                -Text ("Winlogon Userinit is not the default: {0}" -f $winlogon.Userinit) `
                -Recommendation "This runs before the desktop loads at every logon - investigate immediately." `
                -IOC @{ RegistryKey = $winlogonPath; Command = $winlogon.Userinit } | Out-Null
        } else {
            Add-Line ("Userinit: {0} (normal)" -f $winlogon.Userinit)
        }
    }
    $notifyPath = Join-Path $winlogonPath 'Notify'
    if (Test-Path $notifyPath) {
        $notifySubkeys = Get-ChildItem $notifyPath -ErrorAction SilentlyContinue
        if ($notifySubkeys) {
            foreach ($nk in $notifySubkeys) {
                Add-Finding -Category 'Persistence' -Severity 'MEDIUM' -Confidence 'LOW' -MitreId 'T1547.004' `
                    -Text ("Winlogon Notify package present (legacy mechanism, rarely used post-Vista): {0}" -f $nk.PSChildName) `
                    -Recommendation "This mechanism is essentially unused on modern Windows - verify what installed it." `
                    -IOC @{ RegistryKey = $nk.PSPath } | Out-Null
            }
        } else {
            Add-Line "No Winlogon Notify packages (normal)."
        }
    }

    # --- ShellServiceObjectDelayLoad ---
    Add-Line ""
    Add-Line "--- ShellServiceObjectDelayLoad ---"
    $ssodlPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad'
    if (Test-Path $ssodlPath) {
        $ssodl = Get-ItemProperty -Path $ssodlPath -ErrorAction SilentlyContinue
        $ssodl.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } | ForEach-Object {
            Add-Line ("Entry: {0} = {1} (cross-check the referenced CLSID under HKCR\CLSID manually if unfamiliar)" -f $_.Name, $_.Value)
        }
    }

    # --- AppInit_DLLs ---
    Add-Line ""
    Add-Line "--- AppInit_DLLs ---"
    $appInit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    if ($appInit -and $appInit.AppInit_DLLs -and $appInit.AppInit_DLLs.Trim() -ne '') {
        Add-Finding -Category 'Persistence' -Severity 'HIGH' -Confidence 'MEDIUM' -MitreId 'T1546.009' `
            -Text ("AppInit_DLLs is set: {0}" -f $appInit.AppInit_DLLs) `
            -Recommendation "Any DLL listed here loads into almost every process that uses user32.dll - verify it is expected." `
            -IOC @{ RegistryKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Command = $appInit.AppInit_DLLs } | Out-Null
    } else {
        Add-Line "AppInit_DLLs is empty (normal)."
    }

    # --- PowerShell profiles ---
    Add-Line ""
    Add-Line "--- PowerShell profile scripts ---"
    $profilePaths = @(
        "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
        "$env:ProgramFiles\WindowsPowerShell\Modules\..\profile.ps1"
    )
    $profileFound = 0
    foreach ($pp in $profilePaths) {
        if (Test-Path $pp) {
            $content = Get-Content $pp -Raw -ErrorAction SilentlyContinue
            if ($content -and $content.Trim() -ne '') {
                $profileFound++
                Add-Finding -Category 'Persistence' -Severity 'LOW' -Confidence 'LOW' -MitreId 'T1546.013' `
                    -Text ("Non-empty PowerShell profile found: {0}" -f $pp) `
                    -Recommendation "PowerShell profiles run automatically whenever PowerShell starts - review the content of this file." `
                    -IOC @{ Path = $pp } | Out-Null
            }
        }
    }
    if ($profileFound -eq 0) { Add-Context "No non-empty PowerShell profile scripts found." }

    # --- COM hijacking (HKCU CLSID overrides pointing outside trusted dirs) ---
    Add-Line ""
    Add-Line "--- COM object hijacking (HKCU CLSID overrides) ---"
    $script:comFound = 0
    $hkcuClsid = 'HKCU:\Software\Classes\CLSID'
    $script:ComSuspiciousDirs = @('\Temp\', '\AppData\Local\Temp\', '\Downloads\', '\Users\Public\', '\ProgramData\')
    # Trusted base folders resolved from environment variables rather than a
    # hardcoded "C:\" prefix, and explicitly including Program Files (x86).
    $script:ComTrustedBaseFolders = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }

    # Shared logic for both server subkeys a CLSID can register: InprocServer32
    # (a DLL, loaded in-process) and LocalServer32 (an EXE, launched as its own
    # process). Both are legitimate COM hijack targets and were previously
    # only checked for InprocServer32.
    function Test-ComServerEntry($clsidKeyPath, $clsidName, $serverType, $extension) {
        $serverPath = Join-Path $clsidKeyPath $serverType
        if (-not (Test-Path $serverPath)) { return }
        $rawValue = (Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue).'(default)'
        if (-not $rawValue) { return }

        # Clean quotes and any trailing arguments (LocalServer32 values are
        # often a full command line, e.g. "C:\App\app.exe" /automation), then
        # expand %ENV% variables before trusting/checking the result.
        $resolvedPath = $rawValue.Trim().Trim('"')
        if ($resolvedPath -match ('^"?([^"]+\.{0})"?' -f $extension)) { $resolvedPath = $Matches[1] }
        $resolvedPath = [System.Environment]::ExpandEnvironmentVariables($resolvedPath)

        $isTrusted = $false
        foreach ($tb in $script:ComTrustedBaseFolders) {
            if (Test-PathUnderDirectory $resolvedPath $tb) { $isTrusted = $true; break }
        }
        if ($isTrusted) { return }

        $script:comFound++
        $verdict = Get-SignatureVerdict $resolvedPath
        $isSuspiciousDir = $false
        foreach ($sd in $script:ComSuspiciousDirs) { if ($resolvedPath -match [regex]::Escape($sd)) { $isSuspiciousDir = $true; break } }

        # Baseline severity from the target's own signature verdict ONLY -
        # location alone (e.g. sitting in AppData with a Valid or Unavailable
        # signature) never produces HIGH by itself; it only escalates an
        # ALREADY-bad signature.
        $sev = 'LOW'; $conf = 'LOW'
        if ($verdict -eq 'NotSigned' -or $verdict -eq 'Untrusted') { $sev = 'MEDIUM'; $conf = 'LOW' }
        elseif ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }
        if ($isSuspiciousDir -and ($verdict -eq 'NotSigned' -or $verdict -eq 'Untrusted')) { $sev = 'HIGH'; $conf = 'MEDIUM' }
        elseif ($isSuspiciousDir -and $verdict -eq 'Invalid') { $sev = 'CRITICAL'; $conf = 'HIGH' }

        $publisher = ""
        if ($verdict -eq 'Valid') {
            $sig = Get-SignatureSafe $resolvedPath
            if ($sig -and $sig.SignerCertificate) { $publisher = " | Publisher: $($sig.SignerCertificate.Subject)" }
        }
        $hash = Get-FileHashSafe $resolvedPath

        Add-Finding -Category 'Persistence' -Severity $sev -Confidence $conf -MitreId 'T1546.015' `
            -Text ("HKCU CLSID override ({0}) points outside trusted folders (signature: {1}): {2} -> {3}{4}" -f $serverType, $verdict, $clsidName, $resolvedPath, $publisher) `
            -Recommendation "Per-user CLSID overrides in HKCU silently redirect COM object loads without needing admin rights - a known hijack technique. Severity reflects the target's signature, and is escalated further only when it ALSO sits in a commonly-abused folder." `
            -IOC @{ RegistryPath = $serverPath; ValueName = '(default)'; CLSID = $clsidName; ResolvedPath = $resolvedPath; SignatureVerdict = $verdict; SHA256 = $hash; Path = $resolvedPath } | Out-Null
    }

    if (Test-Path $hkcuClsid) {
        Get-ChildItem $hkcuClsid -ErrorAction SilentlyContinue | Select-Object -First $Config.MaxRegistryKeysToScan | ForEach-Object {
            $script:ScanCoverage.RegistryKeysChecked++
            Test-ComServerEntry $_.PSPath $_.PSChildName 'InprocServer32' 'dll'
            Test-ComServerEntry $_.PSPath $_.PSChildName 'LocalServer32' 'exe'
        }
    }
    if ($script:comFound -eq 0) { Add-Context "No suspicious HKCU CLSID overrides found." }
}

# =================================================================
# 3. SCHEDULED TASKS (including hidden tasks)
# =================================================================
function Get-ScheduledTaskIndicators {
    Add-Section "SCHEDULED TASKS"
    $nonMsFound = 0
    $allTasks = @()
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        Set-SourceStatus 'ScheduledTasks' 'OK'
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        Set-SourceStatus 'ScheduledTasks' $code
        Add-ScanError 'Get-ScheduledTaskIndicators' "Get-ScheduledTask failed: $($_.Exception.Message)" 'MEDIUM' $code
    }
    $script:ScanCoverage.ScheduledTasksChecked += (@($allTasks)).Count
    $allTasks | Where-Object { $_.Author -notmatch 'Microsoft' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $nonMsFound++
        Add-Line ("Task: {0}" -f $_.TaskName)
        Add-Line ("  Path: {0}" -f $_.TaskPath)
        Add-Line ("  Author: {0}" -f $_.Author)
        foreach ($act in $_.Actions) {
            Add-Line ("  Command: {0} {1}" -f $act.Execute, $act.Arguments)
        }
        Add-Line ""
    }
    if ($nonMsFound -eq 0) { Add-Context "No non-Microsoft scheduled tasks found." }

    $hiddenFound = 0
    $severityRank = @{ MEDIUM = 0; HIGH = 1; CRITICAL = 2 }
    $confidenceRank = @{ LOW = 0; MEDIUM = 1; HIGH = 2 }

    $allTasks | Where-Object { $_.Settings.Hidden -eq $true -and $_.State -ne 'Disabled' } | ForEach-Object {
        $hiddenFound++
        # A Hidden flag alone is a soft signal - some legitimate maintenance
        # tasks (including a few from Microsoft's own component vendors) set
        # it too. A task can have MULTIPLE actions; checking only the first
        # one (as before) could miss a suspicious second/third action. Every
        # action is evaluated, but they are combined into ONE finding for the
        # task - using the worst (highest) severity/confidence found across
        # all of them - rather than one finding per action.
        $worstSev = 'MEDIUM'; $worstConf = 'LOW'
        $actionSummaries = New-Object System.Collections.Generic.List[string]
        $iocCommands = New-Object System.Collections.Generic.List[string]

        $worstActionExecute = ''; $worstActionArgs = ''; $worstActionWorkDir = ''; $worstActionVerdict = ''

        foreach ($action in $_.Actions) {
            if (-not $action.Execute) { continue }
            $verdict = Get-SignatureVerdict $action.Execute
            $hasSuspiciousArgs = $false
            if ($action.Arguments) {
                $argsLower = $action.Arguments.ToLower()
                foreach ($pat in @('-enc', '-encodedcommand', 'frombase64string', 'downloadstring', 'downloadfile', '-w hidden', '-windowstyle hidden', 'bypass', 'iex ', 'invoke-expression')) {
                    if ($argsLower.Contains($pat)) { $hasSuspiciousArgs = $true; break }
                }
            }

            $sev = 'MEDIUM'; $conf = 'LOW'
            if ($verdict -eq 'Invalid' -and $hasSuspiciousArgs) { $sev = 'CRITICAL'; $conf = 'HIGH' }
            elseif ($verdict -eq 'NotSigned' -and $hasSuspiciousArgs) { $sev = 'CRITICAL'; $conf = 'HIGH' }
            elseif ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }
            elseif ($verdict -eq 'NotSigned') { $sev = 'HIGH'; $conf = 'MEDIUM' }
            elseif ($hasSuspiciousArgs) { $sev = 'HIGH'; $conf = 'MEDIUM' }
            elseif ($verdict -eq 'Untrusted') { $sev = 'MEDIUM'; $conf = 'LOW' }

            if ($severityRank[$sev] -gt $severityRank[$worstSev]) {
                $worstSev = $sev; $worstConf = $conf
                $worstActionExecute = $action.Execute; $worstActionArgs = $action.Arguments; $worstActionWorkDir = $action.WorkingDirectory; $worstActionVerdict = $verdict
            }
            elseif ($severityRank[$sev] -eq $severityRank[$worstSev] -and $confidenceRank[$conf] -gt $confidenceRank[$worstConf]) {
                $worstConf = $conf
                $worstActionExecute = $action.Execute; $worstActionArgs = $action.Arguments; $worstActionWorkDir = $action.WorkingDirectory; $worstActionVerdict = $verdict
            }

            $argNote = if ($hasSuspiciousArgs) { "; suspicious arguments" } else { "" }
            $workDir = if ($action.WorkingDirectory) { $action.WorkingDirectory } else { "(none)" }
            [void]$actionSummaries.Add(("{0} {1} [WorkingDirectory: {2}] (signature: {3}{4})" -f $action.Execute, $action.Arguments, $workDir, $verdict, $argNote))
            [void]$iocCommands.Add(("{0} {1} [WD: {2}]" -f $action.Execute, $action.Arguments, $workDir))
        }

        if ($actionSummaries.Count -eq 0) { return }
        # If every action tied at the initial MEDIUM/LOW baseline, none of them
        # triggered the "worse than current worst" branch above - fall back to
        # the first action's own data so the IOC isn't left blank.
        if (-not $worstActionExecute -and $_.Actions.Count -gt 0) {
            $firstAction = $_.Actions[0]
            $worstActionExecute = $firstAction.Execute; $worstActionArgs = $firstAction.Arguments
            $worstActionWorkDir = $firstAction.WorkingDirectory; $worstActionVerdict = Get-SignatureVerdict $firstAction.Execute
        }

        # Principal context: SYSTEM + RunLevel Highest + a non-interactive
        # logon type together are common for entirely legitimate scheduled
        # maintenance tasks, so this does NOT raise severity by itself. It
        # only raises CONFIDENCE, and only when an action already produced a
        # real signature/argument concern (worstSev is not just the MEDIUM
        # "hidden flag alone" baseline).
        $principal = $_.Principal
        $runsAsSystem = $principal -and $principal.UserId -match 'SYSTEM'
        $runsHighest = $principal -and $principal.RunLevel -eq 'Highest'
        $nonInteractive = $principal -and $principal.LogonType -and $principal.LogonType -ne 'Interactive'
        $privilegedContext = $runsAsSystem -and $runsHighest -and $nonInteractive
        $principalNote = ""
        if ($privilegedContext) {
            $principalNote = " | Runs as SYSTEM, RunLevel=Highest, non-interactive logon"
            if ($worstSev -ne 'MEDIUM' -and $confidenceRank[$worstConf] -lt $confidenceRank['HIGH']) { $worstConf = 'HIGH' }
        }

        Add-Finding -Category 'Persistence' -Severity $worstSev -Confidence $worstConf -MitreId 'T1053.005' `
            -Text ("HIDDEN scheduled task: {0} - {1} action(s){2}: {3}" -f $_.TaskName, $actionSummaries.Count, $principalNote, ($actionSummaries -join ' || ')) `
            -Recommendation "Hidden tasks do not show in the Task Scheduler UI by default. Severity reflects the worst signature/argument combination found across ALL of this task's actions, not just the first one. Running as SYSTEM/Highest/non-interactive is common for legitimate tasks and only raises confidence, not severity, on its own." `
            -IOC @{ Command = ($iocCommands -join ' || '); TaskPath = $_.TaskPath; TaskName = $_.TaskName; ActionCount = $actionSummaries.Count; WorstActionExecute = $worstActionExecute; WorstActionArguments = $worstActionArgs; WorstActionWorkingDirectory = $worstActionWorkDir; WorstActionSignatureVerdict = $worstActionVerdict } | Out-Null
        Add-Line ("  Path: {0}" -f $_.TaskPath)
        foreach ($s in $actionSummaries) { Add-Line ("  Action: {0}" -f $s) }
        Add-Line ""
    }
    if ($hiddenFound -eq 0) { Add-Context "No hidden scheduled tasks found." }
}

# =================================================================
# 4. WINDOWS SERVICES (unsigned executables)
# =================================================================
function Resolve-ServicePath($pathName) {
    # Handles: %ENV% variables, quoted "C:\...\app.exe" -args, unquoted
    # C:\...\app.exe -args, \SystemRoot and \??\ prefixes, and exe/cmd/bat/
    # com/sys extensions. The full raw PathName is preserved separately by
    # the caller for IOC purposes - this only extracts a best-effort
    # executable/argument split for signature checking.
    $result = @{ ExecutablePath = $null; Arguments = '' }
    if (-not $pathName) { return $result }
    $expanded = [System.Environment]::ExpandEnvironmentVariables($pathName)
    $expanded = $expanded -replace '^\\SystemRoot', $env:SystemRoot -replace '^System32\\', "$env:SystemRoot\System32\" -replace '^\\\?\?\\', ''
    $extPattern = '\.(exe|cmd|bat|com|sys)'
    if ($expanded -match ('^"([^"]+' + $extPattern + ')"(.*)$')) {
        $result.ExecutablePath = $Matches[1]
        $result.Arguments = $Matches[3].Trim()
    } elseif ($expanded -match ('^(\S+' + $extPattern + ')(.*)$')) {
        # Unquoted path: takes the first-extension-match reading. This does
        # NOT resolve the classic "unquoted service path" ambiguity (a path
        # containing spaces could genuinely be interpreted at more than one
        # break point) - it picks the same first match Windows itself
        # would try first, not a guaranteed-correct resolution.
        $result.ExecutablePath = $Matches[1]
        $result.Arguments = $Matches[3].Trim()
    } else {
        $result.ExecutablePath = $expanded.Trim()
    }
    return $result
}

function Get-ServiceIndicators {
    Add-Section "WINDOWS SERVICES - SIGNATURE AND PERSISTENCE ANALYSIS"
    $found = 0
    $allServices = @()
    try {
        $allServices = Get-CimInstance Win32_Service -ErrorAction Stop
        Set-SourceStatus 'Services' 'OK'
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        Set-SourceStatus 'Services' $code
        Add-ScanError 'Get-ServiceIndicators' "Get-CimInstance Win32_Service failed: $($_.Exception.Message)" 'MEDIUM' $code
    }
    $allServices | Where-Object { $_.State -eq 'Running' -and $_.PathName } | ForEach-Object {
        $script:ScanCoverage.ServicesChecked++
        $resolved = Resolve-ServicePath $_.PathName
        $exePath = $resolved.ExecutablePath
        if ($exePath -and (Test-Path $exePath)) {
            $verdict = Get-SignatureVerdict $exePath
            if ($verdict -eq 'Valid') { return }
            if ($verdict -eq 'Unavailable') {
                Add-Line ("  Service with unverifiable signature (not evidence of anything): {0} ({1}) - {2}" -f $_.DisplayName, $_.Name, $exePath)
                return
            }
            $found++

            # ServiceIntegrity: a fact about the binary's signature - does NOT
            # by itself confirm T1543.003 (a service CREATED/MODIFIED for
            # persistence). Corroboration: the service's own registry key
            # was written recently, which is genuine supporting evidence a
            # signature fact alone is not.
            $isRecent = $false
            try {
                $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"
                $regItem = Get-Item -LiteralPath $svcRegPath -ErrorAction Stop
                $isRecent = $regItem.LastWriteTime -gt (Get-Date).AddDays(-$Config.RecentDays)
            } catch {}

            $category = 'ServiceIntegrity'
            $mitreId = ''; $mitreConf = 'CONTEXT_ONLY'; $evidenceType = 'CONTEXT'
            $baseSev = if ($verdict -eq 'Untrusted') { 'MEDIUM' } else { 'MEDIUM' }
            $baseConf = if ($verdict -eq 'Untrusted') { 'LOW' } else { 'MEDIUM' }
            if ($isRecent) {
                $category = 'ServicePersistence'
                $mitreId = 'T1543.003'
                $mitreConf = if ($verdict -eq 'Invalid') { 'CONFIRMED' } else { 'HEURISTIC' }
                $evidenceType = if ($mitreConf -eq 'CONFIRMED') { 'DIRECT' } else { 'HEURISTIC' }
                $baseSev = if ($verdict -eq 'Invalid') { 'CRITICAL' } else { 'HIGH' }
            } elseif ($verdict -eq 'Invalid') {
                $baseSev = 'HIGH'  # tamper evidence still worth attention even without recency corroboration
            }

            $signalNote = if ($isRecent) { " | Persistence signal: service registry key modified within the last $($Config.RecentDays) days" } else { " | No persistence signal found - reporting the signature fact only" }
            Add-Finding -Category $category -Severity $baseSev -Confidence $baseConf -MitreId $mitreId -MitreConfidence $mitreConf -EvidenceType $evidenceType `
                -Text ("Service binary signature status '{0}': {1} ({2}){3}" -f $verdict, $_.DisplayName, $_.Name, $signalNote) `
                -Recommendation "An unsigned/invalid-signature service binary is a fact about that file. T1543.003 specifically means the service was CREATED or MODIFIED for persistence - only a recently-touched registry key supports that here, not the missing signature alone." `
                -IOC @{ PathName = $_.PathName; ExecutablePath = $exePath; Arguments = $resolved.Arguments; SHA256 = (Get-FileHashSafe $exePath); Process = $_.Name } | Out-Null
            Add-Line ("  PathName (raw): {0}" -f $_.PathName)
            Add-Line ("  Resolved executable: {0}  |  Arguments: {1}" -f $exePath, $resolved.Arguments)
            Add-Line ("  Start mode: {0}  |  Registry key recently modified: {1}" -f $_.StartMode, $isRecent)
        }
    }
    if ($found -eq 0) { Add-Context "No running services with confirmed unsigned/invalid-signature executables found." }
}

# =================================================================
# 5. KERNEL DRIVER ANALYSIS
# =================================================================
function Get-DriverIndicators {
    Add-Section "KERNEL DRIVER ANALYSIS"
    $driversDir = "$env:SystemRoot\System32\drivers"
    $checked = 0
    $flagged = 0
    $unavailable = 0
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
        $checked++
        $script:ScanCoverage.DriversChecked++
        $driverPath = $_.PathName
        if (-not $driverPath -or $driverPath.Trim() -eq '') {
            $candidate = Join-Path $driversDir ($_.Name + ".sys")
            if (Test-Path $candidate) { $driverPath = $candidate }
        }
        $driverPath = $driverPath -replace '\\SystemRoot', $env:SystemRoot -replace '^System32', "$env:SystemRoot\System32" -replace '^\\\?\?\\', ''
        $verdict = Get-SignatureVerdict $driverPath
        $inDriversDir = $driverPath -and (Test-PathUnderDirectory $driverPath $driversDir)

        if ($verdict -eq 'Unavailable' -or $verdict -eq 'Valid') {
            if ($verdict -eq 'Unavailable') { $unavailable++ }
            return
        }

        $flagged++
        # A driver's own unsigned/invalid signature status is a fact about
        # the FILE (DriverIntegrity) - it does NOT by itself prove the driver
        # was installed as a deliberate PERSISTENCE mechanism (T1547.006).
        # Persistence requires corroboration: either the file was written
        # recently (suggesting deliberate recent installation rather than an
        # old legacy peripheral driver), or its path already shows up as an
        # IOC on another finding from this same scan.
        $isRecent = $false
        try {
            $fileInfo = Get-Item -LiteralPath $driverPath -ErrorAction Stop
            $isRecent = $fileInfo.LastWriteTime -gt (Get-Date).AddDays(-$Config.RecentDays)
        } catch {}
        $corroborated = $false
        foreach ($existing in $script:AllFindings) {
            if ($existing.IOC -and $existing.IOC.ContainsKey('Path') -and $existing.IOC['Path'] -and (Test-PathUnderDirectory $driverPath $existing.IOC['Path'])) { $corroborated = $true; break }
        }
        $hasPersistenceSignal = $isRecent -or $corroborated

        $baseSev = if ($verdict -eq 'Invalid') { (if ($inDriversDir) { 'HIGH' } else { 'CRITICAL' }) } else { (if ($inDriversDir) { 'MEDIUM' } else { 'HIGH' }) }
        $baseConf = if ($verdict -eq 'Invalid') { 'MEDIUM' } else { (if ($inDriversDir) { 'LOW' } else { 'MEDIUM' }) }

        $mitreId = ''
        $mitreConf = 'CONTEXT_ONLY'
        $evidenceType = 'CONTEXT'
        if ($hasPersistenceSignal) {
            $mitreId = 'T1547.006'
            $mitreConf = if ($verdict -eq 'Invalid' -and $isRecent) { 'CONFIRMED' } else { 'HEURISTIC' }
            $evidenceType = if ($mitreConf -eq 'CONFIRMED') { 'DIRECT' } else { 'HEURISTIC' }
        }

        $signalNote = if ($hasPersistenceSignal) { " | Persistence signal: $(if ($isRecent) { 'recently modified file' } else { 'path matches another finding' })" } else { " | No persistence signal found - reporting the signature fact only" }
        $category = if ($hasPersistenceSignal) { 'DriverPersistence' } else { 'DriverIntegrity' }
        Add-Finding -Category $category -Severity $baseSev -Confidence $baseConf -MitreId $mitreId -MitreConfidence $mitreConf -EvidenceType $evidenceType `
            -Text ("Kernel driver signature status '{0}': {1} ({2}){3}" -f $verdict, $_.Name, $_.DisplayName, $signalNote) `
            -Recommendation "An unsigned or invalid-signature driver file is a fact about that binary, not proof it was installed for persistence - the MITRE mapping (if any) here reflects whether recency or cross-correlation actually supports that interpretation." `
            -IOC @{ Path = $driverPath; SHA256 = (Get-FileHashSafe $driverPath); Process = $_.Name } | Out-Null
        Add-Line ("  Path: {0}" -f $driverPath)
        Add-Line ("  In System32\drivers: {0}  |  Recently modified: {1}" -f $inDriversDir, $isRecent)
    }
    Add-Context ("Running drivers checked: {0}, flagged: {1}, signature not checkable: {2}" -f $checked, $flagged, $unavailable)
}

# =================================================================
# 6. NETWORK ANALYSIS
# =================================================================
function Get-NetworkIndicators {
    Add-Section "NETWORK CONNECTIONS AND LISTENING PORTS"

    Add-Line "--- Established external connections ---"
    $conns = $script:TcpEstablished | Where-Object {
        $cls = Get-AddressClassification $_.RemoteAddress
        $cls.IsExternal
    }
    $miningPorts = @(3333, 4444, 5555, 7777, 8080, 9999, 14444, 45700)
    foreach ($c in $conns) {
        $script:ScanCoverage.NetworkConnectionsChecked++
        $proc = $script:ProcessById[[int]$c.OwningProcess]
        $procName = if ($proc) { $proc.Name } else { "unknown" }
        $procPath = if ($proc) { $proc.ExecutablePath } else { "" }
        $line = ("{0}:{1} -> {2}:{3}  [Process: {4} (PID {5})]" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $procName, $c.OwningProcess)

        if ($Config.EnableReverseDns) {
            try {
                $rdns = [System.Net.Dns]::GetHostEntry($c.RemoteAddress).HostName
                if ($rdns) { $line += ("  rDNS: {0}" -f $rdns) }
            } catch {}
        }

        if ($miningPorts -contains $c.RemotePort) {
            # A single connection to this port range is common and NOT proof
            # of anything by itself - port alone stays at the MEDIUM/LOW
            # baseline. It only escalates when corroborated by the owning
            # process ALSO having a bad signature verdict. CPU correlation
            # for these ports is handled separately in
            # Get-CryptominerIndicators (that check needs a 2-second delta
            # sample, which is too expensive to repeat for every connection
            # here). This block only runs for genuinely IsExternal addresses
            # (see the $conns filter above) - loopback/private/link-local/
            # virtualization-range traffic (VMware, WSL2, Docker, VirtualBox,
            # most VPN tunnels) never reaches here at all, so it can't be
            # mistaken for external mining-pool traffic.
            $procVerdict = 'Unavailable'
            if ($procPath) { $procVerdict = Get-SignatureVerdict $procPath }
            $sev = 'MEDIUM'; $conf = 'LOW'
            if ($procVerdict -eq 'NotSigned' -or $procVerdict -eq 'Invalid' -or $procVerdict -eq 'Untrusted') {
                $sev = 'HIGH'; $conf = 'MEDIUM'
            }
            Add-Finding -Category 'Network' -Severity $sev -Confidence $conf -EvidenceType 'HEURISTIC' `
                -Text ("Connection to a common mining-pool port {0}: {1} (owning process signature: {2}, address is external)" -f $c.RemotePort, $line, $procVerdict) `
                -Recommendation "This port is commonly used by cryptomining pools, but plenty of legitimate software uses it too. Severity is raised only when the connecting process itself also has a bad signature verdict." `
                -IOC @{ IP = $c.RemoteAddress; Process = $procName; PID_ = $c.OwningProcess; ParentPID_ = (Get-ParentPidSafe $c.OwningProcess); Path = $procPath } | Out-Null
        } else {
            Add-Line $line
        }
    }
    if (-not $conns) { Add-Context "No established external (non-loopback/private/link-local/virtualization-range) connections found." }

    Add-Line ""
    Add-Line "--- Listening ports ---"
    $commonPorts = @(80, 443, 445, 135, 139, 3389, 5357)
    $script:TcpListening | Sort-Object LocalPort | ForEach-Object {
        $proc = $script:ProcessById[[int]$_.OwningProcess]
        $procName = if ($proc) { $proc.Name } else { "unknown" }
        if ($_.LocalPort -notin $commonPorts) {
            Add-Line ("[?] Port {0,-6} Process: {1} (PID {2})" -f $_.LocalPort, $procName, $_.OwningProcess)
        } else {
            Add-Line ("    Port {0,-6} Process: {1} (PID {2})" -f $_.LocalPort, $procName, $_.OwningProcess)
        }
    }
    Add-Line ""
    Add-Line "Note: [?] marks ports outside the common Windows set - not necessarily malicious, just worth a second look."
}

# =================================================================
# 7. HOSTS FILE / DNS / PROXY
# =================================================================
function Get-HostsDnsProxyIndicators {
    Add-Section "HOSTS FILE, DNS, AND PROXY"

    Add-Line "--- Hosts file ---"
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsLines = Get-Content $hostsPath | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch 'localhost' }
    $securityVendorDomains = @('avast', 'avg.com', 'kaspersky', 'malwarebytes', 'eset', 'norton', 'mcafee', 'windowsupdate.com', 'microsoft.com/security', 'bitdefender', 'sophos', 'trendmicro')
    if ($hostsLines) {
        foreach ($hl in $hostsLines) {
            $isBlockingSecurityVendor = $false
            foreach ($dom in $securityVendorDomains) {
                if ($hl -match [regex]::Escape($dom) -and $hl -match '^(0\.0\.0\.0|127\.0\.0\.1)') {
                    $isBlockingSecurityVendor = $true
                    break
                }
            }
            if ($isBlockingSecurityVendor) {
                Add-Finding -Category 'DefenseEvasion' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1562.001' `
                    -Text ("Hosts file blocks a security-vendor domain: {0}" -f $hl) `
                    -Recommendation "Malware commonly blocks security-vendor domains via the hosts file to prevent updates/telemetry. Remove this entry and run a full offline AV scan." `
                    -IOC @{ Domain = $hl } | Out-Null
            } else {
                Add-Line ("  {0}" -f $hl)
            }
        }
    } else {
        Add-Context "Hosts file looks standard."
    }

    Add-Line ""
    Add-Line "--- DNS servers ---"
    Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object {
        Add-Line ("Adapter: {0}  ->  DNS: {1}" -f $_.InterfaceAlias, ($_.ServerAddresses -join ", "))
    }
    Add-Line "Note: check these against your router/ISP defaults. Unfamiliar public DNS can indicate DNS hijacking, but is not proof by itself."

    Add-Line ""
    Add-Line "--- Proxy settings ---"
    $proxySettings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxySettings.ProxyEnable -eq 1) {
        Add-Finding -Category 'DefenseEvasion' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
            -Text ("System proxy is ENABLED: {0}" -f $proxySettings.ProxyServer) `
            -Recommendation "If you did not configure this proxy yourself, your traffic may be redirected through an attacker's server." `
            -IOC @{ Domain = $proxySettings.ProxyServer } | Out-Null
    } else {
        Add-Line "System proxy is disabled (normal)."
    }
    if ($proxySettings.AutoConfigURL) {
        Add-Finding -Category 'DefenseEvasion' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
            -Text ("Proxy auto-config (PAC) script set: {0}" -f $proxySettings.AutoConfigURL) `
            -Recommendation "Confirm this PAC script location is one you or your organization configured." `
            -IOC @{ Domain = $proxySettings.AutoConfigURL } | Out-Null
    }
    try {
        $winhttpProxy = netsh winhttp show proxy 2>$null
        if ($winhttpProxy) { Add-Line ("WinHTTP proxy: {0}" -f ($winhttpProxy -join ' ')) }
    } catch {}
}

# =================================================================
# 8. FIREWALL
# =================================================================
function Get-FirewallIndicators {
    Add-Section "FIREWALL - CUSTOM INBOUND ALLOW RULES"
    $found = 0
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { $_.Group -eq "" -and $_.DisplayName -notmatch "^(Core Networking|File and Printer|Network Discovery)" } |
        ForEach-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $appFilter = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            $found++
            Add-Line ("Rule: {0}" -f $_.DisplayName)
            Add-Line ("  Program: {0}" -f $(if ($appFilter.Program) { $appFilter.Program } else { "Any" }))
            Add-Line ("  Port: {0}" -f $(if ($portFilter.LocalPort) { $portFilter.LocalPort } else { "Any" }))
            Add-Line ""
        }
    if ($found -eq 0) { Add-Context "No unusual custom inbound firewall rules found." }
    Add-Line "Note: many legitimate apps (games, sync tools, printers) add their own inbound rules."
}

# =================================================================
# 9. BROWSER ANALYSIS (Chrome / Edge / Firefox)
# =================================================================
function Get-BrowserIndicators {
    Add-Section "BROWSER EXTENSIONS, POLICIES, AND HIJACK CHECK"
    $dangerousPermissions = @('<all_urls>', 'webRequest', 'webRequestBlocking', 'nativeMessaging', 'debugger', 'proxy', 'management', 'privacy')

    $browserPaths = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    }
    foreach ($browser in $browserPaths.Keys) {
        $path = $browserPaths[$browser]
        if (Test-Path $path) {
            Add-Line ("--- {0} extensions ---" -f $browser)
            Get-ChildItem $path -Directory | ForEach-Object {
                $script:ScanCoverage.BrowserExtensionsChecked++
                $extId = $_.Name
                $versionFolder = Get-ChildItem $_.FullName -Directory | Select-Object -First 1
                $manifestPath = Join-Path $versionFolder.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $name = if ($manifest.name -match '^__MSG_') { $extId } else { $manifest.name }
                    $allPerms = @($manifest.permissions) + @($manifest.host_permissions)
                    $hasDangerous = $false
                    foreach ($p in $allPerms) {
                        if ($p -and ($dangerousPermissions -contains $p -or $p -eq '<all_urls>' -or $p -eq '*://*/*')) { $hasDangerous = $true }
                    }
                    if ($hasDangerous) {
                        Add-Finding -Category 'Browser' -Severity 'LOW' -Confidence 'LOW' -MitreId 'T1176' `
                            -Text ("{0} extension requests broad permissions: {1} (id: {2}) - {3}" -f $browser, $name, $extId, ($allPerms -join ', ')) `
                            -Recommendation "Broad permissions are common for legitimate extensions too (ad blockers, password managers) - review if you recognize and still use this one." `
                            -IOC @{ Path = $extId } | Out-Null
                    } else {
                        Add-Line ("  {0}  (id: {1}, v{2})" -f $name, $extId, $manifest.version)
                    }
                }
            }
        }
    }

    $firefoxProfilesRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilesRoot) {
        Add-Line "--- Firefox extensions ---"
        Get-ChildItem $firefoxProfilesRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extJsonPath = Join-Path $_.FullName "extensions.json"
            if (Test-Path $extJsonPath) {
                $extData = Get-Content $extJsonPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                foreach ($addon in $extData.addons) {
                    if ($addon.active -and $addon.type -eq 'extension') {
                        $addonName = if ($addon.defaultLocale.name) { $addon.defaultLocale.name } else { $addon.id }
                        Add-Line ("  {0}  (id: {1}, v{2})" -f $addonName, $addon.id, $addon.version)
                    }
                }
            }
        }
    }

    Add-Line ""
    Add-Line "--- Forced homepage / policies ---"
    $hijackKeys = @(
        @{Path = 'HKCU:\Software\Policies\Google\Chrome'; Value = 'HomepageLocation'},
        @{Path = 'HKLM:\Software\Policies\Google\Chrome'; Value = 'HomepageLocation'},
        @{Path = 'HKCU:\Software\Policies\Microsoft\Edge'; Value = 'HomepageLocation'},
        @{Path = 'HKLM:\Software\Policies\Microsoft\Edge'; Value = 'HomepageLocation'}
    )
    $hijackFound = 0
    foreach ($hk in $hijackKeys) {
        if (Test-Path $hk.Path) {
            $val = (Get-ItemProperty -Path $hk.Path -ErrorAction SilentlyContinue).($hk.Value)
            if ($val) {
                $hijackFound++
                Add-Finding -Category 'Browser' -Severity 'MEDIUM' -Confidence 'LOW' -MitreId 'T1176' `
                    -Text ("Browser homepage forced via policy: {0} = {1}" -f $hk.Path, $val) `
                    -Recommendation "Work-managed laptops legitimately use these policies too - if this is a personal PC and you didn't set it, review it." `
                    -IOC @{ RegistryKey = $hk.Path; Domain = $val } | Out-Null
            }
        }
    }
    if ($hijackFound -eq 0) { Add-Context "No forced browser homepage settings found." }

    Add-Line ""
    Add-Line "--- Native messaging hosts (extension-to-native-app bridge) ---"
    $nmHostPaths = @(
        'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts',
        'HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts',
        'HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts',
        'HKCU:\SOFTWARE\Mozilla\NativeMessagingHosts'
    )
    $nmFound = 0
    foreach ($nmPath in $nmHostPaths) {
        if (Test-Path $nmPath) {
            Get-ChildItem $nmPath -ErrorAction SilentlyContinue | ForEach-Object {
                $nmFound++
                Add-Line ("Native messaging host registered: {0}" -f $_.PSChildName)
            }
        }
    }
    if ($nmFound -eq 0) { Add-Context "No native messaging hosts registered." }
    Add-Line "Note: native messaging hosts let a browser extension talk to a native background process - a real but uncommon vector; most entries here are legitimate (password managers, etc.)."
}

# =================================================================
# 10. WMI EVENT SUBSCRIPTIONS
# =================================================================
function Get-WmiPersistenceIndicators {
    Add-Section "WMI EVENT SUBSCRIPTIONS"
    $found = 0
    # Each of the three subscription classes is queried in its own try/catch
    # so a failure can be attributed to the exact class that failed. With a
    # shared -ErrorVariable it was impossible to tell which query broke, and
    # a failed query produced an empty array that then rendered as the
    # reassuring "No WMI subscriptions found" - actively misleading.
    $wmiQueryFailures = New-Object System.Collections.Generic.List[string]
    $wmiFilters = @(); $wmiConsumers = @(); $wmiBindings = @()

    try {
        $wmiFilters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop)
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        [void]$wmiQueryFailures.Add("__EventFilter ($code)")
        Add-ScanError 'Get-WmiPersistenceIndicators' "__EventFilter query failed: $($_.Exception.Message)" 'LOW' $code
    }
    try {
        $wmiConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        [void]$wmiQueryFailures.Add("__EventConsumer ($code)")
        Add-ScanError 'Get-WmiPersistenceIndicators' "__EventConsumer query failed: $($_.Exception.Message)" 'LOW' $code
    }
    try {
        $wmiBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop)
    } catch {
        $code = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        [void]$wmiQueryFailures.Add("__FilterToConsumerBinding ($code)")
        Add-ScanError 'Get-WmiPersistenceIndicators' "__FilterToConsumerBinding query failed: $($_.Exception.Message)" 'LOW' $code
    }

    # Zero subscriptions from a SUCCESSFUL query is the normal result on a
    # clean system. Only an actual query failure downgrades the status.
    if ($wmiQueryFailures.Count -gt 0) {
        $wmiOverall = if (($wmiQueryFailures -join ' ') -match 'PERMISSION_DENIED') { 'PERMISSION_DENIED' } else { 'ERROR' }
        Set-SourceStatus 'WMI' $wmiOverall
        Add-Line ("WMI query FAILURE - the following subscription classes could not be read: {0}" -f ($wmiQueryFailures -join ', '))
        Add-Line "This is a source error, NOT a statement that no WMI persistence exists - that question is unanswered for the failed classes."
    } else {
        Set-SourceStatus 'WMI' 'OK'
    }

    $filterByPath = @{}
    foreach ($f in $wmiFilters) { $filterByPath[$f.__RELPATH] = $f }
    $consumerByPath = @{}
    foreach ($c in $wmiConsumers) { $consumerByPath[$c.__RELPATH] = $c }

    $boundConsumerPaths = New-Object System.Collections.Generic.List[string]
    $boundFilterPaths = New-Object System.Collections.Generic.List[string]

    foreach ($b in $wmiBindings) {
        $found++
        $script:ScanCoverage.WmiSubscriptionsChecked++
        # __FilterToConsumerBinding.Filter/Consumer are reference strings like
        # 'root\subscription:__EventFilter.Name="X"' - extract the __RELPATH
        # portion after the namespace colon to look them up in our maps.
        $filterRef = $b.Filter -replace '^.*:', ''
        $consumerRef = $b.Consumer -replace '^.*:', ''
        [void]$boundFilterPaths.Add($filterRef)
        [void]$boundConsumerPaths.Add($consumerRef)

        $filterObj = $filterByPath[$filterRef]
        $consumerObj = $consumerByPath[$consumerRef]
        $consumerType = if ($consumerObj) { $consumerObj.CimClass.CimClassName } else { "Unknown" }
        $filterQuery = if ($filterObj) { $filterObj.Query } else { "Unknown" }

        if ($consumerType -eq 'NTEventLogEventConsumer') {
            # This consumer type only writes an event log entry - it does not
            # execute code. Real risk here is close to zero; report as context.
            Add-Line ("WMI binding (logging only, does not execute code): filter='{0}' -> NTEventLogEventConsumer consumer='{1}'" -f $filterRef, $consumerRef)
            continue
        }

        if ($consumerType -eq 'CommandLineEventConsumer' -and $consumerObj) {
            $cmdTemplate = $consumerObj.CommandLineTemplate
            $exePart = Resolve-CommandLineExecutable $cmdTemplate
            $verdict = Get-SignatureVerdict $exePart

            # Even a fully signed, legitimate interpreter (powershell.exe,
            # cmd.exe) is worth flagging harder if the ARGUMENTS themselves
            # look like a fileless-malware pattern - the exe's signature alone
            # tells us nothing about what it's being told to do.
            $hasSuspiciousArgs = $false
            if ($cmdTemplate) {
                $cmdLower = $cmdTemplate.ToLower()
                foreach ($pat in @('-enc', '-encodedcommand', 'frombase64string', 'downloadstring', 'downloadfile', 'iex ', 'invoke-expression', '-w hidden', '-windowstyle hidden', 'bypass')) {
                    if ($cmdLower.Contains($pat)) { $hasSuspiciousArgs = $true; break }
                }
            }

            # Signature verdict sets a baseline; suspicious arguments can only
            # raise it, never lower it. Not resolving the executable at all
            # (Unavailable) is NOT treated as suspicious by itself - only the
            # arguments are, which fixes the previous "default to HIGH" bug.
            $sev = 'LOW'; $conf = 'LOW'
            if ($verdict -eq 'Valid') { $sev = 'LOW'; $conf = 'LOW' }
            elseif ($verdict -eq 'Invalid') { $sev = 'CRITICAL'; $conf = 'MEDIUM' }
            elseif ($verdict -eq 'NotSigned') { $sev = 'HIGH'; $conf = 'MEDIUM' }
            elseif ($verdict -eq 'Untrusted') { $sev = 'MEDIUM'; $conf = 'LOW' }
            # else Unavailable - baseline stays LOW/LOW, we simply couldn't verify

            if ($hasSuspiciousArgs) {
                if ($sev -eq 'LOW') { $sev = 'HIGH'; $conf = 'MEDIUM' }
                elseif ($sev -eq 'MEDIUM') { $sev = 'HIGH'; $conf = 'HIGH' }
                elseif ($sev -eq 'HIGH') { $conf = 'HIGH' }
            }

            $argNote = if ($hasSuspiciousArgs) { "; command line contains a fileless-execution pattern" } else { "" }
            Add-Finding -Category 'Persistence' -Severity $sev -Confidence $conf -MitreId 'T1546.003' `
                -Text ("WMI binding executes a command when triggered: filter query='{0}' -> command='{1}' (target signature: {2}{3})" -f $filterQuery, $cmdTemplate, $verdict, $argNote) `
                -Recommendation "CommandLineEventConsumer runs an arbitrary command whenever the filter's WMI query matches - this is genuine code execution, not just logging. A signed interpreter (powershell.exe/cmd.exe) with suspicious arguments is still worth investigating." `
                -IOC @{ Command = $cmdTemplate; Path = $exePart } | Out-Null
            continue
        }

        if ($consumerType -eq 'ActiveScriptEventConsumer' -and $consumerObj) {
            # Inline scripts stored directly in WMI have no file to sign/check,
            # so this is treated as HIGH regardless - it is inherently a
            # script-execution trigger with no signature surface at all.
            $scriptPreview = $consumerObj.ScriptText
            if ($scriptPreview -and $scriptPreview.Length -gt 200) { $scriptPreview = $scriptPreview.Substring(0, 200) + "..." }
            Add-Finding -Category 'Persistence' -Severity 'HIGH' -Confidence 'HIGH' -MitreId 'T1546.003' `
                -Text ("WMI binding executes an inline script when triggered: filter query='{0}', engine='{1}'" -f $filterQuery, $consumerObj.ScriptingEngine) `
                -Recommendation "ActiveScriptEventConsumer runs script code stored directly inside WMI - there is no file to check a signature on, which is itself why this technique is favored for stealthy persistence." `
                -IOC @{ Command = $scriptPreview } | Out-Null
            continue
        }

        # Any other/unknown consumer type bound to a filter - lower confidence
        # since we don't have specific handling, but still worth a look.
        Add-Finding -Category 'Persistence' -Severity 'MEDIUM' -Confidence 'LOW' -MitreId 'T1546.003' `
            -Text ("WMI binding with consumer type '{0}': filter query='{1}'" -f $consumerType, $filterQuery) `
            -Recommendation "Unrecognized consumer type for this scanner - review manually with wbemtest or PowerShell's Get-CimInstance." | Out-Null
    }

    # Filters/consumers that exist but are NOT bound to anything don't trigger
    # on their own - report as low-priority context, not full findings.
    foreach ($f in $wmiFilters) {
        if (-not ($boundFilterPaths -contains $f.__RELPATH)) {
            Add-Line ("Unbound WMI Event Filter (inactive, no consumer attached): {0}" -f $f.Name)
        }
    }
    foreach ($c in $wmiConsumers) {
        if (-not ($boundConsumerPaths -contains $c.__RELPATH)) {
            Add-Line ("Unbound WMI Event Consumer (inactive, no filter attached): {0}" -f $c.Name)
        }
    }

    if ($found -eq 0) {
        if ($wmiQueryFailures.Count -gt 0) {
            Add-Context "No WMI bindings could be enumerated because one or more subscription queries FAILED (see above) - this is not the same as confirming none exist."
        } else {
            Add-Context "No active WMI event subscriptions (filter-to-consumer bindings) found (normal for most systems)."
        }
    }
}

# =================================================================
# 11. LOCAL ADMINISTRATOR ACCOUNTS
# =================================================================
function Get-AdminAccountIndicators {
    Add-Section "LOCAL ADMINISTRATOR ACCOUNTS"
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Line ("Administrator: {0}  ({1})" -f $_.Name, $_.ObjectClass)
    }
    Add-Line ""
    Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
        Add-Line ("Enabled local account: {0}  (Last logon: {1})" -f $_.Name, $_.LastLogon)
    }
    Add-Line ""
    Add-Line "Note: make sure every admin account is one you recognize. An unfamiliar enabled account is a serious red flag - review manually."
}

# =================================================================
# 12. WINDOWS DEFENDER ANALYSIS
# =================================================================
function Get-DefenderIndicators {
    Add-Section "WINDOWS DEFENDER STATUS AND DETECTIONS"
    $defenderStatus = $null
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $script:ScanCoverage.DefenderChecksPerformed++
        Set-SourceStatus 'Defender' 'OK'
    } catch {
        # Defender module absent / third-party AV in place is DataUnavailable,
        # not a scanner error.
        Set-SourceStatus 'Defender' 'UNAVAILABLE'
        Add-ScanError 'Get-DefenderIndicators' "Get-MpComputerStatus unavailable: $($_.Exception.Message)" 'INFO' 'UNAVAILABLE'
    }
    if ($defenderStatus) {
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            Add-Finding -Category 'DefenseEvasion' -Severity 'HIGH' -Confidence 'HIGH' -MitreId 'T1562.001' `
                -Text "Real-time protection is DISABLED." -Recommendation "Re-enable real-time protection unless you disabled it intentionally for a specific task." | Out-Null
        } else { Add-Line "Real-time protection: Enabled (normal)." }
        if (-not $defenderStatus.AntivirusEnabled) {
            Add-Finding -Category 'DefenseEvasion' -Severity 'HIGH' -Confidence 'HIGH' -MitreId 'T1562.001' `
                -Text "Antivirus is DISABLED." | Out-Null
        }
        if ($defenderStatus.PSObject.Properties.Name -contains 'BehaviorMonitorEnabled' -and -not $defenderStatus.BehaviorMonitorEnabled) {
            Add-Finding -Category 'DefenseEvasion' -Severity 'MEDIUM' -Confidence 'HIGH' -MitreId 'T1562.001' -Text "Behavior monitoring is DISABLED." | Out-Null
        }
        if ($defenderStatus.PSObject.Properties.Name -contains 'IoavProtectionEnabled' -and -not $defenderStatus.IoavProtectionEnabled) {
            Add-Finding -Category 'DefenseEvasion' -Severity 'LOW' -Confidence 'MEDIUM' -Text "IOAV (downloaded-file) scanning is DISABLED." | Out-Null
        }
        Add-Line ("Signature age (days): {0}" -f $defenderStatus.AntivirusSignatureAge)
        Add-Line ("Last quick scan: {0}" -f $defenderStatus.QuickScanEndTime)
    } else {
        Add-Context "Could not read Windows Defender status (a third-party antivirus may be active instead)."
        Add-ScanError 'Get-DefenderIndicators' 'Get-MpComputerStatus returned no data (Defender module unavailable or a third-party AV is active)' 'INFO' 'UNAVAILABLE'
    }

    # Defender Preferences is tracked as a SEPARATE source from Defender
    # status: it is entirely possible for Get-MpComputerStatus to succeed
    # (DefenderStatus = OK) while Get-MpPreference fails, and vice versa -
    # collapsing both into one status would hide that. SilentlyContinue is
    # deliberately not used here; a real failure must be visible.
    $pref = $null
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        Set-SourceStatus 'DefenderPreferences' 'OK'
    } catch {
        $prefCode = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' }
                    elseif ($_.Exception.Message -match 'not recognized|CommandNotFound') { 'UNAVAILABLE' }
                    else { 'ERROR' }
        Set-SourceStatus 'DefenderPreferences' $prefCode
        Add-ScanError 'Get-MpPreference' "Get-MpPreference failed: $($_.Exception.Message)" 'LOW' $prefCode
    }
    if ($pref) {
        Add-Line ""
        Add-Line ("Cloud-delivered protection (MAPSReporting): {0}" -f $pref.MAPSReporting)
        Add-Line ("PUA Protection: {0}" -f $pref.PUAProtection)
        if ($pref.AttackSurfaceReductionRules_Ids) {
            Add-Line ("ASR rules configured: {0}" -f $pref.AttackSurfaceReductionRules_Ids.Count)
        }
    } else {
        Add-Line ""
        Add-Line "Defender preferences could not be read (see ScanErrors for the specific reason) - exclusion analysis below may therefore be incomplete."
    }

    Add-Line ""
    Add-Line "--- Exclusions (malware sometimes adds these to hide from scans) ---"
    $riskyExclusionPatterns = @('\\Temp\\', '\\AppData\\', '\\ProgramData\\', '\\Users\\Public\\', '\\Downloads\\')
    if ($pref.ExclusionPath) {
        foreach ($excl in $pref.ExclusionPath) {
            $isRisky = $false
            foreach ($pat in $riskyExclusionPatterns) { if ($excl -match $pat) { $isRisky = $true; break } }
            if ($isRisky) {
                # A risky-looking exclusion path alone is common (some
                # legitimate installers/dev tools add these) and should not
                # jump straight to HIGH. Escalate only with corroboration:
                # a process is actually running from inside that excluded
                # path, or the same path already showed up as an IOC in
                # another finding earlier in this scan.
                $corroborated = $false
                foreach ($cp in $script:CimProcesses) {
                    if ($cp.ExecutablePath -and (Test-PathUnderDirectory $cp.ExecutablePath $excl)) {
                        $corroborated = $true; break
                    }
                }
                if (-not $corroborated) {
                    foreach ($existing in $script:AllFindings) {
                        if ($existing.IOC -and $existing.IOC.Path -and (Test-PathUnderDirectory $existing.IOC.Path $excl)) {
                            $corroborated = $true; break
                        }
                    }
                }
                $sev = if ($corroborated) { 'HIGH' } else { 'MEDIUM' }
                $conf = if ($corroborated) { 'MEDIUM' } else { 'LOW' }
                $corrobNote = if ($corroborated) { " - CORROBORATED by another finding/running process at this path" } else { "" }
                Add-Finding -Category 'DefenseEvasion' -Severity $sev -Confidence $conf -MitreId 'T1562.001' `
                    -Text ("Defender exclusion in a commonly-abused location: {0}{1}" -f $excl, $corrobNote) `
                    -Recommendation "An exclusion in Temp/AppData/Downloads/ProgramData means Defender never scans that folder - verify you (or an installed app) added this intentionally." `
                    -IOC @{ Path = $excl } | Out-Null
            } else {
                Add-Line ("Excluded path: {0}" -f $excl)
            }
        }
    } else {
        Add-Line "No excluded paths configured."
    }
    if ($pref.ExclusionProcess) {
        foreach ($ep in $pref.ExclusionProcess) {
            Add-Finding -Category 'DefenseEvasion' -Severity 'MEDIUM' -Confidence 'LOW' -MitreId 'T1562.001' `
                -Text ("Defender process exclusion: {0}" -f $ep) -IOC @{ Process = $ep } | Out-Null
        }
    }

    Add-Line ""
    Add-Line "--- Recent threat detections ---"
    $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue
    if ($detections) {
        foreach ($d in ($detections | Select-Object -First 20)) {
            Add-Finding -Category 'DefenderDetection' -Severity 'HIGH' -Confidence 'HIGH' `
                -Text ("Defender previously detected a threat: {0} (action: {1}, on {2})" -f $d.ThreatID, $d.ActionSuccess, $d.InitialDetectionTime) `
                -Recommendation "Run Get-MpThreat in PowerShell for full detail, and re-run a full offline scan to confirm removal." | Out-Null
        }
    } else {
        Add-Context "No recent Defender threat detections found in history."
    }
}

# =================================================================
# 13. LOLBIN / SUSPICIOUS COMMAND-LINE DETECTION
# =================================================================
function Get-LOLBinIndicators {
    Add-Section "LOLBIN AND SUSPICIOUS COMMAND-LINE USAGE"

    $lolbins = @('mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msiexec.exe',
                 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'cmstp.exe', 'cscript.exe', 'wscript.exe',
                 'msbuild.exe', 'odbcconf.exe', 'pcalua.exe', 'fodhelper.exe', 'hh.exe')
    $lolbinMitre = @{
        'mshta.exe' = 'T1218.005'; 'regsvr32.exe' = 'T1218.010'; 'rundll32.exe' = 'T1218.011'
        'certutil.exe' = 'T1140'; 'bitsadmin.exe' = 'T1197'; 'msiexec.exe' = 'T1218.007'
    }
    $urlPattern = 'https?://'
    $encodedPattern = 'frombase64|-enc |-encodedcommand'

    $found = 0
    foreach ($p in $script:CimProcesses) {
        $nameLower = $p.Name.ToLower()
        if ($lolbins -contains $nameLower -and $p.CommandLine) {
            $cmdline = $p.CommandLine
            $hasUrl = $cmdline -match $urlPattern
            $hasEncoded = $cmdline -match $encodedPattern
            $parent = $script:ProcessById[[int]$p.ParentProcessId]
            $parentName = if ($parent) { $parent.Name } else { "unknown" }
            $unusualPath = $p.ExecutablePath -and ($p.ExecutablePath -notmatch '\\Windows\\System32\\' -and $p.ExecutablePath -notmatch '\\Windows\\SysWOW64\\')

            if ($hasUrl -or $hasEncoded -or $unusualPath) {
                $found++
                $sev = 'MEDIUM'
                if (($hasUrl -and $hasEncoded) -or $unusualPath) { $sev = 'HIGH' }
                $mitreId = ''
                if ($lolbinMitre.ContainsKey($nameLower)) { $mitreId = $lolbinMitre[$nameLower] }
                Add-HighRiskPid ([int]$p.ProcessId)
                Add-Finding -Category 'LOLBin' -Severity $sev -Confidence 'MEDIUM' -MitreId $mitreId -EvidenceType 'HEURISTIC' `
                    -Text ("{0} (PID {1}, parent: {2}) used with suspicious arguments" -f $p.Name, $p.ProcessId, $parentName) `
                    -Recommendation "$($p.Name) is a legitimate Windows binary that is frequently abused to download or run code while evading detection - review the exact command line." `
                    -IOC @{ Command = $cmdline; Process = $p.Name; PID_ = $p.ProcessId; ParentPID_ = $p.ParentProcessId } | Out-Null
                Add-Line ("    Command line: {0}" -f $cmdline)
                Add-Line ""
            }
        }
    }
    if ($found -eq 0) { Add-Context "No suspicious LOLBin usage found." }

    Add-Line ""
    Add-Line "--- General suspicious command-line patterns (any process) ---"
    $suspiciousCmdPatterns = @(
        '-enc(odedcommand)?\s', '-w(indowstyle)?\s+hidden', 'frombase64string',
        'downloadstring|downloadfile', 'iex\s*\(', '-nop\b|-noprofile',
        'bypass.*-command|-command.*bypass', 'mshta\s+http', 'regsvr32.*(/i:http|scrobj)',
        'certutil.*-decode', 'bitsadmin.*\/transfer'
    )
    $patFound = 0
    foreach ($p in $script:CimProcesses) {
        if (-not $p.CommandLine) { continue }
        foreach ($pattern in $suspiciousCmdPatterns) {
            if ($p.CommandLine -match $pattern) {
                $patFound++
                Add-HighRiskPid ([int]$p.ProcessId)
                Add-Finding -Category 'CommandLine' -Severity 'HIGH' -Confidence 'MEDIUM' -MitreId 'T1059.001' -EvidenceType 'HEURISTIC' `
                    -Text ("{0} (PID {1}) matched pattern '{2}'" -f $p.Name, $p.ProcessId, $pattern) `
                    -Recommendation "Fileless-malware and living-off-the-land patterns are common in both malware and legitimate admin scripts - check whether you recognize the parent app." `
                    -IOC @{ Command = $p.CommandLine; Process = $p.Name; PID_ = $p.ProcessId; ParentPID_ = $p.ParentProcessId } | Out-Null
                Add-Line ("    Command line: {0}" -f $p.CommandLine)
                break
            }
        }
    }
    if ($patFound -eq 0) { Add-Context "No suspicious command-line patterns found." }
}

# =================================================================
# 14. LSA SECURITY PACKAGES
# =================================================================
function Get-LsaSecurityPackageIndicators {
    Add-Section "LSA SECURITY / AUTHENTICATION PACKAGES"
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $defaultSecurityPackages = @('""', 'kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u')
    $defaultAuthPackages = @('msv1_0')
    $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
    $found = 0

    function Resolve-LsaPackageDll($pkgName) {
        # LSA package entries are DLL base names loaded from System32 unless a
        # full path is given. Resolve to a real file so we can actually check
        # its signature/publisher instead of judging by name alone.
        if ($pkgName -match '[\\/]' -or $pkgName -match '^[A-Za-z]:') {
            if ($pkgName -notmatch '\.dll$') { return "$pkgName.dll" }
            return $pkgName
        }
        return (Join-Path "$env:SystemRoot\System32" "$pkgName.dll")
    }

    function Test-LsaPackage($pkg, $kind) {
        $dllPath = Resolve-LsaPackageDll $pkg
        $verdict = Get-SignatureVerdict $dllPath
        $publisher = "Unknown"
        if ($verdict -eq 'Valid') {
            $sig = Get-SignatureSafe $dllPath
            if ($sig -and $sig.SignerCertificate) { $publisher = $sig.SignerCertificate.Subject }
        }

        # Severity graduated by what we could actually confirm about the DLL,
        # not a flat CRITICAL for every non-default name - some legitimate
        # smartcard/2FA/enterprise-auth software registers its own package.
        $sev = 'MEDIUM'; $conf = 'LOW'
        $note = ""
        if ($verdict -eq 'Valid') { $sev = 'LOW'; $conf = 'LOW'; $note = "Signed by: $publisher - still non-default, verify you installed the software that registered it." }
        elseif ($verdict -eq 'NotSigned') { $sev = 'HIGH'; $conf = 'MEDIUM'; $note = "Target DLL is unsigned." }
        elseif ($verdict -eq 'Invalid') { $sev = 'CRITICAL'; $conf = 'MEDIUM'; $note = "Target DLL has an INVALID signature (possible tampering)." }
        else { $sev = 'MEDIUM'; $conf = 'LOW'; $note = "Target DLL could not be located/verified at: $dllPath" }

        Add-Finding -Category 'CredentialAccess' -Severity $sev -Confidence $conf -MitreId 'T1556' `
            -Text ("Non-default LSA {0} Package: {1} - {2}" -f $kind, $pkg, $note) `
            -Recommendation "This mechanism (used maliciously by tools like Mimikatz for credential interception) is also used legitimately by some smartcard/enterprise-auth software. The signature/publisher check above should guide priority." `
            -IOC @{ RegistryKey = $lsaPath; Path = $dllPath } | Out-Null
    }

    if ($lsa) {
        foreach ($pkg in $lsa.'Security Packages') {
            if ($pkg -and ($pkg.ToLower() -notin $defaultSecurityPackages)) {
                $found++
                Test-LsaPackage $pkg 'Security'
            }
        }
        foreach ($pkg in $lsa.'Authentication Packages') {
            if ($pkg -and ($pkg.ToLower() -notin $defaultAuthPackages)) {
                $found++
                Test-LsaPackage $pkg 'Authentication'
            }
        }
    }
    if ($found -eq 0) { Add-Context "LSA security/authentication packages look standard." }
}

# =================================================================
# 15. RECENTLY MODIFIED SYSTEM32 FILES
# =================================================================
function Get-System32ModifiedIndicators {
    Add-Section "RECENTLY MODIFIED SYSTEM32 FILES"
    $cutoff = (Get-Date).AddDays(-$Config.RecentDays)
    $modifiedFiles = Get-ChildItem "$env:SystemRoot\System32" -Filter *.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff }
    $count = (@($modifiedFiles)).Count
    Add-Context ("{0} .exe files in System32 modified in the last {1} days (this is normal right after a Windows Update)." -f $count, $Config.RecentDays)

    # Bulk modification right after a Windows Update is expected and, on its
    # own, tells us nothing - checking every file's signature is the only way
    # to separate "routine update" from "something replaced a system binary".
    # Signed files are reported as context only, exactly as before. A finding
    # is only created for a file that is confirmed NotSigned/Invalid/Untrusted
    # - 'Unavailable' (couldn't check) is also left as context, not a finding.
    $checked = $modifiedFiles | Select-Object -First $Config.MaxFilesPerDirectory
    $flaggedCount = 0
    foreach ($f in $checked) {
        $verdict = Get-SignatureVerdict $f.FullName
        if ($verdict -eq 'Valid' -or $verdict -eq 'Unavailable') {
            Add-Line ("{0}  (modified {1}, signature: {2})" -f $f.FullName, $f.LastWriteTime, $verdict)
            continue
        }
        $flaggedCount++
        $sev = 'HIGH'; $conf = 'MEDIUM'
        if ($verdict -eq 'Invalid') { $sev = 'CRITICAL'; $conf = 'HIGH' }
        Add-Finding -Category 'System32Integrity' -Severity $sev -Confidence $conf `
            -Text ("System32 executable modified recently with signature status '{0}': {1} (modified {2})" -f $verdict, $f.FullName, $f.LastWriteTime) `
            -Recommendation "A genuinely unsigned or hash-mismatched file in System32 is unusual outside of a Windows Update - verify this wasn't replaced by something else." `
            -IOC @{ Path = $f.FullName; SHA256 = (Get-FileHashSafe $f.FullName) } | Out-Null
    }
    if ($count -gt $Config.MaxFilesPerDirectory) {
        Add-Line ("Note: {0} modified files found, only the first {1} had their signature checked (see Config.MaxFilesPerDirectory)." -f $count, $Config.MaxFilesPerDirectory)
    }
    if ($flaggedCount -eq 0) { Add-Context "None of the recently modified System32 executables had a confirmed bad signature." }
}

# =================================================================
# 16. RANSOMWARE INDICATORS (correlated)
# =================================================================
function Get-RansomwareIndicators {
    Add-Section "RANSOMWARE INDICATORS (CORRELATED)"
    $indicatorCount = 0
    $evidenceLines = New-Object System.Collections.Generic.List[string]

    # Two distinct states must not be collapsed into one message: a query
    # that SUCCEEDED and returned zero copies (legitimate context - common
    # on PCs where System Restore was never enabled), versus a query that
    # FAILED (we simply do not know). Neither raises the risk score.
    $shadowCopies = $null
    $shadowQueryOk = $false
    try {
        $shadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop)
        $shadowQueryOk = $true
    } catch {
        $shadowCode = if ($_.Exception.Message -match 'Access is denied|access denied') { 'PERMISSION_DENIED' } else { 'ERROR' }
        Add-ScanError 'Get-RansomwareIndicators' "Win32_ShadowCopy query failed: $($_.Exception.Message)" 'LOW' $shadowCode
    }
    if (-not $shadowQueryOk) {
        Add-Line "Shadow Copy query FAILED - whether Volume Shadow Copies exist is unknown (this is a source error, not a finding, and does not affect the risk score)."
    } elseif ((@($shadowCopies)).Count -eq 0) {
        Add-Line "No Volume Shadow Copies found - query succeeded and returned zero (also normal on PCs where System Restore was never turned on; context only, not counted as a ransomware indicator)."
    } else {
        Add-Line ("Volume Shadow Copies present: {0} (normal)" -f (@($shadowCopies)).Count)
    }

    $ransomNotePatterns = @('*DECRYPT*', '*RECOVER*FILES*', '*HOW_TO*DECRYPT*', '*README*RANSOM*', '*_readme*', '*RESTORE_FILES*', '*HELP_DECRYPT*')
    $ransomExtensions = @('.locked', '.encrypted', '.crypt', '.enc', '.locky', '.cerber', '.zepto', '.crypz', '.wcry', '.wncry')
    $foldersToScan = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    $noteFound = $false
    $extFound = $false
    foreach ($folder in $foldersToScan) {
        if (Test-Path $folder) {
            foreach ($pattern in $ransomNotePatterns) {
                Get-ChildItem -Path $folder -Filter $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $noteFound = $true
                    $evidenceLines.Add("Possible ransom note: $($_.FullName)")
                    Add-Line ("Possible ransom note: {0}" -f $_.FullName)
                }
            }
            Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue |
                Where-Object { $ransomExtensions -contains $_.Extension.ToLower() } | Select-Object -First 10 |
                ForEach-Object {
                    $extFound = $true
                    $evidenceLines.Add("Ransomware-associated extension: $($_.FullName)")
                    Add-Line ("File with ransomware-associated extension: {0}" -f $_.FullName)
                }
        }
    }
    if ($noteFound) { $indicatorCount++ }
    if ($extFound) { $indicatorCount++ }

    $vssCmdFound = $false
    foreach ($p in $script:CimProcesses) {
        if ($p.CommandLine -and ($p.CommandLine -match 'vssadmin.*delete.*shadows' -or $p.CommandLine -match 'wbadmin.*delete.*catalog' -or $p.CommandLine -match 'bcdedit.*recoveryenabled\s+no')) {
            $vssCmdFound = $true
            $indicatorCount++
            $evidenceLines.Add("Shadow-copy/recovery deletion command: $($p.CommandLine)")
            Add-Line ("Recovery-disabling command seen: {0}" -f $p.CommandLine)
        }
    }

    $defenderRansomHits = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.ThreatID -match 'Ransom' }
    if ($defenderRansomHits) { $indicatorCount++; $evidenceLines.Add("Defender flagged a ransomware-family threat") }

    if ($indicatorCount -ge 2) {
        Add-Finding -Category 'Ransomware' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1486' -MitreConfidence 'CONFIRMED' -EvidenceType 'DIRECT' `
            -Text ("Multiple ransomware indicators correlated ({0} independent signals): {1}" -f $indicatorCount, ($evidenceLines -join ' | ')) `
            -Recommendation "Disconnect from the network immediately, do not pay or interact with any ransom note, and get help from a professional incident responder. Do not power off the machine if you plan to seek forensic help - disconnecting the network is safer than shutting down." | Out-Null
    } elseif ($indicatorCount -eq 1) {
        # A single isolated signal - even a ransom-note-looking filename or a
        # suspicious extension - is NOT treated as confirmed ransomware; such
        # files can be legitimate. Severity capped at MEDIUM, MITRE mapping
        # explicitly HEURISTIC, never CONFIRMED, until a second independent
        # signal corroborates it.
        $singleSev = if ($noteFound -or $vssCmdFound) { 'MEDIUM' } else { 'LOW' }
        Add-Finding -Category 'Ransomware' -Severity $singleSev -Confidence 'LOW' -MitreId 'T1490' -MitreConfidence 'HEURISTIC' -EvidenceType 'HEURISTIC' `
            -Text ("A single, weak ransomware-adjacent indicator was found: {0}" -f ($evidenceLines -join ' | ')) `
            -Recommendation "One indicator alone is common and usually benign (a legitimately named file, a renamed archive, etc). Keep an eye out for additional signs before treating this as an active incident." | Out-Null
    } else {
        Add-Context "No ransomware indicators found."
    }
    Add-Line ""
    Add-Line "Note: this is a lightweight heuristic, not a substitute for backups. Keep an offline/cloud backup regardless of these results."
}

# =================================================================
# 17. CRYPTOMINER INDICATORS (correlated)
# =================================================================
function Get-CryptominerIndicators {
    Add-Section "CRYPTOMINER INDICATORS (CORRELATED)"
    $knownMinerNames = @('xmrig', 'xmr-stak', 'cpuminer', 'minerd', 'nheqminer', 'ccminer', 'ethminer', 'cgminer', 'bfgminer', 'nicehash', 't-rex', 'phoenixminer', 'lolminer', 'gminer', 'claymore')
    $miningPorts = @(3333, 4444, 5555, 7777, 8080, 9999, 14444, 45700)
    $found = 0

    Get-Process | Where-Object { $knownMinerNames -contains $_.Name.ToLower() } | ForEach-Object {
        $found++
        $sig = Get-SignatureSafe $_.Path
        Add-Finding -Category 'ResourceHijack' -Severity 'HIGH' -Confidence 'HIGH' -MitreId 'T1496' `
            -Text ("Process name matches a known cryptominer: {0} (PID {1})" -f $_.Name, $_.Id) `
            -IOC @{ Process = $_.Name; PID_ = $_.Id; Path = $_.Path; SHA256 = (Get-FileHashSafe $_.Path) } | Out-Null
    }

    # $_.CPU from Get-Process is CUMULATIVE processor time in seconds since the
    # process started - NOT current utilization. A browser open for hours will
    # trivially exceed any fixed-seconds threshold and is not a "high CPU"
    # signal. Instead: first find candidates with a connection to a mining-pool
    # -style port (cheap, already computed), then only for that small set do a
    # real before/after CPU-time delta sample to get actual current utilization.
    $miningPortPids = New-Object System.Collections.Generic.List[int]
    foreach ($conn in $script:TcpEstablished) {
        if ($miningPorts -contains $conn.RemotePort) {
            $procForConn = $script:ProcessById[[int]$conn.OwningProcess]
            if ($procForConn -and $procForConn.ExecutablePath -and $procForConn.ExecutablePath -notmatch '\\Windows\\') {
                if (-not ($miningPortPids -contains [int]$conn.OwningProcess)) {
                    [void]$miningPortPids.Add([int]$conn.OwningProcess)
                }
            }
        }
    }

    if ($miningPortPids.Count -gt 0) {
        $cpu0 = @{}
        foreach ($pid_ in $miningPortPids) {
            $p0 = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
            if ($p0) { $cpu0[$pid_] = $p0.CPU }
        }
        $t0 = Get-Date
        Start-Sleep -Seconds 2
        $elapsedSeconds = ((Get-Date) - $t0).TotalSeconds
        $coreCount = [Environment]::ProcessorCount

        foreach ($pid_ in $miningPortPids) {
            $p1 = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
            if ($p1 -and $cpu0.ContainsKey($pid_) -and $null -ne $cpu0[$pid_] -and $null -ne $p1.CPU) {
                $deltaCpu = $p1.CPU - $cpu0[$pid_]
                $utilizationPct = 0
                if ($elapsedSeconds -gt 0 -and $coreCount -gt 0) {
                    $utilizationPct = [math]::Round((($deltaCpu / $elapsedSeconds) / $coreCount) * 100, 1)
                }
                if ($utilizationPct -ge 50) {
                    $found++
                    Add-Finding -Category 'ResourceHijack' -Severity 'HIGH' -Confidence 'MEDIUM' -MitreId 'T1496' `
                        -Text ("{0} (PID {1}) is at {2}% current CPU utilization and connects to a mining-pool-style port" -f $p1.Name, $pid_, $utilizationPct) `
                        -Recommendation "Real-time CPU sampled over a 2-second window, normalized to core count. This combination of sustained CPU load and a mining-pool-style outbound connection is a much stronger signal than either alone." `
                        -IOC @{ Process = $p1.Name; PID_ = $pid_; ParentPID_ = (Get-ParentPidSafe $pid_) } | Out-Null
                } else {
                    Add-Line ("Process on a mining-pool-style port but current CPU utilization is only ~{0}%: {1} (PID {2})" -f $utilizationPct, $p1.Name, $pid_)
                }
            }
        }
    }
    if ($found -eq 0) { Add-Context "No correlated cryptominer indicators found." }
    Add-Line ""
    Add-Line "Note: high CPU alone isn't proof of mining - video encoding, compiling, and games spike CPU too."
}

# =================================================================
# 18. REMOTE ACCESS TOOLS / RDP
# =================================================================
function Get-RemoteAccessIndicators {
    Add-Section "REMOTE ACCESS - RDP AND REMOTE-CONTROL TOOLS"
    $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    if ($rdpSetting -and $rdpSetting.fDenyTSConnections -eq 0) {
        Add-Finding -Category 'RemoteAccess' -Severity 'LOW' -Confidence 'MEDIUM' -MitreId 'T1021.001' `
            -Text "Remote Desktop (RDP) is ENABLED on this PC." `
            -Recommendation "RDP is a normal feature many people use intentionally - only a concern if you did not enable it yourself." | Out-Null
    } else {
        Add-Line "Remote Desktop (RDP): disabled (normal for most home PCs)."
    }
    Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Line ("Account allowed to RDP in: {0}" -f $_.Name)
    }
    $remoteToolNames = @('teamviewer', 'anydesk', 'ultraviewer', 'vncserver', 'tvnserver', 'realvnc', 'radmin', 'ammyy', 'logmein', 'splashtop', 'supremo', 'dwservice', 'remoteutilities')
    Get-Process | Where-Object { $remoteToolNames -contains $_.Name.ToLower() } | ForEach-Object {
        Add-Finding -Category 'RemoteAccess' -Severity 'LOW' -Confidence 'LOW' -MitreId 'T1219' `
            -Text ("Remote access tool running: {0} (PID {1})" -f $_.Name, $_.Id) `
            -Recommendation "Legitimate for IT support or your own use - but also the #1 tool in tech-support scams. If you did not start this, disconnect from the internet." | Out-Null
    }
}

# =================================================================
# 19. KEYLOGGER HEURISTICS
# =================================================================
function Get-KeyloggerIndicators {
    Add-Section "KEYLOGGER / INPUT-MONITORING HEURISTICS"
    $suspiciousNameKeywords = @('keylog', 'keystroke', 'spyware', 'stealer', 'hookspy', 'clipspy', 'screenspy', 'logkeys')
    $found = 0
    $autostartValues = @()
    foreach ($key in $script:RunKeysGlobal) {
        if (Test-Path $key) {
            (Get-ItemProperty -Path $key).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                ForEach-Object { $autostartValues += [string]$_.Value }
        }
    }
    foreach ($val in $autostartValues) {
        foreach ($kw in $suspiciousNameKeywords) {
            if ($val -and $val.ToLower().Contains($kw)) {
                $found++
                Add-Finding -Category 'Collection' -Severity 'MEDIUM' -Confidence 'LOW' -EvidenceType 'CONTEXT' `
                    -Text ("Autostart entry matches keylogger-related keyword '{0}': {1}" -f $kw, $val) `
                    -Recommendation "This is a weak name-based heuristic - real keyloggers rarely use obvious names." -IOC @{ Command = $val } | Out-Null
            }
        }
    }
    Get-Process | Where-Object {
        $nameLower = $_.Name.ToLower()
        ($suspiciousNameKeywords | Where-Object { $nameLower.Contains($_) }).Count -gt 0
    } | ForEach-Object {
        $found++
        Add-Finding -Category 'Collection' -Severity 'MEDIUM' -Confidence 'LOW' -EvidenceType 'CONTEXT' `
            -Text ("Process name matches a keylogger-related keyword: {0} (PID {1})" -f $_.Name, $_.Id) -IOC @{ Process = $_.Name; PID_ = $_.Id } | Out-Null
    }
    if ($found -eq 0) { Add-Context "No keylogger-related name patterns found (inconclusive either way - see limitations)." }
}

# =================================================================
# 20. USB AUTORUN / WORM PROPAGATION
# =================================================================
function Get-USBAutorunIndicators {
    Add-Section "USB AUTORUN / WORM PROPAGATION CHECK"
    $autorunPolicy = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction SilentlyContinue
    if ($autorunPolicy -and $autorunPolicy.NoDriveTypeAutoRun) {
        Add-Line ("AutoRun policy value: {0} (255 = fully disabled, safest)" -f $autorunPolicy.NoDriveTypeAutoRun)
    } else {
        Add-Line "No explicit AutoRun policy set (modern Windows defaults are generally safe)."
    }
    $found = 0
    Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | ForEach-Object {
        $autorunPath = "$($_.DriveLetter):\autorun.inf"
        if (Test-Path $autorunPath) {
            $found++
            Add-Finding -Category 'Propagation' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
                -Text ("autorun.inf found on removable drive {0}: - a classic worm propagation file" -f $_.DriveLetter) `
                -Recommendation "Some legitimate USB installers ship an autorun.inf too - check what it points to." -IOC @{ Path = $autorunPath } | Out-Null
        }
    }
    if ($found -eq 0) { Add-Context "No autorun.inf files found on connected removable drives." }
}

# =================================================================
# 21. PROCESS MASQUERADING CHECK
# =================================================================
function Get-ProcessMasqueradeIndicators {
    Add-Section "PROCESS MASQUERADING CHECK"
    $systemProcessNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'wininit.exe', 'services.exe', 'explorer.exe', 'smss.exe', 'spoolsv.exe', 'taskhostw.exe', 'dwm.exe', 'conhost.exe')
    $expectedDirs = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", $env:SystemRoot)
    $found = 0
    Get-Process | Where-Object { $_.Path } | ForEach-Object {
        $exeName = (Split-Path $_.Path -Leaf).ToLower()
        if ($systemProcessNames -contains $exeName) {
            $procDir = Split-Path $_.Path -Parent
            if ($expectedDirs -notcontains $procDir) {
                $found++
                Add-HighRiskPid $_.Id
                Add-Finding -Category 'Defense Evasion' -Severity 'CRITICAL' -Confidence 'HIGH' -MitreId 'T1036' `
                    -Text ("{0} (PID {1}) is running from an unexpected location - likely masquerading as a system process" -f $exeName, $_.Id) `
                    -Recommendation "What matters is which folder it runs from, not the displayed name. Investigate this process immediately." `
                    -IOC @{ Path = $_.Path; SHA256 = (Get-FileHashSafe $_.Path); Process = $exeName; PID_ = $_.Id } | Out-Null
                Add-Line ("    Path: {0}" -f $_.Path)
                Add-Line ("    Expected folder: {0}" -f ($expectedDirs -join ' or '))
                Add-Line ""
            }
        }
    }
    if ($found -eq 0) { Add-Context "No masquerading system-process names found." }
}

# =================================================================
# 22. PARENT-CHILD PROCESS RELATIONSHIPS / PROCESS TREE
# =================================================================
function Get-ParentChildProcessIndicators {
    Add-Section "SUSPICIOUS PARENT-CHILD PROCESS RELATIONSHIPS"
    $sensitiveParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'acrord32.exe', 'acrobat.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe')
    $suspiciousChildren = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe')
    $found = 0
    foreach ($p in $script:CimProcesses) {
        $parent = $script:ProcessById[[int]$p.ParentProcessId]
        if ($parent -and ($suspiciousChildren -contains $p.Name.ToLower()) -and ($sensitiveParents -contains $parent.Name.ToLower())) {
            $found++
            Add-HighRiskPid ([int]$p.ProcessId)
            $ancestry = Get-ProcessAncestry ([int]$p.ProcessId)
            Add-Finding -Category 'Execution' -Severity 'HIGH' -Confidence 'MEDIUM' -MitreId 'T1059' -EvidenceType 'HEURISTIC' `
                -Text ("{0} (PID {1}) was launched by {2} (PID {3})" -f $p.Name, $p.ProcessId, $parent.Name, $parent.ProcessId) `
                -Recommendation "Office apps, PDF readers, or browsers spawning a command shell or scripting engine is a textbook sign of a malicious macro, exploit, or phishing payload executing." `
                -IOC @{ Command = $p.CommandLine; Process = $p.Name; PID_ = $p.ProcessId; ParentPID_ = $p.ParentProcessId } | Out-Null
            Add-Line ("    Ancestry: {0}" -f $ancestry)
            Add-Line ("    Command line: {0}" -f $p.CommandLine)
            Add-Line ""
        }
    }
    if ($found -eq 0) { Add-Context "No suspicious parent-child process relationships found." }
}

# =================================================================
# 23. RECENTLY CREATED EXECUTABLES IN TEMP/APPDATA + light DLL-hijack heuristic
# =================================================================
function Get-BoundedFiles($rootFolder, $extensions, $maxDepth, $maxPerDir) {
    # Get-ChildItem -Recurse -Depth bounds tree DEPTH only, not how many files
    # sit in any single directory. The previous version also assigned the full
    # listing to a variable first ($items = Get-ChildItem ...), which forces
    # PowerShell to enumerate the ENTIRE directory into memory before any
    # filtering happens - Select-Object -First after that point does nothing
    # to bound the actual enumeration cost.
    #
    # Fix: pipe Get-ChildItem directly into Select-Object -First. Select-Object
    # -First implements real early pipeline stopping in PowerShell - it signals
    # the upstream command to stop once N objects have been produced, instead
    # of waiting for the full directory listing. -File/-Directory are used
    # instead of a PSIsContainer filter so each call only walks the provider
    # once for the category it needs. (Deliberately NOT using a
    # ForEach-Object{...break} pattern here: this function already runs inside
    # a `while` loop below, and a bare `break` inside a ForEach-Object script
    # block breaks out of the NEAREST ENCLOSING LOOP KEYWORD if one lexically
    # wraps it - which would silently abort the whole BFS walk, not just stop
    # listing the current directory. Select-Object -First avoids that trap.)
    #
    # IMPORTANT: the extension filter (Where-Object) must run BEFORE
    # Select-Object -First, not after. If -First truncates to N files first
    # and only THEN checks extensions, the first N files of ANY type in a
    # directory consume the whole budget and real .exe/.dll/.scr files later
    # in the listing are silently skipped. Filtering first still gets the
    # early-stop benefit: the pipeline stop signal from Select-Object -First
    # propagates back through Where-Object to Get-ChildItem once N MATCHING
    # files have been found.
    $results = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Path = $rootFolder; Depth = 0 })
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $script:ScanCoverage.DirectoriesChecked++

        # Request one MORE than the cap. If exactly maxPerDir+1 come back, we
        # know for certain the directory had more matching files than the
        # limit allowed. This only records THAT truncation happened, once per
        # directory - it deliberately does NOT claim to know how many files
        # were actually skipped, since getting an exact count would require
        # full enumeration and defeat the point of the cap.
        $dirFileErr = $null
        $matched = Get-ChildItem -LiteralPath $current.Path -File -ErrorAction SilentlyContinue -ErrorVariable dirFileErr |
            Where-Object { $extensions -contains $_.Extension.ToLower() } |
            Select-Object -First ($maxPerDir + 1)
        if ($dirFileErr) { foreach ($e in $dirFileErr) { Add-ScanError 'Get-BoundedFiles' "Access denied listing files in $($current.Path): $($e.Exception.Message)" 'LOW' 'PERMISSION_DENIED' } }
        $matchedList = @($matched)
        if ($matchedList.Count -gt $maxPerDir) {
            $script:ScanCoverage.DirectoriesTruncated++
            $matchedList = $matchedList | Select-Object -First $maxPerDir
        }
        $script:ScanCoverage.FilesChecked += $matchedList.Count
        foreach ($m in $matchedList) { [void]$results.Add($m) }

        if ($current.Depth -lt $maxDepth) {
            $dirDirErr = $null
            Get-ChildItem -LiteralPath $current.Path -Directory -ErrorAction SilentlyContinue -ErrorVariable dirDirErr |
                Select-Object -First $maxPerDir |
                ForEach-Object {
                    $queue.Enqueue(@{ Path = $_.FullName; Depth = $current.Depth + 1 })
                }
            if ($dirDirErr) { foreach ($e in $dirDirErr) { Add-ScanError 'Get-BoundedFiles' "Access denied listing subdirectories in $($current.Path): $($e.Exception.Message)" 'LOW' 'PERMISSION_DENIED' } }
        }
    }
    return $results
}

function Get-TempExecutableIndicators {
    Add-Section "RECENTLY CREATED EXECUTABLES IN TEMP/APPDATA"
    $cutoffTemp = (Get-Date).AddDays(-7)
    $tempFolders = @($env:TEMP, "$env:LOCALAPPDATA\Temp", $env:APPDATA)
    $found = 0
    foreach ($folder in $tempFolders) {
        if (Test-Path $folder) {
            $candidateFiles = Get-BoundedFiles $folder @('.exe', '.dll', '.scr') $Config.ScanDepth $Config.MaxFilesPerDirectory
            $candidateFiles | Where-Object { $_.CreationTime -gt $cutoffTemp } | ForEach-Object {
                    $verdict = Get-SignatureVerdict $_.FullName
                    if ($verdict -eq 'Valid' -or $verdict -eq 'Unavailable') { return }
                    $found++
                    $sev = 'MEDIUM'; $conf = 'LOW'
                    if ($verdict -eq 'Invalid') { $sev = 'HIGH'; $conf = 'MEDIUM' }
                    Add-Finding -Category 'InitialAccess' -Severity $sev -Confidence $conf -MitreId 'T1105' `
                        -Text ("Recently dropped file with signature status '{0}': {1} (created {2})" -f $verdict, $_.FullName, $_.CreationTime) `
                        -Recommendation "Temp and AppData are the most common landing spots for downloaded malware payloads - installers also use these folders temporarily." `
                        -IOC @{ Path = $_.FullName; SHA256 = (Get-FileHashSafe $_.FullName) } | Out-Null
                }
        }
    }
    if ($found -eq 0) { Add-Context "No recently created unsigned executables found in Temp/AppData." }
    Add-Context ("Scan bounded to depth {0} and up to {1} files/subfolders per directory (see Config)." -f $Config.ScanDepth, $Config.MaxFilesPerDirectory)

    Add-Line ""
    Add-Line "--- Light DLL search-order-hijack heuristic ---"
    Add-Line "Note: comprehensive DLL search-order-hijacking detection needs live file-system tracing (Procmon/ETW), which a static script cannot do. This only flags a narrow, weaker pattern."
    $hijackFound = 0
    $userFacingFolders = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", $env:TEMP)
    foreach ($folder in $userFacingFolders) {
        if (Test-Path $folder) {
            $exes = Get-ChildItem -Path $folder -Filter *.exe -File -ErrorAction SilentlyContinue
            foreach ($exe in $exes) {
                $siblingDlls = Get-ChildItem -Path $exe.DirectoryName -Filter *.dll -File -ErrorAction SilentlyContinue
                foreach ($dll in $siblingDlls) {
                    $verdict = Get-SignatureVerdict $dll.FullName
                    if ($verdict -eq 'Valid' -or $verdict -eq 'Unavailable') { continue }
                    $hijackFound++
                    $sev = 'LOW'; $conf = 'LOW'
                    if ($verdict -eq 'Invalid') { $sev = 'MEDIUM'; $conf = 'LOW' }
                    Add-Finding -Category 'DefenseEvasion' -Severity $sev -Confidence $conf -MitreId 'T1574.001' `
                        -Text ("DLL with signature status '{0}' sitting next to an EXE in a user-facing folder: {1}" -f $verdict, $dll.FullName) `
                        -Recommendation "This is a coarse heuristic, not proof - many portable apps legitimately ship unsigned DLLs alongside their EXE." `
                        -IOC @{ Path = $dll.FullName } | Out-Null
                }
            }
        }
    }
    if ($hijackFound -eq 0) { Add-Context "No DLL-beside-EXE pattern found in user-facing folders." }
}

# =================================================================
# 24. ROOT CERTIFICATE ANALYSIS (full detail, not a simple whitelist)
# =================================================================
function Get-RootCertificateIndicators {
    Add-Section "ROOT CERTIFICATE ANALYSIS"
    # NOTE: this whitelist can never be exhaustive - the Windows trust store
    # ships with several hundred root CAs, many under names that don't match
    # the vendor's company name at all (e.g. Let's Encrypt's actual root is
    # named "ISRG Root X1", not "Let's Encrypt"; Sectigo's legacy root is
    # "AddTrust External CA Root"). An earlier version of this list matched
    # only company names and missed both, which produced false positives on
    # two very common, entirely legitimate roots. Because this list can't be
    # complete, "not in this list" is treated as UnknownRootCertificate
    # (informational) and NEVER escalated on its own - only self-signed +
    # recently issued (a combination legitimate old roots essentially never
    # have) pushes severity above LOW.
    $wellKnownCAs = @('Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 'Entrust', "Let's Encrypt", 'ISRG', 'GoDaddy',
                       'Go Daddy', 'Comodo', 'AddTrust', 'VeriSign', 'Thawte', 'GeoTrust', 'USERTrust', 'Amazon',
                       'Google Trust Services', 'GTS Root', 'IdenTrust', 'Certum', 'SSL.com', 'Buypass',
                       'AAA Certificate', 'QuoVadis', 'Starfield', 'Symantec', 'Baltimore', 'DST Root',
                       'Cybertrust', 'SwissSign', 'Actalis', 'D-TRUST', 'Chunghwa Telecom', 'TWCA', 'Network Solutions', 'Trustwave')
    $found = 0
    foreach ($loc in @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')) {
        $storeLocation = if ($loc -match 'LocalMachine') { 'LocalMachine' } else { 'CurrentUser' }
        Get-ChildItem $loc -ErrorAction SilentlyContinue | ForEach-Object {
            $isWellKnown = $false
            foreach ($ca in $wellKnownCAs) {
                if ($_.Issuer -match [regex]::Escape($ca)) { $isWellKnown = $true; break }
            }
            $isSelfSigned = ($_.Subject -eq $_.Issuer)
            $isRecent = $_.NotBefore -gt (Get-Date).AddDays(-90)

            if ($isWellKnown) { return }  # KnownRootCertificate - not reported as a finding at all

            $found++
            # Category reflects what we can actually observe, not a guess at
            # intent. UserStore roots (CurrentUser, not LocalMachine) are
            # slightly more concerning since they don't require admin rights
            # to install - reflected in confidence, not automatically severity.
            $category = 'UnknownRootCertificate'
            $sev = 'LOW'; $conf = 'LOW'; $mitreId = ''; $mitreConf = 'CONTEXT_ONLY'; $evidenceType = 'CONTEXT'
            if ($isSelfSigned -and $isRecent) {
                $category = 'RecentlyAddedRootCertificate'
                $sev = 'MEDIUM'; $conf = if ($storeLocation -eq 'CurrentUser') { 'MEDIUM' } else { 'LOW' }
                $mitreId = 'T1553.004'; $mitreConf = 'LIKELY'; $evidenceType = 'HEURISTIC'
            } elseif ($isSelfSigned) {
                $category = 'SelfSignedRootCertificate'
            } elseif ($storeLocation -eq 'CurrentUser') {
                $category = 'UserStoreRootCertificate'
            }

            Add-Finding -Category $category -Severity $sev -Confidence $conf -MitreId $mitreId -MitreConfidence $mitreConf -EvidenceType $evidenceType `
                -Text ("Root certificate from an unrecognized issuer ({0}): {1}" -f $category, $_.Subject) `
                -Recommendation "An unknown CA is not proof of malware - some VPNs, parental-control tools, and corporate security software legitimately add root certs to inspect HTTPS. Self-signed AND recently issued together is the combination worth checking; either alone is common and usually benign." `
                -IOC @{ CertificateThumbprint = $_.Thumbprint; CertificateSubject = $_.Subject; CertificateIssuer = $_.Issuer } | Out-Null
            Add-Line ("    Issuer: {0}" -f $_.Issuer)
            Add-Line ("    Thumbprint: {0}" -f $_.Thumbprint)
            Add-Line ("    Self-signed: {0}  |  Issued within last 90 days: {1}  |  Store: {2}" -f $isSelfSigned, $isRecent, $storeLocation)
            Add-Line ("    Valid: {0} to {1}" -f $_.NotBefore, $_.NotAfter)
            Add-Line ("    Location: {0}" -f $loc)
            Add-Line ""
        }
    }
    if ($found -eq 0) { Add-Context "All installed root certificates match well-known trusted issuers." }
}

# =================================================================
# 25. SECURITY CONFIGURATION (state shown separately from findings,
#     per spec item 14 - only genuinely risky posture becomes a finding)
# =================================================================
function Get-SecurityConfiguration {
    Add-Section "SECURITY CONFIGURATION STATE"

    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    if ($uac -and $uac.EnableLUA -eq 0) {
        Add-Finding -Category 'SecurityConfig' -Severity 'MEDIUM' -Confidence 'HIGH' -MitreId 'T1562.001' `
            -Text "User Account Control (UAC) is fully DISABLED." `
            -Recommendation "UAC is a real security boundary - re-enable it unless you have a specific, temporary reason to keep it off." | Out-Null
    } else {
        Add-Line ("UAC enabled: {0}" -f $(if ($uac) { $uac.EnableLUA } else { "Unknown" }))
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Line ("Secure Boot enabled: {0}" -f $secureBoot)
    } catch {
        Add-Line "Secure Boot status: could not be determined (legacy BIOS, or requires elevation)."
    }

    $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($deviceGuard) {
        Add-Line ("Memory Integrity / HVCI running: {0}" -f (($deviceGuard.SecurityServicesRunning -contains 2)))
        Add-Line ("Credential Guard running: {0}" -f (($deviceGuard.SecurityServicesRunning -contains 1)))
        Add-Line ("Virtualization-based security status: {0}" -f $deviceGuard.VirtualizationBasedSecurityStatus)
    } else {
        Add-Line "Device Guard/HVCI info not available on this system."
    }

    $lsaProt = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    Add-Line ("LSA Protection (RunAsPPL) enabled: {0}" -f $(if ($lsaProt) { $lsaProt.RunAsPPL } else { "Not set (default)" }))

    Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Line ("Firewall profile [{0}]: Enabled = {1}" -f $_.Name, $_.Enabled)
        if (-not $_.Enabled) {
            Add-Finding -Category 'SecurityConfig' -Severity 'MEDIUM' -Confidence 'HIGH' -MitreId 'T1562.004' `
                -Text ("Windows Firewall profile '{0}' is DISABLED." -f $_.Name) `
                -Recommendation "Re-enable this firewall profile unless you have a specific reason (e.g. a third-party firewall handling it instead)." | Out-Null
        }
    }

    try {
        $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $ruleCount = (@($applockerPolicy.RuleCollections)).Count
        Add-Line ("AppLocker effective rule collections: {0}" -f $ruleCount)
    } catch {
        Add-Line "AppLocker: not configured or service unavailable (normal on most home PCs)."
    }

    Add-Line ""
    Add-Line "Note: this section shows configuration STATE for context. Most home PCs will show several 'off/not configured' items here - that's expected, not a malware finding by itself, unless flagged above."
}

# =================================================================
# 26. EVENT LOG ANALYSIS (config-gated, scoped queries, graceful degradation)
# =================================================================
function Get-EventLogIndicators {
    Add-Section ("EVENT LOG ANALYSIS - last {0} days" -f $Config.EventLogDays)
    $startTime = (Get-Date).AddDays(-$Config.EventLogDays)
    $maxEv = $Config.MaxEvents

    function Get-EventsSafe($logName, $ids) {
        $script:ScanCoverage.EventLogsQueried++
        try {
            $evts = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $ids; StartTime = $startTime } -MaxEvents $maxEv -ErrorAction Stop
            Set-SourceStatus 'EventLogs' 'OK'
            return $evts
        } catch {
            # "No events found" is the normal/expected outcome on most home
            # PCs (log not enabled, or nothing matched) - the log WAS queried
            # successfully, so the source counts as OK.
            if ($_.Exception.Message -match 'No events were found') {
                if ($script:SourceStatus.EventLogs -eq 'NOT_TESTED') { Set-SourceStatus 'EventLogs' 'OK' }
            }
            # is a real coverage gap.
            if ($_.Exception.Message -notmatch 'No events were found') {
                $code = 'ERROR'
                if ($_.Exception.Message -match 'Access is denied|access denied') { $code = 'PERMISSION_DENIED' }
                elseif ($_.Exception.Message -match 'no logs? (were|was) found|does not exist|cannot find') { $code = 'UNAVAILABLE' }
                Add-ScanError 'Get-EventsSafe' "Log '$logName': $($_.Exception.Message)" 'LOW' $code
            }
            return $null
        }
    }

    Add-Line "--- New services installed (System log, Event ID 7045) ---"
    $svcEvents = Get-EventsSafe 'System' 7045
    if ($svcEvents) {
        foreach ($e in ($svcEvents | Select-Object -First 15)) {
            Add-Finding -Category 'EventLog' -Severity 'LOW' -Confidence 'LOW' -MitreId 'T1543.003' `
                -Text ("New service installed at {0}: {1}" -f $e.TimeCreated, $e.Message.Split("`n")[0]) | Out-Null
        }
    } else { Add-Context "No new-service-installation events found (or auditing not enabled for this)." }

    Add-Line ""
    Add-Line "--- New local user accounts created (Security log, Event ID 4720) ---"
    $userEvents = Get-EventsSafe 'Security' 4720
    if ($userEvents) {
        foreach ($e in ($userEvents | Select-Object -First 15)) {
            Add-Finding -Category 'EventLog' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
                -Text ("New local user account created at {0}" -f $e.TimeCreated) | Out-Null
        }
    } else { Add-Context "No new-user-account events found (or Security auditing not enabled for this)." }

    Add-Line ""
    Add-Line "--- Privileged group membership changes (Security log, Event ID 4728/4732/4756) ---"
    $groupEvents = Get-EventsSafe 'Security' @(4728, 4732, 4756)
    if ($groupEvents) {
        foreach ($e in ($groupEvents | Select-Object -First 15)) {
            Add-Finding -Category 'EventLog' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
                -Text ("Privileged group membership change at {0} (Event ID {1})" -f $e.TimeCreated, $e.Id) | Out-Null
        }
    } else { Add-Context "No privileged group membership changes found (or auditing not enabled)." }

    Add-Line ""
    Add-Line "--- Scheduled task created/updated (Task Scheduler operational log, Event ID 106/140) ---"
    $taskEvents = Get-EventsSafe 'Microsoft-Windows-TaskScheduler/Operational' @(106, 140)
    if ($taskEvents) {
        foreach ($e in ($taskEvents | Select-Object -First 15)) {
            Add-Line ("Task Scheduler event at {0}: {1}" -f $e.TimeCreated, $e.Message.Split("`n")[0])
        }
    } else { Add-Context "No scheduled task creation/update events found in this window." }

    Add-Line ""
    Add-Line "--- Windows Defender detections (Operational log, Event ID 1116/1117) ---"
    $defEvents = Get-EventsSafe 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117)
    if ($defEvents) {
        foreach ($e in ($defEvents | Select-Object -First 15)) {
            Add-Finding -Category 'DefenderDetection' -Severity 'HIGH' -Confidence 'HIGH' `
                -Text ("Defender event at {0}: {1}" -f $e.TimeCreated, $e.Message.Split("`n")[0]) | Out-Null
        }
    } else { Add-Context "No Defender detection events found in this window." }

    Add-Line ""
    Add-Line "--- Code Integrity events (3076/3077 blocking, 3089 signature info, 3099/3116/3084 context) ---"
    $ciEventIds = @(3076, 3077, 3089, 3099, 3116, 3084)
    $ciEvents = Get-EventsSafe 'Microsoft-Windows-CodeIntegrity/Operational' $ciEventIds
    if ($ciEvents) {
        # 3077 = a binary was actually blocked (Enforcement mode) - real HIGH finding.
        # 3076 = Audit mode only - the binary WOULD have been blocked, nothing
        #        was actually stopped - MEDIUM, and worded accordingly.
        # 3089 = signature/publisher info tied to a 3076/3077 event via the same
        #        ETW ActivityId. It never creates a finding by itself - it is
        #        only merged into the 3076/3077 finding it belongs to.
        # 3099/3116/3084 = policy load/refresh/context events - never findings,
        #        counted for context only.
        # Correlation by ActivityId only applies to events that actually HAVE
        # a non-empty ActivityId. Grouping on a null/empty ActivityId would
        # lump unrelated events together under one "empty" key and could
        # attach a 3089 to a 3076/3077 it has no real connection to - so those
        # are pulled out and handled separately, one event at a time, with no
        # 3089 correlation performed for them at all.
        function Get-CodeIntegrityDetails($ciEvent) {
            # Structured data first: CodeIntegrity events carry named fields in
            # their EventData (FileName, PolicyGUID/PolicyId, PolicyName,
            # Status/USN etc). Reading the XML representation gets these by
            # NAME rather than guessing positional order, which varies. The
            # Message text regex is only used when XML parsing fails or a
            # specific field isn't present in it - both routes always return
            # $null for anything genuinely unavailable rather than a guess.
            $details = @{ FilePath = $null; PolicyId = $null; PolicyName = $null; Status = $null }
            try {
                [xml]$xml = $ciEvent.ToXml()
                $dataNodes = $xml.Event.EventData.Data
                foreach ($node in $dataNodes) {
                    $name = $node.Name
                    if (-not $name) { continue }
                    $value = $node.'#text'
                    if ($name -match 'FileName|File Name|FilePath' -and -not $details.FilePath) { $details.FilePath = $value }
                    elseif ($name -match 'PolicyGUID|PolicyId' -and -not $details.PolicyId) { $details.PolicyId = $value }
                    elseif ($name -match 'PolicyName' -and -not $details.PolicyName) { $details.PolicyName = $value }
                    elseif ($name -match '^Status$|USN' -and -not $details.Status) { $details.Status = $value }
                }
            } catch {
                Add-ScanError 'Get-CodeIntegrityDetails' "Could not parse Event XML for EventId $($ciEvent.Id) - falling back to Message text: $($_.Exception.Message)" 'INFO' 'PARSE_ERROR'
            }
            if (-not $details.FilePath -and $ciEvent.Message -match 'File Name:\s*(.+)') { $details.FilePath = $Matches[1].Trim() }
            if (-not $details.PolicyName -and $ciEvent.Message -match 'Policy Name:\s*(.+)') { $details.PolicyName = $Matches[1].Trim() }
            return $details
        }

        $ciWithActivity = $ciEvents | Where-Object { $_.ActivityId -and $_.ActivityId -ne [guid]::Empty }
        $ciWithoutActivity = $ciEvents | Where-Object { -not $_.ActivityId -or $_.ActivityId -eq [guid]::Empty }

        $ciGroups = $ciWithActivity | Group-Object ActivityId
        foreach ($grp in $ciGroups) {
            $blockEvent = $grp.Group | Where-Object { $_.Id -eq 3077 } | Select-Object -First 1
            if (-not $blockEvent) { $blockEvent = $grp.Group | Where-Object { $_.Id -eq 3076 } | Select-Object -First 1 }
            if (-not $blockEvent) { continue }

            $sigEvents = $grp.Group | Where-Object { $_.Id -eq 3089 }
            $sigInfo = ""
            if ($sigEvents) {
                # Multiple 3089 events correlated to the same block/audit event
                # are folded into ONE supplementary note, not separate findings.
                $sigLines = $sigEvents | ForEach-Object { $_.Message.Split("`n")[0] }
                $sigInfo = " | Signature info: " + ($sigLines -join ' / ')
            }
            $details = Get-CodeIntegrityDetails $blockEvent
            $ciIoc = @{ EventId = $blockEvent.Id; ActivityId = $blockEvent.ActivityId; TimeCreated = $blockEvent.TimeCreated.ToString("s"); FilePath = $details.FilePath; Path = $details.FilePath; PolicyId = $details.PolicyId; PolicyName = $details.PolicyName; Status = $details.Status }

            if ($blockEvent.Id -eq 3077) {
                Add-Finding -Category 'CodeIntegrity' -Severity 'HIGH' -Confidence 'HIGH' `
                    -Text ("Code Integrity BLOCKED a binary (Enforcement mode) at {0}: {1}{2}" -f $blockEvent.TimeCreated, $blockEvent.Message.Split("`n")[0], $sigInfo) `
                    -Recommendation "This is a real, enforced block, not just an audit warning - identify the referenced file and investigate before assuming it's a false positive." `
                    -IOC $ciIoc | Out-Null
            } else {
                Add-Finding -Category 'CodeIntegrity' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
                    -Text ("Code Integrity Audit Mode - a binary WOULD have been blocked at {0}: {1}{2}" -f $blockEvent.TimeCreated, $blockEvent.Message.Split("`n")[0], $sigInfo) `
                    -Recommendation "Audit mode only - nothing was actually blocked, but this file would fail Code Integrity policy in Enforcement mode. Worth reviewing, not urgent." `
                    -IOC $ciIoc | Out-Null
            }
        }

        # No-ActivityId 3076/3077 events: reported individually, with no
        # 3089 attached, since we cannot prove which (if any) 3089 belongs
        # to each one - safer to show them with signature info missing than
        # to risk borrowing it from an unrelated event.
        foreach ($e in ($ciWithoutActivity | Where-Object { $_.Id -eq 3077 -or $_.Id -eq 3076 })) {
            $details = Get-CodeIntegrityDetails $e
            $ciIoc = @{ EventId = $e.Id; ActivityId = $null; TimeCreated = $e.TimeCreated.ToString("s"); FilePath = $details.FilePath; Path = $details.FilePath; PolicyId = $details.PolicyId; PolicyName = $details.PolicyName; Status = $details.Status }
            if ($e.Id -eq 3077) {
                Add-Finding -Category 'CodeIntegrity' -Severity 'HIGH' -Confidence 'HIGH' `
                    -Text ("Code Integrity BLOCKED a binary (Enforcement mode) at {0}: {1} (no ActivityId - signature-info event, if any, could not be reliably matched)" -f $e.TimeCreated, $e.Message.Split("`n")[0]) `
                    -Recommendation "This is a real, enforced block, not just an audit warning - identify the referenced file and investigate before assuming it's a false positive." `
                    -IOC $ciIoc | Out-Null
            } else {
                Add-Finding -Category 'CodeIntegrity' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
                    -Text ("Code Integrity Audit Mode - a binary WOULD have been blocked at {0}: {1} (no ActivityId - signature-info event, if any, could not be reliably matched)" -f $e.TimeCreated, $e.Message.Split("`n")[0]) `
                    -Recommendation "Audit mode only - nothing was actually blocked, but this file would fail Code Integrity policy in Enforcement mode. Worth reviewing, not urgent." `
                    -IOC $ciIoc | Out-Null
            }
        }

        $contextOnlyCount = ($ciEvents | Where-Object { $_.Id -eq 3089 -or $_.Id -in @(3099, 3116, 3084) }).Count
        if ($contextOnlyCount -gt 0) {
            Add-Line ("Additional signature-info (3089) and policy/context (3099/3116/3084) events in this window: {0} - shown as context only, never treated as findings on their own." -f $contextOnlyCount)
        }
    } else { Add-Context "No Code Integrity events (3076/3077/3089/3099/3116/3084) found in this window." }

    Add-Line ""
    Add-Line "Note: many of these logs require audit policies most home PCs do not enable by default (process-creation auditing, PowerShell script-block logging, etc). An empty result here often means 'not logged', not 'nothing happened'."
}

# =================================================================
# 27. LOADED MODULE ANALYSIS (only for the capped set of high-risk PIDs
#     collected by other functions - keeps this fast, see Config item 21)
# =================================================================
function Get-LoadedModuleIndicators {
    Add-Section "LOADED DLL / MODULE ANALYSIS (HIGH-RISK PROCESSES ONLY)"
    $suspiciousDirs = @('\Temp\', '\AppData\', '\Downloads\', '\Users\Public\', '\ProgramData\')
    $capped = $script:HighRiskPIDs | Select-Object -Unique -First 15
    if (-not $capped -or (@($capped)).Count -eq 0) {
        Add-Context "No high-risk processes were flagged elsewhere, so module inspection was skipped."
        return
    }
    $found = 0
    foreach ($pid_ in $capped) {
        $proc = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        try {
            $modules = $proc.Modules
        } catch {
            Add-Line ("Could not read modules for {0} (PID {1}) - likely a protected process." -f $proc.Name, $pid_)
            continue
        }
        foreach ($m in ($modules | Select-Object -First 200)) {
            $isSuspiciousLoc = $false
            foreach ($sd in $suspiciousDirs) {
                if ($m.FileName -match [regex]::Escape($sd)) { $isSuspiciousLoc = $true; break }
            }
            if ($isSuspiciousLoc) {
                $verdict = Get-SignatureVerdict $m.FileName
                if ($verdict -eq 'Valid' -or $verdict -eq 'Unavailable') { continue }
                $found++
                $sev = 'HIGH'; $conf = 'MEDIUM'
                if ($verdict -eq 'Invalid') { $sev = 'CRITICAL' }
                elseif ($verdict -eq 'Untrusted') { $conf = 'LOW' }
                Add-Finding -Category 'ProcessInjection' -Severity $sev -Confidence $conf -MitreId 'T1055' `
                    -Text ("{0} (PID {1}) has a module loaded from a suspicious location (signature: {2}): {3}" -f $proc.Name, $pid_, $verdict, $m.FileName) `
                    -Recommendation "A process loading an unsigned/invalid-signature DLL from Temp/AppData/Downloads can indicate DLL injection or side-loading." `
                    -IOC @{ Path = $m.FileName; Process = $proc.Name; PID_ = $pid_; ParentPID_ = (Get-ParentPidSafe $pid_) } | Out-Null
            }
        }
    }
    if ($found -eq 0) { Add-Context ("Checked loaded modules for {0} high-risk process(es); nothing suspicious found." -f (@($capped)).Count) }
}

# =================================================================
# RISK ASSESSMENT
# =================================================================
function Get-RiskAssessment {
    $script:SeverityCounts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
    foreach ($f in $script:AllFindings) { $script:SeverityCounts[$f.Severity]++ }

    # Diminishing-returns aggregation instead of a flat sum.
    # A plain sum lets many independent LOW findings (e.g. 30 browser-extension
    # permission notices) add up to the same score as one real CRITICAL, which
    # is not a fair reflection of risk. Findings are sorted by their own score
    # descending, then each successive finding contributes less (0.7^rank).
    # A single CRITICAL still dominates the score; a pile of LOWs converges to
    # a bounded contribution (score / (1 - 0.7) at most) and cannot alone push
    # the total into HIGH/CRITICAL territory.
    #
    # PREVIOUS BUG (fixed here): TotalRiskScore decayed all findings together
    # using ONE global rank, while ConfirmedScore/HeuristicScore/ContextScore
    # each decayed their own SUBSET starting the rank back at 0. The same
    # finding could therefore get rank 3 (multiplier 0.7^3) in the global
    # total but rank 0 (multiplier 1.0, no decay at all) inside its own
    # bucket - the three buckets could sum to MORE than the total. Fixed by
    # computing each finding's decayed contribution EXACTLY ONCE, using its
    # GLOBAL rank, and only THEN splitting that already-computed number into
    # buckets by EvidenceType. The three buckets are a partition of the same
    # set of numbers that make up the total, so they cannot sum to anything
    # other than the total, by construction - this is checked explicitly
    # below as an invariant, not just asserted in a comment.
    $decayFactor = 0.7
    $sortedByScore = $script:AllFindings | Sort-Object RiskScore -Descending
    $script:RawRiskScore = [math]::Round((($script:AllFindings | Measure-Object -Property RiskScore -Sum).Sum), 1)
    if (-not $script:RawRiskScore) { $script:RawRiskScore = 0 }

    $script:ConfirmedScore = 0.0
    $script:HeuristicScore = 0.0
    $script:ContextScore   = 0.0
    $rank = 0
    $decayedSum = 0.0
    foreach ($f in $sortedByScore) {
        $contribution = [math]::Max(0.0, $f.RiskScore) * [math]::Pow($decayFactor, $rank)  # per-finding contribution can never be negative
        $decayedSum += $contribution
        switch ($f.EvidenceType) {
            'DIRECT'    { $script:ConfirmedScore += $contribution }
            'HEURISTIC' { $script:HeuristicScore += $contribution }
            'CONTEXT'   { $script:ContextScore   += $contribution }
            default     { $script:ConfirmedScore += $contribution }  # unset/unrecognized EvidenceType defaults to DIRECT bucket, matching Add-Finding's own default
        }
        $rank++
    }
    # Full precision retained inside the calculation - rounding each bucket
    # to 1 decimal BEFORE the invariant check could make three individually
    # rounded values sum to something up to 0.15 away from the rounded
    # total, producing a false FAIL that is purely a rounding artifact.
    # Raw (unrounded) values drive the invariant; rounded copies are what
    # the reports display.
    $script:ConfirmedScoreRaw = $script:ConfirmedScore
    $script:HeuristicScoreRaw = $script:HeuristicScore
    $script:ContextScoreRaw   = $script:ContextScore
    $script:DecayedRiskScoreRaw = $decayedSum
    $script:DeduplicationAdjustment = 0.0

    $script:TotalRiskScoreRaw = $script:DecayedRiskScoreRaw + $script:DeduplicationAdjustment

    # Invariant checked at full precision, tolerance 0.05.
    $breakdownSumRaw = $script:ConfirmedScoreRaw + $script:HeuristicScoreRaw + $script:ContextScoreRaw + $script:DeduplicationAdjustment
    $script:RiskScoreConsistencyStatus = if ([math]::Abs($breakdownSumRaw - $script:TotalRiskScoreRaw) -lt 0.05) { 'PASS' } else { 'FAIL' }

    # Rounded values for display only - assigned after the check above.
    $script:ConfirmedScore   = [math]::Round($script:ConfirmedScoreRaw, 1)
    $script:HeuristicScore   = [math]::Round($script:HeuristicScoreRaw, 1)
    $script:ContextScore     = [math]::Round($script:ContextScoreRaw, 1)
    $script:DecayedRiskScore = [math]::Round($script:DecayedRiskScoreRaw, 1)
    $script:TotalRiskScore   = [math]::Round($script:TotalRiskScoreRaw, 1)
    $script:FinalRiskScore   = $script:TotalRiskScore

    $script:RiskScoreConsistencyDetail = "Confirmed($([math]::Round($script:ConfirmedScoreRaw,4))) + Heuristic($([math]::Round($script:HeuristicScoreRaw,4))) + Context($([math]::Round($script:ContextScoreRaw,4))) + DedupAdjustment($($script:DeduplicationAdjustment)) = $([math]::Round($breakdownSumRaw,4)) vs Total = $([math]::Round($script:TotalRiskScoreRaw,4)) (checked at full precision, tolerance 0.05)"

    # Thresholds for the decayed scale on their own.
    $nameByRank = @('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

    $scoreRank = 0
    if ($script:TotalRiskScore -le 0) { $scoreRank = 0 }
    elseif ($script:TotalRiskScore -le 6) { $scoreRank = 1 }
    elseif ($script:TotalRiskScore -le 15) { $scoreRank = 2 }
    elseif ($script:TotalRiskScore -le 30) { $scoreRank = 3 }
    else { $scoreRank = 4 }

    # Severity floor: the decayed score is a good defense against a pile of
    # independent LOW findings looking artificially severe, but it must not
    # let a single CONFIRMED CRITICAL/HIGH finding get diluted down to a lower
    # overall level just because there weren't many other findings to add to
    # the sum. A floor based on the presence of specific severe findings (not
    # their count) fixes this without reintroducing the pile-up problem.
    # Rank scale: 0=MINIMAL 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL (see $nameByRank).
    # Note: the floor only affects the categorical RiskLevel, never the
    # numeric TotalRiskScore - the consistency invariant above is unaffected.
    $floorRank = 0
    foreach ($f in $script:AllFindings) {
        if ($f.Severity -eq 'CRITICAL') { if (4 -gt $floorRank) { $floorRank = 4 } }
        elseif ($f.Severity -eq 'HIGH' -and $f.Confidence -eq 'HIGH') { if (3 -gt $floorRank) { $floorRank = 3 } }
    }

    $finalRank = [math]::Max($scoreRank, $floorRank)
    $script:RiskLevel = $nameByRank[$finalRank]

    $script:MitreSummary = $script:AllFindings | Where-Object { $_.MitreId } | Group-Object MitreId |
        ForEach-Object {
            [PSCustomObject]@{
                MitreId = $_.Name
                MitreName = $MitreCatalog[$_.Name]
                Count = $_.Count
            }
        } | Sort-Object Count -Descending

    $script:TopFindings = $script:AllFindings | Sort-Object RiskScore -Descending | Select-Object -First 5

    $script:TopIOCs = New-Object System.Collections.Generic.List[object]
    $seenIocs = @{}
    foreach ($f in ($script:AllFindings | Sort-Object RiskScore -Descending)) {
        if ($f.IOC) {
            foreach ($k in $f.IOC.Keys) {
                if ($f.IOC[$k]) {
                    $iocKey = "$k|$($f.IOC[$k])"
                    if (-not $seenIocs.ContainsKey($iocKey)) {
                        $seenIocs[$iocKey] = $true
                        [void]$script:TopIOCs.Add([PSCustomObject]@{ Type = $k; Value = $f.IOC[$k]; Severity = $f.Severity })
                        if ($script:TopIOCs.Count -ge 15) { break }
                    }
                }
            }
        }
        if ($script:TopIOCs.Count -ge 15) { break }
    }
}

# =================================================================
# MAIN EXECUTION FLOW
# =================================================================
Initialize-ScanContext
Get-SuspiciousProcesses
Get-PersistenceIndicators
Get-ScheduledTaskIndicators
Get-ServiceIndicators
if ($Config.EnableDriverAnalysis) { Get-DriverIndicators }
if ($Config.EnableNetworkAnalysis) { Get-NetworkIndicators } else { Set-SourceStatus 'Network' 'DISABLED' }
Get-HostsDnsProxyIndicators
Get-FirewallIndicators
if ($Config.EnableBrowserAnalysis) { Get-BrowserIndicators }
Get-WmiPersistenceIndicators
Get-AdminAccountIndicators
Get-DefenderIndicators
Get-LOLBinIndicators
Get-LsaSecurityPackageIndicators
Get-System32ModifiedIndicators
Get-RansomwareIndicators
Get-CryptominerIndicators
Get-RemoteAccessIndicators
Get-KeyloggerIndicators
Get-USBAutorunIndicators
Get-ProcessMasqueradeIndicators
Get-ParentChildProcessIndicators
Get-TempExecutableIndicators
Get-RootCertificateIndicators
Get-SecurityConfiguration
if ($Config.EnableEventLogAnalysis) { Get-EventLogIndicators } else { Set-SourceStatus 'EventLogs' 'DISABLED' }
Get-LoadedModuleIndicators

Get-RiskAssessment
Write-Progress -Activity "Security diagnostic scan" -Completed
$script:EndTime = Get-Date
$script:DurationSeconds = [math]::Round(($script:EndTime - $script:StartTime).TotalSeconds, 1)

# =================================================================
# PRE-EXPORT QUALITY GATES - computed here, BEFORE the reports are built,
# so they actually appear INSIDE the TXT/JSON/HTML rather than only in the
# console after the fact. Gates that can only be checked by reading back a
# file that doesn't exist yet (JSON/IOC-JSON round-trip, HTML structure/
# escaping) are necessarily computed AFTER export instead - see the
# POST-EXPORT QUALITY GATES block further down. That split is a physical
# necessity (a file cannot be read back before it is written), not an
# architecture shortcut.
# =================================================================
$script:QualityGates = @{}
$script:QualityGates.ParserStatus = 'PASS'  # this line executing at all already proves it

$readOnlyResult = Test-ReadOnlyCompliance $PSCommandPath
$script:QualityGates.ReadOnlyStatus = $readOnlyResult.Status
$script:QualityGates.ReadOnlyCheckMethod = $readOnlyResult.Method
$script:QualityGates.ReadOnlyCheckWarnings = ($readOnlyResult.Warnings -join ' | ')

$script:QualityGates.RiskScoreConsistencyStatus = $script:RiskScoreConsistencyStatus

# CoverageStatus is driven by $script:SourceStatus (was the source
# successfully QUERIED) rather than by object counts, and the reasons are
# now kept in SEPARATE collections instead of being lumped into one
# MissingSources list. "The source errored", "the source does not exist on
# this system", "the code path never ran" and "the user switched it off"
# are four different situations that call for four different responses.
$script:MissingSources     = New-Object System.Collections.Generic.List[string]  # genuinely absent
$script:FailedSources      = New-Object System.Collections.Generic.List[string]  # ran, but errored (incl. permission denied)
$script:UnavailableSources = New-Object System.Collections.Generic.List[string]  # not present/applicable on this system
$script:NotTestedSources   = New-Object System.Collections.Generic.List[string]  # never reached
$script:DisabledSources    = New-Object System.Collections.Generic.List[string]  # switched off via $Config - NOT a fault
$okSources                 = New-Object System.Collections.Generic.List[string]

foreach ($sourceName in ($script:SourceStatus.Keys | Sort-Object)) {
    switch ($script:SourceStatus[$sourceName]) {
        'OK'                { [void]$okSources.Add($sourceName) }
        'ERROR'             { [void]$script:FailedSources.Add($sourceName) }
        'PERMISSION_DENIED' { [void]$script:FailedSources.Add("$sourceName(PERMISSION_DENIED)") }
        'UNAVAILABLE'       { [void]$script:UnavailableSources.Add($sourceName) }
        'NOT_TESTED'        { [void]$script:NotTestedSources.Add($sourceName) }
        'DISABLED'          { [void]$script:DisabledSources.Add($sourceName) }
        default             { [void]$script:MissingSources.Add("$sourceName($($script:SourceStatus[$sourceName]))") }
    }
}

# Only sources that were actually supposed to run count toward coverage -
# a NON-CRITICAL module the user deliberately disabled must not drag the
# status down. A CRITICAL source is treated differently: see below.
$expectedSources = @($script:SourceStatus.Keys | Where-Object { $script:SourceStatus[$_] -ne 'DISABLED' })

# Critical source policy:
#   OK          -> source verified, no impact
#   DISABLED    -> no technical error, but a critical check genuinely did
#                  not run: CoverageStatus is capped at PARTIAL (never
#                  PASS). Reported via DisabledSources, NOT as a failure -
#                  it must not be disguised as either OK or ERROR.
#   ERROR / NOT_TESTED / UNAVAILABLE / missing key -> CoverageStatus = FAIL
# A critical source missing entirely from $script:SourceStatus is itself a
# source problem, not something to skip over silently - it means the status
# was never recorded at all. Each failure is labelled with the status that
# caused it so the report says WHY, not just which.
$criticalFailed = New-Object System.Collections.Generic.List[string]
$criticalDisabled = New-Object System.Collections.Generic.List[string]
foreach ($cs in $script:CriticalSources) {
    if (-not $script:SourceStatus.ContainsKey($cs)) {
        [void]$criticalFailed.Add("$cs(MISSING_FROM_SOURCESTATUS)")
        continue
    }
    $csStatus = $script:SourceStatus[$cs]
    if ($csStatus -eq 'OK') { continue }
    if ($csStatus -eq 'DISABLED') {
        # Deliberately NOT added to $criticalFailed - it is not a fault,
        # but it does prevent an overall PASS.
        [void]$criticalDisabled.Add($cs)
        continue
    }
    [void]$criticalFailed.Add("$cs($csStatus)")
}

if ($criticalFailed.Count -gt 0) {
    $script:QualityGates.CoverageStatus = 'FAIL'
} elseif ($criticalDisabled.Count -gt 0) {
    # A critical source was switched off: no error, but the scan cannot
    # claim full coverage either.
    $script:QualityGates.CoverageStatus = 'PARTIAL'
} elseif ($okSources.Count -eq $expectedSources.Count) {
    $script:QualityGates.CoverageStatus = 'PASS'
} else {
    $script:QualityGates.CoverageStatus = 'PARTIAL'
}

$script:QualityGates.MissingSources     = if ($script:MissingSources.Count -gt 0) { ($script:MissingSources -join ', ') } else { 'None' }
$script:QualityGates.FailedSources      = if ($script:FailedSources.Count -gt 0) { ($script:FailedSources -join ', ') } else { 'None' }
$script:QualityGates.UnavailableSources = if ($script:UnavailableSources.Count -gt 0) { ($script:UnavailableSources -join ', ') } else { 'None' }
$script:QualityGates.NotTestedSources   = if ($script:NotTestedSources.Count -gt 0) { ($script:NotTestedSources -join ', ') } else { 'None' }
$script:QualityGates.DisabledSources    = if ($script:DisabledSources.Count -gt 0) { ($script:DisabledSources -join ', ') } else { 'None' }
$script:QualityGates.CriticalSources       = ($script:CriticalSources -join ', ')
$script:QualityGates.CriticalSourcesFailed = if ($criticalFailed.Count -gt 0) { ($criticalFailed -join ', ') } else { 'None' }
$script:QualityGates.CriticalSourcesDisabled = if ($criticalDisabled.Count -gt 0) { ($criticalDisabled -join ', ') } else { 'None' }


# Builds the final IOC dataset ONCE, shared by both the JSON export and the
# DuplicateIOCStatus gate so the gate validates exactly what gets written.
# Identity is IOCType + NormalizedValue. SourceFindingIds is provenance
# only - the same real-world object legitimately found by several detectors
# collapses into ONE record listing all of them, rather than N duplicate
# records. Finding.Id is deliberately NOT part of identity (including it
# made every key unique by construction, so nothing could ever be detected
# as a duplicate).
function Get-IocDataset {
    $byIdentity = [ordered]@{}
    foreach ($f in $script:AllFindings) {
        if (-not $f.IOC) { continue }
        foreach ($key in $f.IOC.Keys) {
            if (-not $f.IOC[$key]) { continue }
            $rawValue = $f.IOC[$key]
            $normalized = $null
            try { $normalized = $rawValue.ToString().Trim().ToLower() } catch { $normalized = [string]$rawValue }
            $identity = "{0}|{1}" -f $key, $normalized

            if ($byIdentity.Contains($identity)) {
                # Same IOC seen again from another finding: record the extra
                # provenance, keep the single IOC record.
                $existing = $byIdentity[$identity]
                if ($existing.SourceFindingIds -notcontains $f.Id) { $existing.SourceFindingIds += $f.Id }
                if ($existing.Categories -notcontains $f.Category) { $existing.Categories += $f.Category }
                if ($f.MitreId -and ($existing.MitreIds -notcontains $f.MitreId)) { $existing.MitreIds += $f.MitreId }
                # Keep the highest severity seen across contributing findings.
                if ($SeverityScore[$f.Severity] -gt $SeverityScore[$existing.Severity]) {
                    $existing.Severity = $f.Severity
                    $existing.Confidence = $f.Confidence
                }
                continue
            }

            $byIdentity[$identity] = [PSCustomObject]@{
                IOCType          = $key
                Value            = $rawValue
                NormalizedValue  = $normalized
                SourceFindingIds = @($f.Id)
                Categories       = @($f.Category)
                MitreIds         = if ($f.MitreId) { @($f.MitreId) } else { @() }
                Severity         = $f.Severity
                Confidence       = $f.Confidence
                SHA256           = if ($f.IOC.ContainsKey('SHA256')) { $f.IOC['SHA256'] } else { $null }
                SignatureVerdict = if ($f.IOC.ContainsKey('SignatureVerdict')) { $f.IOC['SignatureVerdict'] } else { $null }
                ProcessId        = if ($f.IOC.ContainsKey('PID_')) { $f.IOC['PID_'] } else { $null }
                ParentProcessId  = if ($f.IOC.ContainsKey('ParentPID_')) { $f.IOC['ParentPID_'] } else { $null }
                User             = if ($f.IOC.ContainsKey('User')) { $f.IOC['User'] } else { $null }
                EventId          = if ($f.IOC.ContainsKey('EventId')) { $f.IOC['EventId'] } else { $null }
                ActivityId       = if ($f.IOC.ContainsKey('ActivityId')) { $f.IOC['ActivityId'] } else { $null }
                RegistryPath     = if ($f.IOC.ContainsKey('RegistryPath')) { $f.IOC['RegistryPath'] } elseif ($f.IOC.ContainsKey('RegistryKey')) { $f.IOC['RegistryKey'] } else { $null }
                TaskPath         = if ($f.IOC.ContainsKey('TaskPath')) { $f.IOC['TaskPath'] } else { $null }
            }
        }
    }
    return @($byIdentity.Values)
}
# DuplicateFindingStatus validates the DEDUPLICATION MECHANISM, not a
# post-hoc grouping of the finished findings.
#
# Why the previous approach was architecturally wrong: Add-Finding only
# deduplicates findings that carry BOTH PID_ and Command, using
# PID + category-family + normalized Command. It deliberately does NOT
# deduplicate anything else. Re-grouping $script:AllFindings afterwards by
# "Category + MitreId + all IOC fields" therefore measured a DIFFERENT
# rule than the one the scanner actually implements, and conflated two
# unrelated situations:
#   (a) genuine duplicate candidates that Add-Finding should have merged;
#   (b) independent, legitimate findings that simply concern the same
#       object (same Path / RegistryKey / Text) and are each meant to
#       stand on their own.
# Case (b) is normal and must never fail this gate.
#
# The gate now checks the invariants the merge path is supposed to
# guarantee, using the merge events Add-Finding actually recorded:
#   1. every merged dedup key resolves to exactly ONE surviving finding;
#   2. the surviving finding kept the ORIGINAL finding Id (no renumbering);
#   3. the merge did not add a second RiskScore contribution - the post
#      merge score equals severity x confidence of the merged result, not
#      the sum of the two inputs;
#   4. severity/confidence never regressed downwards during the merge;
#   5. no duplicate dedup key survives in the final findings collection.
# If any invariant is violated the gate fails with a specific reason. If
# no merges happened at all, there is nothing to validate and the gate
# passes - that is the normal case on a clean scan, not a silent skip.
$dedupViolations = New-Object System.Collections.Generic.List[string]

foreach ($ev in $script:DuplicateMergeEvents) {
    $survivors = @($script:AllFindings | Where-Object { $_.Id -eq $ev.ExistingFindingId })

    # Invariant 1 + 2: exactly one surviving finding, under the original Id.
    if ($survivors.Count -ne 1) {
        [void]$dedupViolations.Add("Merge for key '$($ev.DedupKey)' left $($survivors.Count) findings with Id $($ev.ExistingFindingId) (expected exactly 1)")
        continue
    }
    $survivor = $survivors[0]

    # Invariant 3: no double-counted RiskScore. The merged score must equal
    # severity x confidence of the final merged values.
    $expectedScore = [math]::Round($SeverityScore[$survivor.Severity] * $ConfidenceMultiplier[$survivor.Confidence], 1)
    if ([math]::Abs($survivor.RiskScore - $expectedScore) -gt 0.05) {
        [void]$dedupViolations.Add("Merge for key '$($ev.DedupKey)' left RiskScore $($survivor.RiskScore) but severity/confidence imply $expectedScore (possible double-counting)")
    }

    # Invariant 4: severity/confidence must never have been downgraded.
    if ($SeverityScore[$ev.PostMergeSeverity] -lt $SeverityScore[$ev.PreMergeSeverity]) {
        [void]$dedupViolations.Add("Merge for key '$($ev.DedupKey)' downgraded severity from $($ev.PreMergeSeverity) to $($ev.PostMergeSeverity)")
    }
    if ($ConfidenceMultiplier[$ev.PostMergeConfidence] -lt $ConfidenceMultiplier[$ev.PreMergeConfidence]) {
        [void]$dedupViolations.Add("Merge for key '$($ev.DedupKey)' downgraded confidence from $($ev.PreMergeConfidence) to $($ev.PostMergeConfidence)")
    }

    # Invariant: a merge must not have grown the findings collection.
    if ($ev.FindingsCountAfter -gt $ev.FindingsCountBefore) {
        [void]$dedupViolations.Add("Merge for key '$($ev.DedupKey)' increased the findings count from $($ev.FindingsCountBefore) to $($ev.FindingsCountAfter)")
    }
}

# Invariant 5: no dedup key may appear on more than one surviving finding.
# This uses the SAME rule Add-Finding uses (PID + family + command), so it
# only ever flags findings that the merge path was actually responsible for.
$survivingDedupKeys = @{}
foreach ($f in $script:AllFindings) {
    $k = Get-FindingDedupKey $f
    if (-not $k) { continue }
    if ($survivingDedupKeys.ContainsKey($k)) {
        [void]$dedupViolations.Add("Dedup key '$k' survives on more than one finding (ids $($survivingDedupKeys[$k]) and $($f.Id)) - these should have been merged")
    } else {
        $survivingDedupKeys[$k] = $f.Id
    }
}

$script:QualityGates.DuplicateFindingStatus = if ($dedupViolations.Count -gt 0) { 'FAIL' } else { 'PASS' }
$script:QualityGates.DuplicateCandidateCount = $script:DuplicateMergeEvents.Count
$script:QualityGates.DuplicateMergedCount    = $script:DuplicateMergeEvents.Count
$script:QualityGates.DuplicateCandidateKeys  = if ($script:DuplicateMergeEvents.Count -gt 0) {
    ((($script:DuplicateMergeEvents | ForEach-Object { $_.DedupKey }) | Sort-Object -Unique) -join ' || ')
} else { 'None' }
$script:QualityGates.DuplicateFindingViolations = if ($dedupViolations.Count -gt 0) { ($dedupViolations -join ' || ') } else { 'None' }

# Structured diagnostics for the JSON report: the real merge events plus
# any invariant violations found above.
$script:DuplicateFindingDetails = New-Object System.Collections.Generic.List[object]
foreach ($ev in $script:DuplicateMergeEvents) {
    $survivor = $script:AllFindings | Where-Object { $_.Id -eq $ev.ExistingFindingId } | Select-Object -First 1
    [void]$script:DuplicateFindingDetails.Add([PSCustomObject]@{
        DedupKey            = $ev.DedupKey
        ExistingFindingId   = $ev.ExistingFindingId
        IncomingCategory    = $ev.IncomingCategory
        ExistingCategory    = $ev.ExistingCategory
        PID_                = $ev.PID_
        Command             = $ev.Command
        PreMergeSeverity    = $ev.PreMergeSeverity
        PostMergeSeverity   = $ev.PostMergeSeverity
        PreMergeConfidence  = $ev.PreMergeConfidence
        PostMergeConfidence = $ev.PostMergeConfidence
        PreMergeRiskScore   = $ev.PreMergeRiskScore
        PostMergeRiskScore  = $ev.PostMergeRiskScore
        SurvivorExists      = [bool]$survivor
        SurvivorCategory    = if ($survivor) { $survivor.Category } else { $null }
        SurvivorMergedFrom  = if ($survivor -and $survivor.PSObject.Properties['MergedFromCategories']) { $survivor.MergedFromCategories } else { @() }
        Timestamp           = $ev.Timestamp
    })
}
# DeduplicationStatus is computed further down, after DuplicateIOCStatus,
# so it can aggregate BOTH dedup checks rather than mirroring just this one.

# DuplicateIOCStatus validates the ACTUAL exported IOC dataset, not raw
# per-finding IOC pairs. Two fixes here:
#   1. The old code read $f.IOCType, which is not a property of a finding
#      at all (it was always $null -> 'Unknown'). The real IOC type is the
#      hashtable KEY ($k): Path, SHA256, PID_, Command, RegistryPath, etc.
#   2. The same real-world object legitimately found by several detectors
#      is ONE IOC with several provenance entries, not a duplication bug.
#      Get-IocDataset collapses those into a single record carrying
#      SourceFindingIds; this gate then checks that the emitted dataset
#      really does contain no repeated IOCType+NormalizedValue record. If
#      the collapse logic ever breaks, duplicates reappear here and the
#      gate fails for a real reason. Finding.Id is not part of identity.
$script:IocDataset = Get-IocDataset
$iocIdentitySet = New-Object System.Collections.Generic.HashSet[string]
$dupeIocFound = $false
foreach ($ioc in $script:IocDataset) {
    $identity = "{0}|{1}" -f $ioc.IOCType, $ioc.NormalizedValue
    if (-not $iocIdentitySet.Add($identity)) { $dupeIocFound = $true }
}
$script:QualityGates.DuplicateIOCStatus = if ($dupeIocFound) { 'FAIL' } else { 'PASS' }
$script:QualityGates.IocRecordCount = $script:IocDataset.Count

# DeduplicationStatus is the combined verdict of every deduplication check
# rather than an alias of the findings check alone. It fails only if a
# real duplication defect was found in either dimension.
if ($script:QualityGates.DuplicateFindingStatus -eq 'FAIL' -or $script:QualityGates.DuplicateIOCStatus -eq 'FAIL') {
    $script:QualityGates.DeduplicationStatus = 'FAIL'
} else {
    $script:QualityGates.DeduplicationStatus = 'PASS'
}

$missingFieldFindings = $script:AllFindings | Where-Object {
    -not $_.Id -or -not $_.Category -or -not $_.Text -or -not $_.Severity -or -not $_.Confidence -or ($null -eq $_.RiskScore) -or -not $_.EvidenceType
}
$script:QualityGates.RequiredFieldsStatus = if ($missingFieldFindings) { 'FAIL' } else { 'PASS' }

# SelfExclusionStatus reflects whether the MECHANISM works, not how many
# processes it happened to match. SelfExcludedProcessCount = 0 previously
# forced FAIL, which was wrong: the scanner's own PID being absent from the
# snapshot (a rare timing case) says nothing about the exclusion logic
# being broken. FAIL is now reserved for the mechanism genuinely not being
# in place.
if (-not $script:SelfExclusionImplemented) {
    $script:QualityGates.SelfExclusionStatus = 'FAIL'
} elseif (-not $script:SelfExclusionApplied) {
    # Implemented but never applied - a real failure of the mechanism.
    $script:QualityGates.SelfExclusionStatus = 'FAIL'
} elseif ($script:SelfExclusionVerification -match '^VERIFIED') {
    $script:QualityGates.SelfExclusionStatus = 'PASS'
} else {
    # Applied, but the scanner's own PID was not in the snapshot so the
    # result cannot be positively confirmed - not a failure.
    $script:QualityGates.SelfExclusionStatus = 'PARTIAL'
}

# PowerShellCompatibilityStatus: PASS is reported only when the CURRENT
# runtime matches the environment this script has actually been runtime-
# tested on - Windows PowerShell 5.1, Desktop edition. Any other runtime
# (notably PowerShell 7 / Core) reports NOT_TESTED: the code deliberately
# avoids PS 7-only syntax, but "should work" is not the same as "was run
# and verified there", and this gate must not claim the latter.
$psVer = $PSVersionTable.PSVersion
$psEdition = if ($PSVersionTable.PSObject.Properties['PSEdition']) { $PSVersionTable.PSEdition } else { 'Desktop' }
if ($psVer.Major -eq 5 -and $psVer.Minor -eq 1 -and $psEdition -eq 'Desktop') {
    $script:QualityGates.PowerShellCompatibilityStatus = 'PASS'
    $script:QualityGates.PowerShellCompatibilityNote = "Running on Windows PowerShell $psVer ($psEdition edition) - this matches the runtime this script has been end-to-end tested on."
} elseif ($psVer.Major -ge 6) {
    $script:QualityGates.PowerShellCompatibilityStatus = 'NOT_TESTED'
    $script:QualityGates.PowerShellCompatibilityNote = "Running on PowerShell $psVer ($psEdition edition). PowerShell 7/Core has NOT been runtime-validated for this script; PS 7-only syntax is avoided, but that is a static property, not a verified run."
} else {
    $script:QualityGates.PowerShellCompatibilityStatus = 'NOT_TESTED'
    $script:QualityGates.PowerShellCompatibilityNote = "Running on PowerShell $psVer ($psEdition edition), which is neither the tested Windows PowerShell 5.1 Desktop runtime nor PowerShell 7."
}

# =================================================================
# EXPORT: TEXT REPORT
# =================================================================
function Export-TextReport {
    $overallLine = "No high-confidence indicators were detected by the checks performed."
    if ($script:SeverityCounts.CRITICAL -gt 0 -or $script:SeverityCounts.HIGH -gt 0) {
        $overallLine = "One or more HIGH/CRITICAL severity indicators were found. Review the findings below."
    } elseif ($script:AllFindings.Count -gt 0) {
        $overallLine = "Only LOW/MEDIUM severity indicators were found - review at your convenience."
    }

    # Build a LOCAL output list rather than mutating $report with Insert(0,..).
    # This function is called twice (a validation pass, then the final pass
    # once all quality gates are known); mutating the shared $report would
    # duplicate the whole header block on the second call.
    $out = New-Object System.Collections.Generic.List[string]
    [void]$out.Add("SECURITY DIAGNOSTIC REPORT - $script:ScanDate")
    [void]$out.Add("Computer: $env:COMPUTERNAME | User: $env:USERNAME | Admin: $script:IsAdministrator")
    [void]$out.Add("Scanner: v$script:ScannerVersion | Script SHA256: $script:ScriptSHA256")
    [void]$out.Add("PowerShell: $script:PowerShellVersion | OS: $script:OSVersion")
    [void]$out.Add("Start: $script:StartTime | End: $script:EndTime | Duration: $($script:DurationSeconds)s")
    [void]$out.Add("Risk Score: Raw=$script:RawRiskScore Decayed=$script:DecayedRiskScore DedupAdjustment=$script:DeduplicationAdjustment Final=$script:FinalRiskScore  |  Risk Level: $script:RiskLevel")
    [void]$out.Add("Score Breakdown: Confirmed=$script:ConfirmedScore Heuristic=$script:HeuristicScore Context=$script:ContextScore  |  Invariant check: $script:RiskScoreConsistencyStatus ($script:RiskScoreConsistencyDetail)")
    [void]$out.Add("Findings: $($script:AllFindings.Count) total (CRITICAL: $($script:SeverityCounts.CRITICAL), HIGH: $($script:SeverityCounts.HIGH), MEDIUM: $($script:SeverityCounts.MEDIUM), LOW: $($script:SeverityCounts.LOW))")
    [void]$out.Add("Coverage: Processes=$($script:ScanCoverage.ProcessesChecked) Services=$($script:ScanCoverage.ServicesChecked) Drivers=$($script:ScanCoverage.DriversChecked) ScheduledTasks=$($script:ScanCoverage.ScheduledTasksChecked) RegistryKeys=$($script:ScanCoverage.RegistryKeysChecked) NetworkConnections=$($script:ScanCoverage.NetworkConnectionsChecked) WmiSubscriptions=$($script:ScanCoverage.WmiSubscriptionsChecked) BrowserExtensions=$($script:ScanCoverage.BrowserExtensionsChecked) FilesChecked=$($script:ScanCoverage.FilesChecked) DirectoriesChecked=$($script:ScanCoverage.DirectoriesChecked) DirectoriesTruncated=$($script:ScanCoverage.DirectoriesTruncated) SignatureChecks=$($script:ScanCoverage.SignatureChecksPerformed) SignatureUnavailable=$($script:ScanCoverage.SignatureUnavailable)")
    if ($script:SourceStatus) {
        $srcParts = @()
        foreach ($srcName in ($script:SourceStatus.Keys | Sort-Object)) { $srcParts += "$srcName=$($script:SourceStatus[$srcName])" }
        [void]$out.Add("Source status (was the source successfully QUERIED - independent of how many objects it returned): " + ($srcParts -join ' '))
    }
    if ($script:CriticalSources) {
        [void]$out.Add("CriticalSources: " + ($script:CriticalSources -join ', '))
        $cfDisplay = if ($script:QualityGates -and $script:QualityGates.CriticalSourcesFailed) { $script:QualityGates.CriticalSourcesFailed } else { 'None' }
        [void]$out.Add("CriticalSourcesFailed: $cfDisplay")
        $cdDisplay = if ($script:QualityGates -and $script:QualityGates.CriticalSourcesDisabled) { $script:QualityGates.CriticalSourcesDisabled } else { 'None' }
        [void]$out.Add("CriticalSourcesDisabled: $cdDisplay (not a failure, but caps CoverageStatus at PARTIAL)")
    }
    $realErrCount = @($script:ScanErrors | Where-Object { $_.Code -in $script:RealScanErrorCodes }).Count
    $infoErrCount = @($script:ScanErrors | Where-Object { $_.Code -in $script:InformationalScanErrorCodes }).Count
    [void]$out.Add("ScanErrors: $($script:ScanErrors.Count) event(s) recorded during the scan (see JSON report for full detail - Component/Message/Code/Severity/Timestamp each)")
    [void]$out.Add("  RealScanErrors: $realErrCount (ERROR / PERMISSION_DENIED / PARSE_ERROR - actual scan failures)")
    [void]$out.Add("  InformationalScanErrors: $infoErrCount (UNAVAILABLE / PARSE_WARNING / UNSUPPORTED_SOURCE / TRUNCATED_BY_LIMIT - reported for transparency, NOT scan failures)")
    [void]$out.Add($overallLine)
    [void]$out.Add("This is a diagnostic scanner, not an antivirus/EDR. See the header comment in the .ps1 file for limitations.")
    [void]$out.Add("")

    foreach ($line in $report) { [void]$out.Add($line) }

    # Quality gates section is written INSIDE this function so the final
    # export contains the finalized values, instead of being appended to the
    # file afterwards (which would be lost on a re-export).
    [void]$out.Add("`n" + ("=" * 70))
    $overallGate = if ($script:OverallQualityStatus) { $script:OverallQualityStatus } else { 'NOT_YET_CALCULATED' }
    [void]$out.Add("QUALITY GATES - Overall: $overallGate")
    [void]$out.Add("=" * 70)
    if ($script:QualityGates) {
        foreach ($gate in ($script:QualityGates.Keys | Sort-Object)) {
            [void]$out.Add("$gate = $($script:QualityGates[$gate])")
        }
    }
    [void]$out.Add("")
    [void]$out.Add("Scanner self-identification: PID=$script:ScannerPid Path=$script:ScannerPath Hash=$script:ScannerHash")
    [void]$out.Add("Self-exclusion: implemented=$script:SelfExclusionImplemented applied=$script:SelfExclusionApplied count=$script:SelfExcludedProcessCount verification=$script:SelfExclusionVerification")

    if ($script:DuplicateFindingDetails -and $script:DuplicateFindingDetails.Count -gt 0) {
        [void]$out.Add("")
        [void]$out.Add("=" * 70)
        [void]$out.Add("DEDUPLICATION MERGE EVENTS ($($script:DuplicateFindingDetails.Count) merge(s) performed by Add-Finding)")
        [void]$out.Add("=" * 70)
        [void]$out.Add("Note: merges are NORMAL - they mean the dedup mechanism worked. DuplicateFindingStatus")
        [void]$out.Add("fails only if a merge violated an invariant; see DuplicateFindingViolations.")
        foreach ($dup in $script:DuplicateFindingDetails) {
            [void]$out.Add("Key: $($dup.DedupKey)")
            [void]$out.Add("  SurvivingFindingId: $($dup.ExistingFindingId)  SurvivorExists: $($dup.SurvivorExists)")
            [void]$out.Add("  IncomingCategory: $($dup.IncomingCategory)  ExistingCategory: $($dup.ExistingCategory)  SurvivorCategory: $($dup.SurvivorCategory)")
            [void]$out.Add("  MergedFromCategories: $($dup.SurvivorMergedFrom -join ', ')")
            [void]$out.Add("  PID: $($dup.PID_)")
            [void]$out.Add("  Command: $($dup.Command)")
            [void]$out.Add("  Severity: $($dup.PreMergeSeverity) -> $($dup.PostMergeSeverity)   Confidence: $($dup.PreMergeConfidence) -> $($dup.PostMergeConfidence)")
            [void]$out.Add("  RiskScore: $($dup.PreMergeRiskScore) -> $($dup.PostMergeRiskScore)")
            [void]$out.Add("")
        }
        [void]$out.Add("DuplicateFindingViolations: $($script:QualityGates.DuplicateFindingViolations)")
    }

    $out | Out-File -FilePath $reportPath -Encoding UTF8
}

# =================================================================
# EXPORT: JSON REPORT + IOC FILE
# =================================================================
function Export-JsonReport {
    $findingsForJson = $script:AllFindings | ForEach-Object {
        [PSCustomObject]@{
            Id             = $_.Id
            Category       = $_.Category
            Text           = $_.Text
            Severity       = $_.Severity
            Confidence     = $_.Confidence
            RiskScore      = $_.RiskScore
            MitreId        = $_.MitreId
            MitreName      = $_.MitreName
            MitreConfidence = $_.MitreConfidence
            Recommendation = $_.Recommendation
            IOC            = $_.IOC
            Timestamp      = $_.Timestamp
        }
    }
    $summary = [PSCustomObject]@{
        SchemaVersion     = "1.0"
        ScanDate          = $script:ScanDate.ToString('s')
        Computer          = $env:COMPUTERNAME
        User              = $env:USERNAME
        ScannerVersion    = $script:ScannerVersion
        ScriptSHA256      = $script:ScriptSHA256
        PowerShellVersion = $script:PowerShellVersion
        OSVersion         = $script:OSVersion
        IsAdministrator   = $script:IsAdministrator
        StartTime         = $script:StartTime.ToString('s')
        EndTime           = $script:EndTime.ToString('s')
        DurationSeconds   = $script:DurationSeconds
        TotalFindings     = $script:AllFindings.Count
        RiskScore         = @{
            RawRiskScore             = $script:RawRiskScore
            DecayedRiskScore         = $script:DecayedRiskScore
            DeduplicationAdjustment  = $script:DeduplicationAdjustment
            FinalRiskScore           = $script:FinalRiskScore
            ConfirmedScore           = $script:ConfirmedScore
            HeuristicScore           = $script:HeuristicScore
            ContextScore             = $script:ContextScore
            ConsistencyStatus        = $script:RiskScoreConsistencyStatus
            ConsistencyDetail        = $script:RiskScoreConsistencyDetail
        }
        RiskLevel         = $script:RiskLevel
        SeverityCounts    = $script:SeverityCounts
        MitreTechniques   = $script:MitreSummary
        Coverage          = $script:ScanCoverage
        SourceStatus      = $script:SourceStatus
        ScanErrors        = $script:ScanErrors
        ScanErrorSummary  = @{
            TotalEvents             = $script:ScanErrors.Count
            RealScanErrors          = @($script:ScanErrors | Where-Object { $_.Code -in $script:RealScanErrorCodes }).Count
            InformationalScanErrors = @($script:ScanErrors | Where-Object { $_.Code -in $script:InformationalScanErrorCodes }).Count
            RealScanErrorCodes          = $script:RealScanErrorCodes
            InformationalScanErrorCodes = $script:InformationalScanErrorCodes
        }
        QualityGates      = $script:QualityGates
        OverallQualityStatus = $script:OverallQualityStatus
        DuplicateFindingDiagnostics = @{
            DuplicateFindingCount = if ($script:DuplicateFindingDetails) { $script:DuplicateFindingDetails.Count } else { 0 }
            Duplicates            = $script:DuplicateFindingDetails
        }
        SelfExclusion     = @{
            ScannerPid               = $script:ScannerPid
            ScannerPath              = $script:ScannerPath
            ScannerHash              = $script:ScannerHash
            ScannerCommandLine       = $script:ScannerCommandLine
            SelfExclusionImplemented  = $script:SelfExclusionImplemented
            SelfExclusionApplied     = $script:SelfExclusionApplied
            SelfExclusionVerification = $script:SelfExclusionVerification
            SelfExcludedProcessCount = $script:SelfExcludedProcessCount
        }
    }
    $fullReport = [PSCustomObject]@{ Summary = $summary; Findings = $findingsForJson }
    $fullReport | ConvertTo-Json -Depth 6 | Out-File -FilePath $script:jsonReportPath -Encoding UTF8

    # The IOC dataset is built by the same Get-IocDataset used by the
    # DuplicateIOCStatus gate, so the gate validates exactly what is
    # written here. Records are deduplicated by IOCType + NormalizedValue;
    # an IOC found by several detectors appears ONCE with all contributing
    # finding ids in SourceFindingIds (provenance), instead of N identical
    # records.
    $iocList = Get-IocDataset
    $iocList | ConvertTo-Json -Depth 4 | Out-File -FilePath $script:iocReportPath -Encoding UTF8
}

# =================================================================
# EXPORT: HTML DASHBOARD
# =================================================================
function Export-HtmlReport {
    $riskColors = @{ MINIMAL = '#2ea043'; LOW = '#2ea043'; MEDIUM = '#d29922'; HIGH = '#db6d28'; CRITICAL = '#da3633' }
    $statusColor = $riskColors[$script:RiskLevel]

    $sevBadgeColor = @{ CRITICAL = '#da3633'; HIGH = '#db6d28'; MEDIUM = '#d29922'; LOW = '#388bfd'; INFO = '#6e7681' }

    # --- Findings cards, sorted by risk score ---
    $findingsHtml = New-Object System.Text.StringBuilder
    foreach ($f in ($script:AllFindings | Sort-Object RiskScore -Descending)) {
        $badgeColor = $sevBadgeColor[$f.Severity]
        [void]$findingsHtml.AppendLine("<div class='finding-card' style='border-left-color:$badgeColor'>")
        [void]$findingsHtml.AppendLine("<div class='finding-top'>")
        [void]$findingsHtml.AppendLine("<span class='sev-badge' style='background:$badgeColor'>$($f.Severity)</span>")
        [void]$findingsHtml.AppendLine("<span class='conf-badge'>Confidence: $($f.Confidence)</span>")
        [void]$findingsHtml.AppendLine("<span class='score-badge'>Risk: $($f.RiskScore)</span>")
        [void]$findingsHtml.AppendLine("<span class='cat-badge'>$(HtmlEscape $f.Category)</span>")
        [void]$findingsHtml.AppendLine("</div>")
        [void]$findingsHtml.AppendLine("<div class='finding-text'>$(HtmlEscape $f.Text)</div>")
        if ($f.MitreId) {
            $heuristicNote = if ($f.MitreConfidence -eq 'HEURISTIC') { " <span class='mitre-heuristic'>(heuristic mapping)</span>" } else { "" }
            [void]$findingsHtml.AppendLine("<div class='finding-mitre'>MITRE ATT&amp;CK: $(HtmlEscape $f.MitreId) - $(HtmlEscape $f.MitreName)$heuristicNote</div>")
        }
        if ($f.Recommendation) {
            [void]$findingsHtml.AppendLine("<div class='finding-reco'>Recommended action: $(HtmlEscape $f.Recommendation)</div>")
        }
        [void]$findingsHtml.AppendLine("</div>")
    }
    if ($script:AllFindings.Count -eq 0) {
        [void]$findingsHtml.AppendLine("<p class='muted'>No high-confidence indicators were detected by the checks performed.</p>")
    }

    # --- MITRE technique summary table ---
    $mitreHtml = New-Object System.Text.StringBuilder
    foreach ($m in $script:MitreSummary) {
        [void]$mitreHtml.AppendLine("<tr><td>$(HtmlEscape $m.MitreId)</td><td>$(HtmlEscape $m.MitreName)</td><td>$($m.Count)</td></tr>")
    }
    if ($script:MitreSummary.Count -eq 0) {
        [void]$mitreHtml.AppendLine("<tr><td colspan='3' class='muted'>No MITRE techniques matched.</td></tr>")
    }

    # --- Top 5 findings / Top IOCs ---
    $top5Html = New-Object System.Text.StringBuilder
    foreach ($t in $script:TopFindings) {
        [void]$top5Html.AppendLine("<li><strong>[$($t.Severity)/$($t.RiskScore)]</strong> $(HtmlEscape $t.Text)</li>")
    }
    if ($script:TopFindings.Count -eq 0) { [void]$top5Html.AppendLine("<li class='muted'>No findings recorded.</li>") }

    $iocHtml = New-Object System.Text.StringBuilder
    foreach ($ioc in $script:TopIOCs) {
        [void]$iocHtml.AppendLine("<tr><td>$(HtmlEscape $ioc.Type)</td><td>$(HtmlEscape $ioc.Value)</td><td>$(HtmlEscape $ioc.Severity)</td></tr>")
    }
    if ($script:TopIOCs.Count -eq 0) { [void]$iocHtml.AppendLine("<tr><td colspan='3' class='muted'>No IOCs recorded.</td></tr>") }

    $scanErrorsHtml = New-Object System.Text.StringBuilder
    foreach ($se in $script:ScanErrors) {
        [void]$scanErrorsHtml.AppendLine("<tr><td>$(HtmlEscape $se.Component)</td><td>$(HtmlEscape $se.Message)</td><td>$(HtmlEscape $se.Code)</td><td>$(HtmlEscape $se.Severity)</td><td>$(HtmlEscape $se.Timestamp)</td></tr>")
    }
    if ($script:ScanErrors.Count -eq 0) { [void]$scanErrorsHtml.AppendLine("<tr><td colspan='5' class='muted'>No scan errors recorded.</td></tr>") }

    # --- Quality gates table, built automatically from the existing
    # $script:QualityGates object so any gate added later shows up here
    # without a second hand-maintained list. Both the gate name and its
    # value go through HtmlEscape.
    $qualityGatesHtml = New-Object System.Text.StringBuilder
    if ($script:QualityGates) {
        foreach ($gateName in ($script:QualityGates.Keys | Sort-Object)) {
            $gateValue = $script:QualityGates[$gateName]
            $gateColor = switch ($gateValue) {
                'PASS'       { '#3fb950' }
                'FAIL'       { '#f85149' }
                'PARTIAL'    { '#d29922' }
                'NOT_TESTED' { '#8b949e' }
                default      { '#c9d1d9' }
            }
            [void]$qualityGatesHtml.AppendLine("<tr><td>$(HtmlEscape $gateName)</td><td style='color:$gateColor'>$(HtmlEscape $gateValue)</td></tr>")
        }
    } else {
        [void]$qualityGatesHtml.AppendLine("<tr><td colspan='2' class='muted'>No quality gates recorded.</td></tr>")
    }

    # --- Full narrative log, collapsible (same delimiter-based parser as before) ---
    $delimiterPattern = '^\n?={20,}$'
    $logHtml = New-Object System.Text.StringBuilder
    $i = 0
    $n = $report.Count
    while ($i -lt $n) {
        if ($report[$i] -match $delimiterPattern) {
            $title = $report[$i + 1]
            $i += 3
            $bodyLines = New-Object System.Collections.Generic.List[string]
            while ($i -lt $n -and $report[$i] -notmatch $delimiterPattern) {
                $bodyLines.Add($report[$i]); $i++
            }
            $secFlags = ($bodyLines | Where-Object { $_ -match '^\s*\[!\]' }).Count
            $secWarns = ($bodyLines | Where-Object { $_ -match '^\s*\[\?\]' }).Count
            $badge = "<span class='badge badge-ok'>OK</span>"
            if ($secFlags -gt 0) { $badge = "<span class='badge badge-flag'>$secFlags</span>" }
            elseif ($secWarns -gt 0) { $badge = "<span class='badge badge-warn'>$secWarns</span>" }
            [void]$logHtml.AppendLine("<details class='section'>")
            [void]$logHtml.AppendLine("<summary>$(HtmlEscape $title) $badge</summary>")
            [void]$logHtml.AppendLine("<div class='section-body'>")
            foreach ($bl in $bodyLines) {
                if ([string]::IsNullOrWhiteSpace($bl)) { [void]$logHtml.AppendLine("<div class='spacer'></div>"); continue }
                $cls = 'line'
                if ($bl -match '^\s*\[!\]') { $cls = 'line flag' }
                elseif ($bl -match '^\s*\[\?\]') { $cls = 'line warn' }
                elseif ($bl.TrimStart().StartsWith('Note:') -or $bl.TrimStart().StartsWith('MITRE') -or $bl.TrimStart().StartsWith('Recommended')) { $cls = 'line note' }
                [void]$logHtml.AppendLine("<div class='$cls'>$(HtmlEscape $bl)</div>")
            }
            [void]$logHtml.AppendLine("</div></details>")
        } else { $i++ }
    }

    $overallLine = "No high-confidence indicators were detected by the checks performed."
    if ($script:SeverityCounts.CRITICAL -gt 0 -or $script:SeverityCounts.HIGH -gt 0) {
        $overallLine = "One or more HIGH/CRITICAL severity indicators were found. Review the findings below before deciding this system is safe."
    } elseif ($script:AllFindings.Count -gt 0) {
        $overallLine = "Only LOW/MEDIUM severity indicators were found - review at your convenience."
    }

    $htmlHead = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Diagnostic Report - $(HtmlEscape $env:COMPUTERNAME)</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 16px; font-size: 14px; }
  h2 { font-size: 15px; color: #f0f6fc; margin: 20px 0 8px 0; }
  .header { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .header h1 { margin: 0 0 8px 0; font-size: 18px; color: #f0f6fc; }
  .header .meta { color: #8b949e; font-size: 13px; margin-bottom: 12px; }
  .status-pill { display: inline-block; padding: 6px 14px; border-radius: 20px; font-weight: 600; color: #0d1117; background: $statusColor; margin-right: 8px; }
  .overall-line { margin-top: 10px; color: #f0f6fc; font-size: 13px; }
  .counts { display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
  .count-chip { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 4px 10px; font-size: 12px; }
  .limitations { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; font-size: 12.5px; color: #8b949e; }
  .finding-card { background: #161b22; border: 1px solid #30363d; border-left: 4px solid #888; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; }
  .finding-top { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 6px; }
  .sev-badge, .conf-badge, .score-badge, .cat-badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: 700; color: white; }
  .conf-badge, .score-badge, .cat-badge { background: #30363d; color: #c9d1d9; font-weight: 500; }
  .finding-text { font-size: 13px; color: #f0f6fc; margin-bottom: 4px; }
  .finding-mitre { font-size: 12px; color: #a5a5f0; margin-bottom: 2px; }
  .mitre-heuristic { color: #d29922; font-style: italic; }
  .finding-reco { font-size: 12px; color: #8b949e; font-style: italic; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 12.5px; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: 600; }
  .muted { color: #6e7681; font-style: italic; }
  details.section { background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
  summary { padding: 10px 14px; cursor: pointer; font-weight: 600; color: #f0f6fc; list-style: none; display: flex; justify-content: space-between; align-items: center; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: '\25B8 '; color: #8b949e; }
  details[open] summary::before { content: '\25BE '; }
  .section-body { padding: 4px 14px 12px 14px; border-top: 1px solid #30363d; }
  .line { padding: 2px 0; font-family: Consolas, Menlo, monospace; font-size: 12.5px; white-space: pre-wrap; word-break: break-all; color: #c9d1d9; }
  .line.flag { color: #ff7b72; font-weight: 600; }
  .line.warn { color: #d29922; }
  .line.note { color: #8b949e; font-style: italic; }
  .spacer { height: 6px; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: 700; }
  .badge-flag { background: #da3633; color: white; }
  .badge-warn { background: #9e6a03; color: white; }
  .badge-ok { background: #238636; color: white; }
  ol, ul { font-size: 13px; }
  a { color: #58a6ff; }
</style>
</head>
<body>
<div class="header">
  <h1>Security Diagnostic Report</h1>
  <div class="meta">Computer: $(HtmlEscape $env:COMPUTERNAME) &nbsp;|&nbsp; User: $(HtmlEscape $env:USERNAME) &nbsp;|&nbsp; $script:ScanDate</div>
  <div class="meta">Scanner v$(HtmlEscape $script:ScannerVersion) &nbsp;|&nbsp; PowerShell $(HtmlEscape $script:PowerShellVersion) &nbsp;|&nbsp; $(HtmlEscape $script:OSVersion) &nbsp;|&nbsp; Admin: $script:IsAdministrator &nbsp;|&nbsp; Duration: $($script:DurationSeconds)s</div>
  <div class="meta">Script SHA256: $(HtmlEscape $script:ScriptSHA256)</div>
  <span class="status-pill">Risk Level: $script:RiskLevel</span>
  <span class="status-pill" style="background:#30363d;color:#c9d1d9">Risk Score: $script:TotalRiskScore</span>
  <div class="meta">Raw: $script:RawRiskScore &nbsp;|&nbsp; Decayed: $script:DecayedRiskScore &nbsp;|&nbsp; Dedup adjustment: $script:DeduplicationAdjustment &nbsp;|&nbsp; Final: $script:FinalRiskScore</div>
  <div class="meta">Breakdown - Confirmed: $script:ConfirmedScore &nbsp;|&nbsp; Heuristic: $script:HeuristicScore &nbsp;|&nbsp; Context-only: $script:ContextScore &nbsp;|&nbsp; Invariant: <span style="color:$(if ($script:RiskScoreConsistencyStatus -eq 'PASS') { '#3fb950' } else { '#f85149' })">$script:RiskScoreConsistencyStatus</span></div>
  <div class="overall-line">$(HtmlEscape $overallLine)</div>
  <div class="counts">
    <span class="count-chip">CRITICAL: $($script:SeverityCounts.CRITICAL)</span>
    <span class="count-chip">HIGH: $($script:SeverityCounts.HIGH)</span>
    <span class="count-chip">MEDIUM: $($script:SeverityCounts.MEDIUM)</span>
    <span class="count-chip">LOW: $($script:SeverityCounts.LOW)</span>
    <span class="count-chip">Total findings: $($script:AllFindings.Count)</span>
  </div>
  <div class="counts">
    <span class="count-chip">Processes: $($script:ScanCoverage.ProcessesChecked)</span>
    <span class="count-chip">Services: $($script:ScanCoverage.ServicesChecked)</span>
    <span class="count-chip">Drivers: $($script:ScanCoverage.DriversChecked)</span>
    <span class="count-chip">Scheduled tasks: $($script:ScanCoverage.ScheduledTasksChecked)</span>
    <span class="count-chip">Registry keys: $($script:ScanCoverage.RegistryKeysChecked)</span>
    <span class="count-chip">Network connections: $($script:ScanCoverage.NetworkConnectionsChecked)</span>
    <span class="count-chip">WMI subscriptions: $($script:ScanCoverage.WmiSubscriptionsChecked)</span>
    <span class="count-chip">Browser extensions: $($script:ScanCoverage.BrowserExtensionsChecked)</span>
    <span class="count-chip">Files checked: $($script:ScanCoverage.FilesChecked)</span>
    <span class="count-chip">Directories truncated by limit: $($script:ScanCoverage.DirectoriesTruncated)</span>
    <span class="count-chip">Signature checks: $($script:ScanCoverage.SignatureChecksPerformed)</span>
    <span class="count-chip">Signature unavailable: $($script:ScanCoverage.SignatureUnavailable)</span>
    <span class="count-chip" style="background:$(if (@($script:ScanErrors | Where-Object { $_.Code -in $script:RealScanErrorCodes }).Count -gt 0) { '#9e6a03' } else { '#21262d' })">Real scan errors: $(@($script:ScanErrors | Where-Object { $_.Code -in $script:RealScanErrorCodes }).Count)</span>
    <span class="count-chip">Informational events: $(@($script:ScanErrors | Where-Object { $_.Code -in $script:InformationalScanErrorCodes }).Count)</span>
  </div>
  <div class="meta">Source status (successfully queried, independent of object count): $(HtmlEscape (($script:SourceStatus.Keys | Sort-Object | ForEach-Object { "$_=$($script:SourceStatus[$_])" }) -join '  |  '))</div>
  <div class="meta">Overall quality gate: $(HtmlEscape $script:OverallQualityStatus)</div>
  <div style="display:none"></div>
</div>
<div class="limitations">
  This is a diagnostic scanner, not an antivirus/EDR. Findings are leads to investigate, not verdicts. See the .ps1 file header for full limitations (event-log audit policies, DLL search-order hijacking, per-process integrity level, and more).
</div>

<h2>Top 5 Findings</h2>
<ul>
$($top5Html.ToString())
</ul>

<h2>Recommended Next Steps</h2>
<ol>
  <li>Review every CRITICAL and HIGH finding above manually before concluding anything.</li>
  <li>For unfamiliar files, check the SHA256 hash on virustotal.com.</li>
  <li>Run a full offline scan with Windows Defender or a second-opinion scanner (Malwarebytes) regardless of this report's result.</li>
  <li>If ransomware indicators appear, disconnect from the network immediately and avoid interacting with any ransom note.</li>
  <li>Findings with MEDIUM/LOW severity and LOW confidence are common false positives - use judgment and context, not this report alone.</li>
</ol>

<h2>MITRE ATT&amp;CK Techniques Observed</h2>
<table>
<tr><th>Technique ID</th><th>Name</th><th>Findings</th></tr>
$($mitreHtml.ToString())
</table>

<h2>Top Indicators of Compromise (IOCs)</h2>
<table>
<tr><th>Type</th><th>Value</th><th>Severity</th></tr>
$($iocHtml.ToString())
</table>

<h2>Quality Gates - Overall: $(HtmlEscape $script:OverallQualityStatus)</h2>
<table>
<tr><th>Gate</th><th>Status</th></tr>
$($qualityGatesHtml.ToString())
</table>

<h2>Scan Events and Errors</h2>
<table>
<tr><th>Component</th><th>Message</th><th>Code</th><th>Severity</th><th>Timestamp</th></tr>
$($scanErrorsHtml.ToString())
</table>

<h2>All Findings (sorted by risk score)</h2>
$($findingsHtml.ToString())

<h2>Full Diagnostic Log</h2>
$($logHtml.ToString())

</body>
</html>
"@

    $htmlHead | Out-File -FilePath $htmlReportPath -Encoding UTF8
}

# =================================================================
# VALIDATION EXPORT PASS - writes the reports once so the file-dependent
# quality gates below have something real to inspect. These files are then
# OVERWRITTEN by the final export pass at the end; this is deliberately a
# fixed two-pass sequence (export -> validate -> export), never a loop.
# =================================================================
Export-TextReport
Export-JsonReport
Export-HtmlReport

# =================================================================
# FILE-DEPENDENT QUALITY GATES - these can only be evaluated against files
# that already exist on disk, which is why they run after the validation
# export rather than before it.
# =================================================================
try {
    Get-Content -LiteralPath $jsonReportPath -Raw | ConvertFrom-Json -ErrorAction Stop | Out-Null
    $script:QualityGates.JsonRoundTripStatus = 'PASS'
} catch { $script:QualityGates.JsonRoundTripStatus = 'FAIL' }
try {
    Get-Content -LiteralPath $iocReportPath -Raw | ConvertFrom-Json -ErrorAction Stop | Out-Null
    $script:QualityGates.IocJsonStatus = 'PASS'
} catch { $script:QualityGates.IocJsonStatus = 'FAIL' }

try {
    $htmlContent = Get-Content -LiteralPath $htmlReportPath -Raw -ErrorAction Stop
    $script:QualityGates.HtmlStructureStatus = if ($htmlContent -match '<html' -and $htmlContent -match '</html>' -and $htmlContent.Length -gt 500) { 'PASS' } else { 'PARTIAL' }
} catch { $script:QualityGates.HtmlStructureStatus = 'FAIL'; $htmlContent = '' }

try {
    $unescapedFound = $false
    foreach ($f in $script:AllFindings) {
        if ($f.Text -match '[<>&]' -and $htmlContent.Contains($f.Text)) { $unescapedFound = $true; break }
    }
    $script:QualityGates.HtmlEscapingStatus = if ($unescapedFound) { 'FAIL' } else { 'PASS' }
} catch { $script:QualityGates.HtmlEscapingStatus = 'NOT_TESTED' }

# SourceStatus summarised into a gate. DISABLED is explicitly NOT a
# downgrade - the user chose to switch that module off. UNAVAILABLE (e.g.
# Defender absent because a third-party AV is installed) is a warning.
# A failed CRITICAL source is a real FAIL.
if ($criticalFailed.Count -gt 0) {
    $script:QualityGates.SourceStatusGate = 'FAIL'
} elseif ($script:FailedSources.Count -gt 0 -or $script:NotTestedSources.Count -gt 0 -or $script:UnavailableSources.Count -gt 0) {
    $script:QualityGates.SourceStatusGate = 'PARTIAL'
} else {
    $script:QualityGates.SourceStatusGate = 'PASS'
}
$srcSummary = @()
foreach ($srcName in ($script:SourceStatus.Keys | Sort-Object)) { $srcSummary += "$srcName=$($script:SourceStatus[$srcName])" }
$script:QualityGates.SourceStatusDetail = ($srcSummary -join ' ')

# Aggregate status: FAIL wins over everything; NOT_TESTED/PARTIAL downgrade
# an otherwise-clean run to PASS_WITH_WARNINGS rather than hiding them.
# CoverageStatus = FAIL is checked explicitly as well as via $statusValues,
# so a failed critical source can never be softened into PASS_WITH_WARNINGS
# by an indirect lookup.
$statusValues = $script:QualityGates.Values | Where-Object { $_ -in @('PASS', 'FAIL', 'PARTIAL', 'NOT_TESTED') }
if ($script:QualityGates.CoverageStatus -eq 'FAIL' -or $statusValues -contains 'FAIL') { $script:OverallQualityStatus = 'FAIL' }
elseif ($statusValues -contains 'PARTIAL' -or $statusValues -contains 'NOT_TESTED') { $script:OverallQualityStatus = 'PASS_WITH_WARNINGS' }
else { $script:OverallQualityStatus = 'PASS' }

# =================================================================
# FINAL EXPORT PASS - re-runs all three exporters so the files on disk
# contain the FINALIZED quality gates (including the file-dependent ones
# and OverallQualityStatus). Each exporter writes with Out-File (no
# -Append), so this overwrites rather than appending a second report.
# Export-TextReport builds a local list instead of mutating $report, so
# running it twice does not duplicate the header block.
# =================================================================
Export-TextReport
Export-JsonReport
Export-HtmlReport

Write-Host "`nDone!" -ForegroundColor Green
Write-Host "Text report: $reportPath" -ForegroundColor Green
Write-Host "HTML dashboard: $htmlReportPath (open this one first)" -ForegroundColor Green
Write-Host "JSON report: $jsonReportPath" -ForegroundColor Green
Write-Host "IOC JSON (for SIEM/Wazuh/ELK): $iocReportPath" -ForegroundColor Green
Write-Host "`nQuality Gates (overall: $script:OverallQualityStatus):" -ForegroundColor Cyan
foreach ($gate in $script:QualityGates.Keys) {
    $color = switch ($script:QualityGates[$gate]) { 'PASS' { 'Green' }; 'FAIL' { 'Red' }; 'PARTIAL' { 'Yellow' }; default { 'Gray' } }
    Write-Host ("  {0} = {1}" -f $gate, $script:QualityGates[$gate]) -ForegroundColor $color
}
Write-Host "`nOverall Risk Score: $script:TotalRiskScore  |  Risk Level: $script:RiskLevel" -ForegroundColor $(if ($script:RiskLevel -eq 'CRITICAL' -or $script:RiskLevel -eq 'HIGH') { 'Red' } elseif ($script:RiskLevel -eq 'MEDIUM') { 'Yellow' } else { 'Green' })
Write-Host ("Findings: {0} total (CRITICAL: {1}, HIGH: {2}, MEDIUM: {3}, LOW: {4})" -f $script:AllFindings.Count, $script:SeverityCounts.CRITICAL, $script:SeverityCounts.HIGH, $script:SeverityCounts.MEDIUM, $script:SeverityCounts.LOW) -ForegroundColor Yellow
Write-Host "This is a diagnostic scanner, not an antivirus - review findings manually and check unfamiliar hashes at virustotal.com." -ForegroundColor Yellow

# =================================================================
# EXIT CODES - all reports are already written above; this only sets
# $LASTEXITCODE for automation/CI callers, it does not stop mid-scan.
#   0 = scan completed, no high-risk findings
#   1 = scan completed, findings require review
#   2 = scan completed with REAL errors or genuinely incomplete coverage
#   3 = reserved for a scanner execution failure - not set by this normal
#       completion path; a genuinely fatal error would prevent reaching
#       this line at all rather than being caught and coded here, since
#       this version does not wrap the whole script in a single top-level
#       try/catch (a real architectural change, not attempted here)
# =================================================================
$exitCode = 0

# Not every entry in $script:ScanErrors is a scanner failure. UNAVAILABLE
# means a data source simply is not present on this system (e.g. Defender
# absent because a third-party AV is installed) - that belongs in the
# report, but it is not the scanner erroring out. Only ERROR,
# PERMISSION_DENIED and PARSE_ERROR represent something that actually went
# wrong during the scan.
$realScanErrors = @($script:ScanErrors | Where-Object { $_.Code -in $script:RealScanErrorCodes })

# The same distinction applies to coverage. CoverageStatus = PARTIAL can be
# caused purely by an UNAVAILABLE source (again: third-party AV), which is
# not an incomplete SCAN - so PARTIAL alone is not enough for exit 2.
# FailedSources and NotTestedSources exclude DISABLED and UNAVAILABLE by
# construction, so they identify genuinely missing coverage.
$coverageIncomplete = ($script:QualityGates.CoverageStatus -eq 'FAIL') -or
                      ($script:FailedSources.Count -gt 0) -or
                      ($script:NotTestedSources.Count -gt 0)

if ($realScanErrors.Count -gt 0 -or $coverageIncomplete -or $script:OverallQualityStatus -eq 'FAIL') {
    $exitCode = 2
} elseif ($script:AllFindings.Count -gt 0) {
    $exitCode = 1
}

Write-Host ("Exit reason: realScanErrors={0} (of {1} total entries) coverageIncomplete={2} overallQuality={3} findings={4}" -f `
    $realScanErrors.Count, $script:ScanErrors.Count, $coverageIncomplete, $script:OverallQualityStatus, $script:AllFindings.Count) -ForegroundColor Gray
Write-Host "`nExit code: $exitCode" -ForegroundColor Gray
exit $exitCode
