# Forensic Investigation Methodology

## 1. Overview
This investigation follows the standardized forensic lifecycle defined in **NIST SP 800-86**:
1. **Collection / Acquisition**: Identification and preservation of digital evidence.
2. **Examination**: Processing evidence while preserving integrity.
3. **Analysis**: Interpreting findings, reconstructing timelines, and assessing attack chains.
4. **Reporting**: Presenting verified findings, limitations, and actionable remediation guidance.

## 2. Evidence Integrity & Chain of Custody
- Original evidence files are stored in `evidence/originals/` and marked read-only.
- Prior to analysis, cryptographic hashes (SHA-256) are calculated via `scripts/calculate_hashes.py` and logged in `evidence/manifest.csv`.
- If an official reference hash is provided by the evidence author, it is validated against the computed hash.
- Analysis is executed non-destructively; original memory dumps and disk images are never modified.

## 3. Memory Analysis Methodology (Volatility 3)
Memory analysis follows a structured triage sequence:
1. **OS Identification & Profile Resolution**:
   - Execute `windows.info` to identify kernel base, OS build, processor architecture, and symbol profile requirements.
2. **Process Hierarchy & Anomaly Detection**:
   - `windows.pslist`: Enumerate active EPROCESS blocks.
   - `windows.pstree`: Inspect parent-child relationships for illegitimate ancestry (e.g. `cmd.exe` spawned by `spoolsv.exe`, unexpected office application children).
   - `windows.cmdline`: Extract command-line parameters to identify script blocks, obfuscated arguments, or download cradles.
3. **Network Conformance & Command-and-Control (C2)**:
   - `windows.netscan`: Scan pool allocations for TCP endpoints, listening sockets, and remote connections associated with running or terminated processes.
4. **Code Injection & Memory Modifications**:
   - `windows.malfind`: Locate memory segments with `PAGE_EXECUTE_READWRITE` permissions containing PE headers or injected shellcode.
   - `windows.dlllist`: Inspect loaded modules for unbacked DLLs or suspicious paths.

## 4. Endpoint Artifact Methodology (Triage & Correlation)
When disk images or extracted triage packages are available:
- **$MFT**: Parse file creation, modification, and access timestamps using `MFTECmd`. Note difference between `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps to detect timestomping.
- **Prefetch**: Extract execution frequency, last run times, and referenced files using `PECmd`.
- **Amcache / Shimcache**: Identify binary metadata, compile times, and paths using `AmcacheParser` and `AppCompatCacheParser`. Note that Shimcache establishes application presence and metadata, but not necessarily definitive execution.
- **Event Logs**: Parse Security (4688, 4624, 4672), System (7045), and PowerShell (4104) event logs using `EvtxECmd`.

## 5. Timeline Correlation
All timestamps are extracted from raw plugin/parser outputs and compiled into `timeline/incident-timeline.csv` with source references and UTC normalization. Gaps and uncertainties are explicitly logged.

## 6. Verdict Formulation
Verdicts are strictly categorized into:
- *Confirmed compromise*
- *Likely compromise*
- *Suspicious activity; compromise not established*
- *No evidence of compromise found in the examined artifacts*
- *Inconclusive due to insufficient or incompatible evidence*
