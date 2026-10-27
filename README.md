# Memory & Endpoint Forensics Case Walkthrough (DFIR Mini-Project)

[![DFIR Project](https://img.shields.io/badge/DFIR-Mini--Project-blue.svg)](https://github.com/volatilityfoundation/volatility3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Volatility 3](https://img.shields.io/badge/Volatility-3-orange.svg)](https://volatility3.readthedocs.io/)
[![Verdict: Confirmed Compromise](https://img.shields.io/badge/Verdict-Confirmed%20Compromise-red.svg)](reports/incident-report.md)

An evidence-based, reproducible cybersecurity portfolio project demonstrating physical memory forensics, incident reconstruction, and adversary behavior analysis on a real Windows compromise.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Why This Project Matters to a SOC Analyst](#why-this-project-matters-to-a-soc-analyst)
3. [Core Objectives](#core-objectives)
4. [Beginner's Guide to Key Forensic Concepts](#beginners-guide-to-key-forensic-concepts)
5. [Investigation Workflow](#investigation-workflow)
6. [Tools & Technologies](#tools--technologies)
7. [Dataset Attribution & Evidence Integrity](#dataset-attribution--evidence-integrity)
8. [Setup & Reproduction Guide](#setup--reproduction-guide)
9. [Repository Structure](#repository-structure)
10. [Executive Findings & Incident Verdict](#executive-findings--incident-verdict)
11. [Correlated Incident Timeline](#correlated-incident-timeline)
12. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
13. [Investigation Limitations & Antivirus Considerations](#investigation-limitations--antivirus-considerations)
14. [Ethical & Legal Considerations](#ethical--legal-considerations)
15. [References](#references)

---

## Project Overview

In modern Security Operations Centers (SOCs), triaging sophisticated malware requires more than running automated virus scanners. Threat actors routinely bypass disk-based antivirus detection by injecting code directly into legitimate running processes or staging payload configurations in obfuscated registry keys.

This project delivers a **complete, hands-on, evidence-based memory forensics investigation** of an authorized public case: the **Volatility Foundation Cridex Banking Trojan** memory dump (`cridex.vmem`, 512 MB). The analysis confirms and documents how the Cridex malware executes, persists, injects code into system binaries (`explorer.exe` and `reader_sl.exe`), stages banking WebInject configurations, and establishes Command and Control (C2) communications.

---

## Why This Project Matters to a SOC Analyst

For **Junior Security Analysts**, **SOC Tier 1/2 Analysts**, and **Incident Responders**, memory forensics provides critical capabilities:
- **Detecting Fileless Malware & Code Injection**: When malware executes exclusively in RAM, disk scans find nothing. Memory analysis reveals injected Portable Executables (`MZ` headers) and suspicious Virtual Address Descriptors (VAD).
- **Uncovering True Command Lines & Environment Variables**: Memory retains decrypted strings, active network sockets, and command arguments that were never written to disk logs.
- **Root-Cause Timeline Reconstruction**: By correlating volatile memory timestamps, registry LastWrite times, and UserAssist execution counters, analysts can accurately distinguish the initial infection vector from secondary payloads.
- **Formulating High-Fidelity Incident Reports**: Transforming low-level hex dumps and process trees into actionable C-level executive summaries and MITRE ATT&CK defensive mappings.

---

## Core Objectives

- [x] Establish and verify digital chain of custody using cryptographic SHA-256 hashing.
- [x] Provision an isolated, non-privileged Python analysis environment with Volatility 3 on Windows.
- [x] Analyze kernel memory, process ancestry, command-line arguments, and process memory maps.
- [x] Identify in-memory code injection (`PAGE_EXECUTE_READWRITE`) and process hollowing.
- [x] Extract registry hives from memory to identify autostart persistence and WebInject configurations.
- [x] Extract network telemetry and C2 IP communication channels directly from memory buffers.
- [x] Reconstruct an evidence-grounded incident timeline in UTC.
- [x] Map observed adversary behaviors to the MITRE ATT&CK framework.
- [x] Deliver an incident report, executive summary, and structured CSV finding registers.
- [x] Validate all project deliverables with automated verification scripts.

---

## Beginner's Guide to Key Forensic Concepts

If you are new to Digital Forensics and Incident Response (DFIR), here is what the core concepts and artifacts mean:

### 1. Memory Forensics vs. Endpoint Forensics
- **Memory Forensics**: The capture and examination of volatile RAM. RAM holds active encryption keys, running malware threads, injected code, open network connections, and uncommitted user inputs. It is ephemeral and lost when power is removed.
- **Endpoint Forensics**: The examination of non-volatile disk storage (hard drives, SSDs) and operating system artifacts that persist across system reboots.

### 2. Process Trees & Ancestry
In Windows, every process is spawned by a parent process (tracked via Parent Process ID / PPID). Legitimate processes follow strict hierarchical rules:
- `System` (PID 4) spawns `smss.exe` (Session Manager).
- `smss.exe` initializes sessions and spawns `winlogon.exe` and `csrss.exe`.
- `winlogon.exe` spawns `services.exe` (Service Control Manager) and `lsass.exe` (Local Security Authority).
- `services.exe` spawns background services like `svchost.exe` and `spoolsv.exe`.
- `explorer.exe` (the interactive desktop shell) spawns user programs.
*Anomaly Detection*: If `svchost.exe` is spawned by `explorer.exe` or `cmd.exe` is spawned by `spoolsv.exe`, it represents severe anomaly or compromise.

### 3. Process Injection & Process Hollowing
- **Process Injection**: An attacker writes code into the virtual memory address space of a separate, legitimate running process (like `explorer.exe`) to execute under its security context and evade security monitoring.
- **Memory Permissions**: Legitimate memory segments typically have read-only (`PAGE_READONLY`), read-write (`PAGE_READWRITE`), or execute-read (`PAGE_EXECUTE_READ`) permissions. Segments with **`PAGE_EXECUTE_READWRITE` (RWX)** that contain executable PE headers (`MZ` / `4D 5A 90 00`) are high-confidence indicators of malicious injection.

### 4. Disk & Registry Endpoint Artifacts Explained
- **$MFT (Master File Table)**: The NTFS filesystem database tracking all file records, clusters, and timestamps (Modified, Accessed, Created, Entry Modified).
- **Shimcache (AppCompatCache)**: A Windows registry cache that tracks application compatibility. Proves that an application file existed on the system and was examined by the OS compatibility engine.
- **Amcache**: A dedicated hive (`Amcache.hve`) recording program installation, execution, file hashes (SHA-1), and compilation dates.
- **Prefetch (`.pf`)**: Performance files created by Windows to accelerate program launch. Records the binary name, execution count, last run timestamps, and files loaded during the first 10 seconds of execution.
- **UserAssist**: Registry keys in `NTUSER.DAT` that track programs launched via the Windows GUI Explorer, including run counts and last execution timestamps (stored in ROT13 encoding).

### 5. Persistence Mechanisms
Techniques used by adversaries to retain access across system restarts or logouts:
- **Registry Run Keys**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` automatically execute specified binaries upon user logon or boot.
- **Scheduled Tasks & Services**: Background tasks executed by the Task Scheduler or Service Control Manager.

### 6. Evidence Integrity & Hashing
Cryptographic hashing (such as **SHA-256**) generates a unique fixed-length digital fingerprint of a file. If even a single bit of evidence changes, the hash changes completely. Calculating and recording hashes in a manifest ensures non-repudiation and maintains the legal **Chain of Custody**.

---

## Investigation Workflow

```
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│  Phase 1: Environment  │ ───> │   Phase 2: Tooling     │ ───> │  Phase 4/5: Evidence   │
│  Inspection & Baseline │      │  Python 3.12 + Vol 3   │      │  Download & SHA256     │
└────────────────────────┘      └────────────────────────┘      └────────────────────────┘
                                                                             │
                                                                             ▼
┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
│   Phase 10/11: Report  │ <─── │ Phase 8/9: Timeline &  │ <─── │   Phase 6: Memory      │
│   Verdict & Remediation│      │ ATT&CK Classification  │      │   Analysis Plugins     │
└────────────────────────┘      └────────────────────────┘      └────────────────────────┘
```

---

## Tools & Technologies

| Tool | Version | Role in Project |
|---|---|---|
| **Python** | 3.12.2 (x64) | Core scripting runtime for automation and hashing |
| **Volatility 3** | 2.28.2 | Advanced volatile memory forensics analysis framework |
| **pefile** | 2024.8.26 | PE parsing engine supporting Volatility 3 |
| **capstone** | 5.0.9 | Disassembly engine for memory injection analysis (`malfind`) |
| **pycryptodome** | 4.2.0 | Cryptographic algorithms for registry hive dumping |
| **yara-python** | 4.5.4 | In-memory pattern and signature scanning engine |
| **PowerShell** | 5.1 | Terminal automation, command execution, and file auditing |
| **Git** | 2.45.1 | Project version control and repository tracking |

---

## Dataset Attribution & Evidence Integrity

- **Case Name**: Volatility Foundation Cridex Malware Memory Sample
- **Dataset Source**: Mirrored via [Hugging Face DFIR Validation Data](https://huggingface.co/datasets/jhenning/dfir-validation-data/resolve/main/cridex.vmem) and indexed on the [Volatility Foundation Memory Samples Wiki](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples).
- **Target OS**: Windows XP Professional Service Pack 3 (x86)
- **Evidence File**: `evidence/originals/cridex.vmem`
- **File Size**: 536,870,912 bytes (512 MB)
- **Calculated SHA-256**: `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d`
- **Reference Hash**: `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d`
- **Integrity Status**: **MATCH (Verified with Source Reference)**

---

## Setup & Reproduction Guide

### 1. Automated Setup (Recommended)
Clone the repository and run the safe, non-admin setup script:
```powershell
.\setup.ps1
```

### 2. Manual Setup
```powershell
# 1. Provision virtual environment with Python 3.12
py -3.12 -m venv .venv

# 2. Install dependencies
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 3. Verify Volatility 3
.\.venv\Scripts\vol.exe -h
```

### 3. Reproduce the Analysis
```powershell
# Verify evidence integrity
.\.venv\Scripts\python.exe scripts\calculate_hashes.py evidence\originals\cridex.vmem

# OS identification
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.info

# Process listing & tree
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.pslist
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.pstree

# Detect memory injection
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.malfind

# Inspect persistence Run keys
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.registry.printkey --offset 0xe1a19b60 --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Inspect UserAssist execution history
.\.venv\Scripts\vol.exe -f evidence\originals\cridex.vmem windows.registry.userassist

# Run automated deliverable validation
.\.venv\Scripts\python.exe scripts\validate_results.py
```

---

## Repository Structure

```text
DFIR-Mini-Project/
├── README.md                      # Beginner-friendly project walkthrough & portfolio guide
├── PROJECT_STATUS.md              # Live phase tracking and command audit log
├── LICENSE                        # Open-source MIT license
├── .gitignore                     # Strict rules excluding evidence, venvs, and dumps
├── requirements.txt               # Pinned Python dependencies for exact reproduction
├── environment-report.md          # Phase 1 Windows PC baseline assessment
├── environment-setup.md           # Step-by-step environment setup instructions
├── setup.ps1                      # Non-privileged automated setup script
├── case-notes.md                  # Investigator running log
├── references.md                  # Industry frameworks (NIST, SANS, MITRE) and resources
├── evidence/
│   ├── README.md                  # Evidence handling and chain-of-custody policies
│   ├── manifest.csv               # SHA-256 evidence integrity manifest
│   └── originals/                 # Local evidence storage (strictly git-ignored)
├── scripts/
│   ├── calculate_hashes.py        # Automated streaming SHA-256 evidence hasher
│   ├── collect_environment_info.py# Non-sensitive Windows environment collector
│   └── validate_results.py        # Comprehensive deliverable validation test suite
├── results/
│   ├── README.md                  # Results directory standards
│   ├── memory/                    # Authentic raw outputs from Volatility 3 plugins
│   │   ├── windows_info.txt       # Kernel profile & capture time
│   │   ├── windows_pslist.txt     # Process listings
│   │   ├── windows_psscan.txt     # Pool scanner process verification
│   │   ├── windows_pstree.txt     # Hierarchical process ancestry
│   │   ├── windows_cmdline.txt    # Process command line arguments
│   │   ├── windows_malfind.txt    # Injected executable code stubs
│   │   ├── windows_hivelist.txt   # Memory-resident registry hives
│   │   ├── windows_runkey_user.txt# Persistence autostart key
│   │   ├── windows_userassist.txt # Program execution history
│   │   ├── windows_mutantscan.txt # Active kernel mutexes
│   │   └── windows_handles_1484.txt# Injected process handles
│   └── validation/
│       └── validation_report.txt  # Automated test execution report
├── timeline/
│   ├── README.md                  # Timeline methodology guide
│   └── incident-timeline.csv      # Correlated chronological incident timeline (UTC)
├── reports/
│   ├── incident-report.md         # Full forensic report with technical appendices
│   ├── executive-summary.md       # Leadership summary with impact & business risk
│   └── findings-register.csv      # Tabular register of verified findings
├── screenshots/
│   └── README.md                  # Visual documentation guidelines
├── logs/
│   └── README.md                  # Session audit logs
└── docs/
    ├── methodology.md             # Forensic investigation methodology (NIST SP 800-86)
    ├── artifact-reference.md      # In-depth technical reference for Windows artifacts
    └── limitations.md             # Analytical boundaries and scope constraints
```

---

## Executive Findings & Incident Verdict

### **Final Verdict**: **Confirmed Compromise** | **Confidence**: **High**

| Finding ID | Title | Severity | Impact Summary |
|---|---|---|---|
| **FND-001** | Process Injection into `explorer.exe` & `reader_sl.exe` | **Critical** | Injected PE headers (`MZ`) in RWX memory regions executing malicious threads. |
| **FND-002** | Autostart Registry Run Key Persistence | **High** | Value `KB00207877.exe` created in `HKCU\...\CurrentVersion\Run` for reboot persistence. |
| **FND-003** | Command & Control (C2) Exfiltration | **Critical** | HTTP POST requests to `41.168.5.140:8080` transmitting encrypted telemetry. |
| **FND-004** | Staged Banking WebInject Targets | **High** | Configuration in `HKCU\Software\Microsoft\WSH\8149A9A8` targeting over 20 banking sites. |
| **FND-005** | Active Cridex Mutexes & Kernel Handles | **Medium** | Distinctive mutexes `XMR8149A9A8`, `XMQ8149A9A8`, `XMM...` coordinating threads. |
| **FND-006** | Dropper Execution via `cridex1.exe` | **High** | Initial execution recorded at `2012-07-22 02:31:51 UTC` under user `Robert`. |

---

## Correlated Incident Timeline

```text
2012-07-22 02:26:27 UTC ──> cmd.exe launched by user Robert
2012-07-22 02:31:28 UTC ──> iexplore.exe launched (pre-infection browsing)
2012-07-22 02:31:51 UTC ──> INITIAL INFECTION: C:\WINDOWS\cridex1.exe executed
2012-07-22 02:31:51 UTC ──> PERSISTENCE: HKCU Run key KB00207877.exe created
2012-07-22 02:33:06 UTC ──> WEB-INJECT: Bank targeting list written to WSH\8149A9A8
2012-07-22 02:42:31 UTC ──> System boot (smss.exe PID 368)
2012-07-22 02:42:36 UTC ──> explorer.exe (PID 1484) and reader_sl.exe (PID 1640) launch
2012-07-22 02:42:36 UTC ──> PROCESS HOLLOWING: Malicious PE code injected into PIDs 1484 & 1640
2012-07-22 02:43:00 UTC ──> C2 COMMUNICATION: HTTP POST to 41.168.5.140:8080 (/zb/v_01_a/in/)
2012-07-22 02:45:08 UTC ──> Forensic memory snapshot acquired
```

---

## MITRE ATT&CK Mapping

- **T1204.002 (User Execution: Malicious File)**: User executed `C:\WINDOWS\cridex1.exe`.
- **T1547.001 (Boot or Logon Autostart: Registry Run Keys)**: Persistence via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **T1036.005 (Masquerading: Match Legitimate Name)**: Malicious binary named `KB00207877.exe`.
- **T1055 (Process Injection)**: Unbacked executable memory injected into `explorer.exe` and `reader_sl.exe`.
- **T1071.001 (Application Layer Protocol: Web Protocols)**: Outbound HTTP POST C2 beacons.
- **T1185 (Man-in-the-Browser)**: Staged WebInject configuration for banking credential theft.

---

## Investigation Limitations & Antivirus Considerations

1. **Host Antivirus Protection**: When memory sections containing unpacked malware executables are dumped to physical disk using `malfind --dump`, host endpoint protections (e.g. Windows Defender) immediately detect and quarantine them. For this reason, live payload extraction must always be isolated inside virtual machines, while triage workstations rely on memory hexdump/disassembly logs.
2. **Scope Constraints**: The training case is a standalone physical RAM dump (`.vmem`). Non-volatile disk artifacts ($MFT, Prefetch files, Shadow Copies) were out of scope. Registry and user activity were extracted directly from memory structures.

---

## Ethical & Legal Considerations

This project was conducted exclusively on authorized, publicly accessible training datasets provided by the Volatility Foundation for educational purposes. No live production systems were compromised.

---

## References

- NIST SP 800-86: *Guide to Integrating Forensic Techniques into Incident Response*
- MITRE ATT&CK Enterprise Matrix: [https://attack.mitre.org/](https://attack.mitre.org/)
- Volatility 3 Official Documentation: [https://volatility3.readthedocs.io/](https://volatility3.readthedocs.io/)
- SANS Digital Forensics Posters: [https://www.sans.org/posters/hunt-evil/](https://www.sans.org/posters/hunt-evil/)
