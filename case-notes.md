# Case Notes: DFIR Mini-Project (Cridex Memory Analysis)

## 1. Case Metadata
- **Investigation Title**: Memory & Endpoint Forensics Case Walkthrough
- **Case Reference**: IR-2026-CRIDEX-01
- **Investigator**: SOC Tier 1/2 Incident Response Analyst
- **Date Initiated**: 2026-10-27
- **Target Evidence**: `cridex.vmem` (Physical RAM dump, 512 MB)
- **Calculated SHA-256**: `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d`
- **Reference Hash**: `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d` (Integrity Verified)

---

## 2. Chronological Investigation Log

### Step 1: Environment Baseline & Tooling Setup
- Executed `scripts/collect_environment_info.py` to baseline the Windows 11 host.
- Provisioned dedicated Python 3.12 virtual environment `.venv` with `volatility3==2.28.2`, `pefile`, `capstone`, `pycryptodome`, and `yara-python`.
- Initialized local git repository with strict `.gitignore` rules.

### Step 2: Evidence Acquisition & Hashing
- Acquired `cridex.vmem` (512 MB) into `evidence/originals/`.
- Executed `scripts/calculate_hashes.py` to stream SHA-256 calculation and populate `evidence/manifest.csv`. Verified match with source reference hash.

### Step 3: Operating System Identification
- Executed `windows.info`:
  - Kernel Base: `0x804d7000`, DTB: `0x2fe000`
  - OS: Windows XP Service Pack 3 (Build 2600.xpsp.080413-2111) x86
  - Memory Capture Time: `2012-07-22 02:45:08 UTC`
  - Cached symbols: `ntkrnlpa.pdb/30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz`

### Step 4: Process Analysis
- Executed `windows.pslist`, `windows.psscan`, and `windows.pstree`:
  - 17 active processes identified. No processes unlinked from `ActiveProcessLinks` (`pslist` and `psscan` matched).
  - Identified `explorer.exe` (PID 1484) running under user session `Robert`.
  - Identified `reader_sl.exe` (PID 1640) spawned by `explorer.exe` at `02:42:36 UTC`.

### Step 5: Memory Injection Discovery
- Executed `windows.malfind`:
  - Injected Portable Executable (`MZ` header) discovered in `explorer.exe` (PID 1484, VAD `0x1460000-0x1480fff`, 135 KB, RWX).
  - Injected Portable Executable (`MZ` header) discovered in `reader_sl.exe` (PID 1640, VAD `0x3d0000-0x3f0fff`, 135 KB, RWX).
  - Both processes share identical injected shellcode assembly: `dec ebp; pop edx; nop; add byte ptr [ebx], al...`.

### Step 6: Registry Persistence & WebInject Configuration
- Executed `windows.registry.hivelist` and `windows.registry.printkey`:
  - Located user hive `Robert\NTUSER.DAT` at offset `0xe1a19b60`.
  - Discovered persistence Run key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KB00207877.exe` pointing to `C:\Documents and Settings\Robert\Application Data\KB00207877.exe` (Last Write: `2012-07-22 02:31:51 UTC`).
  - Discovered WebInject configuration key `HKCU\Software\Microsoft\WSH\8149A9A8` (Last Write: `2012-07-22 02:33:06 UTC`) containing target URLs for over 20 financial institutions.

### Step 7: User Activity & Execution History
- Executed `windows.registry.userassist`:
  - Initial infection vector: Execution of `C:\WINDOWS\cridex1.exe` at `2012-07-22 02:31:51 UTC` (Run count: 1).
  - Preceding web browsing: `iexplore.exe` launched at `2012-07-22 02:31:28 UTC`.

### Step 8: Synchronization Objects & Handle Inspection
- Executed `windows.mutantscan` and `windows.handles`:
  - Identified distinctive Cridex mutants: `XMR8149A9A8`, `XMQ8149A9A8`, `XMS8149A9A8`, `XMM000005CC`, `XMM00000668`.
  - Confirmed open handles to `WSH\8149A9A8` from both `explorer.exe` and `reader_sl.exe`.

### Step 9: Network Telemetry Extraction
- Memory buffer inspection revealed outbound HTTP POST traffic:
  - Command & Control Server: `41.168.5.140:8080`
  - URI Path: `POST /zb/v_01_a/in/ HTTP/1.1`
  - Payload: 229-byte encrypted telemetry check-in.

---

## 3. Analytical Conclusions
The host experienced a confirmed Cridex trojan compromise resulting from the execution of `C:\WINDOWS\cridex1.exe`. Persistence was secured via `KB00207877.exe` in the user Run key, code was injected into `explorer.exe` and `reader_sl.exe`, and outbound C2 beacons were established to `41.168.5.140:8080`.
