# Forensic Artifact Reference Guide

This reference provides beginner-friendly technical context on forensic artifacts analyzed during Windows investigations, their investigative value, and their analytical limitations.

---

## 1. Volatile Memory Artifacts

### Active Process Listings (`EPROCESS`)
- **What it is**: In Windows memory, every process is represented by an `_EPROCESS` structure in kernel space. Volatility's `windows.pslist` walks the doubly-linked list (`ActiveProcessLinks`), while `windows.psscan` scans memory for unlinked or terminated `_EPROCESS` pools.
- **Investigative Value**: Establishes which binaries were active, their process IDs (PIDs), parent process IDs (PPIDs), creation times, and exit times.
- **Limitations**: Rootkits can unhook `ActiveProcessLinks` (Direct Kernel Object Manipulation / DKOM), hiding processes from `pslist`. Hence, `psscan` must be correlated against `pslist`.

### Command-Line Arguments (`PEB`)
- **What it is**: Stored within the Process Environment Block (PEB) in userland memory, accessed via `windows.cmdline`.
- **Investigative Value**: Reveals execution arguments, paths, encoded scripts (e.g. `powershell.exe -enc ...`), and network proxies.
- **Limitations**: Attackers can spoof or overwrite their PEB arguments after process initialization.

### Network Sockets & Pools (`_TCPT_OBJECT` / `_LOCAL_ADDRESS`)
- **What it is**: Network connection blocks scanned by `windows.netscan`.
- **Investigative Value**: Identifies established TCP connections, foreign IP addresses, listening ports, and the owning PID at acquisition time.
- **Limitations**: Short-lived network connections closed before memory acquisition may be overwritten or show `CLOSED` / `TIME_WAIT` states without foreign IP fidelity.

### Memory Injections (`VAD` / `PAGE_EXECUTE_READWRITE`)
- **What it is**: Virtual Address Descriptors (VAD) map process memory segments. `windows.malfind` flags allocations marked `PAGE_EXECUTE_READWRITE` (RWX) or containing unbacked executable headers (`MZ` / `PE`).
- **Investigative Value**: Pinpoints process hollowing, DLL injection, and reflective shellcode execution.
- **Limitations**: Legitimate Just-In-Time (JIT) engines (e.g., .NET CLR, browser JavaScript engines) also allocate RWX memory, producing potential false positives.

---

## 2. Disk & Registry Endpoint Artifacts

### Master File Table (`$MFT`)
- **What it is**: The central database of the NTFS filesystem, tracking all file records, data runs, and metadata.
- **Investigative Value**: Contains `$STANDARD_INFORMATION` ($SI) and `$FILE_NAME` ($FN) timestamps (Modified, Accessed, Created, Entry Modified - MACB). Comparing $SI and $FN helps identify timestomping.
- **Limitations**: Access timestamps can be delayed or disabled by default Windows performance configurations (`NtfsDisableLastAccessUpdate`).

### Windows Prefetch (`.pf`)
- **What it is**: Designed to optimize application startup speed. Records binary execution details, execution count, last 8 execution timestamps (on Windows 8+), and loaded DLLs/files within the first 10 seconds of launch.
- **Investigative Value**: Solid evidence of binary execution from specific directory paths.
- **Limitations**: Typically disabled by default on Windows Server editions.

### Application Compatibility Cache (`Shimcache` / `AppCompatCache`)
- **What it is**: Maintained by the Windows Application Compatibility subsystem in the `SYSTEM` registry hive to manage application shims.
- **Investigative Value**: Records file path, file size, and last modified timestamp of executed or browsed executables.
- **Limitations**: An entry in Shimcache proves the executable existed and was inspected by the compatibility engine; it does not definitively prove execution occurred in isolation.

### Amcache (`Amcache.hve`)
- **What it is**: A dedicated registry hive (`C:\Windows\appcompat\Programs\Amcache.hve`) tracking application installations, updates, executions, and file SHA-1 hashes.
- **Investigative Value**: Provides cryptographic SHA-1 hashes, compilation times, and paths of executed binaries, even if the binary itself was deleted.
- **Limitations**: File deletion does not immediately clear Amcache, but timestamp resolution varies across Windows versions.
