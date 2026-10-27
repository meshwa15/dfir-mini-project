# Forensic Limitations & Scope Boundaries

## 1. Scope Constraints
- **Evidence Availability**: Analysis is strictly bound to the forensic image(s) acquired. If only a volatile memory dump is provided, non-volatile disk artifacts (such as full NTFS journal `$LogFile`, Volume Shadow Copies, or unallocated space carving) cannot be examined directly.
- **Volatile Data Ephemerality**: Memory represents a single snapshot in time. Events that occurred hours prior to acquisition may have been paged out or overwritten by ongoing OS operations.

## 2. Tooling Limitations
- **Volatility 3 Symbol Requirements**: Volatility 3 requires symbol tables (`Intermediate Symbol Format` / ISF) to resolve kernel offsets. While Volatility 3 automatically downloads symbols from Microsoft's public symbol server when connected to the Internet, custom or patched kernels without public symbols can limit plugin fidelity.
- **Heuristic Indicators**: Plugins like `malfind` flag RWX memory sections. RWX allocations are common in legitimate JIT runtimes (such as Java, .NET, or Chromium). Analysts must inspect the disassembled bytes and VAD tags rather than treating every flagged hit as malicious.

## 3. Anti-Forensic Considerations
- **Timestomping**: Attackers may alter `$STANDARD_INFORMATION` attributes on disk files. Memory timestamps for process creation are pulled from kernel structures and are harder to tamper with while the kernel is running.
- **Argument Obfuscation**: Command-line arguments may be masked, encoded in Base64, or launched via indirect execution wrappers.

## 4. Legal & Chain of Custody Note
- This investigation is performed strictly on authorized public training datasets for educational and portfolio demonstration purposes. No operational production systems were compromised or accessed.
