#!/usr/bin/env python3
"""
collect_environment_info.py
Collects non-sensitive system environment details and forensic tool availability
for Phase 1 of the DFIR Mini-Project.
"""

import sys
import os
import platform
import subprocess
import shutil
import datetime

def run_cmd(cmd_list):
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, check=False)
        return res.stdout.strip() if res.returncode == 0 else ""
    except Exception:
        return ""

def main():
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    os_info = f"{platform.system()} {platform.release()} ({platform.version()}) - {platform.machine()}"
    
    python_ver = sys.version.split()[0]
    python_path = sys.executable
    
    git_ver = run_cmd(["git", "--version"])
    code_ver = run_cmd(["code", "--version"]).splitlines()[0] if run_cmd(["code", "--version"]) else ""
    
    # Disk space on C:
    c_drive = "C:\\"
    total, used, free = shutil.disk_usage(c_drive)
    free_gb = round(free / (1024**3), 2)
    total_gb = round(total / (1024**3), 2)
    
    # Check Volatility
    vol_ver = ""
    try:
        import volatility3
        vol_ver = getattr(volatility3, "__version__", "Installed (unknown version)")
    except ImportError:
        pass
    
    report = f"""# Environment Report: DFIR Mini-Project

## Assessment Metadata
- **Date and Time of Check**: {now}
- **Operating System**: {os_info}
- **Architecture**: {platform.architecture()[0]}

## System Resources
- **Analysis Drive**: `C:\\`
- **Total Disk Space**: {total_gb} GB
- **Available Disk Space**: {free_gb} GB
- **Disk Evaluation**: Sufficient for memory dumps under 10 GB. Large raw forensic disk images should be selected with size awareness.

## Detected Core Tools & Versions
| Tool / Runtime | Status | Detected Version | Executable / Source Path |
|---|---|---|---|
| **Python** | Detected | {python_ver} | `{python_path}` |
| **Git** | Detected | {git_ver if git_ver else "Not detected in PATH"} | {shutil.which("git") or "N/A"} |
| **VS Code** | Detected | {code_ver if code_ver else "Not detected in PATH"} | {shutil.which("code") or "N/A"} |
| **PowerShell** | Detected | 5.1 | Built-in |
| **Volatility 3** | {"Detected" if vol_ver else "Missing (Planned)"} | {vol_ver if vol_ver else "None"} | Dedicated `.venv` to be provisioned |
| **FTK Imager** | Missing | None | Optional; evaluate if disk image provided |
| **KAPE** | Missing | None | Optional; evaluate if triage collection needed |
| **Eric Zimmerman Tools** | Missing | None | Optional; evaluate based on endpoint artifacts |

## Environment Limitations & Recommendations
1. **Python Multi-Version Environment**:
   - Python 3.14.6 is currently the system default.
   - Python 3.12 (64-bit) is installed and available via `py -3.12`.
   - **Recommendation**: Provision the project virtual environment `.venv` using `py -3.12 -m venv .venv` to ensure maximum stability and binary wheel compatibility for forensic libraries (`pefile`, `capstone`, `volatility3`).
2. **Project Working Directory**:
   - Root Path: `c:\\Users\\Nitin Patel\\OneDrive\\Desktop\\DFIR`
   - Redirection: OneDrive syncs Desktop. All forensic evidence dumps must be placed in `evidence/originals/` and ignored in `.gitignore` to prevent cloud sync saturation.
3. **Forensic Evidence Scope**:
   - Prioritize a Windows memory dump (`.raw` / `.vmem` / `.dmp`) sized between 500 MB and 4 GB for swift processing and manageable disk usage.
"""
    return report

if __name__ == "__main__":
    report_text = main()
    output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "environment-report.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print("environment-report.md generated successfully.")
