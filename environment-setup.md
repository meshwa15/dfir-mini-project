# Environment Setup: DFIR Mini-Project

This document outlines the setup process, Python environment configuration, and dependency installation for reproducing the Memory & Endpoint Forensics Case Walkthrough on Windows.

## Prerequisites
- **Operating System**: Windows 10 or Windows 11 (64-bit recommended)
- **PowerShell**: Version 5.1 or later
- **Python**: Python 3.10 to 3.12 (64-bit). In our environment, Python 3.12.2 was selected due to optimal binary wheel availability for forensic packages (`capstone`, `pefile`, `yara-python`).
- **Git**: Version 2.30+ for version control

## Automated Setup (`setup.ps1`)
To provision the project virtual environment cleanly without manual intervention:

```powershell
# From the DFIR repository root
.\setup.ps1
```

The script will:
1. Locate Python 3.12 (via the Python Launcher `py -3.12` or `python`).
2. Create an isolated virtual environment at `.venv`.
3. Upgrade `pip`.
4. Install all dependencies from `requirements.txt`.
5. Verify the `vol.exe` command line interface.

## Manual Setup Step-by-Step

### 1. Create the Virtual Environment
```powershell
py -3.12 -m venv .venv
```

### 2. Activate the Environment (Optional) or Call Directly
If PowerShell script execution is restricted (`Restricted` ExecutionPolicy), you can directly invoke the executables without activating:
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Alternatively, if your policy allows script activation:
```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Verify Volatility 3
Run the help command to confirm plugin registration:
```powershell
.\.venv\Scripts\vol.exe -h
```

Expected output:
- Volatility version banner (e.g. `Volatility 3 Framework 2.28.2`)
- Listing of core plugins including `windows.info`, `windows.pslist`, `windows.pstree`, `windows.netscan`, `windows.malfind`, `windows.registry.hivelist`, etc.

## Safety & Non-Privileged Execution
- **No Administrator Privileges Required**: All packages are installed into the project-local `.venv` directory.
- **No System Alterations**: System-level Python and PATH variables are untouched.
- **Evidence Isolation**: Evidence is placed under `evidence/originals/` and excluded from source control.
