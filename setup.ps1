# setup.ps1
# Safe, repeatable setup script for DFIR Mini-Project
# Does not require Administrator privileges, does not download malware, and does not alter system security settings.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " DFIR Mini-Project - Environment Setup (Windows)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Determine Python interpreter
$pythonCmd = $null

if (Get-Command py -ErrorAction SilentlyContinue) {
    try {
        $pyList = & py --list 2>&1
        if ($pyList -match "3\.12") {
            $pythonCmd = "py -3.12"
            Write-Host "[+] Found Python 3.12 via Python Launcher (py -3.12)." -ForegroundColor Green
        } elseif ($pyList -match "3\.11") {
            $pythonCmd = "py -3.11"
            Write-Host "[+] Found Python 3.11 via Python Launcher." -ForegroundColor Green
        }
    } catch {}
}

if (-not $pythonCmd) {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
        Write-Host "[+] Using default python executable in PATH." -ForegroundColor Yellow
    } else {
        Write-Error "[-] Python not found. Please install Python 3.10-3.12 before running this script."
        exit 1
    }
}

# 2. Check / Create Virtual Environment
$venvPath = Join-Path $PSScriptRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[*] Creating virtual environment at .venv..." -ForegroundColor Cyan
    Invoke-Expression "$pythonCmd -m venv `"$venvPath`""
    if (-not (Test-Path $venvPython)) {
        Write-Error "[-] Failed to create virtual environment."
        exit 1
    }
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Existing virtual environment detected at .venv." -ForegroundColor Green
}

# 3. Upgrade pip and install dependencies
$reqFile = Join-Path $PSScriptRoot "requirements.txt"
if (Test-Path $reqFile) {
    Write-Host "[*] Upgrading pip and installing requirements..." -ForegroundColor Cyan
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -r $reqFile --quiet
    Write-Host "[+] Dependencies installed successfully." -ForegroundColor Green
} else {
    Write-Warning "[!] requirements.txt not found. Skipping package installation."
}

# 4. Verify Volatility 3
$volExe = Join-Path $venvPath "Scripts\vol.exe"
if (Test-Path $volExe) {
    Write-Host "[*] Verifying Volatility 3 installation..." -ForegroundColor Cyan
    $volCheck = & $volExe --version 2>&1
    Write-Host "[+] Volatility 3 is ready: $volCheck" -ForegroundColor Green
} else {
    Write-Warning "[!] vol.exe not found in .venv\Scripts. Check installation output."
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Setup Complete! You are ready to analyze memory dumps." -ForegroundColor Green
Write-Host " Use: .\.venv\Scripts\vol.exe -f <path_to_dump> <plugin>" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
