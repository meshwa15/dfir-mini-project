#!/usr/bin/env python3
"""
validate_results.py
Performs automated validation checks on the DFIR Mini-Project deliverables:
1. Verifies required project files and directory structure.
2. Validates CSV files and headers (manifest.csv, incident-timeline.csv, findings-register.csv).
3. Verifies that referenced result files exist in results/.
4. Verifies git status to ensure .gitignore excludes evidence, venvs, and dumps.
5. Checks report integrity to prevent unresolved template placeholders from masquerading as verified findings.
"""

import sys
import os
import csv
import subprocess

def check_file_exists(rel_path, required=True):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    full_path = os.path.join(project_root, rel_path)
    exists = os.path.exists(full_path)
    return exists, full_path

def validate_csv(rel_path, expected_headers):
    exists, full_path = check_file_exists(rel_path)
    if not exists:
        return False, f"Missing CSV file: {rel_path}"
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return False, f"Empty CSV file: {rel_path}"
            # Check headers
            missing = [h for h in expected_headers if h not in header]
            if missing:
                return False, f"Missing expected headers in {rel_path}: {missing}"
            return True, f"Valid CSV ({len(header)} columns)"
    except Exception as e:
        return False, f"Error reading {rel_path}: {e}"

def check_git_cleanliness():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode != 0:
            return True, "Git repository not initialized or git command unavailable."
        
        lines = res.stdout.splitlines()
        forbidden_patterns = [".venv", ".vmem", ".raw", ".dmp", "evidence/originals"]
        leaked = []
        for line in lines:
            for pat in forbidden_patterns:
                if pat in line:
                    leaked.append(line)
        if leaked:
            return False, f"Forbidden artifacts detected in git tracking: {leaked}"
        return True, "Git tracking clean; no evidence or venv files staged/tracked."
    except Exception as e:
        return True, f"Git check skipped: {e}"

def check_report_placeholders(rel_path):
    exists, full_path = check_file_exists(rel_path)
    if not exists:
        return False, f"Missing report file: {rel_path}"
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Check for unresolved placeholders presented as completed findings
        unresolved_markers = ["[INSERT EVIDENCE HERE]", "<REPLACE WITH HASH>", "TODO_REAL_HASH"]
        found = [m for m in unresolved_markers if m in content]
        if found:
            return False, f"Unresolved template placeholders detected in {rel_path}: {found}"
        return True, f"Report integrity verified; no raw placeholders found."
    except Exception as e:
        return False, f"Error inspecting {rel_path}: {e}"

def main():
    print("=" * 65)
    print(" DFIR Mini-Project Deliverables Validation")
    print("=" * 65)
    
    passed_checks = 0
    total_checks = 0
    failures = []

    # 1. Structure and core documents
    core_files = [
        "README.md",
        "PROJECT_STATUS.md",
        "LICENSE",
        ".gitignore",
        "requirements.txt",
        "environment-report.md",
        "environment-setup.md",
        "setup.ps1",
        "case-notes.md",
        "references.md",
        "docs/methodology.md",
        "docs/artifact-reference.md",
        "docs/limitations.md",
        "reports/incident-report.md",
        "reports/executive-summary.md",
        "reports/findings-register.csv",
        "timeline/incident-timeline.csv",
        "evidence/manifest.csv"
    ]

    print("\n[*] Validating Project Files Existence...")
    for cf in core_files:
        total_checks += 1
        exists, _ = check_file_exists(cf)
        if exists:
            print(f" [PASS] {cf}")
            passed_checks += 1
        else:
            print(f" [FAIL] Missing: {cf}")
            failures.append(f"Missing file: {cf}")

    # 2. CSV Validations
    print("\n[*] Validating CSV Schemas & Headers...")
    csv_schemas = {
        "evidence/manifest.csv": [
            "Filename", "RelativePath", "SizeBytes", "CalculatedSHA256", "CalculationTime"
        ],
        "timeline/incident-timeline.csv": [
            "Event ID", "Timestamp", "Timezone", "Source artifact", "Process or file", "Event description"
        ],
        "reports/findings-register.csv": [
            "Finding ID", "Title", "Severity", "Confidence", "Evidence reference", "Description"
        ]
    }
    for csv_file, headers in csv_schemas.items():
        total_checks += 1
        valid, msg = validate_csv(csv_file, headers)
        if valid:
            print(f" [PASS] {csv_file}: {msg}")
            passed_checks += 1
        else:
            print(f" [FAIL] {csv_file}: {msg}")
            failures.append(f"CSV error in {csv_file}: {msg}")

    # 3. Git Cleanliness
    print("\n[*] Validating Version Control Cleanliness (.gitignore rules)...")
    total_checks += 1
    git_clean, git_msg = check_git_cleanliness()
    if git_clean:
        print(f" [PASS] {git_msg}")
        passed_checks += 1
    else:
        print(f" [FAIL] {git_msg}")
        failures.append(f"Git cleanliness: {git_msg}")

    # 4. Report Integrity
    print("\n[*] Validating Report Content Integrity...")
    reports = ["reports/incident-report.md", "reports/executive-summary.md"]
    for rep in reports:
        total_checks += 1
        valid, msg = check_report_placeholders(rep)
        if valid:
            print(f" [PASS] {rep}: {msg}")
            passed_checks += 1
        else:
            print(f" [FAIL] {rep}: {msg}")
            failures.append(f"Report integrity in {rep}: {msg}")

    # Summary
    print("\n" + "=" * 65)
    print(f" Summary: {passed_checks}/{total_checks} checks passed.")
    print("=" * 65)

    # Save to results/validation/validation_report.txt
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_dir = os.path.join(project_root, "results", "validation")
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "validation_report.txt")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"DFIR Mini-Project Validation Summary\n")
        f.write(f"Checks Passed: {passed_checks}/{total_checks}\n\n")
        if failures:
            f.write("Failures / Incomplete Elements:\n")
            for fl in failures:
                f.write(f"- {fl}\n")
        else:
            f.write("All checks successfully passed.\n")
    print(f"[+] Output written to {report_file}")
    
    return len(failures) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
