#!/usr/bin/env python3
"""
calculate_hashes.py
Calculates SHA-256 cryptographic hashes for forensic evidence files,
generating or updating evidence/manifest.csv to maintain chain of custody.
"""

import sys
import os
import hashlib
import csv
import datetime
import argparse

BUFFER_SIZE = 65536  # 64 KB chunks for memory-efficient streaming

def hash_file(file_path):
    """Calculates SHA-256 hash and byte size of a file."""
    sha256 = hashlib.sha256()
    total_bytes = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            total_bytes += len(chunk)
    return sha256.hexdigest(), total_bytes

def process_target(target_path, manifest_path=None, source_ref="", reference_hash=""):
    """Processes a file or directory of files, recording results to manifest."""
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        print(f"[ERROR] Target path does not exist: {target_path}", file=sys.stderr)
        return False

    files_to_hash = []
    if os.path.isfile(target_path):
        files_to_hash.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                files_to_hash.append(os.path.join(root, file))

    if not files_to_hash:
        print(f"[WARNING] No files found at target: {target_path}")
        return False

    records = []
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    evidence_root = os.path.join(project_root, "evidence")

    for file_path in files_to_hash:
        rel_path = os.path.relpath(file_path, evidence_root) if file_path.startswith(evidence_root) else os.path.relpath(file_path, project_root)
        filename = os.path.basename(file_path)
        calc_time = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        
        try:
            print(f"[*] Calculating SHA-256 for: {filename}...")
            calc_hash, file_size = hash_file(file_path)
            
            # Integrity check against reference if supplied
            match_status = "N/A (No Reference Hash Provided)"
            if reference_hash:
                if calc_hash.lower() == reference_hash.lower():
                    match_status = "MATCH (Verified with Source Reference)"
                else:
                    match_status = "MISMATCH (Hash does not match source reference!)"

            record = {
                "Filename": filename,
                "RelativePath": rel_path.replace("\\", "/"),
                "SizeBytes": file_size,
                "CalculatedSHA256": calc_hash,
                "CalculationTime": calc_time,
                "SourceReference": source_ref if source_ref else "Local File",
                "ReferenceHash": reference_hash if reference_hash else "None",
                "IntegrityStatus": match_status
            }
            records.append(record)
            print(f"[+] SHA-256: {calc_hash} ({file_size} bytes)")
        except Exception as e:
            print(f"[ERROR] Failed to read {file_path}: {e}", file=sys.stderr)

    # Write or append to manifest CSV
    if not manifest_path:
        manifest_path = os.path.join(evidence_root, "manifest.csv")

    file_exists = os.path.exists(manifest_path) and os.path.getsize(manifest_path) > 0
    fieldnames = [
        "Filename",
        "RelativePath",
        "SizeBytes",
        "CalculatedSHA256",
        "CalculationTime",
        "SourceReference",
        "ReferenceHash",
        "IntegrityStatus"
    ]

    with open(manifest_path, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for rec in records:
            writer.writerow(rec)

    print(f"[+] Manifest updated: {manifest_path}")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate SHA-256 hashes for evidence and record in manifest.")
    parser.add_argument("target", help="File or directory path to hash")
    parser.add_argument("--manifest", help="Custom path to manifest.csv", default=None)
    parser.add_argument("--source", help="Source reference (e.g. download URL or acquisition authority)", default="")
    parser.add_argument("--ref-hash", help="Known reference hash provided by source", default="")
    
    args = parser.parse_args()
    success = process_target(args.target, args.manifest, args.source, args.ref_hash)
    sys.exit(0 if success else 1)
