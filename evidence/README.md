# Evidence Directory

## Purpose
This directory manages raw forensic evidence acquired for the DFIR Mini-Project.

## Structure
- `originals/`: Local storage for downloaded memory dumps, disk images, or triage archives.
  - **Notice**: This folder is strictly ignored by version control (`.gitignore`) to avoid committing untrusted binary evidence or violating distribution licenses.
- `manifest.csv`: Cryptographic hash manifest documenting all evidence files, sizes, acquisition times, calculated SHA-256 hashes, and reference hashes.

## Evidence Handling Guidelines
1. **Never modify original evidence**: Always preserve acquisition timestamps and treat files as read-only.
2. **Hash Verification**: Compute SHA-256 hashes immediately upon acquisition using `scripts/calculate_hashes.py`.
3. **Chain of Custody**: Record evidence source, original filename, download URL, acquisition date/time, and analyst details.
