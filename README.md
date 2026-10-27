# Memory & Endpoint Forensics Case Walkthrough (DFIR Mini-Project)

> **Project status: In progress — forensic evidence has not yet been acquired or analyzed.**  
> This repository is being prepared as a beginner-friendly Digital Forensics and Incident Response (DFIR) portfolio project. Findings, event timelines, indicators of compromise, and an incident verdict will be added only after a real, authorized training dataset has been examined.

## Overview

This project investigates a publicly available digital-forensics training case to determine whether the available evidence supports a suspected Windows endpoint compromise. The goal is to practice the evidence-handling and analysis workflow commonly used in Security Operations Center (SOC) investigations.

The investigation will use memory evidence first. If the selected case also provides suitable disk images or extracted Windows artifacts, the project may be extended to endpoint artifact analysis.

### Objectives

- Preserve and document the source of forensic evidence.
- Calculate and record SHA-256 hashes to help track evidence integrity.
- Examine a Windows memory image with Volatility 3, where compatible evidence is available.
- Investigate processes, process relationships, command-line arguments, and network artifacts where supported by the image.
- Examine Windows endpoint artifacts such as `$MFT`, Prefetch, Amcache, Shimcache, and event logs only if the case supplies suitable evidence.
- Correlate observations into an evidence-supported incident timeline.
- Document findings, confidence, limitations, and recommended response actions in a professional report.

## Project Status

See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) for the current phase, completed tasks, blockers, and next steps. If this file does not yet exist, create it before starting the investigation.

Current known state:

- [x] Project concept and investigation scope defined
- [ ] Windows environment checked
- [ ] Python and Git availability verified
- [ ] Volatility 3 installed and verified
- [ ] Authorized training case selected
- [ ] Evidence acquired and inventoried
- [ ] Memory analysis performed
- [ ] Disk artifact analysis performed, if applicable
- [ ] Timeline and findings reviewed
- [ ] Incident report completed and validated

A checkbox must only be marked complete when the corresponding action has actually been performed.

## Tools and Technologies

| Tool | Intended use | Required for the first version? |
|---|---|---|
| Python | Run helper scripts and support analysis workflows | Yes, if the chosen workflow uses Python scripts |
| Volatility 3 | Analyze compatible memory images | Yes, for the memory-forensics phase |
| Git | Track code and documentation changes | Recommended |
| FTK Imager | Inspect or acquire forensic disk images where appropriate | Optional; only if disk evidence is included |
| KAPE | Collect or process selected Windows artifacts | Optional; only if the case supports this workflow |
| Eric Zimmerman's Tools | Parse artifacts such as `$MFT`, Prefetch, Amcache, and event logs | Optional; select tools based on available artifacts |
| MITRE ATT&CK | Map evidence-supported adversary behaviors to techniques | Reference framework, not an evidence collection tool |

Tool names in this table describe the planned workflow. Do not state that a tool was used until it has actually been run and its version recorded.

## Repository Structure

The structure may be adjusted as the investigation progresses. Original evidence must remain separate from generated analysis results.

```text
DFIR-Mini-Project/
├── README.md
├── PROJECT_STATUS.md
├── environment-report.md
├── environment-setup.md
├── case-notes.md
├── references.md
├── requirements.txt
├── .gitignore
├── evidence/
│   ├── README.md
│   ├── manifest.csv
│   └── originals/          # Local only; never commit evidence files
├── scripts/
│   ├── calculate_hashes.py
│   ├── collect_environment_info.py
│   └── validate_results.py
├── results/
│   ├── memory/
│   ├── endpoint/
│   └── validation/
├── timeline/
│   └── incident-timeline.csv
├── reports/
│   ├── incident-report.md
│   ├── executive-summary.md
│   └── findings-register.csv
├── screenshots/
├── logs/
└── docs/
    ├── methodology.md
    ├── artifact-reference.md
    └── limitations.md
```

Some files may not exist yet. Create them as the relevant phase begins, and keep templates clearly marked as templates until they contain verified results.

## Getting Started on Windows

### 1. Check the environment

Open Command Prompt or PowerShell and run:

```powershell
py --version
python --version
git --version
```

Not every command will necessarily be available. Record the actual output in `environment-report.md`; do not assume a missing command means the project cannot proceed.

### 2. Create the project folders

For a new project, the following PowerShell commands create a folder on the current user's Desktop:

```powershell
$Project = Join-Path $env:USERPROFILE 'Desktop\DFIR-Mini-Project'
New-Item -ItemType Directory -Force -Path $Project | Out-Null
$Folders = @(
    'evidence',
    'evidence\originals',
    'scripts',
    'results\memory',
    'results\endpoint',
    'results\validation',
    'timeline',
    'reports',
    'screenshots',
    'logs',
    'docs'
)
foreach ($Folder in $Folders) {
    New-Item -ItemType Directory -Force -Path (Join-Path $Project $Folder) | Out-Null
}
Set-Location $Project
```

If a project folder already exists, inspect it before creating files or overwriting anything.

### 3. Set up a Python virtual environment

Only do this after confirming that a supported Python installation is available:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install volatility3
.\.venv\Scripts\vol.exe --help
```

If `py` is not recognized, check whether `python` works and follow the official Python installation instructions. Use a project-local virtual environment rather than installing project packages globally. Installation options can differ depending on the installed Python version and Windows configuration.

Official documentation: [Volatility 3](https://volatility3.readthedocs.io/en/latest/).

## Training Evidence

Use a dataset made available by a reputable training or research source and follow its access terms. Possible starting points include:

- [CyberDefenders](https://cyberdefenders.org/)
- [DFIR Diva](https://dfirdiva.com/)
- [NIST Computer Forensics Tool Testing (CFTT)](https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt)

Before choosing a case, confirm the actual evidence types supplied, operating system details, access requirements, and approximate download size. A memory-forensics challenge may provide only a memory dump and not a disk image.

Do not commit a dataset to this repository unless its license and the source's terms explicitly permit redistribution. Prefer documenting the case name and source URL in `case-notes.md` and `references.md`.

### Evidence handling principles

1. Keep the original files unchanged.
2. Record the source, filename, size, acquisition date, and source-provided hashes if available.
3. Calculate a SHA-256 hash of each acquired file and record the result in `evidence/manifest.csv`.
4. Preserve tool output and note the exact commands and tool versions used.
5. Work on a verified copy when appropriate and when storage permits.
6. Never execute suspected malware. Treat forensic images and extracted files as untrusted data.
7. Do not upload evidence that may contain personal, company, or other sensitive information to public services.

A matching hash helps verify that a file has not changed relative to a trusted reference. A hash by itself does not prove where a file came from or that it is authentic.

## Investigation Workflow

### Phase 1 — Environment and case preparation

- Record Windows, Python, Git, and relevant tool versions.
- Select a training case that can be accessed lawfully.
- Document the case scope and the evidence actually supplied.
- Inventory evidence and calculate SHA-256 hashes.

### Phase 2 — Memory analysis

Once a compatible memory image is available, use Volatility 3 to identify the image and inspect available artifacts. Depending on the image and plugin support, useful commands include:

```powershell
.\.venv\Scripts\vol.exe -f "<path-to-memory-image>" windows.info
.\.venv\Scripts\vol.exe -f "<path-to-memory-image>" windows.pslist
.\.venv\Scripts\vol.exe -f "<path-to-memory-image>" windows.pstree
.\.venv\Scripts\vol.exe -f "<path-to-memory-image>" windows.cmdline
.\.venv\Scripts\vol.exe -f "<path-to-memory-image>" windows.netscan
```

Replace `<path-to-memory-image>` with the actual path. These are examples, not completed commands or findings. Check the installed version's help and plugin availability, because supported commands and results depend on the evidence and Volatility version.

Save the real command output under `results/memory/`. Record errors as well as successful output. A missing process or artifact in one output does not prove it never existed.

### Phase 3 — Endpoint artifact analysis (if evidence is available)

If the case provides a suitable disk image or extracted Windows artifacts, select tools based on the evidence available:

- **FTK Imager:** inspect a supplied disk image and its filesystems.
- **KAPE:** collect or process selected Windows artifacts from a compatible source.
- **MFTECmd:** parse `$MFT` data.
- **PECmd:** parse Prefetch artifacts.
- **AmcacheParser:** parse supported Amcache data.
- **AppCompatCacheParser:** examine Shimcache/AppCompatCache-related data.
- **EvtxECmd:** parse Windows event logs.
- **Timeline Explorer:** review supported tabular output when useful.

Check each installed tool's own help and documentation for correct parameters. Do not claim that disk artifacts were analyzed if the case supplied only a memory image.

### Phase 4 — Correlation and timeline

Record each relevant event in `timeline/incident-timeline.csv`. Suggested fields include:

- Event ID
- Timestamp and timezone
- Source artifact
- Process or file
- Event description
- Evidence reference
- Confidence
- Interpretation
- Follow-up required

Correlate multiple sources where possible. Account for timezone differences, clock drift, timestamp semantics, and artifacts that do not prove execution on their own.

### Phase 5 — Findings and incident report

For every finding, include the observed fact, source artifact, supporting evidence, confidence, potential impact, and recommended next step. Keep severity separate from confidence.

Possible verdict categories include:

- Confirmed compromise
- Likely compromise
- Suspicious activity; compromise not established
- No evidence of compromise found in the examined artifacts
- Inconclusive due to insufficient or incompatible evidence

Choose a verdict only after reviewing the real evidence and state the scope and limitations of the investigation. The absence of evidence in the examined artifacts is not proof that an incident never occurred.

## Windows Artifacts: What They Can Tell You

| Artifact | Potential investigative value | Important limitation |
|---|---|---|
| Process tree | Shows process parent-child relationships recoverable from the memory image | A relationship can be suspicious without being malicious |
| Command-line data | May show arguments used to launch processes | Data can be missing or incomplete |
| Network artifacts | May identify connections or sockets represented in the capture | Not all historical network activity remains in memory |
| `$MFT` | Filesystem records and metadata for files and directories | Metadata must be interpreted carefully; it does not alone prove malicious execution |
| Prefetch | Can provide supporting evidence about program execution and related activity | Availability and contents vary; it is not a complete execution log |
| Amcache | May contain application inventory and compatibility-related information | Presence alone does not prove execution or maliciousness |
| Shimcache | May preserve compatibility-cache information about executable paths | It should not be treated as definitive proof of execution |
| Windows event logs | May document logon, process, service, or other system events, depending on logging configuration | Logging may be incomplete, disabled, rotated, or unavailable |

## Reporting Standards

The incident report should distinguish among:

- **Observation:** what the evidence directly shows.
- **Interpretation:** what the observation may mean.
- **Hypothesis:** a possible explanation that still needs testing.
- **Conclusion:** a finding supported by the evidence reviewed.

Record contradictions and unanswered questions. Map activity to [MITRE ATT&CK](https://attack.mitre.org/) only when the evidence supports the proposed technique. Include remediation recommendations proportionate to the findings.

## Security and Git Hygiene

Before making a Git commit, review `.gitignore` and the staged file list. Do not commit:

- Memory dumps or disk images
- Extracted personal or organizational data
- Credentials, access tokens, or other secrets
- Virtual environments or caches
- Large generated files or restricted challenge content

A suggested `.gitignore` should include entries for `.venv/`, `__pycache__/`, local evidence, and temporary analysis output. Commit only files that are appropriate to publish.

Publishing to GitHub is optional. Review the final repository contents and choose its visibility deliberately before uploading.

## Deliverables

The completed project is expected to contain:

- Environment and setup documentation
- Evidence inventory and integrity manifest
- Reproducible memory-analysis results
- Endpoint artifact results, if available
- An evidence-supported timeline
- A findings register
- A professional incident report
- Screenshots of genuine analysis results, if appropriate
- Validation output and a record of limitations

Until the investigation is run, these are planned deliverables rather than completed results.

## References

- [Volatility 3 documentation](https://volatility3.readthedocs.io/en/latest/)
- [CyberDefenders](https://cyberdefenders.org/)
- [DFIR Diva](https://dfirdiva.com/)
- [NIST CFTT](https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt)
- [FTK Imager — Exterro](https://www.exterro.com/ftk-imager)
- [KAPE — Kroll](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape)
- [Eric Zimmerman's forensic tools](https://ericzimmerman.github.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## Disclaimer

This is an educational portfolio project. Perform analysis only on evidence you are authorized to access. Do not use these procedures to access or investigate systems without permission. Findings and conclusions must be limited to the artifacts actually examined.
