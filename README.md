# TryDecode

**Automated configuration extraction and C2 traffic decryption for modern RAT families.**

TryDecode is a modular malware analysis framework designed to automate the triage, static configuration extraction, and network traffic decryption of modern Remote Access Trojans (RATs).

## Features
- **YARA Triage:** Automatically identifies the malware family before analysis.
- **Static .NET Extraction:** Uses `dnlib` to safely extract and decrypt settings (Mutex, C2, Ports) from .NET assemblies without executing them.
- **MACO Standardized Output:** Outputs extracted configs in a JSON format compatible with enterprise pipelines.

## Supported Families
- [x] XWorm (Static Config Extraction)
- [ ] AsyncRAT (In Progress)
- [ ] QuasarRAT (Planned)

## Setup Instructions

1. Install the required Python libraries:
   `pip install -r requirements.txt`

2. Download `dnlib.dll`:
   The XWorm extractor relies on `dnlib` to parse .NET assemblies. You must download `dnlib.dll` (e.g., from the official dnlib GitHub releases or NuGet) and place it in the root directory of this project.

## Usage

Run the main orchestrator script against a malware sample:
`python main.py path/to/sample.exe`
