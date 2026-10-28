# TryDecode

**Automated configuration extraction and C2 traffic decryption for modern RAT families.**

TryDecode is a modular malware analysis framework designed to automate the triage, static configuration extraction, and network traffic decryption of modern Remote Access Trojans (RATs).

## Features
- **YARA Triage:** Automatically identifies the malware family before analysis.
- **Static Extraction:** Uses `dnlib` for .NET assemblies and Regex for legacy binaries.
- **Automatic Unpacking:** Detects UPX-packed samples and unpacks them before analysis.
- **Professional CLI:** Interactive command-line interface for scanning, extracting, and unpacking.
- **JSON Reporting:** Saves extracted configs in a clean JSON format in the `reports/` folder.

## Supported Families
- [x] XWorm
- [x] AsyncRAT
- [x] DcRAT
- [x] VenomRAT
- [x] QuasarRAT
- [x] RedLine Stealer
- [x] njRAT
- [x] DarkComet
- [x] Remcos

## Setup Instructions

1. Install the required Python libraries:
   `pip install -r requirements.txt`

2. Download Required Binaries:
   - **dnlib.dll**: Required for .NET parsing. Place it in the root directory.
   - **upx.exe**: Required for unpacking UPX samples. Place it in the root directory.

## Usage

TryDecode uses a subcommand-based CLI.

**Scan a file (YARA only):**
`python cli.py scan path/to/sample.exe`

**Extract configuration (Unpack -> YARA -> Extract -> Save Report):**
`python cli.py extract path/to/sample.exe`

**Unpack a UPX-packed file only:**
`python cli.py unpack path/to/sample.exe`
