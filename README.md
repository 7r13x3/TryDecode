# TryDecode

**Automated configuration extraction and C2 traffic decryption for modern RAT families.**

TryDecode is a modular malware analysis framework designed to automate the triage, static configuration extraction, and network traffic decryption of modern Remote Access Trojans (RATs).

## Features
- **YARA Triage:** Automatically identifies the malware family before analysis.
- **Static .NET Extraction:** Uses `dnlib` to safely extract and decrypt settings (Mutex, C2, Ports) from .NET assemblies without executing them.
- **Automatic Unpacking:** Detects UPX-packed samples and unpacks them before analysis.
- **MACO Standardized Output:** Outputs extracted configs in a clean JSON format.

## Supported Families
- [x] XWorm (AES-ECB)
- [x] AsyncRAT (AES-256-CBC)
- [x] DcRAT (AsyncRAT Fork)
- [x] VenomRAT (AsyncRAT Fork)
- [x] QuasarRAT (AES-256-CBC)
- [x] RedLine Stealer (Base64 JSON Config)

## Setup Instructions

1. Install the required Python libraries:
   `pip install -r requirements.txt`

2. Download Required Binaries:
   - **dnlib.dll**: Required for .NET parsing. Place it in the root directory.
   - **upx.exe**: Required for unpacking UPX samples. Place it in the root directory.

## Usage

Run the main orchestrator script against a malware sample:
`python main.py path/to/sample.exe`

All extracted reports will be saved automatically to the `reports/` folder.
