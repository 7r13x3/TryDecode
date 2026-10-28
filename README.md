<div align="center">
  <img src="assets/fucking_rat.png" width="220" alt="TryDecode Logo">
  
  <h1>TryDecode</h1>
  
  <p><b>Automated configuration extraction and C2 traffic decryption for modern RAT families.</b></p>
</div>

---

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
   ```bash
   pip install -r requirements.txt
