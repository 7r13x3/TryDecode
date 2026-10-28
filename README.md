<div align="center">
  <img src="assets/fucking_rat.png" width="280" alt="TryDecode Logo">
  
  <h1>TryDecode</h1>
  
  <p><b>Automated configuration extraction and C2 traffic decryption for modern RAT families.</b></p>

  <a href="https://github.com/7r13x3/TryDecode/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey.svg" alt="Platform">
</div>

---

## 📖 Overview

**TryDecode** is a modular malware analysis framework designed to automate the triage, static configuration extraction, and network traffic decryption of modern Remote Access Trojans (RATs). Built for speed and reliability, it processes packed samples and outputs clean, standardized JSON reports for seamless integration into SIEMs and SOAR platforms.

### 🔄 Workflow Pipeline
```text
[ Sample.exe ]  ──>  [ UPX Unpacker ]  ──>  [ YARA Triage ]
                                                    │
[ JSON Report ] <──  [ MACO Formatter ] <──  [ Static Extractor ]
