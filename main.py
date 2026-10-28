import sys
from core.yara_scanner import YaraScanner
from extractors.xworm import XWormExtractor

def main(file_path):
    print(f"[*] Analyzing file: {file_path}")
    
    scanner = YaraScanner()
    matches = scanner.scan(file_path)
    
    if not matches:
        print("[-] No YARA rules matched. Unknown file.")
        return

    print(f"[+] Detected Families: {', '.join(matches)}")

    if "XWorm_Generic" in matches:
        print("[*] Launching XWorm Extractor...")
        extractor = XWormExtractor(file_path)
        result = extractor.extract()
        
        if result:
            print("\n[+] Extraction Successful!")
            print(result.model_dump_json(indent=4))
        else:
            print("[-] Failed to extract XWorm configuration.")
    else:
        print("[!] Extractor for this family is not built yet.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_sample>")
        sys.exit(1)
    
    main(sys.argv[1])
