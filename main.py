import sys
from core.yara_scanner import YaraScanner
from extractors.xworm import XWormExtractor
from extractors.asyncrat import AsyncRatExtractor
from extractors.quasarrat import QuasarRatExtractor
from preprocessors.upx import UPXUnpacker

def main(file_path):
    print(f"[*] Analyzing file: {file_path}")
    
    unpacker = UPXUnpacker(file_path)
    processed_file = unpacker.unpack()
    
    scanner = YaraScanner()
    matches = scanner.scan(processed_file)
    
    if not matches:
        print("[-] No YARA rules matched. Unknown file.")
        return

    print(f"[+] Detected Families: {', '.join(matches)}")

    result = None

    if "XWorm_Generic" in matches:
        print("[*] Launching XWorm Extractor...")
        extractor = XWormExtractor(processed_file)
        result = extractor.extract()
            
    elif "AsyncRAT_Generic" in matches:
        print("[*] Launching AsyncRAT Extractor...")
        extractor = AsyncRatExtractor(processed_file)
        result = extractor.extract()
            
    elif "QuasarRAT_Generic" in matches:
        print("[*] Launching QuasarRAT Extractor...")
        extractor = QuasarRatExtractor(processed_file)
        result = extractor.extract()

    if result:
        print("\n[+] Extraction Successful!")
        print(result.model_dump_json(indent=4))
    else:
        print("[-] Failed to extract configuration or extractor not built.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_sample>")
        sys.exit(1)
    
    main(sys.argv[1])
