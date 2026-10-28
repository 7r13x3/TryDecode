import sys
from core.yara_scanner import YaraScanner
from core.reporter import Reporter
from extractors.xworm import XWormExtractor
from extractors.asyncrat import AsyncRatExtractor
from extractors.quasarrat import QuasarRatExtractor
from extractors.redline import RedLineExtractor
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
        result = XWormExtractor(processed_file).extract()
            
    elif any(x in matches for x in ["AsyncRAT_Generic", "DcRAT_Generic", "VenomRAT_Generic"]):
        print("[*] Launching AsyncRAT Family Extractor...")
        result = AsyncRatExtractor(processed_file).extract()
            
    elif "QuasarRAT_Generic" in matches:
        print("[*] Launching QuasarRAT Extractor...")
        result = QuasarRatExtractor(processed_file).extract()

    elif "RedLine" in matches or "RedLine_Generic" in matches:
        print("[*] Launching RedLine Extractor...")
        result = RedLineExtractor(processed_file).extract()

    if result:
        print("\n[+] Extraction Successful!")
        print(result.model_dump_json(indent=4))
        
        reporter = Reporter()
        reporter.save(result, file_path)
    else:
        print("[-] Failed to extract configuration or extractor not built.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_sample>")
        sys.exit(1)
    
    main(sys.argv[1])
