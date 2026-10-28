import argparse
import sys
from core.yara_scanner import YaraScanner
from core.reporter import Reporter
from extractors.xworm import XWormExtractor
from extractors.asyncrat import AsyncRatExtractor
from extractors.quasarrat import QuasarRatExtractor
from extractors.redline import RedLineExtractor
from extractors.njrat import NjratExtractor
from extractors.darkcomet import DarkCometExtractor
from extractors.remcos import RemcosExtractor
from preprocessors.upx import UPXUnpacker

EXTRACTORS = {
    "XWorm_Generic": XWormExtractor,
    "AsyncRAT_Generic": AsyncRatExtractor,
    "DcRAT_Generic": AsyncRatExtractor,
    "VenomRAT_Generic": AsyncRatExtractor,
    "QuasarRAT_Generic": QuasarRatExtractor,
    "RedLine_Generic": RedLineExtractor,
    "njRAT_Generic": NjratExtractor,
    "DarkComet_Generic": DarkCometExtractor,
    "Remcos_Generic": RemcosExtractor,
}

def cmd_scan(args):
    scanner = YaraScanner()
    matches = scanner.scan(args.file)
    if matches:
        print(f"[+] Matches: {', '.join(matches)}")
    else:
        print("[-] No matches found.")

def cmd_extract(args):
    unpacker = UPXUnpacker(args.file)
    processed_file = unpacker.unpack()
    
    scanner = YaraScanner()
    matches = scanner.scan(processed_file)
    
    if not matches:
        print("[-] No YARA rules matched. Unknown file.")
        return

    result = None
    for match in matches:
        if match in EXTRACTORS:
            print(f"[*] Launching {match} extractor...")
            extractor_class = EXTRACTORS[match]
            result = extractor_class(processed_file).extract()
            if result:
                break

    if result:
        print("\n[+] Extraction Successful!")
        print(result.model_dump_json(indent=4))
        reporter = Reporter()
        reporter.save(result, args.file)
    else:
        print("[-] Failed to extract configuration.")

def cmd_unpack(args):
    unpacker = UPXUnpacker(args.file)
    output = unpacker.unpack()
    if output != args.file:
        print(f"[+] Unpacked to: {output}")
    else:
        print("[-] File was not packed or unpacking failed.")

def main():
    parser = argparse.ArgumentParser(description="TryDecode - RAT Configuration Extractor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file with YARA rules")
    scan_parser.add_argument("file", help="Path to the file")
    scan_parser.set_defaults(func=cmd_scan)

    extract_parser = subparsers.add_parser("extract", help="Extract configuration from a RAT sample")
    extract_parser.add_argument("file", help="Path to the file")
    extract_parser.set_defaults(func=cmd_extract)

    unpack_parser = subparsers.add_parser("unpack", help="Unpack a UPX-packed file")
    unpack_parser.add_argument("file", help="Path to the file")
    unpack_parser.set_defaults(func=cmd_unpack)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
