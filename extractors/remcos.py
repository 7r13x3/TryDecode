import re
import base64
from Crypto.Cipher import ARC4
from core.maco_model import ExtractorModel, NetworkConfig

class RemcosExtractor:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
        except Exception:
            return None

        rc4_key_pattern = re.compile(rb'[A-Za-z0-9]{8,32}')
        key_match = rc4_key_pattern.search(data)
        
        if key_match:
            key = key_match.group(0)
            cipher = ARC4.new(key)
            decrypted_data = cipher.decrypt(data)
            
            host_match = re.search(rb'([a-zA-Z0-9\.\-]+):(\d+):', decrypted_data)
            if host_match:
                host = host_match.group(1).decode('utf-8', errors='ignore')
                port = int(host_match.group(2))
                return ExtractorModel(
                    family="Remcos",
                    network=[NetworkConfig(host=host, port=port, protocol="TCP")],
                    raw_config={"extracted_from": "RC4_block"}
                )
                
        host_match = re.search(rb'([a-zA-Z0-9\.\-]+):(\d+)', data)
        if host_match:
            host = host_match.group(1).decode('utf-8', errors='ignore')
            port = int(host_match.group(2))
            return ExtractorModel(
                family="Remcos",
                network=[NetworkConfig(host=host, port=port, protocol="TCP")],
                raw_config={"extracted_from": "plaintext"}
            )
            
        return None
