import re
from core.maco_model import ExtractorModel, NetworkConfig

class NjratExtractor:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
        except Exception:
            return None

        host_match = re.search(rb'host=([a-zA-Z0-9\.\-]+)', data)
        port_match = re.search(rb'port=(\d+)', data)
        
        if not host_match:
            host_match = re.search(rb'host\x00=([a-zA-Z0-9\.\-]+)', data)
        if not port_match:
            port_match = re.search(rb'port\x00=(\d+)', data)

        host = host_match.group(1).decode('utf-8', errors='ignore') if host_match else None
        port = int(port_match.group(1)) if port_match else None

        if host or port:
            return ExtractorModel(
                family="njRAT",
                network=[NetworkConfig(host=host, port=port, protocol="TCP")] if host else [],
                raw_config={"extracted_from": "raw_bytes"}
            )
            
        return None
