import re
from core.maco_model import ExtractorModel, NetworkConfig

class DarkCometExtractor:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
        except Exception:
            return None

        fwb_matches = re.finditer(rb'FWB', data)
        for match in fwb_matches:
            start = match.end()
            chunk = data[start:start+500]
            if b'NET' in chunk or b'PORT' in chunk:
                host_match = re.search(rb'NET([^\x00]+)', chunk)
                port_match = re.search(rb'PORT(\d+)', chunk)
                
                host = host_match.group(1).decode('utf-8', errors='ignore').strip() if host_match else None
                port = int(port_match.group(1)) if port_match else None
                
                if host:
                    return ExtractorModel(
                        family="DarkComet",
                        network=[NetworkConfig(host=host, port=port, protocol="TCP")],
                        raw_config={"extracted_from": "FWB_delimiter"}
                    )
        return None
