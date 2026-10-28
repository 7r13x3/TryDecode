import re
import base64
import json
from core.maco_model import ExtractorModel, NetworkConfig

try:
    from dnlib.DotNet import ModuleDefMD
except ImportError:
    ModuleDefMD = None

class RedLineExtractor:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract(self):
        try:
            module = ModuleDefMD.Load(self.file_path)
        except Exception:
            return None

        extracted_strings = []
        for mtype in module.GetTypes():
            for method in mtype.Methods:
                if method.HasBody:
                    for ins in method.Body.Instructions:
                        if "ldstr" in str(ins):
                            val = str(ins).split(" ")[-1].strip('"')
                            extracted_strings.append(val)

        for string in extracted_strings:
            try:
                decoded = base64.b64decode(string).decode('utf-8', errors='ignore')
                if '"address"' in decoded and '"port"' in decoded:
                    config = json.loads(decoded)
                    return ExtractorModel(
                        family="RedLine Stealer",
                        network=[NetworkConfig(host=config.get("address"), port=int(config.get("port")))],
                        raw_config=config
                    )
            except Exception:
                continue

        return None
