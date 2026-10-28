import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from core.maco_model import ExtractorModel, NetworkConfig

try:
    from dnlib.DotNet import ModuleDefMD
except ImportError:
    ModuleDefMD = None

class QuasarRatExtractor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.module = None
        self.aes_key = None
        self.config_dict = {}

    def _load_assembly(self):
        try:
            self.module = ModuleDefMD.Load(self.file_path)
            return True
        except Exception:
            return False

    def _decrypt(self, b64_data):
        try:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=b'\x00'*16)
            decrypted = cipher.decrypt(base64.b64decode(b64_data))
            return unpad(decrypted, AES.block_size).decode('utf-8', errors='ignore')
        except Exception:
            return b64_data

    def _extract_settings(self):
        target_type = None
        for mtype in self.module.GetTypes():
            if "Settings" in str(mtype.Name):
                target_type = mtype
                break
        
        if not target_type:
            return False

        constructors = [m for m in target_type.Methods if m.Name in (".cctor", ".ctor")]
        for constructor in constructors:
            if constructor.HasBody:
                ins = constructor.Body.Instructions
                for i in range(len(ins) - 1):
                    if "ldstr" in str(ins[i]) and "stsfld" in str(ins[i+1]):
                        field_name = str(ins[i+1]).split("::")[-1]
                        value = str(ins[i]).split(" ")[-1].strip('"')
                        
                        if field_name == "Key":
                            self.aes_key = hashlib.sha256(base64.b64decode(value)).digest()[:16]
                        else:
                            self.config_dict[field_name] = value
        return True

    def extract(self):
        if not self._load_assembly() or not self._extract_settings():
            return None

        decrypted_config = {}
        for key, val in self.config_dict.items():
            decrypted_config[key] = self._decrypt(val) if self.aes_key else val

        hosts = decrypted_config.get("Hosts", "")
        ports = decrypted_config.get("Ports", "")

        return ExtractorModel(
            family="QuasarRAT",
            network=[NetworkConfig(host=hosts.split(",")[0], port=int(ports.split(",")[0]))] if hosts and ports else [],
            mutex=decrypted_config.get("Mutex"),
            raw_config=decrypted_config
        )
