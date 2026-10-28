import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from core.maco_model import ExtractorModel, NetworkConfig

try:
    import clr
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dll_path = os.path.join(root_dir, "dnlib.dll")
    if os.path.exists(dll_path):
        clr.AddReference(dll_path)
    else:
        print("[-] CRITICAL: dnlib.dll not found in the root directory.")
    from dnlib.DotNet import ModuleDefMD
except ImportError:
    ModuleDefMD = None
    print("[-] Warning: pythonnet or dnlib not found. Extractor disabled.")

class AsyncRatExtractor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.module = None
        self.aes_key = None
        self.config_dict = {}

    def _load_assembly(self):
        try:
            self.module = ModuleDefMD.Load(self.file_path)
            return True
        except Exception as e:
            print(f"[-] Failed to load .NET assembly: {e}")
            return False

    def _derive_key(self, b64_key):
        try:
            decoded = base64.b64decode(b64_key)
            return hashlib.sha256(decoded).digest()
        except Exception:
            return None

    def _decrypt(self, b64_data):
        if not self.aes_key:
            return b64_data
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
                        
                        if field_name == "Key" or field_name == "AuthKey":
                            self.aes_key = self._derive_key(value)
                        else:
                            self.config_dict[field_name] = value
        return True

    def extract(self):
        if not self._load_assembly() or not self._extract_settings():
            return None

        decrypted_config = {}
        for key, val in self.config_dict.items():
            decrypted_config[key] = self._decrypt(val)

        host = decrypted_config.get("Hosts", "").split(",")[0]
        port_str = decrypted_config.get("Ports", "").split(",")[0]
        port = int(port_str) if port_str.isdigit() else None

        return ExtractorModel(
            family="AsyncRAT/Venom/DcRAT",
            network=[NetworkConfig(host=host, port=port, protocol="TCP")] if host else [],
            mutex=decrypted_config.get("Mutex"),
            raw_config=decrypted_config
        )
