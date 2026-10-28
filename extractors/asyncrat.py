import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from core.maco_model import ExtractorModel, NetworkConfig

try:
    import clr
    from dnlib.DotNet import ModuleDefMD
except ImportError:
    clr = None
    print("[-] Warning: pythonnet or dnlib not found. AsyncRAT Extractor will be disabled.")

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

    def _decrypt_value(self, encrypted_b64):
        try:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=b'\x00'*16)
            plaintext = cipher.decrypt(base64.b64decode(encrypted_b64))
            return unpad(plaintext, AES.block_size).decode('utf-8', errors='ignore')
        except Exception:
            return encrypted_b64

    def _extract_settings(self):
        target_type = None
        for mtype in self.module.GetTypes():
            if mtype.Name == "Settings":
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
                            decoded_key = base64.b64decode(value)
                            self.aes_key = hashlib.sha256(decoded_key).digest()
                        else:
                            self.config_dict[field_name] = value
        return True

    def extract(self):
        if not self._load_assembly():
            return None

        if not self._extract_settings():
            print("[-] Could not locate AsyncRAT Settings class.")
            return None

        decrypted_config = {}
        for key, val in self.config_dict.items():
            decrypted_config[key] = self._decrypt_value(val)

        hosts_str = decrypted_config.get("Hosts", "")
        ports_str = decrypted_config.get("Ports", "")
        
        host = hosts_str.split(",")[0] if hosts_str else None
        port_str = ports_str.split(",")[0] if ports_str else None
        port = int(port_str) if port_str and port_str.isdigit() else None

        result = ExtractorModel(
            family="AsyncRAT",
            network=[NetworkConfig(host=host, port=port, protocol="TCP")] if host else [],
            mutex=decrypted_config.get("Mutex"),
            raw_config=decrypted_config
        )
        
        return result
