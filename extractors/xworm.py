import os
import hashlib
import base64
from Crypto.Cipher import AES
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

class XWormExtractor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.module = None
        self.mutex = None
        self.aes_key = None
        self.config_dict = {}

    def _load_assembly(self):
        try:
            self.module = ModuleDefMD.Load(self.file_path)
            return True
        except Exception as e:
            print(f"[-] Failed to load .NET assembly: {e}")
            return False

    def _derive_key(self):
        if not self.mutex:
            return
        md5 = hashlib.md5(self.mutex.encode('utf-8')).digest()
        self.aes_key = bytearray([0]*32)
        self.aes_key[0:16] = md5[0:16]
        self.aes_key[15:31] = md5[0:16]

    def _decrypt_value(self, encrypted_b64):
        try:
            cipher = AES.new(bytes(self.aes_key), AES.MODE_ECB)
            plaintext = cipher.decrypt(base64.b64decode(encrypted_b64))
            return "".join(chr(i) for i in plaintext if chr(i).isprintable())
        except Exception:
            return encrypted_b64

    def _extract_settings(self):
        target_type = None
        for mtype in self.module.GetTypes():
            if "Settings" in str(mtype.Name):
                target_type = mtype
                break
        
        if not target_type:
            for mtype in self.module.GetTypes():
                fields = [f.Name for f in mtype.Fields]
                if "Mutex" in fields and "Host" in fields:
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
                        
                        if "Mutex" in field_name:
                            self.mutex = value
                        else:
                            self.config_dict[field_name] = value
        return True

    def extract(self):
        if not self._load_assembly():
            return None

        if not self._extract_settings():
            print("[-] Could not locate XWorm Settings class.")
            return None

        print(f"[+] Found Mutex: {self.mutex}")
        self._derive_key()

        decrypted_config = {}
        for key, val in self.config_dict.items():
            decrypted_config[key] = self._decrypt_value(val)

        host = decrypted_config.get("Host") or decrypted_config.get("Hosts")
        port_str = decrypted_config.get("Port")
        port = int(port_str) if port_str and port_str.isdigit() else None

        result = ExtractorModel(
            family="XWorm",
            mutex=self.mutex,
            network=[NetworkConfig(host=host, port=port, protocol="TCP")] if host else [],
            raw_config=decrypted_config
        )
        return result
