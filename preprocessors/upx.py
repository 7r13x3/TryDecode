import os
import subprocess
import tempfile
import pefile

class UPXUnpacker:
    def __init__(self, file_path, upx_path="upx.exe"):
        self.file_path = file_path
        self.upx_path = upx_path

    def is_upx_packed(self):
        try:
            pe = pefile.PE(self.file_path)
            for section in pe.sections:
                if b"UPX" in section.Name:
                    return True
        except Exception:
            pass
        return False

    def unpack(self):
        if not self.is_upx_packed():
            return self.file_path
            
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        local_upx = os.path.join(project_root, "upx.exe")
        
        if not os.path.exists(local_upx) and not os.path.exists(self.upx_path):
            print(f"[-] Warning: upx.exe not found in root directory. Skipping unpacking.")
            return self.file_path

        executable = local_upx if os.path.exists(local_upx) else self.upx_path

        try:
            temp_dir = tempfile.gettempdir()
            output_path = os.path.join(temp_dir, "unpacked_" + os.path.basename(self.file_path))
            
            print(f"[*] UPX detected. Unpacking to temporary file...")
            subprocess.run([executable, "-d", self.file_path, "-o", output_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[+] Successfully unpacked.")
            return output_path
            
        except subprocess.CalledProcessError:
            print(f"[-] UPX unpacking failed. The file might be corrupted or use a modified UPX.")
            return self.file_path
