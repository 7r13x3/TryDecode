import os
import json

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save(self, result, file_path):
        file_name = os.path.basename(file_path) + "_report.json"
        out_path = os.path.join(self.output_dir, file_name)
        
        try:
            with open(out_path, "w") as f:
                json.dump(result.model_dump(), f, indent=4)
            print(f"[+] Report saved successfully to: {out_path}")
        except Exception as e:
            print(f"[-] Failed to save report: {e}")
