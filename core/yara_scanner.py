import yara
import os

class YaraScanner:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        # Load all .yar files from the rules folder
        try:
            filepaths = {}
            if os.path.exists(self.rules_dir):
                for filename in os.listdir(self.rules_dir):
                    if filename.endswith(".yar"):
                        filepaths[filename] = os.path.join(self.rules_dir, filename)
                if filepaths:
                    self.rules = yara.compile(filepaths=filepaths)
        except Exception as e:
            print(f"[-] Error compiling YARA rules: {e}")

    def scan(self, file_path):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path)
            # Return a list of rule names that matched
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[-] Error scanning file: {e}")
            return []
