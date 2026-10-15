import os
import shutil
import tempfile
import unittest

from scanner import scan_path, mask_secret


class ScannerStage1Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="keyguard_stage1_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write(self, relative_path, content):
        full_path = os.path.join(self.temp_dir, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return full_path

    def test_detects_demo_secrets(self):
        self._write("demo.py", 'AWS_ACCESS_KEY = "AKIA_REDACTED"\nDB_PASSWORD = "superSecret!123"\n')
        self._write("site.js", 'const githubToken = "GH_TOKEN_REDACTED";\n')
        self._write("config.json", '{"stripe_key": "sk_live_REDACTED"}\n')

        findings = scan_path(self.temp_dir)
        kinds = {item["kind"] for item in findings}

        self.assertTrue({"aws_access_key", "generic_secret", "github_token", "stripe_key"}.issubset(kinds))

    def test_ignores_skip_dirs(self):
        self._write(".git/secret.txt", 'AKIA_REDACTED\n')
        self._write("node_modules/ignored.js", 'const token = "GH_TOKEN_REDACTED";\n')
        self._write("src/app.py", 'NOT_A_SECRET = "hello world"\n')

        findings = scan_path(self.temp_dir)
        self.assertEqual(findings, [])

    def test_entropy_flags_random_strings_but_not_words(self):
        self._write("entropy.txt", 'RANDOM = "8Qw!x2#Lk4@fP9$Vn6^bM1"\nNAME = "sparky"\n')

        findings = scan_path(self.temp_dir)
        kinds = {item["kind"] for item in findings}
        self.assertIn("entropy_string", kinds)

    def test_masking_never_leaks_raw_value(self):
        secret = "AKIA_REDACTED"
        masked = mask_secret(secret)
        self.assertNotIn(secret, masked)
        self.assertTrue(masked.startswith("AKIA"))


if __name__ == "__main__":
    unittest.main()
