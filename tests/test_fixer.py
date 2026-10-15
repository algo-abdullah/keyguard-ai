import os
import shutil
import tempfile
import unittest

from fixer import verify


class FixerStage3Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="keyguard_stage3_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verifier_rejects_patch_that_keeps_secret(self):
        original = 'API_KEY = "AKIA_REDACTED"\nprint("ok")\n'
        patched = 'API_KEY = "AKIA_REDACTED"\nprint("ok")\n'
        checks = verify(original, patched, "AKIA_REDACTED", "API_KEY")
        self.assertFalse(checks["secret_removed"]["passed"])

    def test_verifier_rejects_broken_python(self):
        original = 'API_KEY = "AKIA_REDACTED"\nprint("ok")\n'
        patched = 'API_KEY = os.environ["API_KEY"\nprint("bad")\n'
        checks = verify(original, patched, "AKIA_REDACTED", "API_KEY")
        self.assertFalse(checks["syntax_ok"]["passed"])

    def test_verifier_rejects_patch_changing_more_than_3_lines(self):
        original = 'API_KEY = "AKIA_REDACTED"\nprint("a")\nprint("b")\nprint("c")\nprint("d")\n'
        patched = 'API_KEY = os.environ["API_KEY"]\nprint("x")\nprint("y")\nprint("z")\nprint("w")\n'
        checks = verify(original, patched, "AKIA_REDACTED", "API_KEY")
        self.assertFalse(checks["minimal_change"]["passed"])

    def test_verifier_passes_correct_patch(self):
        original = 'API_KEY = "AKIA_REDACTED"\nprint("ok")\n'
        patched = 'import os\nAPI_KEY = os.environ["API_KEY"]\nprint("ok")\n'
        checks = verify(original, patched, "AKIA_REDACTED", "API_KEY")
        self.assertTrue(checks["secret_removed"]["passed"])
        self.assertTrue(checks["env_var_present"]["passed"])
        self.assertTrue(checks["minimal_change"]["passed"])
        self.assertTrue(checks["syntax_ok"]["passed"])


if __name__ == "__main__":
    unittest.main()
