import importlib.util
import json
from pathlib import Path
import sys
import unittest


class EngineCheckTests(unittest.TestCase):
    @unittest.skipIf(hasattr(sys, "getandroidapilevel"), "Desktop refusal gate")
    def test_desktop_execution_cannot_claim_android_or_hosting_acceptance(self):
        path = Path(__file__).parents[2] / "spikes/android-authority/src/main/python/authority_check.py"
        spec = importlib.util.spec_from_file_location("engine_check", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = json.loads(module.run("not-a-real-core-version"))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stage"], "Android runtime")
        self.assertFalse(report["authority_hosting_accepted"])
        self.assertEqual(report["checks"], [])


if __name__ == "__main__":
    unittest.main()
