import fnmatch
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).parents[2] / ".github/workflows/android-authority-wheels.yml"


def matches(path, pattern):
    def parts_match(path, pattern):
        if not pattern:
            return not path
        if pattern[0] == "**":
            return any(parts_match(path[i:], pattern[1:]) for i in range(len(path) + 1))
        return bool(path) and fnmatch.fnmatchcase(path[0], pattern[0]) and parts_match(path[1:], pattern[1:])
    return parts_match(path.split("/"), pattern.split("/"))


class WorkflowPathTests(unittest.TestCase):
    def patterns(self):
        block = WORKFLOW.read_text().split("  pull_request:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0]
        return re.findall(r"^\s+- ['\"]([^'\"]+)['\"]\s*$", block, re.MULTILINE)

    def test_probe_only_change_and_its_regressions_trigger_source_qualification(self):
        patterns = self.patterns()
        for changed in ("scripts/probe-android-authority.py", "scripts/tests/test_android_authority_probe.py"):
            self.assertTrue(any(matches(changed, p) for p in patterns), changed)
        self.assertFalse(any(matches("README.md", p) for p in patterns))

    def test_executed_repository_scripts_and_key_inputs_cannot_silently_skip_gate(self):
        text = WORKFLOW.read_text()
        required = set(re.findall(r"scripts/[A-Za-z0-9_./-]+\.py", text)) | {
            "apps/connect/authority/core-requirements.txt", "scripts/check-android-apk.py",
            "scripts/tests/test_android_apk.py", "scripts/android-authority-native.lock.json",
            "scripts/android-authority-sources.lock.json", "scripts/android-authority-patches/example.patch",
            "apps/connect/authority/embedded/owner_adapter.py", "apps/connect/authority/embedded/state_storage.py",
            "apps/connect/authority/embedded/local_server.py", "apps/connect/authority/embedded/member_renewal.py",
            "apps/connect/authority/test_embedded_owner.py",
            "apps/connect/native/android/src/main/java/org/genesismesh/connect/authority/OwnerKeyVault.java",
        }
        for changed in required:
            self.assertTrue(any(matches(changed, p) for p in self.patterns()), changed)


if __name__ == "__main__":
    unittest.main()
