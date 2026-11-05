import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).parents[1]))
try:
    import android_authority_bundle as bundle
finally:
    sys.path.pop(0)


class BundleTests(unittest.TestCase):
    def wheel(self, root, name, version="1", requirements=()):
        tag = "py2.py3-none-any"
        path = root / f"{name.replace('-', '_')}-{version}-{tag}.whl"
        prefix = f"{name.replace('-', '_')}-{version}.dist-info"
        with zipfile.ZipFile(path, "w") as wheel:
            wheel.writestr(prefix + "/METADATA", f"Name: {name}\nVersion: {version}\nRequires-Python: >=3.12\n" + "".join(f"Requires-Dist: {r}\n" for r in requirements))
            wheel.writestr(prefix + "/WHEEL", f"Wheel-Version: 1.0\nTag: {tag}\n")
        return path

    def root_wheel(self, root, requirements):
        pin = bundle.sources.pin()
        return self.wheel(root, pin.name, next(iter(pin.specifier)).version, requirements)

    def test_android_dependencies_are_required_and_windows_markers_are_not(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            self.root_wheel(root, ['android-dep==1; sys_platform=="android"', 'windows-dep==1; sys_platform=="win32"'])
            with self.assertRaisesRegex(ValueError, "android-dep"):
                bundle.verify(root)
            self.wheel(root, "android-dep")
            result = bundle.verify(root)
            self.assertEqual(len(result["packages"]), 2)
            self.assertEqual(result["target_marker_environment"]["sys_platform"], "android")
            self.assertFalse(result["hosting_accepted"])

    def test_python_target_and_requested_extras_are_checked_transitively(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            self.root_wheel(root, ["dependency[read]==1"])
            self.wheel(root, "dependency", requirements=['extra-dep==1; extra=="read" and python_version>="3.13"'])
            with self.assertRaisesRegex(ValueError, "extra-dep"):
                bundle.verify(root)
            self.wheel(root, "extra-dep")
            self.assertEqual(len(bundle.verify(root)["packages"]), 3)

    def test_duplicate_versions_do_not_form_a_qualified_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            self.root_wheel(root, ["dependency>=1"])
            self.wheel(root, "dependency", "1")
            self.wheel(root, "dependency", "2")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                bundle.verify(root)


if __name__ == "__main__":
    unittest.main()
