import importlib.util
import hashlib
import json
import struct
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
    def wheel(self, root, name, version="1", requirements=(), native=False):
        tag = "cp313-cp313-android_24_arm64_v8a" if native else "py2.py3-none-any"
        path = root / f"{name.replace('-', '_')}-{version}-{tag}.whl"
        prefix = f"{name.replace('-', '_')}-{version}.dist-info"
        with zipfile.ZipFile(path, "w") as wheel:
            wheel.writestr(prefix + "/METADATA", f"Name: {name}\nVersion: {version}\nRequires-Python: >=3.12\n" + "".join(f"Requires-Dist: {r}\n" for r in requirements))
            wheel.writestr(prefix + "/WHEEL", f"Wheel-Version: 1.0\nTag: {tag}\n")
            if native:
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<H", header, 18, 183)
                struct.pack_into("<Q", header, 32, 64)
                struct.pack_into("<HH", header, 54, 56, 1)
                wheel.writestr(name + "/_test.so", header + struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 16384))
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
                bundle.validate_graph(root)
            self.wheel(root, "android-dep")
            result = bundle.validate_graph(root)
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
                bundle.validate_graph(root)
            self.wheel(root, "extra-dep")
            self.assertEqual(len(bundle.validate_graph(root)["packages"]), 3)

    def test_duplicate_versions_do_not_form_a_qualified_closure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            self.root_wheel(root, ["dependency>=1"])
            self.wheel(root, "dependency", "1")
            self.wheel(root, "dependency", "2")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                bundle.validate_graph(root)

    def test_diamond_constraints_are_checked_in_both_traversal_orders(self):
        for order in (("left", "right"), ("right", "left")):
            with self.subTest(order=order), tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "wheels"
                root.mkdir()
                self.root_wheel(root, [f"{name}==1" for name in order])
                self.wheel(root, "left", requirements=["shared==1"])
                self.wheel(root, "right", requirements=["shared>=2"])
                self.wheel(root, "shared", "1")
                with self.assertRaisesRegex(ValueError, "shared>=2"):
                    bundle.validate_graph(root)

    def test_repeated_compatible_constraints_and_cycles_terminate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            self.root_wheel(root, ["left==1", "right==1"])
            self.wheel(root, "left", requirements=["shared>=1"])
            self.wheel(root, "right", requirements=["shared<2"])
            self.wheel(root, "shared", requirements=["left>=1"])
            self.assertEqual(len(bundle.validate_graph(root)["packages"]), 4)

    def bound_fixture(self, root):
        lock = json.loads(bundle.sources.LOCK.read_text())
        entries = {}
        requirements = []
        for name, source in lock["packages"].items():
            wheel = self.wheel(root, name, source["version"], native=True)
            report = bundle.sources.inspect_wheel(wheel)
            entries[report["name"]] = {k: report[k] for k in ("wheel", "version", "sha256")}
            requirements.append(f"{name}>=2" if name == "cffi" else f"{name}=={source['version']}")
        self.root_wheel(root, requirements)
        path = root.parent / "native-manifest.json"
        path.write_text(json.dumps({"schema": 1, "authority_pin_sha256": hashlib.sha256(str(bundle.sources.pin()).encode()).hexdigest(),
            "source_lock_sha256": bundle.lock_digest(bundle.sources.LOCK),
            "native_lock_sha256": bundle.lock_digest(bundle.sources.LOCK.with_name("android-authority-native.lock.json")), "wheels": entries}))
        return path

    def test_exact_native_manifest_binds_the_qualified_result(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            manifest = self.bound_fixture(root)
            result = bundle.verify(root, manifest)
            self.assertTrue(result["native_artifacts_bound"])
            self.assertEqual(result["status"], "available")
            self.assertFalse(result["hosting_accepted"])

    def test_freeze_requires_bound_artifacts_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            manifest = self.bound_fixture(root)
            self.wheel(root, "unused-package")
            output = root.parent / "requirements.txt"
            bundle.freeze(root, manifest, output)
            lines = output.read_text().splitlines()
            expected = sorted(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}"
                              for r in bundle.verify(root, manifest)["packages"])
            self.assertEqual(lines, expected)
            self.assertFalse(any("unused-package" in line for line in lines))
            with self.assertRaises(FileExistsError):
                bundle.freeze(root, manifest, output)
            self.assertEqual(output.read_text().splitlines(), expected)
            with zipfile.ZipFile(next(root.glob("cffi-*.whl")), "a") as wheel:
                wheel.writestr("modified.txt", "unreviewed")
            refused = root.parent / "refused.txt"
            with self.assertRaisesRegex(ValueError, "native artifact differs"):
                bundle.freeze(root, manifest, refused)
            self.assertFalse(refused.exists())

    def test_compatible_but_unreviewed_native_version_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            manifest = self.bound_fixture(root)
            old = next(root.glob("cffi-*.whl"))
            old.unlink()
            version = json.loads(bundle.sources.LOCK.read_text())["packages"]["cffi"]["version"] + ".post1"
            self.wheel(root, "cffi", version, native=True)
            self.assertEqual(bundle.validate_graph(root)["status"], "graph_valid")
            with self.assertRaisesRegex(ValueError, "native artifact differs"):
                bundle.verify(root, manifest)

    def test_same_version_different_bytes_cannot_replace_reviewed_native_wheel(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "wheels"
            root.mkdir()
            manifest = self.bound_fixture(root)
            with zipfile.ZipFile(next(root.glob("cffi-*.whl")), "a") as wheel:
                wheel.writestr("different-build.txt", "same version, different artifact")
            self.assertEqual(bundle.validate_graph(root)["status"], "graph_valid")
            with self.assertRaisesRegex(ValueError, "native artifact differs"):
                bundle.verify(root, manifest)


if __name__ == "__main__":
    unittest.main()
