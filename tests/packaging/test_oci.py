"""Independent OCI fixtures and adversarial acceptance for release images."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERSION = "1.2.3-rc.1+fixture"
INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def add_blob(members, value, media_type):
    body = json_bytes(value) if isinstance(value, dict) else value
    digest = hashlib.sha256(body).hexdigest()
    members["blobs/sha256/" + digest] = body
    return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(body)}


def oci_members(version=VERSION, architectures=("amd64", "arm64"), *, nested=True, change_config=None):
    """Build an OCI layout independently from the production verifier."""
    members = {"oci-layout": json_bytes({"imageLayoutVersion": "1.0.0"})}
    images = []
    for architecture in architectures:
        config = {
            "architecture": architecture,
            "os": "linux",
            "config": {
                "User": "65532:65532",
                "Entrypoint": ["/usr/local/bin/secretwright"],
                "Cmd": ["help"],
                "WorkingDir": "/work",
                "Labels": {"org.opencontainers.image.version": version},
            },
            "rootfs": {"type": "layers", "diff_ids": []},
        }
        if change_config:
            change_config(config, architecture)
        # A real, independent tar layer keeps the fixture useful to scanners
        # without borrowing an implementation-created image or binary.
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w") as layer_tar:
            content = ("independent OCI layer for " + architecture).encode()
            entry = tarfile.TarInfo("fixture")
            entry.size, entry.mode = len(content), 0o644
            layer_tar.addfile(entry, io.BytesIO(content))
        layer = layer_buffer.getvalue()
        config["rootfs"]["diff_ids"] = ["sha256:" + hashlib.sha256(layer).hexdigest()]
        config_descriptor = add_blob(members, config, CONFIG)
        layer_descriptor = add_blob(members, layer, LAYER)
        image = add_blob(members, {"schemaVersion": 2, "mediaType": MANIFEST,
                                  "config": config_descriptor, "layers": [layer_descriptor]}, MANIFEST)
        image["platform"] = {"os": "linux", "architecture": architecture}
        images.append(image)
    index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": images}
    if nested:
        inner = add_blob(members, index, INDEX)
        inner["annotations"] = {"org.opencontainers.image.ref.name": "secretwright:" + version}
        index = {"schemaVersion": 2, "mediaType": INDEX, "manifests": [inner]}
    members["index.json"] = json_bytes(index)
    return members


def write_oci(path, members, *, extra_entries=()):
    with tarfile.open(path, "w") as archive:
        for name, body in members.items():
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o644, len(body)
            archive.addfile(entry, io.BytesIO(body))
        for entry, body in extra_entries:
            archive.addfile(entry, io.BytesIO(body) if body is not None else None)


def write_valid_oci(path: Path, version: str) -> None:
    """Test-only fixture API shared with final release-bundle acceptance."""
    write_oci(path, oci_members(version))


class OCIReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("secretwright_verify_oci_test", ROOT / "scripts/verify_oci.py")
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="secretwright-oci-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "release.oci.tar"

    def verify(self, members=None, **options):
        write_oci(self.path, oci_members() if members is None else members, **options)
        return self.verifier.verify_oci(self.path, VERSION)

    def reject(self, members=None, **options):
        with self.assertRaises(self.verifier.VerificationError) as caught:
            self.verify(members, **options)
        self.assertNotIn("private-oci-marker", str(caught.exception))
        self.assertNotIn(str(self.path), str(caught.exception))

    def test_valid_flat_and_nested_multiarch_layouts(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                report = self.verify(oci_members(nested=nested))
                self.assertEqual(report["version"], VERSION)
                self.assertEqual(report["platforms"], ["linux/amd64", "linux/arm64"])

    def test_missing_duplicate_and_unexpected_platforms(self):
        for architectures in (("amd64",), ("amd64", "amd64"), ("amd64", "arm64", "s390x")):
            with self.subTest(architectures=architectures):
                self.reject(oci_members(architectures=architectures))

    def test_platform_descriptor_must_match_config(self):
        def mismatch(config, architecture):
            if architecture == "arm64":
                config["architecture"] = "amd64"
        self.reject(oci_members(change_config=mismatch))
        self.reject(oci_members(change_config=lambda config, _: config.update(os="windows")))

    def test_runtime_policy_and_version_are_enforced(self):
        changes = [
            lambda c: c.update(User="0:0"),
            lambda c: c.update(User=""),
            lambda c: c.update(Entrypoint=["/bin/sh", "-c"]),
            lambda c: c.update(Cmd=["version"]),
            lambda c: c.update(WorkingDir="/"),
            lambda c: c.update(Labels={"org.opencontainers.image.version": "wrong"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.reject(oci_members(change_config=lambda config, _: change(config["config"])))

    def test_missing_and_tampered_referenced_blobs(self):
        original = oci_members()
        for blob in [name for name in original if name.startswith("blobs/")]:
            for mutation in ("missing", "changed"):
                members = dict(original)
                if mutation == "missing":
                    members.pop(blob)
                else:
                    members[blob] = b"private-oci-marker"
                with self.subTest(blob_kind=blob[:12], mutation=mutation):
                    self.reject(members)

    def test_descriptor_size_digest_and_media_type_are_verified(self):
        for key, value in (("size", 1), ("size", -1), ("size", True),
                           ("digest", "sha512:" + "a" * 128),
                           ("digest", "sha256:" + "../private-oci-marker"),
                           ("mediaType", "application/private-oci-marker")):
            members = oci_members(nested=False)
            index = json.loads(members["index.json"])
            index["manifests"][0][key] = value
            members["index.json"] = json_bytes(index)
            with self.subTest(key=key):
                self.reject(members)

    def test_layout_and_index_documents_are_strict(self):
        for name, value in (("oci-layout", b'{}'), ("oci-layout", b'{"imageLayoutVersion":"9.0"}'),
                            ("index.json", b'{}'), ("index.json", b'[]'),
                            ("index.json", b'{"schemaVersion":2,"schemaVersion":1}'),
                            ("index.json", b'private-oci-marker')):
            members = oci_members()
            members[name] = value
            with self.subTest(name=name, value=value[:10]):
                self.reject(members)

    def test_archive_rejects_paths_duplicates_links_and_unlisted_files(self):
        for name in ("../private-oci-marker", "/private-oci-marker", "blobs/../private-oci-marker", "private-oci-marker"):
            members = oci_members()
            members[name] = b"private-oci-marker"
            self.reject(members)
        duplicate = tarfile.TarInfo("index.json")
        body = oci_members()["index.json"]
        duplicate.size = len(body)
        self.reject(extra_entries=[(duplicate, body)])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            entry = tarfile.TarInfo("blobs/sha256/" + "a" * 64)
            entry.type, entry.linkname = kind, "/private-oci-marker"
            self.reject(extra_entries=[(entry, None)])

    def test_oci_archive_itself_must_be_regular_and_not_a_symlink(self):
        target = self.path.with_name("private-oci-marker")
        write_valid_oci(target, VERSION)
        self.path.symlink_to(target)
        with self.assertRaises(self.verifier.VerificationError):
            self.verifier.verify_oci(self.path, VERSION)

    def test_cli_emits_only_safe_summary_or_static_failure(self):
        write_valid_oci(self.path, VERSION)
        command = [sys.executable, str(ROOT / "scripts/verify_oci.py"), str(self.path), "--version", VERSION]
        good = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(good.returncode, 0)
        self.assertEqual(good.stderr, "")
        self.assertEqual(json.loads(good.stdout)["platforms"], ["linux/amd64", "linux/arm64"])
        self.path.write_bytes(b"private-oci-marker")
        bad = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(bad.stdout, "")
        self.assertNotIn("private-oci-marker", bad.stderr)
        self.assertNotIn(str(self.path), bad.stderr)


if __name__ == "__main__":
    unittest.main()
