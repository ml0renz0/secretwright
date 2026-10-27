"""Acceptance tests for release bundles, independent of their build pipeline."""

from pathlib import Path
import hashlib
import importlib.util
import io
import json
import os
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_release", ROOT / "scripts" / "verify_release.py")
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)
VERSION = "1.2.3"
PLATFORMS = [(system, machine) for system in ("linux", "darwin", "windows") for machine in ("amd64", "arm64")]


def binary_fixture(system, machine):
    """Minimal independent executable headers; actual Go binaries are tested in CI."""
    if system == "linux":
        identity = b"\x7fELF\x02\x01\x01" + bytes(9)
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62 if machine == "amd64" else 183, 1,
                             0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 124, 124, 4096)
        return identity + header + segment + b"SW13"
    if system == "darwin":
        return struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007 if machine == "amd64" else 0x0100000C,
                           3 if machine == "amd64" else 0, 2, 0, 0, 0x00200000, 0)
    body = bytearray(512)
    body[:2] = b"MZ"
    struct.pack_into("<I", body, 0x3C, 128)
    body[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", body, 132, 0x8664 if machine == "amd64" else 0xAA64, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", body, 152, 0x20B)
    struct.pack_into("<H", body, 220, 3)
    return bytes(body)


def archive_name(system, machine, version=VERSION):
    extension = "zip" if system == "windows" else "tar.gz"
    return f"secretwright_{version}_{system}_{machine}.{extension}"


def sbom_name(system, machine, version=VERSION, image=False):
    suffix = ".image" if image else ""
    return f"secretwright_{version}_{system}_{machine}{suffix}.spdx.json"


def write_archive(directory, system, machine, *, version=VERSION, members=None):
    executable = "secretwright.exe" if system == "windows" else "secretwright"
    if members is None:
        members = [(executable, binary_fixture(system, machine), 0o755),
                   ("README.md", b"# Secretwright\n", 0o644), ("LICENSE", b"MIT License\n", 0o644)]
    destination = directory / archive_name(system, machine, version)
    if system == "windows":
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, body, mode in members:
                    item = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                    item.create_system = 3
                    item.external_attr = (stat.S_IFREG | mode) << 16
                    archive.writestr(item, body)
    else:
        with tarfile.open(destination, "w:gz") as archive:
            for name, body, mode in members:
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(body), mode, 0
                archive.addfile(item, io.BytesIO(body))
    return destination


def spdx_fixture(version=VERSION):
    # Syft identifies the source separately from Go's main module (devel).
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "secretwright", "documentNamespace": "https://spdx.org/spdxdocs/secretwright-fixture",
        "creationInfo": {"creators": ["Tool: syft-1.55.0"], "created": "2026-01-01T00:00:00Z"},
        "documentDescribes": ["SPDXRef-Source"],
        "packages": [
            {"name": "secretwright", "SPDXID": "SPDXRef-Source", "versionInfo": version,
             "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
             "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"},
            {"name": "github.com/ml0renz0/secretwright", "SPDXID": "SPDXRef-MainModule",
             "versionInfo": "(devel)", "downloadLocation": "NOASSERTION", "filesAnalyzed": False},
            {"name": "github.com/hashicorp/vault/api", "SPDXID": "SPDXRef-VaultAPI", "versionInfo": "v1.23.0",
             "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                               "referenceLocator": "pkg:golang/github.com/hashicorp/vault/api@v1.23.0"}]},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Source", "relationshipType": "DESCRIBES"},
            {"spdxElementId": "SPDXRef-Source", "relatedSpdxElement": "SPDXRef-MainModule", "relationshipType": "CONTAINS"},
            {"spdxElementId": "SPDXRef-MainModule", "relatedSpdxElement": "SPDXRef-VaultAPI", "relationshipType": "DEPENDS_ON"},
        ],
    }


def rewrite_manifest(directory, version=VERSION):
    assets = [path for path in directory.iterdir() if path.is_file() and
              (path.name.endswith((".tar.gz", ".zip", ".spdx.json", ".oci.tar")))]
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(assets)]
    destination = directory / f"secretwright_{version}_checksums.txt"
    destination.write_text("".join(lines), encoding="ascii")
    return destination


def write_bundle(directory, version=VERSION):
    for system, machine in PLATFORMS:
        write_archive(directory, system, machine, version=version)
        (directory / sbom_name(system, machine, version)).write_text(json.dumps(spdx_fixture(version)))
    return rewrite_manifest(directory, version)


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secretwright-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.manifest = write_bundle(self.directory)

    def verify(self):
        return VERIFY.verify_release(self.directory, VERSION, containers=False)

    def rejected(self, *, containers=False):
        with self.assertRaises(VERIFY.VerificationError) as failure:
            VERIFY.verify_release(self.directory, VERSION, containers=containers)
        diagnostic = str(failure.exception)
        self.assertNotIn(str(self.directory), diagnostic)
        self.assertNotIn("private-fixture-marker", diagnostic)

    def replace_binary(self, system, machine, body, mode=0o755):
        name = "secretwright.exe" if system == "windows" else "secretwright"
        write_archive(self.directory, system, machine, members=[
            (name, body, mode), ("README.md", b"# Secretwright\n", 0o644), ("LICENSE", b"MIT License\n", 0o644)])
        rewrite_manifest(self.directory)

    def test_all_six_platforms_and_spdx_accept_main_module_devel(self):
        summary = self.verify()
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary.get("version"), VERSION)
        self.assertEqual(len(self.manifest.read_text().splitlines()), 12)
        self.assertNotIn(str(self.directory), json.dumps(summary))

    def test_prerelease_version_is_supported_without_v_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            version = "2.0.0-rc.1"
            write_bundle(directory, version)
            self.assertEqual(VERIFY.verify_release(directory, version, containers=False).get("version"), version)

    def test_snapshot_semver_source_version_is_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            version = "0.0.0-snapshot.1234abc"
            write_bundle(directory, version)
            self.assertEqual(VERIFY.verify_release(directory, version, containers=False).get("version"), version)

    def test_default_final_bundle_requires_container_assets(self):
        self.rejected(containers=True)

    def test_archive_and_sbom_tampering_fail_the_existing_manifest(self):
        for filename in [archive_name("linux", "amd64"), sbom_name("windows", "arm64")]:
            with self.subTest(filename=filename):
                path = self.directory / filename
                original = path.read_bytes()
                path.write_bytes(original + b"private-fixture-marker")
                self.rejected()
                path.write_bytes(original)

    def test_missing_or_unlisted_distributable_is_rejected(self):
        path = self.directory / archive_name("darwin", "arm64")
        body = path.read_bytes()
        path.unlink()
        self.rejected()
        path.write_bytes(body)
        extra = self.directory / "private-fixture-marker.zip"
        extra.write_bytes(b"not a release asset")
        self.rejected()
        rewrite_manifest(self.directory)
        self.rejected()

    def test_manifest_rejects_duplicates_unsorted_entries_and_unsafe_names(self):
        original = self.manifest.read_text()
        lines = original.splitlines(keepends=True)
        for changed in [original + lines[0], "".join(reversed(lines)),
                        original.replace("  secretwright_", "  ../secretwright_", 1),
                        original.replace("  secretwright_", "  /secretwright_", 1),
                        original.replace("  secretwright_", "  nested/secretwright_", 1),
                        original.replace(lines[0][:64], lines[0][:64].upper(), 1)]:
            with self.subTest(change=changed[:8]):
                self.manifest.write_text(changed)
                self.rejected()
        self.manifest.write_text(original)

    def test_artifacts_and_manifest_must_be_regular_not_symlinks(self):
        for path in [self.directory / archive_name("linux", "amd64"),
                     self.directory / sbom_name("linux", "amd64"), self.manifest]:
            with self.subTest(asset=path.name):
                body = path.read_bytes()
                backing = self.directory / "private-fixture-marker"
                backing.write_bytes(body)
                path.unlink()
                path.symlink_to(backing)
                self.rejected()
                path.unlink()
                path.write_bytes(body)
                backing.unlink()

    def test_named_asset_directory_is_not_a_regular_artifact(self):
        path = self.directory / archive_name("linux", "arm64")
        path.unlink()
        path.mkdir()
        self.rejected()

    def test_archives_require_exact_member_names_without_links_or_duplicates(self):
        for system in ["linux", "windows"]:
            executable = "secretwright.exe" if system == "windows" else "secretwright"
            base = [(executable, binary_fixture(system, "amd64"), 0o755),
                    ("README.md", b"readme", 0o644), ("LICENSE", b"MIT", 0o644)]
            for invalid in ["../private-fixture-marker", "/private-fixture-marker", "nested/secretwright",
                            "private-fixture-marker", "README.md", "C:\\private-fixture-marker"]:
                with self.subTest(system=system, name=invalid):
                    write_archive(self.directory, system, "amd64", members=base + [(invalid, b"marker", 0o644)])
                    rewrite_manifest(self.directory)
                    self.rejected()
            write_archive(self.directory, system, "amd64")
        rewrite_manifest(self.directory)

    def test_tar_symbolic_and_hard_links_cannot_replace_the_binary(self):
        destination = self.directory / archive_name("linux", "amd64")
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE]:
            with self.subTest(kind=kind):
                with tarfile.open(destination, "w:gz") as archive:
                    item = tarfile.TarInfo("secretwright")
                    item.type, item.linkname, item.mode = kind, "private-fixture-marker", 0o755
                    archive.addfile(item)
                    for name in ["README.md", "LICENSE"]:
                        item = tarfile.TarInfo(name)
                        item.size, item.mode = 3, 0o644
                        archive.addfile(item, io.BytesIO(b"doc"))
                rewrite_manifest(self.directory)
                self.rejected()

    def test_zip_symlink_cannot_replace_the_binary(self):
        destination = self.directory / archive_name("windows", "amd64")
        with zipfile.ZipFile(destination, "w") as archive:
            item = zipfile.ZipInfo("secretwright.exe")
            item.create_system, item.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
            archive.writestr(item, "private-fixture-marker")
            archive.writestr("README.md", "doc")
            archive.writestr("LICENSE", "doc")
        rewrite_manifest(self.directory)
        self.rejected()

    def test_unix_archive_requires_exact_executable_and_document_modes(self):
        for binary_mode, document_mode in [(0o644, 0o644), (0o777, 0o644), (0o4755, 0o644), (0o755, 0o666)]:
            with self.subTest(binary_mode=binary_mode, document_mode=document_mode):
                write_archive(self.directory, "linux", "amd64", members=[
                    ("secretwright", binary_fixture("linux", "amd64"), binary_mode),
                    ("README.md", b"doc", document_mode), ("LICENSE", b"MIT", 0o644)])
                rewrite_manifest(self.directory)
                self.rejected()

    def test_platform_and_machine_are_checked_in_binary_not_filename(self):
        for system, machine in PLATFORMS:
            with self.subTest(system=system, machine=machine):
                other = "arm64" if machine == "amd64" else "amd64"
                self.replace_binary(system, machine, binary_fixture(system, other))
                self.rejected()
                self.replace_binary(system, machine, binary_fixture(system, machine))
        self.replace_binary("linux", "amd64", binary_fixture("windows", "amd64"))
        self.rejected()

    def test_truncated_invalid_and_32_bit_executable_headers_are_rejected(self):
        for system in ["linux", "darwin", "windows"]:
            for body in [b"", b"private-fixture-marker", binary_fixture(system, "amd64")[:12]]:
                with self.subTest(system=system, size=len(body)):
                    self.replace_binary(system, "amd64", body)
                    self.rejected()
            self.replace_binary(system, "amd64", binary_fixture(system, "amd64"))
        body = bytearray(binary_fixture("linux", "amd64"))
        body[4] = 1
        self.replace_binary("linux", "amd64", bytes(body))
        self.rejected()

    def test_linux_dynamic_interpreter_is_rejected(self):
        body = bytearray(binary_fixture("linux", "amd64"))
        struct.pack_into("<I", body, 64, 3)  # PT_INTERP instead of PT_LOAD.
        self.replace_binary("linux", "amd64", bytes(body))
        self.rejected()

    def test_linux_dynamic_needed_library_is_rejected(self):
        identity = b"\x7fELF\x02\x01\x01" + bytes(9)
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 218, 218, 4096)
        dynamic = struct.pack("<IIQQQQQQ", 2, 6, 176, 0x4000B0, 0x4000B0, 32, 32, 8)
        needed = struct.pack("<QQQQ", 1, 1, 0, 0)  # DT_NEEDED then DT_NULL.
        self.replace_binary("linux", "amd64", identity + header + load + dynamic + needed + b"libc.so.6\0")
        self.rejected()

    def test_sbom_requires_supported_spdx_application_version_and_vault_dependency(self):
        destination = self.directory / sbom_name("linux", "amd64")
        invalid = []
        document = spdx_fixture(); document["spdxVersion"] = "SPDX-2.2"; invalid.append(document)
        document = spdx_fixture(); document["packages"][0]["versionInfo"] = "9.9.9"; invalid.append(document)
        document = spdx_fixture(); document["packages"][0]["name"] = "private-fixture-marker"; invalid.append(document)
        document = spdx_fixture(); document["packages"] = document["packages"][:2]; invalid.append(document)
        invalid.extend([{}, [], "private-fixture-marker"])
        for document in invalid:
            with self.subTest(document_type=type(document).__name__):
                destination.write_text(json.dumps(document))
                rewrite_manifest(self.directory)
                self.rejected()
        destination.write_text('{"private-fixture-marker":')
        rewrite_manifest(self.directory)
        self.rejected()

    def test_invalid_release_version_cannot_select_paths_or_echo_input(self):
        for version in ["", "v1.2.3", "01.2.3", "1.2", "../private-fixture-marker", "1.2.3\nprivate-fixture-marker"]:
            with self.subTest(version=version[:5]):
                with self.assertRaises(VERIFY.VerificationError) as failure:
                    VERIFY.verify_release(self.directory, version, containers=False)
                self.assertNotIn("private-fixture-marker", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
