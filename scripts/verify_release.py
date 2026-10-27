#!/usr/bin/env python3
"""Inspect a bounded release bundle without extracting or executing its files."""

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib


MAX_ARCHIVE = 128 << 20
MAX_BINARY = 128 << 20
MAX_DOCUMENT = 4 << 20
MAX_SBOM = 32 << 20
MAX_OCI = 512 << 20
MAX_MANIFEST = 64 << 10
PLATFORMS = tuple((system, machine) for system in ("linux", "darwin", "windows") for machine in ("amd64", "arm64"))
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.+-]*)\Z")


class VerificationError(Exception):
    """Controlled diagnostics never include paths, input bytes or upstream text."""


def fail(message="invalid or incomplete release bundle"):
    raise VerificationError(message)


def valid_version(version):
    if not isinstance(version, str) or len(version) > 128:
        return False
    match = SEMVER.fullmatch(version)
    return match is not None and not any(part.isdigit() and len(part) > 1 and part[0] == "0"
                                         for part in (match.group(4) or "").split("."))


def evidence(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
        fail("release artifacts must be bounded regular files")
    return info


def unchanged(first, second):
    return (first.st_dev, first.st_ino, first.st_mode, first.st_size, first.st_mtime_ns) == (
        second.st_dev, second.st_ino, second.st_mode, second.st_size, second.st_mtime_ns)


def read_regular(path, limit):
    before = evidence(path, limit)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        if not unchanged(before, os.fstat(source.fileno())):
            fail()
        body = source.read(limit + 1)
        if len(body) != before.st_size or not unchanged(before, os.fstat(source.fileno())):
            fail()
    if not unchanged(before, path.lstat()):
        fail()
    return body, before


def hash_regular(path, limit):
    before = evidence(path, limit)
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        if not unchanged(before, os.fstat(source.fileno())):
            fail()
        count = 0
        while chunk := source.read(1 << 20):
            count += len(chunk)
            if count > limit:
                fail()
            digest.update(chunk)
        if count != before.st_size or not unchanged(before, os.fstat(source.fileno())):
            fail()
    if not unchanged(before, path.lstat()):
        fail()
    return digest.hexdigest(), before


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("invalid release SBOM")
        result[key] = value
    return result


def reject_constant(_):
    fail("invalid release SBOM")


def verify_sbom(body, version):
    value = json.loads(body.decode("utf-8"), object_pairs_hook=strict_object, parse_constant=reject_constant)
    if not isinstance(value, dict) or value.get("spdxVersion") != "SPDX-2.3" or value.get("SPDXID") != "SPDXRef-DOCUMENT":
        fail("invalid release SBOM")
    creation = value.get("creationInfo")
    if (value.get("dataLicense") != "CC0-1.0" or not isinstance(value.get("name"), str) or not value["name"]
            or not isinstance(value.get("documentNamespace"), str) or not value["documentNamespace"]
            or not isinstance(creation, dict) or not isinstance(creation.get("created"), str) or not creation["created"]
            or not isinstance(creation.get("creators"), list) or not creation["creators"]
            or any(not isinstance(creator, str) or not creator for creator in creation["creators"])):
        fail("invalid release SBOM")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > 100000 or any(not isinstance(package, dict) for package in packages):
        fail("invalid release SBOM")
    identifiers = set()
    for package in packages:
        identifier = package.get("SPDXID")
        if (not isinstance(identifier, str) or not identifier.startswith("SPDXRef-") or identifier in identifiers
                or not isinstance(package.get("name"), str) or not package["name"]
                or not isinstance(package.get("downloadLocation"), str) or not package["downloadLocation"]):
            fail("invalid release SBOM")
        identifiers.add(identifier)
    application = any(package.get("name") in {"secretwright", "github.com/ml0renz0/secretwright"}
                      and package.get("versionInfo") == version for package in packages)
    vault = any(package.get("name") == "github.com/hashicorp/vault/api"
                and isinstance(package.get("versionInfo"), str) and package["versionInfo"] for package in packages)
    if not application or not vault:
        fail("release SBOM lacks the application identity or required dependency")


def verify_elf(body, machine):
    if len(body) < 64 or body[:7] != b"\x7fELF\x02\x01\x01":
        fail("invalid release executable format")
    kind, architecture, revision, _, offset, _, _, size, entry_size, entries, _, _, _ = struct.unpack_from("<HHIQQQIHHHHHH", body, 16)
    if kind not in (2, 3) or architecture != {"amd64": 62, "arm64": 183}[machine] or revision != 1 or size != 64:
        fail("invalid release executable platform")
    if not 0 < entries <= 128 or entry_size != 56 or offset < 64 or offset + entries * entry_size > len(body):
        fail("invalid release executable format")
    for index in range(entries):
        segment, _, file_offset, _, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", body, offset + index * entry_size)
        if file_offset + file_size > len(body):
            fail("invalid release executable format")
        if segment == 3:
            fail("Linux release executable requires a dynamic interpreter")
        if segment == 2:
            if file_size % 16:
                fail("invalid release executable format")
            for position in range(file_offset, file_offset + file_size, 16):
                tag, _ = struct.unpack_from("<QQ", body, position)
                if tag == 0:
                    break
                if tag == 1:
                    fail("Linux release executable requires a shared library")


def verify_macho(body, machine):
    if len(body) < 32:
        fail("invalid release executable format")
    magic, architecture, _, kind, commands, command_bytes, _, _ = struct.unpack_from("<IIIIIIII", body)
    if magic != 0xFEEDFACF or architecture != {"amd64": 0x01000007, "arm64": 0x0100000C}[machine] or kind != 2:
        fail("invalid release executable platform")
    if commands > 256 or 32 + command_bytes > len(body):
        fail("invalid release executable format")
    offset = 32
    for _ in range(commands):
        if offset + 8 > 32 + command_bytes:
            fail("invalid release executable format")
        _, length = struct.unpack_from("<II", body, offset)
        if length < 8 or offset + length > 32 + command_bytes:
            fail("invalid release executable format")
        offset += length
    if offset != 32 + command_bytes:
        fail("invalid release executable format")


def verify_pe(body, machine):
    if len(body) < 64 or body[:2] != b"MZ":
        fail("invalid release executable format")
    offset = struct.unpack_from("<I", body, 60)[0]
    if offset < 64 or offset + 24 > len(body) or body[offset:offset + 4] != b"PE\0\0":
        fail("invalid release executable format")
    architecture, sections, _, _, _, optional_size, flags = struct.unpack_from("<HHIIIHH", body, offset + 4)
    if architecture != {"amd64": 0x8664, "arm64": 0xAA64}[machine] or not flags & 2:
        fail("invalid release executable platform")
    if not 0 < sections <= 128 or optional_size < 112 or offset + 24 + optional_size + sections * 40 > len(body):
        fail("invalid release executable format")
    if struct.unpack_from("<H", body, offset + 24)[0] != 0x20B:
        fail("invalid release executable format")


def verify_executable(body, system, machine):
    {"linux": verify_elf, "darwin": verify_macho, "windows": verify_pe}[system](body, machine)


def verify_archive(body, system, machine):
    executable = "secretwright.exe" if system == "windows" else "secretwright"
    allowed = {executable, "README.md", "LICENSE"}
    seen = set()

    def member(name, mode, size, source):
        if name not in allowed or name in seen or size <= 0 or size > (MAX_BINARY if name == executable else MAX_DOCUMENT):
            fail("invalid release archive contents")
        if system != "windows" and mode != (0o755 if name == executable else 0o644):
            fail("invalid release archive permissions")
        seen.add(name)
        content = source.read(size + 1)
        if len(content) != size:
            fail("invalid release archive contents")
        if name == executable:
            verify_executable(content, system, machine)

    if system == "windows":
        # Bound central-directory object allocation before ZipFile parses it.
        end = body.rfind(b"PK\x05\x06", max(0, len(body) - 65557))
        if end < 0 or end + 22 > len(body):
            fail("invalid release archive")
        disk, directory_disk, disk_count, total, _, _, comment_size = struct.unpack_from("<HHHHIIH", body, end + 4)
        if disk or directory_disk or disk_count != 3 or total != 3 or end + 22 + comment_size != len(body):
            fail("invalid release archive contents")
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            for item in archive.infolist():
                kind = stat.S_IFMT(item.external_attr >> 16)
                if item.is_dir() or kind not in (0, stat.S_IFREG) or item.flag_bits & 1:
                    fail("invalid release archive contents")
                with archive.open(item) as source:
                    member(item.filename, (item.external_attr >> 16) & 0o7777, item.file_size, source)
    else:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            for item in archive:
                if not item.isfile() or item.issym() or item.islnk() or item.sparse is not None:
                    fail("invalid release archive contents")
                source = archive.extractfile(item)
                if source is None:
                    fail("invalid release archive contents")
                with source:
                    member(item.name, item.mode, item.size, source)
    if seen != allowed:
        fail("invalid release archive contents")


def container_verifier(path, version):
    spec = importlib.util.spec_from_file_location("secretwright_verify_oci", Path(__file__).with_name("verify_oci.py"))
    if spec is None or spec.loader is None:
        fail("container verification is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    try:
        return module.verify_oci(path, version)
    except module.VerificationError:
        fail("invalid release container image")


def _verify_release(directory, version, containers):
    if not valid_version(version) or not isinstance(containers, bool):
        fail("invalid release verification options")
    directory = Path(directory)
    if not stat.S_ISDIR(directory.lstat().st_mode):
        fail("release bundle directory is unavailable")
    expected = {}
    for system, machine in PLATFORMS:
        prefix = f"secretwright_{version}_{system}_{machine}"
        expected[prefix + (".zip" if system == "windows" else ".tar.gz")] = ("archive", system, machine)
        expected[prefix + ".spdx.json"] = ("sbom", system, machine)
    if containers:
        expected[f"secretwright_{version}_linux_multiarch.oci.tar"] = ("oci", "linux", "multiarch")
        for machine in ("amd64", "arm64"):
            expected[f"secretwright_{version}_linux_{machine}.image.spdx.json"] = ("sbom", "linux", machine)
    manifest_name = f"secretwright_{version}_checksums.txt"
    optional = {f"secretwright_{version}_checksums.sig", f"secretwright_{version}_signing-key.pem"}
    actual = set()
    for path in directory.iterdir():
        actual.add(path.name)
        if len(actual) > len(expected) + 1 + len(optional):
            fail("release bundle has missing or unexpected assets")
    if actual - (set(expected) | {manifest_name} | optional) or not (set(expected) | {manifest_name}) <= actual:
        fail("release bundle has missing or unexpected assets")
    proof = {}
    for name in actual & optional:
        proof[name] = evidence(directory / name, 16 << 10)
    manifest, proof[manifest_name] = read_regular(directory / manifest_name, MAX_MANIFEST)
    lines = manifest.decode("ascii").splitlines()
    matches = [MANIFEST_LINE.fullmatch(line) for line in lines]
    if any(match is None for match in matches):
        fail("invalid release checksum manifest")
    names = [match.group(2) for match in matches]
    if names != sorted(expected):
        fail("release checksum manifest must cover every asset exactly once")
    for match in matches:
        digest, name = match.groups()
        category, system, machine = expected[name]
        if category == "oci":
            computed, proof[name] = hash_regular(directory / name, MAX_OCI)
            if computed != digest:
                fail("release artifact checksum mismatch")
            container_verifier(directory / name, version)
        else:
            body, proof[name] = read_regular(directory / name, MAX_ARCHIVE if category == "archive" else MAX_SBOM)
            if hashlib.sha256(body).hexdigest() != digest:
                fail("release artifact checksum mismatch")
            if category == "archive":
                verify_archive(body, system, machine)
            else:
                verify_sbom(body, version)
    if any(not unchanged(info, (directory / name).lstat()) for name, info in proof.items()):
        fail("release assets changed during verification")
    return {"version": version, "archives": 6, "sboms": 8 if containers else 6,
            "artifacts": len(expected), "containers": containers,
            "platforms": [f"{system}/{machine}" for system, machine in PLATFORMS]}


def verify_release(directory: Path, version: str, *, containers: bool = True) -> dict:
    """Verify distribution bytes and metadata, leaving native execution to CI."""
    try:
        return _verify_release(directory, version, containers)
    except VerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError,
            struct.error, tarfile.TarError, zipfile.BadZipFile, zlib.error, RuntimeError, EOFError, RecursionError):
        raise VerificationError("invalid or incomplete release bundle") from None


class SafeParser(argparse.ArgumentParser):
    def error(self, _):
        fail("invalid release verification options")


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--without-containers", action="store_true")
    try:
        options = parser.parse_args()
        report = verify_release(options.directory, options.version, containers=not options.without_containers)
    except VerificationError as failure:
        print("Release verification failed: " + str(failure), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
