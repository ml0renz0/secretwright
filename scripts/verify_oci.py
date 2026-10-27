#!/usr/bin/env python3
"""Verify a bounded, self-contained two-platform Secretwright OCI archive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile


class VerificationError(Exception):
    """A fixed diagnostic that never includes artifact contents or paths."""


INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
          "application/vnd.oci.image.layer.v1.tar+zstd"}
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_BLOB_BYTES = 128 * 1024 * 1024
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_DESCRIPTORS = 128
MAX_DEPTH = 8
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOB_PATH = re.compile(r"blobs/sha256/[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,127}\Z")


def invalid():
    raise VerificationError("invalid or inconsistent OCI release artifact")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            invalid()
        result[key] = value
    return result


def member_name(member):
    name = member.name
    if name.startswith("./"):
        name = name[2:]
    if member.isdir():
        name = name.rstrip("/")
        if name in {"", "."}:
            return "."
    if not name or name.startswith("/") or "\\" in name or any(part in {"", ".", ".."} for part in name.split("/")):
        invalid()
    return name


def _verify_oci(path, version):
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        invalid()
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_ARCHIVE_BYTES:
        invalid()
    with open(path, "rb") as source:
        opened = os.fstat(source.fileno())
        if not os.path.samestat(info, opened):
            invalid()
        with tarfile.open(fileobj=source, mode="r:") as archive:
            members = {}
            total = 0
            for member in archive:
                if len(members) >= MAX_MEMBERS:
                    invalid()
                name = member_name(member)
                if name in members:
                    invalid()
                if member.isdir():
                    if name not in {".", "blobs", "blobs/sha256"}:
                        invalid()
                elif not member.isfile() or name not in {"oci-layout", "index.json"} and BLOB_PATH.fullmatch(name) is None:
                    invalid()
                if member.size < 0 or member.size > MAX_BLOB_BYTES or member.isdir() and member.size != 0:
                    invalid()
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    invalid()
                members[name] = member
            if "oci-layout" not in members or "index.json" not in members:
                invalid()

            # Hash every blob before considering its metadata. JSON documents
            # and layer bytes are both covered, including unused injected blobs.
            blobs = {name for name in members if name.startswith("blobs/sha256/")}
            for name in blobs:
                digest = hashlib.sha256()
                stream = archive.extractfile(members[name])
                remaining = members[name].size
                with stream:
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            invalid()
                        digest.update(chunk)
                        remaining -= len(chunk)
                if digest.hexdigest() != name.rsplit("/", 1)[1]:
                    invalid()

            def document(name):
                member = members.get(name)
                if member is None or not member.isfile() or member.size > MAX_DOCUMENT_BYTES:
                    invalid()
                with archive.extractfile(member) as stream:
                    body = stream.read(MAX_DOCUMENT_BYTES + 1)
                if len(body) != member.size:
                    invalid()
                value = json.loads(body, object_pairs_hook=unique_object,
                                   parse_constant=lambda _: invalid())
                if not isinstance(value, dict):
                    invalid()
                return value

            layout = document("oci-layout")
            if layout != {"imageLayoutVersion": "1.0.0"}:
                invalid()
            referenced = set()
            platforms = set()
            descriptors = 0

            def resolve(descriptor, allowed):
                nonlocal descriptors
                descriptors += 1
                if descriptors > MAX_DESCRIPTORS or not isinstance(descriptor, dict):
                    invalid()
                digest, size = descriptor.get("digest"), descriptor.get("size")
                if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None or type(size) is not int or size <= 0:
                    invalid()
                if descriptor.get("mediaType") not in allowed or descriptor.get("urls") or descriptor.get("data"):
                    invalid()
                name = "blobs/sha256/" + digest[7:]
                if name not in blobs or members[name].size != size:
                    invalid()
                referenced.add(name)
                return name

            def image(descriptor, name):
                platform = descriptor.get("platform")
                if not isinstance(platform, dict) or platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}:
                    invalid()
                architecture = platform["architecture"]
                if platform.get("variant") not in {None, "", "v8" if architecture == "arm64" else ""}:
                    invalid()
                identity = "linux/" + architecture
                if identity in platforms:
                    invalid()
                manifest = document(name)
                if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != MANIFEST:
                    invalid()
                config_name = resolve(manifest.get("config"), {CONFIG})
                config = document(config_name)
                if config.get("os") != "linux" or config.get("architecture") != architecture:
                    invalid()
                runtime = config.get("config")
                if not isinstance(runtime, dict) or runtime.get("User") != "65532:65532" or runtime.get("Entrypoint") != ["/usr/local/bin/secretwright"] or runtime.get("Cmd") != ["help"] or runtime.get("WorkingDir") != "/work":
                    invalid()
                labels = runtime.get("Labels")
                if not isinstance(labels, dict) or labels.get("org.opencontainers.image.version") != version:
                    invalid()
                if runtime.get("Volumes") or runtime.get("ExposedPorts"):
                    invalid()
                environment = runtime.get("Env", [])
                if not isinstance(environment, list) or any(not isinstance(item, str) or item.startswith("VAULT_") for item in environment):
                    invalid()
                layers = manifest.get("layers")
                rootfs = config.get("rootfs")
                if not isinstance(layers, list) or not layers or len(layers) > 64 or not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
                    invalid()
                diff_ids = rootfs.get("diff_ids")
                if not isinstance(diff_ids, list) or len(diff_ids) != len(layers) or any(not isinstance(value, str) or DIGEST.fullmatch(value) is None for value in diff_ids):
                    invalid()
                for layer in layers:
                    resolve(layer, LAYERS)
                platforms.add(identity)

            def index(value, depth):
                if depth > MAX_DEPTH or value.get("schemaVersion") != 2 or value.get("mediaType", INDEX) != INDEX:
                    invalid()
                children = value.get("manifests")
                if not isinstance(children, list) or not children or len(children) > 16:
                    invalid()
                for descriptor in children:
                    name = resolve(descriptor, {INDEX, MANIFEST})
                    if descriptor["mediaType"] == INDEX:
                        index(document(name), depth + 1)
                    else:
                        image(descriptor, name)

            index(document("index.json"), 0)
            if platforms != {"linux/amd64", "linux/arm64"} or referenced != blobs:
                invalid()
        after = os.fstat(source.fileno())
        current = os.lstat(path)
        if not os.path.samestat(opened, current) or not os.path.samestat(opened, after) or any(
                evidence.st_size != opened.st_size or evidence.st_mtime_ns != opened.st_mtime_ns
                for evidence in (after, current)):
            invalid()
    return {"version": version, "platforms": ["linux/amd64", "linux/arm64"]}


def verify_oci(path: Path, version: str) -> dict:
    """Validate without extracting any image files into the host filesystem."""
    try:
        return _verify_oci(Path(path), version)
    except VerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError, RecursionError, OverflowError):
        raise VerificationError("invalid or inconsistent OCI release artifact") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--version", required=True)
    options = parser.parse_args()
    try:
        report = verify_oci(options.archive, options.version)
    except VerificationError:
        print("invalid or inconsistent OCI release artifact", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
