#!/usr/bin/env bash
# Build local-only OCI and native acceptance images from verified archives.
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."
if [[ "$#" != 2 ]]; then
  echo 'Usage: build_container.sh DIST VERSION' >&2
  exit 1
fi
distribution="$1"
release_version="$2"
if [[ ! "$release_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,127}$ ]]; then
  echo 'Invalid container release version.' >&2
  exit 1
fi

command -v docker >/dev/null || { echo 'Docker with Buildx is required.' >&2; exit 1; }
docker buildx version >/dev/null

# This directory is exclusively owned by this invocation. Never reuse a staged
# context: a prior directory could contain private or unrelated input files.
stage=".container"
if ! mkdir "$stage"; then
  echo 'Container staging directory must not already exist.' >&2
  exit 1
fi
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  rm -rf "$stage"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "$distribution" "$release_version" "$stage" <<'PY_STAGE'
from pathlib import Path
import os
import stat
import struct
import sys
import tarfile

try:
    destination, version, stage = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    if not destination.is_dir() or (destination / ('secretwright_' + version + '_linux_multiarch.oci.tar')).exists():
        raise ValueError()
    for architecture, machine in [('amd64', 62), ('arm64', 183)]:
        source = destination / ('secretwright_' + version + '_linux_' + architecture + '.tar.gz')
        if not stat.S_ISREG(os.lstat(source).st_mode):
            raise ValueError()
        with tarfile.open(source, 'r:gz') as archive:
            entries = archive.getmembers()
            selected = [entry for entry in entries if entry.name == 'secretwright']
            if len(selected) != 1 or not selected[0].isfile() or not 64 <= selected[0].size <= 128 * 1024 * 1024:
                raise ValueError()
            with archive.extractfile(selected[0]) as stream:
                binary = stream.read(128 * 1024 * 1024 + 1)
            if len(binary) != selected[0].size or binary[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', binary, 18)[0] != machine:
                raise ValueError()
        directory = stage / ('linux_' + architecture)
        directory.mkdir(mode=0o700)
        with open(directory / 'secretwright', 'xb') as output:
            output.write(binary)
        os.chmod(directory / 'secretwright', 0o755)
except Exception:
    raise SystemExit('Could not stage validated Linux release binaries.') from None
PY_STAGE

# COPY-only images need no emulator. The OCI exporter includes exactly the two
# platforms; attestations are disabled here because signed SBOMs are assets.
docker buildx build --platform linux/amd64,linux/arm64 \
  --provenance=false --sbom=false --build-arg "VERSION=$release_version" \
  --tag secretwright:packaging-test \
  --output "type=oci,dest=$stage/image.oci.tar" .
python3 scripts/verify_oci.py "$stage/image.oci.tar" --version "$release_version"

native_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
case "$native_platform" in
  linux/amd64|linux/arm64) ;;
  *) echo 'Native container acceptance requires a Linux amd64 or arm64 Docker server.' >&2; exit 1 ;;
esac
docker buildx build --platform "$native_platform" --load \
  --provenance=false --sbom=false --build-arg "VERSION=$release_version" \
  --tag secretwright:packaging-test .

python3 - "$distribution" "$release_version" "$stage/image.oci.tar" <<'PY_PUBLISH'
from pathlib import Path
import os
import shutil
import sys

try:
    target = Path(sys.argv[1]) / ('secretwright_' + sys.argv[2] + '_linux_multiarch.oci.tar')
    with open(sys.argv[3], 'rb') as source, open(target, 'xb') as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(target, 0o644)
except Exception:
    raise SystemExit('Could not publish the new local OCI release artifact.') from None
PY_PUBLISH
echo 'Built and verified local multiarch OCI archive and native acceptance image; nothing was pushed.'
