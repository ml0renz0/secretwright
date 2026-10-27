#!/usr/bin/env bash
set -euo pipefail
umask 077

# Checksums are the SHA-256 digests of these exact official GitHub release assets:
# https://api.github.com/repos/goreleaser/goreleaser/releases/tags/v2.19.0
# https://api.github.com/repos/anchore/syft/releases/tags/v1.55.0
readonly goreleaser_version=2.19.0
readonly goreleaser_sha256=ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b
readonly syft_version=1.55.0
readonly syft_sha256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d

if [[ $# -gt 1 || "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf '%s\n' 'Release tool installation requires Linux amd64 and an optional destination directory.' >&2
  exit 1
fi
tool_directory="${1:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/secretwright-release-tools}"
if [[ -z "$tool_directory" || "$tool_directory" == *$'\n'* || "$tool_directory" == *$'\r'* ]]; then
  printf '%s\n' 'Invalid release tool installation directory.' >&2
  exit 1
fi
temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT

install_tool() {
  local name="$1" version="$2" archive="$3" digest="$4" owner="$5"
  local download="$temporary/$name.tar.gz"
  curl --fail --silent --show-error --location --connect-timeout 15 --max-time 120 \
    --retry 2 --output "$download" \
    "https://github.com/$owner/releases/download/v$version/$archive"
  printf '%s  %s\n' "$digest" "$download" | sha256sum --check --status
  tar --extract --gzip --file "$download" --directory "$temporary" -- "$name"
  test -f "$temporary/$name" && test ! -L "$temporary/$name"
  mkdir -p -- "$tool_directory"
  install -m 0755 -- "$temporary/$name" "$tool_directory/$name"
}

install_tool goreleaser "$goreleaser_version" goreleaser_Linux_x86_64.tar.gz "$goreleaser_sha256" goreleaser/goreleaser
install_tool syft "$syft_version" "syft_${syft_version}_linux_amd64.tar.gz" "$syft_sha256" anchore/syft

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$tool_directory" >> "$GITHUB_PATH"
fi
printf '%s\n' "Installed checksum-verified GoReleaser $goreleaser_version and Syft $syft_version."
