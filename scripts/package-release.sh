#!/bin/sh
# Build an allowlisted source ZIP and checksums; no network access.
set -eu
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
version=${1-}
if [ "$#" -ne 1 ] || ! printf '%s\n' "$version" | awk '/^[0-9]+\.[0-9]+\.[0-9]+$/ {ok=1} END {exit !ok}'; then
    printf '%s\n' 'Usage: sh scripts/package-release.sh MAJOR.MINOR.PATCH' >&2
    exit 2
fi
sha256_files() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}
stage=$(mktemp -d "${TMPDIR:-/tmp}/brotli-release.XXXXXX")
trap 'rm -rf "$stage"' 0
trap 'exit 2' HUP INT TERM
mkdir -p "$stage/brotli-check" "$root/dist"
set -- check-brotli.sh test_shell.sh README.md VALIDATION.md CHANGELOG.md scripts/package-release.sh
if [ -f "$root/LICENSE" ]; then set -- "$@" LICENSE; fi
(cd "$root" && sha256_files "$@") > "$root/SHA256SUMS"
for file do
    mkdir -p "$(dirname "$stage/brotli-check/$file")"
    cp "$root/$file" "$stage/brotli-check/$file"
done
cp "$root/SHA256SUMS" "$stage/brotli-check/SHA256SUMS"
archive="brotli-check-v$version.zip"
rm -f "$root/dist/$archive"
(cd "$stage" && zip -q -r "$root/dist/$archive" brotli-check)
(cd "$root/dist" && sha256_files "$archive") > "$root/dist/SHA256SUMS"
printf 'Created dist/%s and dist/SHA256SUMS\n' "$archive"
