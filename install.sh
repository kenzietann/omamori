#!/bin/sh
# Installs Omamori from a GitHub release: picks the archive for this system, checks its sha256 against
# checksums.txt of the same release, and puts the binary in a folder on the PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/kenzietann/omamori/main/install.sh | sh
#
# Settings (environment variables):
#   OMAMORI_VERSION      a version like v0.2.0 (default: the latest release)
#   OMAMORI_INSTALL_DIR  where the binary goes (default: /usr/local/bin if it can be written, else ~/.local/bin)
#   OMAMORI_BASE_URL     where the archives are (default: the GitHub release of that version; used by tests)
set -eu

repo="kenzietann/omamori"

fail() { echo "install: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is needed"
command -v tar >/dev/null 2>&1 || fail "tar is needed"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported system $(uname -s): Omamori has binaries for macOS and Linux" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported processor $(uname -m): Omamori has binaries for amd64 and arm64" ;;
esac

version="${OMAMORI_VERSION:-}"
if [ -z "$version" ]; then
  # The latest release is found through the redirect of /releases/latest, so no API token is needed.
  final=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
    fail "could not find the latest release; set OMAMORI_VERSION=v0.2.0"
  version="${final##*/}"
fi
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "the version must look like v0.2.0, got '$version'" ;;
esac
number="${version#v}"

base="${OMAMORI_BASE_URL:-https://github.com/$repo/releases/download/$version}"
name="omamori_${number}_${os}_${arch}"
archive="$name.tar.gz"

dir="${OMAMORI_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading Omamori $number for $os/$arch"
curl -fsSL -o "$tmp/$archive" "$base/$archive" || fail "could not download $base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "could not download $base/checksums.txt"

# The checksum line of this archive must exist and must match; nothing is installed otherwise.
want=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "checksums.txt has no entry for $archive"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$archive" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')
fi
[ "$got" = "$want" ] || fail "the checksum of $archive does not match (wanted $want, got $got); nothing was installed"

tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/$name/omamori" ] || fail "the archive has no omamori binary"

mkdir -p "$dir" || fail "cannot create $dir; set OMAMORI_INSTALL_DIR to a folder you can write"
if [ -w "$dir" ]; then
  install -m 0755 "$tmp/$name/omamori" "$dir/omamori"
else
  echo "$dir needs administrator rights."
  sudo install -m 0755 "$tmp/$name/omamori" "$dir/omamori"
fi

echo "Installed $("$dir/omamori" version) to $dir/omamori"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not on your PATH. Add it, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
