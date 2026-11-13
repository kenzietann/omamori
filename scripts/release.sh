#!/bin/sh
# Builds the release archives of Omamori into dist/: one for each system, a checksum file, and the
# release notes taken from CHANGELOG.md. Usage: scripts/release.sh v0.1.0
set -eu

tag="${1:?usage: scripts/release.sh v0.1.0}"
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "the tag must look like v0.1.0" >&2; exit 1 ;;
esac
version="${tag#v}"

# The notes are the section of CHANGELOG.md for this version. A release without notes is refused.
notes=$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' CHANGELOG.md)
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no section for $version" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="omamori_${version}_${os}_${arch}"
  mkdir -p "dist/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.stampedVersion=$version" -o "dist/$name/omamori" ./cmd/omamori
  cp README.md LICENSE CHANGELOG.md "dist/$name/"
  tar -C dist -czf "dist/$name.tar.gz" "$name"
  rm -rf "dist/${name:?}"
done

if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd dist && $sum ./*.tar.gz | sed 's| \./| |' > checksums.txt)
printf '%s\n' "$notes" > dist/notes.md
echo "Built Omamori $version:"
ls -1 dist
