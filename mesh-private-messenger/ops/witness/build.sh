#!/usr/bin/env bash
# Builds the witness reproducibly: the binary and the OCI image for one
# platform, then writes SHA256SUMS (binary, image archive, image digest) and
# BUILDINFO (every input). Two builds from the same inputs give the same sums;
# --verify builds the binary twice without cache and fails if they differ.
#
#   ops/witness/build.sh [--platform linux/amd64|linux/arm64] [--verify]
#
# MESH_LANG_REVISION  mesh-lang commit to build meshc from (default: the newest
#                     published Mesh release). It must have File.rename and
#                     File.sync, which v0.1.8 and earlier lack.
# MESH_LANG_DIR       build meshc from this local checkout instead
#                     (development only: BUILDINFO marks the build unpinned).
# SOURCE_DATE_EPOCH   default: the commit time of the Morse revision.
# OUT                 output directory (default ops/witness/dist).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"
platform=linux/amd64
verify=false
while (($#)); do
  case "$1" in
    --platform) platform="$2"; shift 2 ;;
    --verify) verify=true; shift ;;
    *) echo "usage: $0 [--platform linux/amd64|linux/arm64] [--verify]" >&2; exit 2 ;;
  esac
done
case "$platform" in
  linux/amd64 | linux/arm64) arch="${platform#linux/}" ;;
  *) echo "unsupported platform $platform" >&2; exit 2 ;;
esac
out="${OUT:-$script_dir/dist}"
mkdir -p "$out"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

morse_revision="$(git -C "$repo_root" rev-parse HEAD)"
morse_state=clean
if [[ -n "$(git -C "$repo_root" status --porcelain -- \
  mesh-private-messenger/packages/messenger-protocol \
  mesh-private-messenger/services/transparency-witness \
  mesh-private-messenger/ops/witness/Dockerfile \
  mesh-private-messenger/ops/witness/Dockerfile.dockerignore)" ]]; then
  morse_state="modified (not reproducible from $morse_revision)"
fi
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}"

mesh_source="$(mktemp -d "${TMPDIR:-/tmp}/morse-witness-mesh.XXXXXX")"
trap 'rm -rf "$mesh_source"' EXIT
if [[ -n "${MESH_LANG_DIR:-}" ]]; then
  # Tracked and untracked-but-not-ignored files, as the working tree has them.
  (cd "$MESH_LANG_DIR" && git ls-files -z --cached --others --exclude-standard \
    | while IFS= read -r -d '' file; do [[ -f "$file" ]] && printf '%s\0' "$file"; done \
    | tar --null -T - -cf -) | tar -C "$mesh_source" -xf -
  mesh_pin="local tree $MESH_LANG_DIR at $(git -C "$MESH_LANG_DIR" rev-parse HEAD 2>/dev/null || echo unknown), unpinned"
else
  revision="${MESH_LANG_REVISION:-$(node "$repo_root/mesh-private-messenger/scripts/mesh-release.mjs")}"
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "MESH_LANG_REVISION must be a 40-hex commit" >&2; exit 2; }
  git -C "$mesh_source" init -q
  git -C "$mesh_source" fetch -q --depth 1 https://github.com/snowdamiz/mesh-lang.git "$revision"
  git -C "$mesh_source" archive FETCH_HEAD | tar -C "$mesh_source" -xf -
  rm -rf "$mesh_source/.git"
  mesh_pin="github.com/snowdamiz/mesh-lang $revision"
fi

build() {
  docker buildx build \
    --platform "$platform" \
    --file "$script_dir/Dockerfile" \
    --build-context "mesh-lang=$mesh_source" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    "$@" \
    "$repo_root"
}

binary_dir="$out/binary-$arch"
build --target binary --output "type=local,dest=$binary_dir"
cp "$binary_dir/transparency-witness" "$out/transparency-witness-$arch"

if $verify; then
  build --no-cache --target binary --output "type=local,dest=$binary_dir.again"
  first="$(sha256 "$binary_dir/transparency-witness" | cut -d' ' -f1)"
  second="$(sha256 "$binary_dir.again/transparency-witness" | cut -d' ' -f1)"
  rm -rf "$binary_dir.again"
  if [[ "$first" != "$second" ]]; then
    echo "witness binary is not reproducible: $first != $second" >&2
    exit 1
  fi
  echo "reproducible: two uncached builds gave $first"
fi
rm -rf "$binary_dir"

image="$out/morse-witness-$arch.oci.tar"
build --target runtime \
  --output "type=oci,dest=$image,name=morse-witness:${morse_revision:0:12},rewrite-timestamp=true" \
  --metadata-file "$out/metadata-$arch.json"
digest="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1]))["containerimage.digest"])' \
  "$out/metadata-$arch.json")"
rm -f "$out/metadata-$arch.json"

(
  cd "$out"
  sha256 "transparency-witness-$arch" "morse-witness-$arch.oci.tar"
  # The OCI manifest digest: what `docker image ls --digests` and a registry show.
  echo "${digest#sha256:}  morse-witness-$arch@image"
) >"$out/SHA256SUMS-$arch"

cat >"$out/BUILDINFO-$arch" <<EOF
morse: $morse_revision ($morse_state)
mesh-lang: $mesh_pin
platform: $platform
source_date_epoch: $SOURCE_DATE_EPOCH
dockerfile_sha256: $(sha256 "$script_dir/Dockerfile" | cut -d' ' -f1)
EOF
cat "$out/SHA256SUMS-$arch" "$out/BUILDINFO-$arch"
