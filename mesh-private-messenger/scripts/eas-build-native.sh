#!/usr/bin/env bash
set -euo pipefail

# EAS runs this before npm install, prebuild, and CocoaPods need the archives.
[[ "${EAS_BUILD:-}" == true ]] || { echo 'Run this hook on an EAS build worker.' >&2; exit 1; }
case "${EAS_BUILD_PLATFORM:-}" in
  ios) targets=(aarch64-apple-ios aarch64-apple-ios-sim) ;;
  android) targets=(aarch64-linux-android x86_64-linux-android) ;;
  *) echo 'EAS_BUILD_PLATFORM must be ios or android.' >&2; exit 1 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
mesh_root="$repo_root/mesh-lang"
# Keep aligned with the compiler tested by .github/workflows/ci.yml.
mesh_revision="$(cat "$repo_root/mesh-private-messenger/mesh-revision")"
[[ "$mesh_revision" =~ ^[0-9a-f]{40}$ ]]
rust_version=1.97.0
llvm_version=21.1.8

# The separate compiler checkout is deliberately excluded from the EAS upload.
git init "$mesh_root"
git -C "$mesh_root" remote add origin https://github.com/snowdamiz/mesh-lang.git
git -C "$mesh_root" fetch --depth 1 origin "$mesh_revision"
git -C "$mesh_root" checkout --detach FETCH_HEAD
[[ "$(git -C "$mesh_root" rev-parse HEAD)" == "$mesh_revision" ]]

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    llvm_platform=macOS-ARM64
    llvm_sha256=b95bdd32a33a81ee4d40363aaeb26728a26783fcef26a4d80f65457433ea4669
    HOMEBREW_NO_AUTO_UPDATE=1 brew install pkgconf openssl@3 zstd
    ;;
  Linux-x86_64)
    llvm_platform=Linux-X64
    llvm_sha256=b3b7f2801d15d50736acea3c73982994d025b01c2f035b91ae3b49d1b575732b
    sudo apt-get update
    sudo apt-get install --no-install-recommends -y \
      build-essential pkg-config libssl-dev zlib1g-dev libzstd-dev libxml2-dev libtinfo-dev
    ;;
  *) echo 'Unsupported EAS worker architecture.' >&2; exit 1 ;;
esac
toolchain_dir="$(mktemp -d)"
archive="$toolchain_dir/llvm.tar.xz"
curl --fail --location --retry 3 \
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-$llvm_version/LLVM-$llvm_version-$llvm_platform.tar.xz" \
  --output "$archive"
printf '%s  %s\n' "$llvm_sha256" "$archive" | shasum -a 256 -c -
mkdir "$toolchain_dir/llvm"
tar -xf "$archive" --strip-components=1 -C "$toolchain_dir/llvm"
rm "$archive"
export LLVM_SYS_211_PREFIX="$toolchain_dir/llvm"

export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
    https://sh.rustup.rs --output "$toolchain_dir/rustup.sh"
  sh "$toolchain_dir/rustup.sh" -y --profile minimal --default-toolchain "$rust_version"
fi
rustup toolchain install "$rust_version" --profile minimal
export RUSTUP_TOOLCHAIN="$rust_version"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR="$mesh_root/target"
rustup target add "${targets[@]}"

if [[ "$EAS_BUILD_PLATFORM" == android ]]; then
  export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  : "${ANDROID_NDK_HOME:?The EAS Android image must provide the NDK}"
  ndk_bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android26-clang"
  export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$ndk_bin/x86_64-linux-android26-clang"
  export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
  export CC_x86_64_linux_android="$CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
  export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
  export AR_x86_64_linux_android="$ndk_bin/llvm-ar"
else
  export IPHONEOS_DEPLOYMENT_TARGET=16.4
fi

cd "$mesh_root"
cargo build --locked -p meshc -p mesh-rt
for target in "${targets[@]}"; do
  cargo build --locked -p mesh-rt --lib --target "$target"
done
MESHC="$CARGO_TARGET_DIR/debug/meshc" bash "$script_dir/build-mobile-native.sh" "$EAS_BUILD_PLATFORM"
