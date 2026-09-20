#!/bin/sh
# Install or update Morse for macOS from the newest desktop release:
#
#   curl -fsSL https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.sh | sh
#
# Options are environment variables, set on the `sh` side of the pipe:
#   MORSE_VERSION      release to install (for example 0.1.0) instead of the newest
#   MORSE_INSTALL_DIR  folder that receives Morse.app (default: /Applications, or
#                      ~/Applications when that is not writable)
#   MORSE_NO_LAUNCH    set to anything to skip opening Morse afterwards
#
# Windows: irm https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.ps1 | iex
set -eu

repo="snowdamiz/whatsdown"
releases_api="${MORSE_RELEASES_API_URL:-https://api.github.com/repos/$repo/releases?per_page=100}"
release_base="${MORSE_RELEASE_BASE_URL:-https://github.com/$repo/releases/download}"

fail() {
  printf 'morse: %s\n' "$*" >&2
  exit 1
}

# Nothing runs until the last line arrives, so a truncated download cannot
# execute half an installer.
main() {
  [ $# -eq 0 ] || fail "options are environment variables; see the top of this script"

  case "$(uname -s)" in
    Darwin) ;;
    MINGW* | MSYS* | CYGWIN*) fail "on Windows run: irm https://raw.githubusercontent.com/$repo/main/install.ps1 | iex" ;;
    *) fail "Morse desktop releases support macOS and Windows only" ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64)
      # A Rosetta shell on Apple silicon still gets the native build.
      if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then arch=aarch64; else arch=x64; fi
      ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac

  version="${MORSE_VERSION:-}"
  version="${version#desktop-}"
  version="${version#v}"
  if [ -z "$version" ]; then
    # Mobile and backend tags share this repository, so "latest" is not enough.
    # ponytail: reads the newest 100 releases; page the API if desktop tags fall off it.
    version="$(curl -fsSL "$releases_api" | grep -o '"tag_name": *"desktop-v[^"]*"' |
      sed 's/.*"desktop-v//; s/"$//' | sort -V | tail -n 1)"
  fi
  case "$version" in
    '') fail "no desktop release found at $releases_api" ;;
    *[!0-9A-Za-z.+-]*) fail "unexpected release version: $version" ;;
  esac

  dir="${MORSE_INSTALL_DIR:-/Applications}"
  if [ -z "${MORSE_INSTALL_DIR:-}" ] && [ ! -w "$dir" ]; then dir="$HOME/Applications"; fi
  dest="$dir/Morse.app"
  if pgrep -f "$dest/Contents/MacOS/" >/dev/null 2>&1; then
    fail "Morse is running from $dest; quit it and run this installer again"
  fi

  asset="Morse_${version}_${arch}.dmg"
  url="$release_base/desktop-v$version"
  tmp="$(mktemp -d)"
  mnt="$tmp/mnt"
  trap 'hdiutil detach -quiet "$mnt" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  printf 'Downloading Morse %s (%s)...\n' "$version" "$arch"
  curl -fL --progress-bar -o "$tmp/$asset" "$url/$asset" || fail "could not download $url/$asset"
  curl -fsSL -o "$tmp/SHA256SUMS" "$url/SHA256SUMS" || fail "could not download $url/SHA256SUMS"
  expected="$(awk -v name="$asset" '$2 == name { print $1; exit }' "$tmp/SHA256SUMS")"
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    fail "$asset does not match its SHA256SUMS entry; nothing was installed"
  fi

  mkdir "$mnt"
  hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$tmp/$asset"
  app="$mnt/Morse.app"
  [ -d "$app" ] || fail "$asset does not contain Morse.app"
  # curl does not quarantine downloads, so macOS would never check this app on
  # its own. Ask Gatekeeper directly: only a Developer ID-signed, notarized
  # build is installed.
  spctl --assess --type execute "$app" ||
    fail "$asset failed Gatekeeper verification; nothing was installed"

  mkdir -p "$dir"
  rm -rf "$dest"
  ditto "$app" "$dest"

  printf 'Installed Morse %s to %s\n' "$version" "$dest"
  if [ -z "${MORSE_NO_LAUNCH:-}" ]; then
    open "$dest"
  else
    printf 'Start it with: open "%s"\n' "$dest"
  fi
}

main "$@"
