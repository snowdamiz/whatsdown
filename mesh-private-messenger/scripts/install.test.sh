#!/usr/bin/env bash
set -euo pipefail

test_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_script_dir
test_repo_root="$(cd "$test_script_dir/../.." && pwd -P)"
readonly test_repo_root

fixture="$(mktemp -d)"
readonly fixture
readonly release="$fixture/www/download/desktop-v0.10.0"
readonly installed="$fixture/apps/Morse.app/payload"
readonly log="$fixture/log"
server_pid=
# Reaping the server here keeps bash's "Terminated" job notice out of the output.
trap '{ [[ -z "$server_pid" ]] || { kill "$server_pid"; wait "$server_pid"; }; } 2>/dev/null || true; rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/apps" "$release"

# The newest desktop release is neither first in API order nor last in string
# order, and another product's tags share the list.
printf '%s\n' '[{"tag_name": "desktop-v0.9.0"},{"tag_name":"mobile-v9.9.9"},' \
  '{"tag_name": "desktop-v0.10.0"},{"tag_name": "desktop-v0.2.0"}]' > "$fixture/www/releases"
for arch in aarch64 x64; do
  printf '%s build\n' "$arch" > "$release/Morse_0.10.0_$arch.dmg"
done
printf 'windows build\n' > "$release/Morse_0.10.0_x64-setup.exe"
(cd "$release" && shasum -a 256 Morse_* > SHA256SUMS)

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
readonly base="http://127.0.0.1:$port"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$fixture/www" >/dev/null 2>&1 &
server_pid=$!
for _ in {1..100}; do
  if curl --fail --silent "$base/releases" >/dev/null; then break; fi
  sleep 0.1
done

stub() {
  printf '#!/bin/sh\n%s\n' "$2" > "$fixture/bin/$1"
  chmod +x "$fixture/bin/$1"
}
# shellcheck disable=SC2016
{
  stub uname 'case "$1" in -s) echo "${FAKE_OS:-Darwin}" ;; -m) echo "${FAKE_ARCH:-arm64}" ;; esac'
  stub sysctl 'echo "${FAKE_ARM64_HARDWARE:-0}"'
  # The fake disk image is its own payload, so an install traces back to its download.
  stub hdiutil 'if [ "$1" = attach ]; then
  while [ $# -gt 1 ]; do [ "$1" != -mountpoint ] || mnt=$2; shift; done
  mkdir -p "$mnt/Morse.app" && cp "$1" "$mnt/Morse.app/payload"
fi'
  stub spctl 'exit "${FAKE_GATEKEEPER_STATUS:-0}"'
  stub ditto 'cp -R "$1" "$2"'
  stub pgrep 'exit 1'
  stub open 'echo "$1" > "$FIXTURE/opened"'
}

fail() {
  printf 'install test: %s\n' "$*" >&2
  [[ ! -s "$log" ]] || cat "$log" >&2
  exit 1
}

run_installer() {
  env PATH="$fixture/bin:$PATH" FIXTURE="$fixture" MORSE_INSTALL_DIR="$fixture/apps" \
    MORSE_RELEASES_API_URL="$base/releases" MORSE_RELEASE_BASE_URL="$base/download" "$@" \
    sh "$test_repo_root/install.sh" >"$log" 2>&1
}

run_installer || fail "Apple silicon install failed"
[[ "$(cat "$installed")" == "aarch64 build" ]] || fail "expected the newest aarch64 build"
[[ "$(cat "$fixture/opened")" == "$fixture/apps/Morse.app" ]] || fail "Morse was not opened"

rm "$fixture/opened"
run_installer FAKE_ARCH=x86_64 MORSE_VERSION=v0.10.0 MORSE_NO_LAUNCH=1 || fail "pinned Intel install failed"
[[ "$(cat "$installed")" == "x64 build" ]] || fail "expected the x64 build"
[[ ! -e "$fixture/opened" ]] || fail "MORSE_NO_LAUNCH still opened Morse"

run_installer FAKE_ARCH=x86_64 FAKE_ARM64_HARDWARE=1 MORSE_NO_LAUNCH=1 || fail "Rosetta install failed"
[[ "$(cat "$installed")" == "aarch64 build" ]] || fail "a Rosetta shell must get the native build"

if run_installer FAKE_ARCH=x86_64 FAKE_GATEKEEPER_STATUS=3; then
  fail "an app Gatekeeper rejected was installed"
fi
[[ "$(cat "$installed")" == "aarch64 build" ]] || fail "a rejected app replaced the installed one"

if run_installer FAKE_OS=Linux; then
  fail "a platform without a desktop release was accepted"
fi

run_windows_installer() {
  # shellcheck disable=SC2016
  env FIXTURE="$fixture" INSTALL_PS1="$test_repo_root/install.ps1" \
    MORSE_RELEASES_API_URL="$base/releases" MORSE_RELEASE_BASE_URL="$base/download" "$@" \
    pwsh -NoProfile -NonInteractive -Command '
      function Get-AuthenticodeSignature { [pscustomobject]@{ Status = $env:FAKE_SIGNATURE } }
      function Start-Process { param($FilePath, $ArgumentList, [switch]$PassThru)
        "$(Get-Content -Raw $FilePath)$ArgumentList" | Set-Content "$env:FIXTURE/setup"
        [pscustomobject]@{ Handle = 0; ExitCode = 0 } | Add-Member -PassThru ScriptMethod WaitForExit { }
      }
      Get-Content -Raw $env:INSTALL_PS1 | Invoke-Expression' >"$log" 2>&1
}

# Windows-only cmdlets are stubbed; pwsh still runs the script the way `irm | iex` does.
if command -v pwsh >/dev/null 2>&1; then
  run_windows_installer FAKE_SIGNATURE=Valid || fail "Windows install failed"
  [[ "$(cat "$fixture/setup")" == $'windows build\n/S /R' ]] || fail "expected a silent install that opens Morse"
  run_windows_installer FAKE_SIGNATURE=Valid MORSE_VERSION=0.10.0 MORSE_NO_LAUNCH=1 || fail "pinned Windows install failed"
  [[ "$(cat "$fixture/setup")" == $'windows build\n/S' ]] || fail "MORSE_NO_LAUNCH still opened Morse"
  # Release signing is not configured yet: unsigned installs, loudly. A signature
  # that is present but invalid means tampering and never runs.
  rm "$fixture/setup"
  run_windows_installer FAKE_SIGNATURE=NotSigned || fail "signing blocked an unsigned Windows release"
  [[ -e "$fixture/setup" ]] || fail "signing blocked an unsigned Windows release"
  grep -q 'not code signed' "$log" || fail "an unsigned Windows installer ran without a warning"
  rm "$fixture/setup"
  if run_windows_installer FAKE_SIGNATURE=HashMismatch; then
    fail "an installer with an invalid Authenticode signature was run"
  fi
  [[ ! -e "$fixture/setup" ]] || fail "an installer with an invalid Authenticode signature was run"
else
  printf 'pwsh not found; skipped install.ps1\n'
fi

# Both checksum gates see a download that no longer matches SHA256SUMS.
printf 'tampered\n' | tee -a "$release/Morse_0.10.0_aarch64.dmg" >> "$release/Morse_0.10.0_x64-setup.exe"
if run_installer MORSE_NO_LAUNCH=1; then
  fail "a download that does not match SHA256SUMS was installed"
fi
[[ "$(cat "$installed")" == "aarch64 build" ]] || fail "a tampered download replaced the installed app"
if command -v pwsh >/dev/null 2>&1 && run_windows_installer FAKE_SIGNATURE=Valid; then
  fail "a Windows download that does not match SHA256SUMS was run"
fi
[[ ! -e "$fixture/setup" ]] || fail "a Windows download that does not match SHA256SUMS was run"

printf 'installer release selection, platform mapping, checksum, and signature gate tests passed\n'
