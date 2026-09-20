#!/usr/bin/env bash
set -euo pipefail

test_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_script_dir
test_repo_root="$(cd "$test_script_dir/../.." && pwd -P)"
readonly test_repo_root

# shellcheck disable=SC1091
source "$test_repo_root/run.sh"

compose() {
  return 0
}
(
  child_pids=()
  cleanup
)

built=()
build_service() {
  built+=("$1")
}
build_services
[[ "${built[*]}" == "directory-delivery privacy-edge push-broker object-store transparency-witness" ]] || exit 1

started=()
start_process() {
  started+=("$1")
}
wait_for_health() {
  return 0
}
curl() { return 1; }
ps() { return 0; }
configure_environment
start_services
[[ "${started[*]}" == "push-broker directory-delivery privacy-edge object-store witness-a witness-b desktop" ]] || {
  printf 'expected desktop stack, got: %s\n' "${started[*]}" >&2
  exit 1
}

curl() { return 0; }
start_landing
[[ "${started[*]}" == "push-broker directory-delivery privacy-edge object-store witness-a witness-b desktop landing" ]] || {
  printf 'expected landing page, got: %s\n' "${started[*]}" >&2
  exit 1
}

(
  fake_rust_bin="$(mktemp -d)"
  trap 'rm -rf "$fake_rust_bin"' EXIT
  ln -s /usr/bin/false "$fake_rust_bin/cargo"
  ln -s /usr/bin/false "$fake_rust_bin/rustc"
  PATH="$fake_rust_bin:$PATH"
  build_mesh() {
    [[ "$(command -v cargo)" == "$(rustup which cargo)" ]]
    [[ "$(command -v rustc)" == "$(rustup which rustc)" ]]
  }
  build_services() { return 0; }
  build_desktop() { return 0; }
  build_all
)

MESSENGER_PUSH_BROKER_SEED_HEX=invalid
if configure_environment >/dev/null 2>&1; then
  printf 'malformed development key was accepted\n' >&2
  exit 1
fi

(
  checkout_fixture="$(mktemp -d)"
  trap 'rm -rf "$checkout_fixture"' EXIT
  cp "$test_repo_root/run.sh" "$checkout_fixture/run.sh"
  mkdir "$checkout_fixture/external"
  touch "$checkout_fixture/external/Cargo.toml"
  MESH_LANG_DIR="$checkout_fixture/external" bash -c '
    source "$1/run.sh"
    cargo() { [[ "$PWD" == "$mesh_root" ]] || fail "Mesh compiler configuration was not loaded from its checkout"; }
    build_mesh
    [[ -L "$script_dir/mesh-lang" ]] || fail "external Mesh dependencies were not linked"
    [[ "$(cd "$script_dir/mesh-lang" && pwd -P)" == "$mesh_root" ]]
    build_mesh
    rm "$script_dir/mesh-lang"
    mkdir "$script_dir/mesh-lang"
    if build_mesh >/dev/null 2>&1; then
      fail "a conflicting Mesh checkout was accepted"
    fi
    [[ -d "$script_dir/mesh-lang" && ! -L "$script_dir/mesh-lang" ]]
  ' bash "$checkout_fixture"
)

python3 - "$test_repo_root/run.sh" <<'PY'
import http.server
import os
import signal
import subprocess
import sys
import threading
import tempfile
import pathlib
import shutil
import time
import urllib.request
import urllib.error

release = threading.Event()
requests = []

class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        if len(requests) == 1:
            release.wait()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Health)
threading.Thread(target=server.serve_forever, daemon=True).start()
process = subprocess.Popen(
    ["bash", "-c", 'source "$1"; wait_for_health stalled "$2"', "bash",
     sys.argv[1], f"http://127.0.0.1:{server.server_port}"],
    start_new_session=True,
)
try:
    assert process.wait(timeout=15) == 0
    assert requests == ["/health", "/health"], requests
finally:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    release.set()
    server.shutdown()
    server.server_close()

# Exercise the real CLI without compiling native code or touching the user's Docker.
with tempfile.TemporaryDirectory(prefix="morse runner ") as temp:
    root = pathlib.Path(temp).resolve()
    shutil.copy(sys.argv[1], root / "run.sh")
    commands = root / "bin"
    commands.mkdir()
    mesh = root / "mesh-lang"
    (mesh / "target/debug").mkdir(parents=True)
    (mesh / "Cargo.toml").touch()
    services = root / "mesh-private-messenger/services"
    for name in ("directory-delivery", "privacy-edge", "push-broker", "object-store", "transparency-witness"):
        (services / name).mkdir(parents=True)
    scripts = root / "mesh-private-messenger/scripts"
    scripts.mkdir()
    mobile = root / "mesh-private-messenger/apps/mobile"
    podspecs = mobile / "node_modules/example/ios"
    podspecs.mkdir(parents=True)
    (podspecs / "Example.podspec").write_text("real podspec\n")
    (podspecs / "._Example.podspec").write_bytes(b"AppleDouble metadata")
    landing = root / "mesh-private-messenger/apps/landing"
    landing.mkdir(parents=True)
    (landing / "index.html").write_text("landing fixture\n")
    state = root / "state"
    state.mkdir()
    # An interrupted launch can leave a lock directory without its PID file.
    (state / "run.lock").mkdir()

    def executable(path, body):
        path.write_text("#!/bin/bash\nset -eu\n" + body)
        path.chmod(0o755)

    executable(commands / "rustup", 'if [[ "$1" == which ]]; then printf "%s/bin/cargo\\n" "$FIXTURE"; fi\n')
    executable(commands / "cargo", "exit 0\n")
    executable(commands / "uname", "echo Darwin\n")
    executable(commands / "open", 'touch "$MORSE_STATE_DIR/docker-ready"\n')
    executable(commands / "python3", 'echo $$ > "$MORSE_STATE_DIR/landing.pid"\nexec "$REAL_PYTHON" "$@"\n')
    executable(commands / "ps", "echo /CoreSimulator/Devices/example/Morse.app/Morse\n")
    executable(commands / "docker", '''
echo "$*" >> "$MORSE_STATE_DIR/docker-calls"
if [[ "$1" == info ]]; then test -f "$MORSE_STATE_DIR/docker-ready"; fi
''')
    executable(commands / "curl", '''
case "${!#}" in
  *:18080/) exec "$REAL_CURL" "$@";;
  *:18086/health) name=directory-delivery;;
  *:18087/health) name=privacy-edge;;
  *:18088/health) name=push-broker;;
  *:18089/health) name=object-store;;
  *) exit 1;;
esac
test -f "$MORSE_STATE_DIR/$name.ready"
''')
    executable(mesh / "target/debug/meshc", '''
cat > "$4" <<'SH'
#!/bin/bash
name=$(basename "$(dirname "$0")")
if [[ "$name" == transparency-witness ]]; then exit 0; fi
echo $$ > "$MORSE_STATE_DIR/$name.pid"
touch "$MORSE_STATE_DIR/$name.ready"
exec sleep 300
SH
chmod +x "$4"
''')
    executable(commands / "npm", '''
echo "$*" >> "$MORSE_STATE_DIR/npm-calls"
if [[ "$*" == *"run dev" ]]; then
  echo $$ > "$MORSE_STATE_DIR/desktop.pid"
  exec sleep 300
elif [[ "$*" == *"run ios" ]]; then
  test -f "$MORSE_STATE_DIR/mobile-built"
  echo $$ > "$MORSE_STATE_DIR/mobile.pid"
  exec sleep 300
fi
''')
    executable(scripts / "build-mobile-native.sh", '''
test "$1" = ios
touch "$MORSE_STATE_DIR/mobile-built"
''')
    # An independently running service must be reused and survive shutdown.
    (state / "privacy-edge.ready").touch()
    env = {**os.environ, "PATH": f"{commands}:{os.environ['PATH']}",
           "MORSE_STATE_DIR": str(state), "MESH_LANG_DIR": str(mesh), "FIXTURE": str(root),
           "REAL_PYTHON": sys.executable, "REAL_CURL": shutil.which("curl")}
    output = root / "runner.log"
    with output.open("w") as log:
        runner = subprocess.Popen(["bash", str(root / "run.sh")], env=env, stdout=log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
    try:
        def landing_contents():
            try:
                with urllib.request.urlopen("http://127.0.0.1:18080/", timeout=1) as page:
                    return page.read()
            except (OSError, urllib.error.URLError):
                return None

        deadline = time.monotonic() + 30
        while (not all((state / f"{client}.pid").exists() for client in ("desktop", "mobile", "landing"))
               or landing_contents() != b"landing fixture\n") and runner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert (state / "desktop.pid").exists(), output.read_text()
        assert (state / "mobile.pid").exists(), "simulator app was not started:\n" + output.read_text()
        assert (state / "landing.pid").exists(), "landing page was not started:\n" + output.read_text()
        assert landing_contents() == b"landing fixture\n", output.read_text()
        assert not (podspecs / "._Example.podspec").exists(), "AppleDouble podspec breaks CocoaPods autolinking"
        assert (podspecs / "Example.podspec").read_text() == "real podspec\n"
        assert not (state / "privacy-edge.pid").exists(), "duplicated a healthy service"
        second = subprocess.run(["bash", str(root / "run.sh")], env=env, capture_output=True, text=True, timeout=5)
        assert second.returncode == 0 and "already running" in second.stdout, second
        assert (state / "npm-calls").read_text().count("run dev") == 1
        assert (state / "npm-calls").read_text().count("run ios") == 1
        runner.terminate()
        runner.wait(timeout=10)
        for pidfile in state.glob("*.pid"):
            try:
                os.kill(int(pidfile.read_text()), 0)
            except ProcessLookupError:
                continue
            raise AssertionError(f"orphaned process: {pidfile.name}")
        assert " down" not in (state / "docker-calls").read_text(), "stopped a shared database"
        docker_calls = (state / "docker-calls").read_text()
        with output.open("w") as log:
            runner = subprocess.Popen(["bash", str(root / "run.sh"), "landing"], env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 30
        while landing_contents() != b"landing fixture\n" and runner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert landing_contents() == b"landing fixture\n", output.read_text()
        assert (state / "docker-calls").read_text() == docker_calls, "standalone landing mode started Docker"
        runner.terminate()
        runner.wait(timeout=10)
        previous_npm = (state / "npm-calls").read_text()
        executable(commands / "ps", 'echo "$FIXTURE/mesh-private-messenger/apps/desktop/src-tauri/target/debug/Morse"\n')
        with output.open("w") as log:
            runner = subprocess.Popen(["bash", str(root / "run.sh"), "desktop"], env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 30
        while "Morse desktop is already running" not in output.read_text() and runner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "Morse desktop is already running" in output.read_text(), output.read_text()
        assert (state / "npm-calls").read_text() == previous_npm, "rebuilt an open desktop app"
        runner.terminate()
        runner.wait(timeout=10)
        executable(commands / "npm", '''
if [[ "$*" == *"run ios" ]]; then
  echo "simulator fixture build failure" >&2
  exit 17
fi
''')
        failed = subprocess.run(["bash", str(root / "run.sh")], env=env,
                                capture_output=True, text=True, timeout=15)
        assert failed.returncode != 0, failed
        assert "simulator fixture build failure" in failed.stderr, "app failure was hidden in a log file"
        assert not (state / "run.lock").exists(), "failed launch left a stale lock"
    finally:
        if runner.poll() is None:
            runner.terminate()
            runner.wait(timeout=10)
        for pidfile in state.glob("*.pid"):
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
PY

printf 'root runner topology, Docker startup, reuse, shutdown, and stalled-probe tests passed\n'
