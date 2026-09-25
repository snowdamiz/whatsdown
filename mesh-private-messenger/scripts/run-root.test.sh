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
  : &
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

# Without MESH_LANG_DIR the launcher builds the latest Mesh release: fetched into
# the state directory on every run and linked where scripts and packages look.
(
  release_fixture="$(mktemp -d)"
  trap 'rm -rf "$release_fixture"' EXIT
  origin="$release_fixture/mesh-origin"
  git init --quiet "$origin"
  git -C "$origin" config uploadpack.allowAnySHA1InWant true
  touch "$origin/Cargo.toml"
  git -C "$origin" add Cargo.toml
  git -C "$origin" -c user.name=fixture -c user.email=fixture@example.invalid commit --quiet -m v1
  first="$(git -C "$origin" rev-parse HEAD)"
  git -C "$origin" -c user.name=fixture -c user.email=fixture@example.invalid commit --quiet --allow-empty -m v2
  second="$(git -C "$origin" rev-parse HEAD)"
  cp "$test_repo_root/run.sh" "$release_fixture/run.sh"
  mkdir "$release_fixture/older-checkout"
  ln -s "$release_fixture/older-checkout" "$release_fixture/mesh-lang"
  MORSE_STATE_DIR="$release_fixture/state" MESH_LANG_REPOSITORY="file://$origin" bash -c '
    source "$1/run.sh"
    cargo() { [[ "$PWD" == "$mesh_root" ]] || fail "the compiler was not built in the release checkout"; }
    for revision in "$2" "$3"; do
      MESH_LANG_REVISION="$revision" build_mesh
      [[ "$(git -C "$mesh_root" rev-parse HEAD)" == "$revision" ]] || fail "the release checkout is not at $revision"
      [[ "$(cd "$script_dir/mesh-lang" && pwd -P)" == "$(cd "$mesh_root" && pwd -P)" ]] ||
        fail "scripts would not find the release compiler"
    done
  ' bash "$release_fixture" "$first" "$second"
)

# A cached witness checkpoint outlives the database it attests, and the witness
# then refuses to sign a log that went backwards, so reset must clear both.
(
  reset_fixture="$(mktemp -d)"
  trap 'rm -rf "$reset_fixture"' EXIT
  MORSE_STATE_DIR="$reset_fixture" bash -c '
    source "$1/run.sh"
    ensure_docker() { :; }
    compose() { printf "%s\n" "$*" >>"$state_dir/compose-calls"; }
    mkdir -p "$state_dir/objects"
    touch "$state_dir/objects/blob" "$state_dir/witness-a.checkpoint" \
      "$state_dir/witness-b.checkpoint" "$schema_stamp"
    reset_database >/dev/null
    [[ "$(cat "$state_dir/compose-calls")" == "down --volumes" ]] || fail "reset kept the database volume"
    [[ ! -e "$state_dir/witness-a.checkpoint" && ! -e "$state_dir/witness-b.checkpoint" ]] ||
      fail "reset kept a witness checkpoint that outranks the new database"
    [[ ! -e "$state_dir/objects" ]] || fail "reset kept objects whose rows are gone"
    [[ ! -e "$schema_stamp" ]] || fail "reset kept the migration record"
  ' bash "$test_repo_root"
)

# Docker can lose the volume without a reset (Desktop reset, `down --volumes`), so
# a launch that creates the database clears the checkpoints too, and only then.
(
  fresh_fixture="$(mktemp -d)"
  trap 'rm -rf "$fresh_fixture"' EXIT
  MORSE_STATE_DIR="$fresh_fixture" bash -c '
    source "$1/run.sh"
    compose() { :; }
    docker() { return 0; }
    touch "$state_dir/witness-a.checkpoint" "$state_dir/witness-b.checkpoint"
    start_database 2>/dev/null
    [[ -e "$state_dir/witness-a.checkpoint" ]] || fail "a launch discarded checkpoints of a database it kept"
    docker() { return 1; }
    start_database
    [[ ! -e "$state_dir/witness-a.checkpoint" && ! -e "$state_dir/witness-b.checkpoint" ]] ||
      fail "a new database kept witness checkpoints that outrank it"
  ' bash "$test_repo_root"
)

# Production wakes the witnesses when the directory makes a checkpoint. Locally
# each watches for one and signs it once; a failed pass is tried again.
(
  witness_fixture="$(mktemp -d)"
  trap 'rm -rf "$witness_fixture"' EXIT
  cp "$test_repo_root/run.sh" "$witness_fixture/run.sh"
  witness="$witness_fixture/mesh-private-messenger/services/transparency-witness"
  mkdir -p "$witness"
  # shellcheck disable=SC2016
  printf '#!/bin/bash\necho pass >>"%s/passes"\n[[ "$(wc -l <"%s/passes")" -gt 1 ]]\n' \
    "$witness_fixture" "$witness_fixture" >"$witness/output"
  chmod +x "$witness/output"
  bash -c '
    source "$1/run.sh"
    MESSENGER_PORT=1
    # The directory serves checkpoint A for two reads, then B.
    curl() {
      local reads
      reads=$(($(cat "$script_dir/reads" 2>/dev/null || echo 0) + 1))
      echo "$reads" >"$script_dir/reads"
      if ((reads < 3)); then echo A; else echo B; fi
    }
    ticks=0
    sleep() { ((++ticks < 5)) || exit 0; }
    witness_loop witness-a seed key "$script_dir/witness-a.checkpoint"
  ' bash "$witness_fixture"
  [[ "$(wc -l <"$witness_fixture/passes" | tr -d " ")" == 3 ]] || {
    printf 'expected a failed and a retried pass for A and one for B, got %s passes\n' \
      "$(wc -l <"$witness_fixture/passes" | tr -d " ")" >&2
    exit 1
  }
)

# A stopped Docker Desktop answers its socket and then never replies, so the
# probe has to give up rather than hang the launcher before it prints anything.
(
  stalled_docker="$(mktemp -d)"
  trap 'rm -rf "$stalled_docker"' EXIT
  printf '#!/bin/bash\nexec sleep 300\n' >"$stalled_docker/docker"
  chmod +x "$stalled_docker/docker"
  PATH="$stalled_docker:$PATH"
  probe_started=$SECONDS
  if docker_ready; then
    printf 'a stalled daemon was reported ready\n' >&2
    exit 1
  fi
  if ((SECONDS - probe_started > 15)); then
    printf 'a stalled daemon probe was not bounded\n' >&2
    exit 1
  fi
)

# The health deadline is long enough for a freshly linked binary's first-launch
# scan, so a service that has already exited must not wait it out.
bash -c '
  source "$1/run.sh"
  curl() { return 1; }
  false &
  if wait_for_health exited http://127.0.0.1:1 "$!" 2>/dev/null; then
    printf "an exited service was reported healthy\n" >&2
    exit 1
  fi
  if ((SECONDS > 5)); then
    printf "an exited service waited out the health deadline\n" >&2
    exit 1
  fi
' bash "$test_repo_root"

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
    migrations = services / "directory-delivery/migrations"
    migrations.mkdir()
    for name in ("001_initial.sql", "002_durable_backend.sql"):
        (migrations / name).write_text("SELECT 1;\n")
    scripts = root / "mesh-private-messenger/scripts"
    scripts.mkdir()
    mobile = root / "mesh-private-messenger/apps/mobile"
    podspecs = mobile / "node_modules/example/ios"
    podspecs.mkdir(parents=True)
    (podspecs / "Example.podspec").write_text("real podspec\n")
    (podspecs / "._Example.podspec").write_bytes(b"AppleDouble metadata")
    # Expo's xcframework script, reduced to the two globs that meet AppleDouble
    # files. Xcode writes those mid-build, after the launcher's cleanup has run.
    expo_script = mobile / "node_modules/expo-modules-jsi/apple/scripts/build-xcframework.sh"
    expo_script.parent.mkdir(parents=True)
    expo_script.write_text('''#!/bin/bash
modules_dir="$1"
PACKAGE_NAME=Fixture
find "${modules_dir}/${PACKAGE_NAME}.swiftmodule" -type f \\
  \\( -name '*.private.swiftinterface' -o -name '*.package.swiftinterface' \\) -delete
find "${modules_dir}/${PACKAGE_NAME}.swiftmodule" -name '*.swiftinterface'
''')
    swiftmodule = root / "Fixture.swiftmodule"
    swiftmodule.mkdir()
    for name in ("arm64.swiftinterface", "arm64.private.swiftinterface"):
        (swiftmodule / name).write_text("// swift-interface-format-version: 1.0\n")
        (swiftmodule / f"._{name}").write_bytes(b"\x00\x05\x16\x07AppleDouble metadata")
    # This fixture's path has a space. React Native and Expo split such a project
    # path in these lines, each shown as upstream ships it and as it must become.
    assert " " in str(mobile)
    spaced_path_lines = {
        "node_modules/expo-constants/ios/EXConstants.podspec": (
            r'''    :script => "bash -l -c \"#{env_vars}$PODS_TARGET_SRCROOT/../scripts/get-app-config-ios.sh\"",''',
            r'''    :script => "#{env_vars}bash -l \"$PODS_TARGET_SRCROOT/../scripts/get-app-config-ios.sh\"",'''),
        "node_modules/expo-constants/scripts/get-app-config-ios.sh": (
            r'''PROJECT_DIR_BASENAME=$(basename $PROJECT_DIR)''',
            r'''PROJECT_DIR_BASENAME=$(basename "$PROJECT_DIR")'''),
        "node_modules/expo-updates/ios/EXUpdates.podspec": (
            r'''      :script => force_bundling_flag + 'bash -l -c "$PODS_TARGET_SRCROOT/../scripts/create-updates-resources-ios.sh"',''',
            r'''      :script => force_bundling_flag + 'bash -l "$PODS_TARGET_SRCROOT/../scripts/create-updates-resources-ios.sh"','''),
        "ios/Pods/Pods.xcodeproj/project.pbxproj": (
            r'''			shellScript = "bash -l -c \"$PODS_TARGET_SRCROOT/../scripts/get-app-config-ios.sh\"";''',
            r'''			shellScript = "bash -l \"$PODS_TARGET_SRCROOT/../scripts/get-app-config-ios.sh\"";'''),
        "ios/Morse.xcodeproj/project.pbxproj": (
            r'''			shellScript = "export SKIP_BUNDLING=1\n`\"$NODE_BINARY\" --print \"require('path').dirname(require.resolve('react-native/package.json')) + '/scripts/react-native-xcode.sh'\"`\n";''',
            r'''			shellScript = "export SKIP_BUNDLING=1\n\"$(\"$NODE_BINARY\" --print \"require('path').dirname(require.resolve('react-native/package.json')) + '/scripts/react-native-xcode.sh'\")\"\n";'''),
    }
    # `expo prebuild` writes ios/, so a first launch has nothing there to patch yet.
    prebuilt = root / "prebuilt"
    for path, (upstream, _) in spaced_path_lines.items():
        target = (prebuilt if path.startswith("ios/") else mobile) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(upstream + "\n")
    # pod install writes the checkout's absolute path into ios/Pods.
    vfs_overlay = "ios/Pods/React-Core-prebuilt/React-VFS.yaml"
    (prebuilt / vfs_overlay).parent.mkdir(parents=True)
    (prebuilt / vfs_overlay).write_text(f"  - name: '{mobile}/ios/Pods/React-Core-prebuilt/React.xcframework/Headers'\n")
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
    # Neither the simulator app nor the installed release app is the development desktop.
    executable(commands / "ps", "echo /CoreSimulator/Devices/example/Morse.app/Morse\n"
                                "echo /Applications/Morse.app/Contents/MacOS/Morse\n")
    executable(commands / "docker", '''
echo "$*" >> "$MORSE_STATE_DIR/docker-calls"
if [[ "$1" == info ]]; then test -f "$MORSE_STATE_DIR/docker-ready"; fi
if [[ "$1 ${2:-}" == "volume inspect" ]]; then test -f "$MORSE_STATE_DIR/docker-volume"; fi
if [[ "$*" == *"up --detach --wait postgres" ]]; then touch "$MORSE_STATE_DIR/docker-volume"; fi
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
if [[ "$*" == *"expo prebuild"* ]]; then
  cp -R "$FIXTURE/prebuilt/ios" "$FIXTURE/mesh-private-messenger/apps/mobile/ios"
elif [[ "$*" == *"run dev" ]]; then
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
        interfaces = subprocess.run(["bash", str(expo_script), str(root)], capture_output=True, text=True, check=True).stdout
        assert interfaces == f"{swiftmodule / 'arm64.swiftinterface'}\n", \
            "Expo's sed fails the iOS build on a binary AppleDouble interface:\n" + interfaces
        assert not (swiftmodule / "arm64.private.swiftinterface").exists(), "private interfaces must still be removed"
        assert (swiftmodule / "._arm64.private.swiftinterface").exists(), \
            "the volume removes a sidecar with its file, so deleting it again fails Expo's find"
        for path, (_, quoted) in spaced_path_lines.items():
            assert (mobile / path).read_text() == quoted + "\n", f"{path} still splits a project path that has a space"
        assert (mobile / vfs_overlay).exists(), "reinstalled pods that this checkout installed"
        assert not (state / "privacy-edge.pid").exists(), "duplicated a healthy service"
        assert (state / "postgres-migrations").read_text() == "001_initial.sql\n002_durable_backend.sql\n", \
            "the database this launch created was not recorded:\n" + output.read_text()
        assert "migrations changed" not in output.read_text(), "reported drift for a database it just created"
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
        (migrations / "003_added_later.sql").write_text("SELECT 1;\n")
        # A Cargo target directory outside the checkout still holds the development desktop.
        executable(commands / "ps", 'echo /Users/example/Library/Caches/morse-desktop/target/debug/Morse\n')
        with output.open("w") as log:
            runner = subprocess.Popen(["bash", str(root / "run.sh"), "desktop"], env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 30
        while "Morse desktop is already running" not in output.read_text() and runner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "Morse desktop is already running" in output.read_text(), output.read_text()
        assert "migrations changed" in output.read_text(), \
            "a migration added after the database was created was not reported:\n" + output.read_text()
        assert (state / "npm-calls").read_text() == previous_npm, "rebuilt an open desktop app"
        runner.terminate()
        runner.wait(timeout=10)
        executable(commands / "npm", '''
if [[ "$*" == *"run ios" ]]; then
  echo "simulator fixture build failure" >&2
  exit 17
fi
''')
        # The checkout moved (here, its volume was renamed) after pod install.
        (mobile / vfs_overlay).write_text(
            "  - name: '/Volumes/SSK SSD/whatsdown/mesh-private-messenger/apps/mobile/ios/Pods/React-Core-prebuilt/React.xcframework/Headers'\n")
        failed = subprocess.run(["bash", str(root / "run.sh")], env=env,
                                capture_output=True, text=True, timeout=15)
        assert failed.returncode != 0, failed
        assert "simulator fixture build failure" in failed.stderr, "app failure was hidden in a log file"
        assert not (state / "run.lock").exists(), "failed launch left a stale lock"
        assert not (mobile / "ios/Pods").exists(), "kept pods that name another checkout path, so Xcode cannot find them"
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

printf 'root runner topology, Docker startup, database recording, reuse, shutdown, and stalled-probe tests passed\n'
