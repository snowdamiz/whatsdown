import contextlib, fcntl, hashlib, json, os, pathlib, shlex, signal, subprocess, time

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[3]
BASE = '0d6826b5d02e3439d93568ecc1d6fa996135a505'
LANG = pathlib.Path('/Users/andreyyurlov/Documents/dev/mesh-lang')
RELEASE = LANG / '.tmp/builtin-try-from/release-artifacts'
MESHC = RELEASE / 'bin/meshc'
SNAP = ROOT / 'snapshot'
PINS = {
    str(MESHC): '19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85',
    str(RELEASE / 'lib/libmesh_rt.a'): 'd1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8',
    str(RELEASE / 'lib/libmesh_test_rt.a'): '9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33',
}

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def save(path, value):
    path = ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')

def run(name, argv, cwd=ROOT, timeout=180, sandbox=False):
    outdir = ROOT / 'logs' / name
    outdir.mkdir(parents=True, exist_ok=False)
    tmp = ROOT / 'tmp' / name
    tmp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    overrides = {'TMPDIR': str(tmp) + '/', 'MESH_RT_LIB_PATH': str(RELEASE / 'lib/libmesh_rt.a'),
        'MESH_TEST_RT_LIB_PATH': str(RELEASE / 'lib/libmesh_test_rt.a'),
        'CLANG_MODULE_CACHE_PATH': str(tmp / 'clang-cache'), 'NO_COLOR': '1'}
    env.update(overrides)
    args = [str(x) for x in argv]
    if sandbox:
        args = ['/usr/bin/sandbox-exec', '-f', str(ROOT / 'offline.sb')] + args
    record = {'argv': args, 'shell_display': shlex.join(args), 'cwd': str(cwd),
        'environment_overrides': overrides, 'timeout_seconds': timeout, 'start_unix': time.time()}
    is_compiler = str(MESHC) in args
    lock_context = (ROOT / 'compiler.lock').open('a') if is_compiler else contextlib.nullcontext(None)
    with lock_context as lock, (outdir / 'stdout.log').open('wb') as out, (outdir / 'stderr.log').open('wb') as err:
        if lock is not None:
            # Parent's disk steering applies to every future invocation,
            # including separate manual driver invocations in this proof root.
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record['proof_compiler_concurrency_limit'] = 1
        proc = subprocess.Popen(args, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            record['exit_code'] = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            record['exit_code'] = proc.returncode
            record['timed_out'] = True
    record['elapsed_seconds'] = time.time() - record['start_unix']
    save(outdir / 'command.json', record)
    return record

def capture():
    sources = json.loads((ROOT / 'source-pins.json').read_text())
    deps = json.loads((ROOT / 'dependency-pins.json').read_text())
    return {'tools': {p: sha(p) for p in PINS},
        'snapshot': {x['path']: sha(SNAP / x['path']) for x in sources},
        'live_app': {x['path']: sha(REPO / x['path']) if (REPO / x['path']).exists() else None for x in sources},
        'language_inputs': {p: sha(p) for p in deps}}
