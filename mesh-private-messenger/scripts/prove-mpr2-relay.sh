#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repository="$(cd "$product/.." && pwd -P)"
work="${MORSE_MPR2_RELAY_PROOF_OUTPUT:-$repository/.morse/mpr2-relay-proof}"
mkdir -p "$work"
if [[ -e "$work/qualification.json" ]]; then
  echo 'Refusing to overwrite a qualified proof; select a fresh proof output directory' >&2
  exit 1
fi
git -C "$repository" diff --quiet HEAD -- || { echo 'Commit tracked changes before qualifying a proof' >&2; exit 1; }
bridge_target=''
trap 'if [[ -n "$bridge_target" ]]; then rm -rf "$bridge_target"; fi' EXIT
export MORSE_MPR2_RELAY_PROOF_OUTPUT="$work"
export MORSE_TOKEN_CUSTODY_FIXTURES_PATH="${MORSE_TOKEN_CUSTODY_FIXTURES_PATH:-/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/token-custody-fixtures.json}"
export MORSE_MPR2_RELAY_VECTORS_PATH="${MORSE_MPR2_RELAY_VECTORS_PATH:-/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/collateral-v2-operator/sdk-vector-subset-final3.json}"
export MORSE_MPR2_LEGACY_FIXTURES_PATH="${MORSE_MPR2_LEGACY_FIXTURES_PATH:-/Users/andreyyurlov/Documents/dev/whatsdown/.morse/witness-proof/adjudication-account-fixtures.json}"
retained="${MORSE_MPR2_RETAINED_PROOF:-/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-63282176/.morse/grace-assessment}"
export MORSE_JUDGE_SBF_PATH="${MORSE_JUDGE_SBF_PATH:-$retained/sbf/morse_judge.so}"
export MORSE_TOKEN_SBF_PATH="${MORSE_TOKEN_SBF_PATH:-$retained/sbf/morse_token.so}"
export MORSE_REWARDS_SBF_PATH="${MORSE_REWARDS_SBF_PATH:-$retained/sbf/morse_rewards.so}"
compiler="${MESHC:-/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts/bin/meshc}"
export MESH_RT_LIB_PATH="$(cd "$(dirname "$compiler")/../lib" && pwd -P)/libmesh_rt.a"
export MESH_TEST_RT_LIB_PATH="$(dirname "$MESH_RT_LIB_PATH")/libmesh_test_rt.a"

# A retained SBF binary is eligible only while every recorded source it links
# still matches this checkout. Examples/tests do not contribute to deployed ELF.
python3 - "$repository" "$retained/receipt.json" "$compiler" "$work" <<'PY'
import hashlib,json,os,pathlib,subprocess,sys
repo,receipt,compiler,work=map(pathlib.Path,sys.argv[1:]); retained=json.loads(receipt.read_text())
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
expected={str(compiler):'19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85',
os.environ['MESH_RT_LIB_PATH']:'d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8',
os.environ['MESH_TEST_RT_LIB_PATH']:'9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33',
os.environ['MORSE_TOKEN_CUSTODY_FIXTURES_PATH']:'448e6668036e6dd2184bc7a4fd60e2740545b1270ba070c59858c9bb7eb196b5',
os.environ['MORSE_MPR2_RELAY_VECTORS_PATH']:'6c34a4b1979a3d6518d165f26e1467a1251b48446db5d9e988d1cf7d91c7aa97'}
expected[os.environ['MORSE_MPR2_LEGACY_FIXTURES_PATH']]='b439d014e2680e0f5efff7f708c116c058ac2cee5ac1ce0afeac897fdac6866a'
for role in ['JUDGE','TOKEN','REWARDS']:
 path=os.environ[f'MORSE_{role}_SBF_PATH']
 values=[v for k,v in retained['artifacts'].items() if k.endswith(f'/morse_{role.lower()}.so')]
 assert len(values)==1,role
 expected[path]=values[0]
for path,value in expected.items():assert sha(path)==value,f'Artifact hash mismatch: {path}'
sources={}
for path,value in retained['sources'].items():
 if '/programs/' in path and ('/src/' in path or path.endswith(('Cargo.toml','Cargo.lock'))):
  assert sha(repo/path)==value,f'SBF source mismatch; rebuild retained programs: {path}'
  sources[path]=value
assert sources,'Retained SBF source manifest missing'
roots=[
 (str(repo/'mesh-private-messenger/ops/relay'),['.mjs'],False),
 (str(repo/'mesh-private-messenger/ops/relay-mpr2'),['.mpl','.toml'],True),
 (str(repo/'mesh-private-messenger/ops/collateral-v2'),['.mpl','.toml'],True),
 (str(repo/'mesh-private-messenger/packages/messenger-protocol'),['.mpl','.toml'],True),
 (str(repo/'mesh-private-messenger/ops/chain-writer'),['.mjs'],True),
 ('/Users/andreyyurlov/Documents/dev/mesh-lang/packages/mesh-solana',['.mpl','.toml'],True),
 ('/Users/andreyyurlov/Documents/dev/mesh-lang/packages/mesh-binary',['.mpl','.toml'],True),
 ('/Users/andreyyurlov/Documents/dev/mesh-lang/packages/mesh-lightning',['.mpl','.toml'],True)]
watched={}
for directory,suffixes,recursive in roots:
 root=pathlib.Path(directory);assert root.is_dir(),directory
 for p in (root.rglob('*') if recursive else root.glob('*')):
  if p.is_file() and p.suffix in suffixes:watched[str(p.resolve())]=sha(p)
explicit=[str(repo/'mesh-private-messenger/programs/morse-judge/examples/mpr2_relay_bridge.rs'),str(repo/'mesh-private-messenger/scripts/prove-mpr2-relay.sh')]
explicit += [str(repo/path) for path in sources]
for path in explicit:watched[path]=sha(path)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=repo,text=True).strip()
(work/'source-before.json').write_text(json.dumps({'schema_version':1,'head':head,'tree':tree,'roots':roots,'explicit':explicit,'sources':watched},indent=2)+'\n')
(work/'inputs.json').write_text(json.dumps({'schema_version':1,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
'retained_receipt':{'path':str(receipt),'sha256':sha(receipt)},'artifacts':expected,'sbf_sources':sources,
'source_manifest':{'path':str(work/'source-before.json'),'sha256':sha(work/'source-before.json')},
'execution':'Compiled production Mesh relay -> Kit -> FULL SQLite journal -> local signed SBF',
'limits':['Initialized custody fixture reused; new checkpoints, witness attestations and relay packets signed at current time.',
'Three loopback origins share one bank; no validator finality or provider independence.']},indent=2)+'\n')
PY

if ! command -v cargo >/dev/null 2>&1; then
  export PATH="/Users/andreyyurlov/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin:$PATH"
fi
if [[ -z "${MORSE_MPR2_RELAY_SBF_BRIDGE:-}" ]]; then
  bridge_target="$(mktemp -d "$work/bridge-target.XXXXXX")"
  export CARGO_TARGET_DIR="$bridge_target"
  cargo build --manifest-path "$product/programs/Cargo.toml" --locked \
    -p morse-judge --features svm --example mpr2_relay_bridge > "$work/bridge-build.txt" 2>&1
  cp "$CARGO_TARGET_DIR/debug/examples/mpr2_relay_bridge" "$work/mpr2_relay_bridge"
  export MORSE_MPR2_RELAY_SBF_BRIDGE="$work/mpr2_relay_bridge"
fi

if [[ "${MORSE_MPR2_RUN_BASELINE:-0}" == 1 ]]; then
  "$compiler" build "$product/tools/relay-scheduler-proof" --opt-level 2 --output "$work/legacy-scheduler-reader" > "$work/legacy-reader-build.txt" 2>&1
  if MORSE_MPR2_RELAY_BINARY='' MORSE_MPR2_BASELINE_BINARY="$work/legacy-scheduler-reader" \
      node --test --test-name-pattern='current compiled' "$product/ops/relay/mpr2-sbf.test.mjs" > "$work/current-relay-red.txt" 2>&1; then
    echo 'Baseline unexpectedly accepted MPR2; inspect retained red proof' >&2
    exit 1
  fi
  rg -q 'invalid_anchor_custody|invalid_slash_receipt' "$work/current-relay-red.txt"
fi

if [[ -n "${MORSE_MPR2_PREPARED_BASELINE_BINARY:-}" ]]; then
  mkdir -p "$work/red"
  cp "$product/ops/relay/mpr2-sbf.test.mjs" "$work/red/mpr2-sbf.test.source.mjs"
  if MORSE_MPR2_RELAY_BINARY="$MORSE_MPR2_PREPARED_BASELINE_BINARY" MORSE_MPR2_RELAY_PROOF_OUTPUT="$work/red" \
      node --test --test-name-pattern='competing PREPARED' "$product/ops/relay/mpr2-sbf.test.mjs" > "$work/red/sbf-red.txt" 2>&1; then
    echo 'Prepared-winner baseline unexpectedly passed; inspect retained red proof' >&2
    exit 1
  fi
  python3 - "$work/red" "$MORSE_MPR2_PREPARED_BASELINE_BINARY" <<'PY'
import hashlib,json,pathlib,sys
work,binary=map(pathlib.Path,sys.argv[1:]);case=json.loads((work/'case-prepared-winner.json').read_text())
assert case['verdict']=='FAIL' and case['prepared_receipt']['status']=='prepared'
assert case['prepared_balances']==['0']*4 and case['competing_native']['code']!=0
assert 'collateral_proof_quorum_unavailable_or_disagreed' in case['competing_native']['stdout']
assert 'Relay verification refused' in case['failure']['message'],case['failure']
paths=[binary,pathlib.Path(str(binary)+'.plaintext.json')]+[p for p in work.iterdir() if p.is_file() and p.name!='red-evidence.json']
(work/'red-evidence.json').write_text(json.dumps({'schema_version':1,'verdict':'EXPECTED FAIL',
'boundary':'B admitted before A prepares; A stops; compiled B scheduler refuses the authenticated competing PREPARED winner',
'artifacts':{str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}},indent=2)+'\n')
PY
fi

if [[ -z "${MORSE_MPR2_RELAY_BINARY:-}" ]]; then
  "$compiler" build "$product/ops/relay-mpr2" --opt-level 2 --output "$work/relay-mpr2" > "$work/mesh-build.txt" 2>&1
  export MORSE_MPR2_RELAY_BINARY="$work/relay-mpr2"
fi
python3 - "$work" "$MORSE_MPR2_RELAY_BINARY" "$MORSE_MPR2_RELAY_SBF_BRIDGE" <<'PY'
import hashlib,json,pathlib,sys
work=pathlib.Path(sys.argv[1]);before=json.loads((work/'source-before.json').read_text())
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
current={}
for directory,suffixes,recursive in before['roots']:
 root=pathlib.Path(directory)
 for p in (root.rglob('*') if recursive else root.glob('*')):
  if p.is_file() and p.suffix in suffixes:current[str(p.resolve())]=sha(p)
for p in before['explicit']:current[p]=sha(p)
drift=[p for p in before['sources'].keys()|current.keys() if before['sources'].get(p)!=current.get(p)]
assert not drift,f'Source drift during build; refusing to run a mixed proof: {drift}'
assert json.loads((work/'inputs.json').read_text())['source_manifest']['sha256']==sha(work/'source-before.json'),'Pre-build source manifest changed'
paths=[pathlib.Path(p) for p in sys.argv[2:]]
native=pathlib.Path(str(paths[0])+'.plaintext.json');assert native.is_file(),'Native compiler source receipt required'
modules=json.loads(native.read_text())['modules'];hashes=set(before['sources'].values())
missing=[m for m in modules if m['source_sha256'] not in hashes]
assert not missing,f'Native source receipt differs from pre-build sources: {missing}'
paths.append(native)
(work/'execution-before.json').write_text(json.dumps({'schema_version':1,'source_before_sha256':sha(work/'source-before.json'),
'native_modules_verified':len(modules),'watched_sources':len(before['sources']),
'artifacts':{str(p.resolve()):sha(p) for p in paths}},indent=2)+'\n')
PY
node --test "$product/ops/relay/mpr2-sbf.test.mjs" 2>&1 | tee "$work/sbf-green.txt"
if [[ -n "$bridge_target" ]]; then
  rm -rf "$bridge_target"
  python3 - "$work" "$bridge_target" <<'PY'
import json,pathlib,sys
work,target=map(pathlib.Path,sys.argv[1:]);assert not target.exists()
(work/'bridge-cleanup.json').write_text(json.dumps({'target':str(target),'removed':True})+'\n')
PY
fi
python3 - "$work" "$MORSE_MPR2_RELAY_BINARY" "$MORSE_MPR2_RELAY_SBF_BRIDGE" "$repository" <<'PY'
import hashlib,json,pathlib,subprocess,sys
work=pathlib.Path(sys.argv[1]);repo=pathlib.Path(sys.argv[4]);paths=[pathlib.Path(p) for p in sys.argv[2:4]]
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
before=json.loads((work/'source-before.json').read_text());execution=json.loads((work/'execution-before.json').read_text());current={}
assert execution['source_before_sha256']==sha(work/'source-before.json'),'Pre-execution source manifest changed'
assert json.loads((work/'inputs.json').read_text())['source_manifest']['sha256']==sha(work/'source-before.json'),'Pre-build source manifest changed'
for directory,suffixes,recursive in before['roots']:
 root=pathlib.Path(directory)
 for p in (root.rglob('*') if recursive else root.glob('*')):
  if p.is_file() and p.suffix in suffixes:current[str(p.resolve())]=sha(p)
for p in before['explicit']:current[p]=sha(p)
head_end=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert head_end==before['head'],'Git HEAD changed during proof'
assert subprocess.run(['git','diff','--quiet','HEAD','--'],cwd=repo).returncode==0,'Tracked worktree changed during proof'
drift=[p for p in before['sources'].keys()|current.keys() if before['sources'].get(p)!=current.get(p)]
artifact_drift=[p for p,h in execution['artifacts'].items() if sha(p)!=h]
artifact_drift += [p for p,h in json.loads((work/'inputs.json').read_text())['artifacts'].items() if sha(p)!=h]
(work/'source-after.json').write_text(json.dumps({'schema_version':1,'head':head_end,'sources':current,'source_drift':drift,'artifact_drift':artifact_drift},indent=2)+'\n')
assert not drift and not artifact_drift,f'Source or execution artifacts drifted; refusing PASS: {drift+artifact_drift}'
paths+=list(work.glob('case-*.json'))+list(work.glob('journal-*.sqlite'))+[work/'inputs.json',work/'sbf-green.txt',work/'legacy-replay.json',work/'source-before.json',work/'source-after.json',work/'execution-before.json']
paths+=[p for pattern in ['bank-input-*.json','pins-*.json','evidence-*.frk','request-*.json','phone-*','bridge-build.txt','bridge-cleanup.json','frozen-native.json','red/*'] for p in work.glob(pattern) if p.is_file()]
for name in ['prepared','settled','legacy']:
 capture=json.loads((work/f'phone-{name}.json').read_text())
 assert all(sha(p)==h for p,h in capture['artifacts'].items()),f'{name} capture artifact drift'
 assert all(sha(p)==h for p,h in capture['sources'].items()),f'{name} capture source drift'
 assert capture['boundary']['signed_packet_count'] == (0 if name=='legacy' else 11 if name=='prepared' else 13)
 assert capture['status']==('prepared' if name=='prepared' else 'settled')
prepared=json.loads((work/'phone-prepared.json').read_text());settled=json.loads((work/'phone-settled.json').read_text())
assert prepared['proof_hash']==settled['proof_hash'] and prepared['wire_identity']==settled['wire_identity']
assert prepared['ordered_keys']==settled['ordered_keys']
case=json.loads((work/'case-prepared-winner.json').read_text());assert case['verdict']=='PASS'
packet_count=sum(len(json.loads((work/f'case-{name}.json').read_text())['packets']) for name in ['2','16','prepared-winner'])
assert packet_count==80,packet_count
(work/'qualification.json').write_text(json.dumps({'schema_version':1,'verdict':'PASS',
'head_start':before['head'],'head_end':head_end,'tree':before['tree'],'signed_packets':packet_count,'source_manifest_sha256':sha(work/'source-before.json'),
'native_modules_verified':execution['native_modules_verified'],'watched_sources':execution['watched_sources'],
'executed_artifacts':execution['artifacts'],'source_drift':[],'artifact_drift':[],
'artifacts':{str(p):sha(p) for p in paths}},indent=2)+'\n')
PY
