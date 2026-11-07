from pathlib import Path
import os,subprocess,json,hashlib,sys
out=Path(sys.argv[1]).resolve(); family=Path('/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts');adapter=Path('/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-f9098070/.morse/continuation-20261106/viewonce-composed/core-tests/fixture-paths.dylib')
env=os.environ.copy();env.update(MESH_RT_LIB_PATH=str(family/'lib/libmesh_rt.a'),MESH_TEST_RT_LIB_PATH=str(family/'lib/libmesh_test_rt.a'),DYLD_INSERT_LIBRARIES=str(adapter),MORSE_OWNED_LEGACY_ROOT=str(out/'legacy'));(out/'legacy').mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={str(p):sha(p) for p in sorted((out/'mesh-private-messenger/packages').rglob('*.mpl'))}; inputs.update({str(p):sha(p) for p in sorted((out/'mesh-lang/packages').rglob('*.mpl'))}); inputs.update({str(p):sha(p) for p in [family/'bin/meshc',family/'lib/libmesh_rt.a',family/'lib/libmesh_test_rt.a',adapter]})
cmd=[str(family/'bin/meshc'),'test',sys.argv[2]]
assert not (out/'test.log').exists()
with (out/'test.log').open('w') as f:r=subprocess.run(cmd,cwd=out/'mesh-private-messenger/packages/mobile-core',env=env,stdout=f,stderr=subprocess.STDOUT,timeout=300)
record={'command':cmd,'exit':r.returncode,'inputs':inputs,'drift':[p for p,h in inputs.items() if sha(Path(p))!=h],'log_sha256':sha(out/'test.log')};(out/'result.json').write_text(json.dumps(record,indent=2)+'\n'); print(json.dumps({k:v for k,v in record.items() if k!='inputs'},indent=2)); print((out/'test.log').read_text()[-4500:])
