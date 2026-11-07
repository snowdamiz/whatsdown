import os, sys, subprocess, json, hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[2]
out=root/'.morse/sibling-authority'/sys.argv[1];out.mkdir(parents=True,exist_ok=True)
tool=Path('/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts')
env=os.environ.copy()
env.update(MESH_RT_LIB_PATH=str(tool/'lib/libmesh_rt.a'),MESH_TEST_RT_LIB_PATH=str(tool/'lib/libmesh_test_rt.a'),DYLD_INSERT_LIBRARIES='/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-f9098070/.morse/continuation-20261106/viewonce-composed/core-tests/fixture-paths.dylib',MORSE_OWNED_LEGACY_ROOT=str(out/'legacy'))
(out/'legacy').mkdir(exist_ok=True)
names=sys.argv[2:] or ['sibling_authority']
def sources():
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root/'mesh-private-messenger/packages').rglob('*.mpl'))}
before=sources()
(out/'sources-before.json').write_text(json.dumps(before,indent=2)+'\n')
results=[]
for name in names:
 cmd=[str(tool/'bin/meshc'),'test','tests/'+name+'.test.mpl']
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(cmd,cwd=root/'mesh-private-messenger/packages/mobile-core',env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
 results.append({'test':name,'command':cmd,'exit':r.returncode,'log_sha256':hashlib.sha256((out/(name+'.log')).read_bytes()).hexdigest()})
 print(name,r.returncode,flush=True)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')

after=sources()
(out/'sources-after.json').write_text(json.dumps(after,indent=2)+'\n')
assert before==after, 'source drift during proof'
