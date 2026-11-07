from pathlib import Path
import os, sys, time, subprocess, json, fcntl, hashlib
root=Path(__file__).resolve().parent
family=Path('/Users/andreyyurlov/Documents/dev/mesh-lang/.tmp/builtin-try-from/release-artifacts')
expected={'bin/meshc':'19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85','lib/libmesh_rt.a':'d1e2b001783fe819f03644f5e4dcf42bc362bb1cecd04e475097d80cf9d3a8f8','lib/libmesh_test_rt.a':'9283206f47c6a52fa075a108773854ad7a12aae437c16b04c4fc747740674c33'}
for name,digest in expected.items(): assert hashlib.sha256((family/name).read_bytes()).hexdigest()==digest
name,variant,test=sys.argv[1:4]
log=root/'logs'/name;log.mkdir(parents=True,exist_ok=False)
tmp=root/'tmp'/name;tmp.mkdir(parents=True)
env=dict(os.environ)
overrides={'MESH_RT_LIB_PATH':str(family/'lib/libmesh_rt.a'),'MESH_TEST_RT_LIB_PATH':str(family/'lib/libmesh_test_rt.a'),'TMPDIR':str(tmp)+'/', 'CLANG_MODULE_CACHE_PATH':str(tmp/'clang-cache'),'NO_COLOR':'1'}
env.update(overrides)
args=['/usr/bin/sandbox-exec','-f',str(root/(sys.argv[4] if len(sys.argv)>4 else 'offline.sb')),str(family/'bin/meshc'),'test',str(root/variant/'tests'/test)]
record={'argv':args,'cwd':str(root/variant),'env':overrides,'start_unix':time.time(),'compiler_concurrency':1}
with (root/'compiler.lock').open('a') as lock, (log/'stdout.log').open('w') as out, (log/'stderr.log').open('w') as err:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try: record['exit_code']=subprocess.run(args,cwd=root/variant,env=env,stdout=out,stderr=err,timeout=240).returncode
 except subprocess.TimeoutExpired: record['timeout']=True
record['elapsed_seconds']=time.time()-record['start_unix']
(log/'command.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record));print((log/'stdout.log').read_text());print((log/'stderr.log').read_text())
