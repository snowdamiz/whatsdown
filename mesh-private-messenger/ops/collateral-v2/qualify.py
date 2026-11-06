#!/usr/bin/env python3
"""Bounded local qualification. Requires real captured SBF state; no providers/signing."""
import argparse, concurrent.futures, hashlib, json, os, subprocess, time
from pathlib import Path

PINS={"MESH_COMPILER_BIN":"25a8e3f78695e3c190bc2fc153c5294336451c3b120564ceca6f0e33c6333ef1","MESH_RT_LIB_PATH":"347da0ed305c88999ea82c9f1f1a82a04eed643c180db014a938b0edb1d88fdf","MESH_TEST_RT_LIB_PATH":"c10c5256d6c1a65aeb6e5047253fc7c0830eb2ca241087d704588650232a093b"}
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--vectors',required=True);p.add_argument('--close-vectors',required=True);p.add_argument('--output',required=True);a=p.parse_args();here=Path(__file__).resolve().parent;out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=False)
 env=os.environ.copy()
 for key,expected in PINS.items():assert key in env and digest(env[key])==expected,(key,'toolchain pin mismatch')
 vectors=Path(a.vectors).resolve();data=json.loads(vectors.read_text());assert data['scope']=='actual-local-SBF-SDK-vector-subset' and len(data['cases'])>=144
 env.update(MORSE_COLLATERAL_OPERATOR_VECTORS_PATH=str(vectors),MORSE_COLLATERAL_OPERATOR_CLOSE_VECTORS_PATH=str(Path(a.close_vectors).resolve()),MORSE_COLLATERAL_OPERATOR_CLOSE_INSTRUCTIONS_PATH=str(out/'owner-close-instructions.json'),MORSE_COLLATERAL_CLOSE_HTTP_OUTPUT=str(out/'close-rpc'),MORSE_COLLATERAL_OPERATOR_INSTRUCTIONS_PATH=str(out/'mesh-instructions.json'),MORSE_COLLATERAL_OPERATOR_EXTRA_KEYS_OUTPUT=str(out/'query-keys.json'),MORSE_COLLATERAL_OPERATOR_RPC_OUTPUT=str(out/'rpc'),MORSE_COLLATERAL_PROOF_HTTP_OUTPUT=str(out/'proof-rpc'))
 source_roots=[here,here/'../../packages/messenger-protocol',here/'../../../mesh-lang/packages/mesh-solana',here/'../../../mesh-lang/packages/mesh-binary',here/'../../../mesh-lang/packages/mesh-lightning']
 sources=sorted(set(p.resolve() for root in source_roots for p in root.rglob('*') if p.is_file() and p.suffix in ['.mpl','.toml','.py','.mjs','.md']))
 before={str(path):digest(path) for path in sources};(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
 compiler=env['MESH_COMPILER_BIN'];jobs=[('origins',[compiler,'test','tests/origins.test.mpl']),('write',[compiler,'test','tests/write.test.mpl']),('boundaries',[compiler,'test','tests/boundaries.test.mpl']),('read',[compiler,'test','tests/read.test.mpl']),('proof',[compiler,'test','tests/proof.test.mpl']),('workflow',[compiler,'test','tests/workflow.test.mpl']),('keys',[compiler,'test','tests/keys.test.mpl']),('rpc',['node','tests/rpc.mjs']),('proof-rpc',['node','tests/proof_rpc.mjs']),('close',[compiler,'test','tests/close.test.mpl']),('close-rpc',['node','tests/close_rpc.mjs']),('cli',[compiler,'build','.', '--output',str(out/'collateral-v2'),'--opt-level','2'])]
 def run(job):
  name,command=job;start=time.monotonic()
  with (out/(name+'.log')).open('w') as log:r=subprocess.run(command,cwd=here,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
  return dict(name=name,command=command,exit_code=r.returncode,seconds=round(time.monotonic()-start,3),log=name+'.log')
 results=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  for result in pool.map(run,jobs):results.append(result);print(json.dumps(result),flush=True)
 style=[]
 for source in sorted([*here.glob('*.mpl'),*here.joinpath('tests').glob('*.mpl'),here/'../../packages/messenger-protocol/transparency/token_collateral_write.mpl',here/'../../packages/messenger-protocol/transparency/token_proof_write.mpl']):
  if source.name=='token_write.mpl':continue
  for verb in [('fmt','--check'),('lint',)]:
   r=subprocess.run([compiler,*verb,str(source)],cwd=here,env=env,capture_output=True,text=True);style.append({'source':str(source),'check':verb[0],'exit_code':r.returncode,'output':r.stdout+r.stderr})
 (out/'style.json').write_text(json.dumps(style,indent=2)+'\n')
 after={str(path):digest(path) for path in sources};assert before==after,'source changed during qualification'
 for key,expected in PINS.items():assert digest(env[key])==expected,key
 result={'schema_version':1,'scope':'local-compiled-Mesh-and-fresh-local-HTTP-replay; SBF execution is a separate recorded gate','vectors':str(vectors),'vectors_sha256':digest(vectors),'close_vectors_sha256':digest(a.close_vectors),'source_count':len(before),'source_sha256':digest(out/'source-before.json'),'toolchain':{key:{'path':env[key],'sha256':expected} for key,expected in PINS.items()},'results':results,'style_passed':all(x['exit_code']==0 and x['output']=='' for x in style)}
 (out/'results.json').write_text(json.dumps(result,indent=2)+'\n');assert all(x['exit_code']==0 for x in results) and result['style_passed'],'qualification failed; logs preserved'
if __name__=='__main__':main()
