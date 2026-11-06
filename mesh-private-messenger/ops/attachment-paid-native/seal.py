#!/usr/bin/env python3
"""Seal funded native proof without archiving keys, bearer frames or databases."""
from pathlib import Path
import argparse,hashlib,json,subprocess
from build import verify_work,pinned,TARGETS,WIRE
PRODUCT=Path(__file__).resolve().parents[2];ROOT=PRODUCT.parent;HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--run-id',default='first');a=p.parse_args()
    assert not (a.work/'manifest.json').exists(),'sealed manifest is immutable; choose a fresh work directory'
    backend,qualification=verify_work(a.work)
    selected=WIRE.qualification_selection(qualification)
    run=a.work/'runs'/a.run_id;snapshot=Path(backend['snapshot'])
    evidence=run/'native-paid-attachment/evidence.json';result=json.loads(evidence.read_text())
    assert result['status']=='passed_dual_native_paid_attachment_actual_services'
    assert WIRE.record_selection(result,'native_production_exports')==selected,'funded result attachment profile differs'
    assert result['server']=={'spent_tokens':2,'attachment_effects':2,'completed_objects':2,'object_parts':516}
    assert set(result['platforms'])=={'ios','android'}
    assert len(set(result['private_postgres_ports']))==3 and 55438 not in result['private_postgres_ports']
    for platform,row in result['platforms'].items():
        assert row['actual_maturity_seconds']>=600 and len(row['payment_hash'])==64
        assert row['actual_action_expiry_seconds']>=600 and row['cancel_expires']-row['cancel_started_unix']>=599
        assert len(row['cases'])==13
        if selected['wire_profile']==4:
            assert row['write_shape']=={'manifest_bytes':514,'first_cipher_bytes':65576,'last_cipher_bytes':65576,'last_plaintext_bytes':1}
    successful_grants={}
    denied=[]
    for row in result['http']:
        if row['route']!='/v1/attachments/paid-grant':continue
        if row['status'] in [200,201]:successful_grants.setdefault(row['request_sha256'],[]).append(row)
        else:denied.append(row)
    assert len(successful_grants)==2
    for rows in successful_grants.values():
        assert [r['status'] for r in rows]==[201,200,200,200]
        assert len({r['response_sha256'] for r in rows})==1
        assert all(r['response_bytes']==290 for r in rows)
    assert len(denied)==2 and all(r['status']==503 and r['injected_before_upstream'] for r in denied)
    puts={}
    for row in result['http']:
        if row['method']=='PUT':puts.setdefault(row['route'],[]).append(row)
    assert len(puts)==516
    assert sum(len(rows)-1 for rows in puts.values())==2
    assert all(len({r['request_sha256'] for r in rows})==1 and all(r['status'] in [200,201] for r in rows) for rows in puts.values())
    cancellations=[r for r in result['http'] if r['route']=='/v1/credits/reconcile']
    assert len(cancellations)==4 and all(r['status']==200 and r['response_bytes']==172 for r in cancellations)
    assert sha(Path(backend['compiler']))==backend['compiler_sha256'] and sha(Path(backend['runtime']))==backend['runtime_sha256']
    source_versions={}
    def source(path,digest=None):
        path=Path(path);digest=digest or sha(path)
        source_versions.setdefault(str(path),[])
        if digest not in source_versions[str(path)]:source_versions[str(path)].append(digest)
        return digest
    for path,digest in backend['sources'].items():
        f=snapshot/path;assert sha(f)==digest;source(f,digest)
    proof_sources=json.loads((run/'proof-source-inputs.json').read_text())
    for path,digest in proof_sources.items():
        assert sha(run/'sources-by-sha'/digest)==digest;source(path,digest)
    for f in [HERE/'seal.py',HERE/'README.md']:source(f)
    host=json.loads((a.work/'host-build.json').read_text())
    for path,digest in host['inputs'].items():assert sha(a.work/'host-inputs'/digest)==digest;source(path,digest)
    native_qualification=pinned(qualification['material_qualification'])
    # Include the qualified native's complete immutable source closure, rather
    # than implying the new service closure was its compilation input.
    manifest=json.loads(pinned(qualification['source_manifest']).read_text())
    for path,row in manifest['files'].items():assert sha(Path(path))==row['sha256'];source(path,row['sha256'])
    for path,digest in qualification['issuer_files'].items():source(Path(qualification['issuer_root'])/path,digest)
    source(a.work/'qualification.json',backend['qualification_sha256'])
    for name in ['source_manifest','native_manifest','material_qualification','canonical_report','expected_abi']:
        source(pinned(qualification[name]),qualification[name]['sha256'])
    for path,digest in backend['build_inputs'].items():
        assert sha(a.work/'build-inputs'/digest)==digest;source(path,digest)
    compiled=run/'issuer/compiled'
    for f in (compiled/'sources-by-sha').glob('*.mpl'):
        assert sha(f)==f.stem;source(f,f.stem)
    bodies=a.work/'sources-by-sha';bodies.mkdir(exist_ok=True)
    for path,digests in source_versions.items():
        for digest in digests:
            target=bodies/digest
            if target.exists():assert sha(target)==digest;continue
            original=Path(path)
            if sha(original)!=digest:
                original=next(f for f in [run/'sources-by-sha'/digest,a.work/'host-inputs'/digest,a.work/'build-inputs'/digest] if f.is_file() and sha(f)==digest)
            subprocess.run(['cp','-c',str(original),str(target)],check=True);assert sha(target)==digest
    artifacts={}
    def artifact(f):
        if f.is_file():artifacts[str(f.relative_to(a.work))]=sha(f)
    for name,row in backend['executables'].items():
        assert sha(a.work/name)==row['sha256'];assert sha(a.work/(name+'.plaintext.json'))==row['report_sha256']
        artifact(a.work/name);artifact(a.work/(name+'.plaintext.json'));artifact(a.work/(name+'-build.log'))
    for name in ['backend.json','host-build.json','android-host-build.log','qualification.json']:artifact(a.work/name)
    for target in ['aarch64-apple-ios-sim','aarch64-linux-android']:
        for f in (a.work/target).iterdir():artifact(f)
    artifact(a.work/'native-product/apps/mobile/modules/mesh-messenger/android/build/ach3-proof/arm64-v8a/libmessenger_mobile.so')
    for f in compiled.iterdir():
        if f.is_file():artifact(f)
    for name in ['lightning-issuance-build.log','lightning-production-build.log','lightning-issuance-selected-local.json','native-action-extension.json']:artifact(run/'issuer'/name)
    for name in ['evidence.json','core.log','edge.log','object-store.log','http-trace.json','native-security-config.txt','native-network-config.txt','issuer-ca-resource.bin']:artifact(run/'native-paid-attachment'/name)
    for platform in ['ios','android']:
        for f in (run/'native-paid-attachment'/platform/'native').rglob('*'):
            assert f.suffix not in ['.key','.p12','.db','.db-wal','.db-shm']
            artifact(f)
    artifact(run/'proof-source-inputs.json')
    report={'schema_version':1,'status':'passed_frozen_dual_native_paid_attachment_actual_services','server':result['server'],'native_verified_tokens':200,
      'native_final_available_per_wallet':99,'platforms':result['platforms'],'compiler_sha256':backend['compiler_sha256'],'host_runtime_sha256':backend['runtime_sha256'],
      'native_source_manifest_sha256':qualification['source_manifest']['sha256'],'native_prior_qualification_sha256':sha(native_qualification),'native_build_manifest_sha256':qualification['native_manifest']['sha256'],'qualification_sha256':backend['qualification_sha256'],
      'native_production_exports':qualification['expected']['exports'],'wire_profile':selected['wire_profile'],'native_fixture_exports':0,'native_plaintext_sites':qualification['expected']['sites'],'native_production_modules':qualification['expected']['modules'],'private_postgres_ports':result['private_postgres_ports'],'http_requests':len(result['http']),'sources':source_versions,'artifacts':artifacts,
      'limits':['Owned regtest Bitcoin/LND and explicit price-account RPC fixture; no live funds or Pyth guardian proof.','Simulator/emulator ABI and actual OS storage, not physical-device or rendered UI acceptance.','Real600-second credit maturity and separate600-second action expiry; no clock bypass.','Current frozen Core/edge/object-store; explicit qualified issuer source and production native libraries reused.','No signer/native seed/bearer frames/databases/private TLS keys archived; no deployment/activation.']}
    with (a.work/'manifest.json').open('x') as output:output.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'source_versions':sum(len(v) for v in source_versions.values()),'artifacts':len(artifacts),'manifest_sha256':sha(a.work/'manifest.json')}))
if __name__=='__main__':main()
