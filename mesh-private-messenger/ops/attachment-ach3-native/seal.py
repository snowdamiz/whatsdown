#!/usr/bin/env python3
"""Archive the exact frozen source/proof bodies and both terminal OS results."""
from pathlib import Path
import argparse,hashlib,json,subprocess
from build import verify_fixture_modules
from wire_profile import work_selection, record_selection, material_status, validate_material_result
PRODUCT=Path(__file__).resolve().parents[2];ROOT=PRODUCT.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def checked_source_inputs(source):
    current={path:record['sha256'] for path,record in source.get('files',{}).items()}
    inputs=source.get('snapshot_inputs',current)
    assert inputs,'empty source checkpoint'
    if 'snapshot_inputs' in source and 'files' in source:
        assert inputs==current,'conflicting source checkpoint schemas'
    for path,digest in inputs.items():
        assert sha(Path(path))==digest,('frozen closure changed',path)
    return inputs

def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,default=ROOT/'.morse/witness-proof/ach3-native-87085');p.add_argument('--run-id',default='final');p.add_argument('--source-manifest',type=Path,default=ROOT/'.morse/witness-proof/ach3-current-final-source-manifest.json');p.add_argument('--baseline-report',type=Path,default=ROOT/'.morse/witness-proof/ach3-current-final-report.json');p.add_argument('--wire-profile',type=int,choices=[3,4]);p.add_argument('--expected-production-exports',type=int,choices=[162,163]);a=p.parse_args()
    work=a.work;selected=work_selection(work,a.wire_profile,a.expected_production_exports);source=json.loads(a.source_manifest.read_text());sources={}
    assert not (work/'manifest.json').exists(),'sealed evidence is immutable; choose a fresh work directory'
    sources.update(checked_source_inputs(source))
    canonical=json.loads(a.baseline_report.read_text())
    site_count=sum(len(m['sites']) for m in canonical['modules'])
    platforms={}
    for platform in ['ios','android']:
        evidence=work/(platform+'-'+a.run_id)/'evidence.json';r=json.loads(evidence.read_text())
        validate_material_result(r,selected,platform)
        assert r['source_inputs']==json.loads((evidence.parent/'source-inputs.json').read_text())
        sources.update(r['source_inputs']);platforms[platform]={'evidence':str(evidence),'sha256':sha(evidence),'groups':r['groups'],'calls':len(r['calls']),'requests':len(r['http'])}
        for path,digest in r['source_inputs'].items():
            # run.py may be superseded only by a separately named, archived run;
            # the selected evidence always has exact original source bodies.
            body=evidence.parent/'sources-by-sha'/digest;assert sha(body)==digest
    host=json.loads((work/'host-build.json').read_text())
    assert record_selection(host,'production_exports')==selected,'prepared host profile differs'
    for path,digest in host['inputs'].items():
        assert sha(work/'host-inputs'/digest)==digest
        sources[path]=digest
    builds=json.loads((work/'builds.json').read_text())
    for build in builds:
        assert record_selection(build)==selected and len(build['proof_only_exports'])==6 and build['plaintext_sites']==site_count
        assert build['baseline_report_sha256']==sha(a.baseline_report)
        assert build['compiler_sha256']==builds[0]['compiler_sha256']
        output=work/build['target']
        for name,digest in build['artifacts'].items():assert sha(output/name)==digest
        verify_fixture_modules(json.loads((output/'libmessenger_mobile.a.plaintext.json').read_text()),canonical,work/'driver')
    # The archiver and README are outside the executed native dependency set,
    # but their final exact bodies are retained for checkpoint reproduction.
    for f in [Path(__file__),Path(__file__).with_name('README.md')]:sources[str(f)]=sha(f)
    versions={path:[digest] for path,digest in sources.items()}
    for platform in ['ios','android']:
        for path,digest in json.loads((work/(platform+'-'+a.run_id)/'source-inputs.json').read_text()).items():
            versions.setdefault(path,[])
            if digest not in versions[path]:versions[path].append(digest)
    bodies=work/'sources-by-sha';bodies.mkdir(exist_ok=True)
    for path,digest in [(p,d) for p,ds in versions.items() for d in ds]:
        target=bodies/digest
        if not target.exists():
            f=Path(path)
            if sha(f)!=digest:
                candidates=[*work.glob('*/sources-by-sha/'+digest),work/'host-inputs'/digest]
                f=next(x for x in candidates if x.is_file() and sha(x)==digest)
            subprocess.run(['cp','-c',str(f),str(target)],check=True)
        assert sha(target)==digest
    artifacts={}
    for target in ['aarch64-apple-ios-sim','aarch64-linux-android']:
        for f in (work/target).iterdir():
            if f.is_file():artifacts[str(f.relative_to(work))]=sha(f)
    for platform in ['ios','android']:
        for f in (work/(platform+'-'+a.run_id)).rglob('*'):
            if f.is_file() and 'sources-by-sha' not in f.parts and f.suffix not in ['.key','.p12']:
                # No live custody, local DB, private TLS key or generated test
                # keystore is an evidence artifact. Native executable/APK and
                # public resource frames are retained explicitly by the harness.
                if f.name.endswith(('.db','.db-wal','.db-shm')):continue
                if 'credit-tls' in f.parts and f.name not in ['ca.pem','server.pem','extensions.cnf']:continue
                if f.suffix in ['.o','.jar','.dex','.class']:continue
                artifacts[str(f.relative_to(work))]=sha(f)
    report={'schema_version':1,'status':material_status(selected,sealed=True),'wire_profile':selected['wire_profile'],'source_manifest':str(a.source_manifest),'source_manifest_sha256':sha(a.source_manifest),'compiler_sha256':builds[0]['compiler_sha256'],'production_exports_unchanged':selected['production_exports'],'proof_only_exports':6,'plaintext_sites':site_count,'baseline_report_sha256':sha(a.baseline_report),'platforms':platforms,'sources':sources,'source_versions':versions,'artifacts':artifacts,'provenance_checks':['Every frozen application source body matches its selected checkpoint.','Each proof helper has its exact source hash and zero disclosure sites.','Every production module and reviewed site equals the selected canonical report.','Both terminal OS results and all native build artifacts retain their recorded hashes.'],'limits':['Simulator/emulator, not physical devices; no production installation or deployment.','Owned object HTTP/TLS fixture; no funded paid grant.','Paid material-only status3 exercises actual production writer/recovery without synthesized credits.','Legacy fixture writers are test-only inputs; new upload wire profile is explicitly selected and checked.','No screen capture or computer-use service required.']}
    (work/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'source_bodies':sum(len(v) for v in versions.values()),'artifacts':len(artifacts),'manifest_sha256':sha(work/'manifest.json')}))
if __name__=='__main__':main()
