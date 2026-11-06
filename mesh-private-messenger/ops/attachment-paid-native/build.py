#!/usr/bin/env python3
"""Freeze real services against explicit immutable native/source/toolchain pins."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,subprocess,tomllib
PRODUCT=Path(__file__).resolve().parents[2];ROOT=PRODUCT.parent;HERE=Path(__file__).resolve().parent
TARGETS=('aarch64-apple-ios-sim','aarch64-linux-android')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
_wire_spec=importlib.util.spec_from_file_location('attachment_native_wire_profile',PRODUCT/'ops/attachment-ach3-native/wire_profile.py')
WIRE=importlib.util.module_from_spec(_wire_spec);_wire_spec.loader.exec_module(WIRE)

def is_source(path):
    return path.suffix in ['.mpl','.toml','.sql'] or path.name.endswith('.mpl.fixture')

def source_files(root):
    return {str(f.relative_to(root)):sha(f) for f in sorted(root.rglob('*')) if f.is_file() and is_source(f)}

def package_paths(q):
    closure=Path(q['closure']).resolve()
    names=('mesh-binary','mesh-solana','mesh-lightning','messenger-protocol')
    if 'source_packages' not in q:
        return {name:closure/name for name in names}
    mapping=q['source_packages'];assert set(mapping)==set(names),'incomplete source package mapping'
    paths={}
    for name in names:
        relative=Path(mapping[name])
        assert not relative.is_absolute() and '..' not in relative.parts,'package path escapes closure'
        path=(closure/relative).resolve()
        assert path.is_relative_to(closure) and path.is_dir(),'package path outside frozen closure'
        manifest=tomllib.loads((path/'mesh.toml').read_text())
        assert manifest['package']['name']==name,'package mapping identity differs'
        paths[name]=path
    return paths

def pinned(ref):
    path=Path(ref['path']);assert path.is_absolute() and path.is_file(),'missing absolute qualification input'
    assert sha(path)==ref['sha256'],'qualification input hash mismatch: '+str(path)
    return path

def normalize_report(report):
    rows=[(r['module'],r['source_sha256'],r['sites']) for r in report['modules']]
    assert len({r[0] for r in rows})==len(rows),'duplicate report module'
    return sorted(rows,key=lambda r:r[0])

def validate_native(q,root=None):
    native_root=Path(q['native_manifest']['path']).parent if root is None else Path(root)
    manifest=json.loads(pinned(q['native_manifest']).read_text());expected=q['expected']
    canonical=json.loads(pinned(q['canonical_report']).read_text());abi=json.loads(pinned(q['expected_abi']).read_text())
    assert len(canonical['modules'])==expected['modules'] and sum(len(r['sites']) for r in canonical['modules'])==expected['sites']
    assert len(abi['exports'])==expected['exports'] and len({r['symbol'] for r in abi['exports']})==expected['exports']
    for target in TARGETS:
        artifacts={name:digest for name,digest in manifest['file_manifest'].items() if name.startswith(target+'/')}
        required={target+'/'+name for name in ['libmessenger_mobile.a','libmessenger_mobile.abi.json','libmessenger_mobile.a.plaintext.json']}
        assert required<=set(artifacts),'missing native target artifact'
        for name,digest in artifacts.items():
            relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts
            assert sha(native_root/relative)==digest,'native artifact drift: '+name
        output=native_root/target
        actual_abi=json.loads((output/'libmessenger_mobile.abi.json').read_text())
        assert actual_abi['target']==target
        assert {k:v for k,v in actual_abi.items() if k!='target'}=={k:v for k,v in abi.items() if k!='target'},'native ABI changed beyond target'
        report=json.loads((output/'libmessenger_mobile.a.plaintext.json').read_text())
        assert normalize_report(report)==normalize_report(canonical),'native report differs from canonical source/site inventory'
        row=next(row for row in manifest['targets'] if row['target']==target)
        assert sha(output/'libmessenger_mobile.a')==row['library']['sha256']
    return manifest

def load_qualification(path):
    q=json.loads(Path(path).read_text());assert q['schema_version']==1
    for name in ['source_manifest','native_manifest','material_qualification','canonical_report','expected_abi','compiler','runtime']:pinned(q[name])
    expected=q['expected'];assert all(type(expected[k]) is int and expected[k]>0 for k in ['exports','modules','sites'])
    selected=WIRE.qualification_selection(q)
    source_manifest=json.loads(pinned(q['source_manifest']).read_text());closure=Path(q['closure']).resolve()
    recorded={}
    for name,row in source_manifest['files'].items():
        file=Path(name).resolve();assert file.is_relative_to(closure),'source outside pinned closure'
        digest=row['sha256'];assert sha(file)==digest,'native source body drift: '+name
        recorded[str(file.relative_to(closure))]=digest
    # A full application checkpoint may also pin native hosts and other inputs.
    # Verify all recorded bytes above, and still reject any unrecorded Mesh,
    # manifest or migration source that compilation could consume.
    assert {name:digest for name,digest in recorded.items() if is_source(Path(name))}==source_files(closure),'native source closure missing or contains unrecorded sources'
    if 'source_packages' in q:package_paths(q)
    native=json.loads(pinned(q['native_manifest']).read_text())
    assert native['source_manifest']['sha256']==q['source_manifest']['sha256']
    assert native['compiler']['sha256']==q['compiler']['sha256']
    assert (native['exports'],native['modules'],native['candidate_sites'])==(expected['exports'],expected['modules'],expected['sites'])
    canonical=json.loads(pinned(q['canonical_report']).read_text())
    assert all(row['source_sha256'] in recorded.values() for row in canonical['modules']),'canonical report source absent from closure'
    material=json.loads(pinned(q['material_qualification']).read_text())
    assert material['status']==WIRE.material_status(selected,sealed=True)
    assert WIRE.record_selection(material)==selected,'material attachment profile differs from qualification'
    assert material['source_manifest_sha256']==q['source_manifest']['sha256'] and material['compiler_sha256']==q['compiler']['sha256']
    assert material['production_exports_unchanged']==expected['exports'] and material['plaintext_sites']==expected['sites']
    assert material['baseline_report_sha256']==q['canonical_report']['sha256']
    assert source_files(Path(q['issuer_root']))==q['issuer_files'],'reused issuer source drift'
    if 'prior_funded_archive' in q:pinned(q['prior_funded_archive'])
    validate_native(q)
    return q

def verify_work(work):
    work=Path(work).resolve()
    backend=json.loads((work/'backend.json').read_text());qualification=work/'qualification.json'
    assert sha(qualification)==backend['qualification_sha256'],'qualification selection drift'
    q=load_qualification(qualification)
    selected=WIRE.qualification_selection(q)
    assert WIRE.record_selection(backend,'native_production_exports')==selected,'backend attachment profile differs'
    assert backend['compiler']==q['compiler']['path'] and backend['compiler_sha256']==q['compiler']['sha256']
    assert backend['runtime']==q['runtime']['path'] and backend['runtime_sha256']==q['runtime']['sha256']
    snapshot=Path(backend['snapshot'])
    assert backend['sources']=={str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()},'frozen service source drift'
    for name,row in backend['executables'].items():
        assert sha(work/name)==row['sha256']
        assert sha(work/(name+'.plaintext.json'))==row['report_sha256']
        report=json.loads((work/(name+'.plaintext.json')).read_text())
        assert all(m['source_sha256'] in backend['sources'].values() for m in report['modules'])
    validate_native(q,work)
    host=json.loads((work/'host-build.json').read_text())
    assert WIRE.record_selection(host,'production_exports')==selected,'prepared host attachment profile differs'
    if selected['wire_profile']==4:
        assert any(Path(path).resolve()==qualification.resolve() and digest==sha(qualification) for path,digest in host['selection_inputs'].items()),'prepared host qualification differs'
    for name,digest in host['inputs'].items():assert sha(work/'host-inputs'/digest)==digest
    native=work/'native-product/apps/mobile/modules/mesh-messenger'
    assert sha(native/'android/build/ach3-proof/arm64-v8a/libmessenger_mobile.so')==host['library_sha256']
    for target,destination in [('aarch64-apple-ios-sim','native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a'),('aarch64-linux-android','native/android/arm64-v8a/libmessenger_mobile.a')]:
        assert sha(native/destination)==sha(work/target/'libmessenger_mobile.a')
    for ext in ['h','swift','kt','jni.c','ts']:
        assert sha(native/'generated'/('libmessenger_mobile.'+ext))==sha(work/TARGETS[0]/('libmessenger_mobile.'+ext))
    return backend,q

def clone(source,target):
    target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists(),'immutable output already exists: '+str(target)
    subprocess.run(['cp','-c',str(source),str(target)],check=True);assert sha(source)==sha(target)

def sources(source,target):
    for name in source_files(source):
        destination=target/name
        clone(source/name,destination)
        # Rebase dependency paths and add fixture routes only in this new copy.
        # APFS clones preserve sealed inputs' read-only permissions.
        destination.chmod(destination.stat().st_mode | 0o200)

def snapshot_packages(q,snapshot):
    snapshot=Path(snapshot).resolve()
    paths=package_paths(q)
    for name,source in paths.items():sources(source,snapshot/'packages'/name)
    # Current manifests retain the public sibling checkout geometry. Create
    # these owned aliases before compilation, while preserving older flattened
    # checkpoints whose absolute dependency paths are rebased in the copy.
    public=snapshot.parent/'mesh-lang/packages';public.mkdir(parents=True)
    for name in ['mesh-binary','mesh-solana','mesh-lightning']:
        (public/name).symlink_to(snapshot/'packages'/name,target_is_directory=True)
    for name in paths:
        manifest=snapshot/'packages'/name/'mesh.toml'
        manifest.write_text(manifest.read_text().replace(str(Path(q['closure']).resolve()),str(snapshot/'packages')))
        dependencies=tomllib.loads(manifest.read_text()).get('dependencies',{})
        for dependency in dependencies.values():
            if isinstance(dependency,dict) and 'path' in dependency:
                resolved=(manifest.parent/dependency['path']).resolve()
                assert resolved.is_relative_to(snapshot/'packages') and resolved.is_dir(),'copied dependency escapes snapshot'

def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--qualification',type=Path,required=True);p.add_argument('--jobs',type=int,choices=[1,2],default=1);a=p.parse_args()
    q=load_qualification(a.qualification)
    selected=WIRE.qualification_selection(q)
    a.work=a.work.resolve();a.work.mkdir(parents=True,exist_ok=False)
    clone(a.qualification,a.work/'qualification.json')
    closure=Path(q['closure']);snapshot=a.work/'product-snapshot'
    snapshot_packages(q,snapshot)
    sources(PRODUCT/'packages/service-jobs',snapshot/'packages/service-jobs')
    for name in ['directory-delivery','privacy-edge','object-store']:sources(PRODUCT/'services'/name,snapshot/'services'/name)
    sources(Path(q['issuer_root']),snapshot/'services/credit-issuer')
    for manifest in snapshot.rglob('mesh.toml'):
        manifest.write_text(manifest.read_text().replace(str(closure),str(snapshot/'packages')))
    core=snapshot/'services/directory-delivery';clone(HERE/'core_fixture.mpl.fixture',core/'proof/attachment_fixture.mpl')
    main=core/'main.mpl';body=main.read_text();assert 'HTTP.serve(build_router(), port)' in body
    main.write_text('from Proof.AttachmentFixture import proof_router\n'+body.replace('HTTP.serve(build_router(), port)','HTTP.serve(proof_router(build_router()), port)'))
    before={str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()}
    compiler=pinned(q['compiler']);runtime=pinned(q['runtime']);env=dict(os.environ,MESH_RT_LIB_PATH=str(runtime))
    def build(name):
        binary=a.work/name;command=[str(compiler),'build',str(snapshot/'services'/name),'--opt-level','0','-o',str(binary)]
        with (a.work/(name+'-build.log')).open('x') as log:subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        report=json.loads(binary.with_name(binary.name+'.plaintext.json').read_text());assert all(m['source_sha256'] in before.values() for m in report['modules'])
        return name,{'command':command,'sha256':sha(binary),'report_sha256':sha(binary.with_name(binary.name+'.plaintext.json'))}
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:built=dict(pool.map(build,['directory-delivery','privacy-edge','object-store']))
    assert before=={str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()}
    native=json.loads(pinned(q['native_manifest']).read_text());native_root=Path(q['native_manifest']['path']).parent
    for name,digest in native['file_manifest'].items():
        if any(name.startswith(target+'/') for target in TARGETS):
            assert sha(native_root/name)==digest;clone(native_root/name,a.work/name)
    validate_native(q,a.work)
    prepare=PRODUCT/'ops/attachment-ach3-native/prepare.py'
    input_paths=[HERE/'build.py',HERE/'core_fixture.mpl.fixture',prepare,prepare.with_name('wire_profile.py')]
    inputs={str(file):sha(file) for file in input_paths};archive=a.work/'build-inputs'
    for file,digest in inputs.items():
        if not (archive/digest).exists():clone(Path(file),archive/digest)
    subprocess.run(['python3',str(prepare),'--work',str(a.work),'--wire-profile',str(selected['wire_profile']),'--expected-production-exports',str(selected['production_exports'])],check=True)
    assert inputs=={str(file):sha(file) for file in input_paths},'proof build inputs drifted'
    load_qualification(a.work/'qualification.json')
    (a.work/'backend.json').write_text(json.dumps({'compiler':str(compiler),'compiler_sha256':sha(compiler),'runtime':str(runtime),'runtime_sha256':sha(runtime),'snapshot':str(snapshot),'sources':before,'executables':built,'native_production_exports':q['expected']['exports'],'wire_profile':selected['wire_profile'],'native_extra_fixture_exports':0,'qualification_sha256':sha(a.work/'qualification.json'),'build_inputs':inputs,'maximum_concurrent_builds':a.jobs},indent=2)+'\n')
    verify_work(a.work)
    print(json.dumps({'status':'built_real_native_paid_attachment_fixture','executables':list(built),'sources':len(before),'native_plaintext_sites':q['expected']['sites']}),flush=True)
if __name__=='__main__':main()
