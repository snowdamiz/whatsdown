#!/usr/bin/env python3
"""Build proof-only native extensions against a caller-selected immutable closure."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, time
from wire_profile import selection, work_selection, record_selection, unique_exports
PRODUCT=Path(__file__).resolve().parents[2]
ROOT=PRODUCT.parent
HERE=Path(__file__).resolve().parent
sha=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def verify_fixture_modules(report, canonical, driver):
    # Only these local proof modules may differ from the selected production
    # closure. Historical verify-only runs have no legacy helper and retain the
    # original one-module comparison; never populate a sealed driver from live.
    sources={'Main':driver/'main.mpl'}
    legacy=driver/'fixture/legacy.mpl'
    if legacy.exists(): sources['Fixture.Legacy']=legacy
    for name, source in sources.items():
        modules=[m for m in report['modules'] if m['module']==name]
        assert len(modules)==1 and modules[0]['file']==str(source.relative_to(driver))
        assert modules[0]['source_sha256']==sha(source)
        assert modules[0]['sites']==[],modules
    normalize=lambda m:(m['module'],m['source_sha256'],m['sites'])
    assert sorted(map(normalize,(m for m in report['modules'] if m['module'] not in sources)))==sorted(map(normalize,(m for m in canonical['modules'] if m['module']!='Main'))),'production module hashes/sites changed'
    assert sum(len(m['sites']) for m in report['modules'])==sum(len(m['sites']) for m in canonical['modules'])

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--closure',type=Path,default=ROOT/'.morse/ach3-current-final-work')
    parser.add_argument('--toolchain',type=Path,default=ROOT/'.morse/witness-proof/displays162')
    parser.add_argument('--work',type=Path,default=ROOT/'.morse/witness-proof/ach3-native-87085')
    parser.add_argument('--baseline-report',type=Path,default=ROOT/'.morse/witness-proof/ach3-current-final-report.json')
    parser.add_argument('--baseline-abi',type=Path,help='Exact production ABI; defaults to closure/production.abi.json')
    parser.add_argument('--opt-level',type=int,choices=range(4),help='New builds default to 0; verification preserves the recorded build level')
    parser.add_argument('--jobs',type=int,choices=[1,2],default=2)
    parser.add_argument('--wire-profile',type=int,choices=[3,4],help='Historical default3; profile4 must explicitly select163 exports')
    parser.add_argument('--expected-production-exports',type=int,choices=[162,163])
    parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    selected=(work_selection(args.work,args.wire_profile,args.expected_production_exports)
              if args.verify_only else selection(args.wire_profile,args.expected_production_exports))
    expected_exports=selected['production_exports']
    targets=['aarch64-apple-ios-sim','aarch64-linux-android']
    previous_builds={}
    if args.verify_only:
        # Verify every requested level before writing any target evidence.
        # Older commands omitted the flag and used the compiler's default 0.
        for target in targets:
            previous=json.loads((args.work/target/'build.json').read_text())
            assert record_selection(previous)==selected,'recorded build attachment profile differs'
            command=previous['command']
            level=int(command[command.index('--opt-level')+1]) if '--opt-level' in command else 0
            if level not in range(4) or previous.get('opt_level',level)!=level:
                raise ValueError('recorded optimization differs from executed build command')
            if args.opt_level is not None and args.opt_level!=level:
                raise ValueError('verification cannot change the recorded optimization level')
            previous_builds[target]=(previous,level)
    if not args.verify_only and any((args.work/t/'libmessenger_mobile.a').exists() for t in ['aarch64-apple-ios-sim','aarch64-linux-android']):
        parser.error('existing proof artifacts are immutable; choose a new --work directory or --verify-only')
    if not args.verify_only and ((args.work/'manifest.json').exists() or (args.work/'builds.json').exists()):
        parser.error('sealed or built proof output exists; pass a fresh --work path or --verify-only')
    args.work.mkdir(parents=True,exist_ok=True)
    driver=args.work/'driver';driver.mkdir(exist_ok=True)
    if not args.verify_only:
        shutil.copyfile(HERE/'driver/main.mpl',driver/'main.mpl')
        (driver/'fixture').mkdir(exist_ok=True)
        shutil.copyfile(PRODUCT/'packages/messenger-protocol/tests/legacy_attachment_fixture.mpl',driver/'fixture/legacy.mpl')
        (driver/'mesh.toml').write_text('[package]\nname="ach3-native-proof"\nversion="0.1.0"\n[dependencies]\nmessenger-mobile-core={path="'+str(args.closure/'mobile-core')+'"}\n')
    assert (driver/'main.mpl').is_file() and (driver/'mesh.toml').is_file()
    baseline_abi=args.baseline_abi or args.closure/'production.abi.json'
    baseline=unique_exports(json.loads(baseline_abi.read_text()),expected_exports)
    compiler=args.toolchain/'compiler/meshc'
    canonical=json.loads(args.baseline_report.read_text())
    site_count=sum(len(m['sites']) for m in canonical['modules'])
    def build(target):
        output=args.work/target;output.mkdir(exist_ok=True)
        runtime=args.toolchain/'runtime'/target/'libmesh_rt.a'
        artifact=output/'libmessenger_mobile.a'
        level=args.opt_level if args.opt_level is not None else 0
        command=[str(compiler),'build',str(driver),'--artifact','staticlib','--target',target,'--output',str(artifact),'--opt-level',str(level)]
        if args.verify_only:
            previous,level=previous_builds[target]
            command=previous['command']
        env=dict(os.environ,MESH_RT_LIB_PATH=str(runtime),IPHONEOS_DEPLOYMENT_TARGET='16.4',ANDROID_NDK_HOME='/opt/homebrew/share/android-commandlinetools/ndk/28.2.13676358')
        started=time.monotonic()
        if not args.verify_only:
            with (output/'build.log').open('w') as log:
                subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        actual=unique_exports(json.loads(artifact.with_suffix('.abi.json').read_text()),expected_exports+6)
        assert all(actual.get(k)==v for k,v in baseline.items()),'selected production ABI changed'
        added=set(actual)-set(baseline)
        assert len(added)==6 and all(k.startswith('mesh_ach3_fixture_') for k in added),added
        report=json.loads(Path(str(artifact)+'.plaintext.json').read_text())
        # Proof helpers only produce ciphertext and signatures; no added display,
        # declassification or unlabelled plaintext sink is permitted.
        verify_fixture_modules(report,canonical,driver)
        record={'target':target,'seconds':round(time.monotonic()-started,2),'command':command,'opt_level':level,
          'compiler_sha256':sha(compiler),'runtime_sha256':sha(runtime),
          'production_exports_unchanged':expected_exports,'wire_profile':selected['wire_profile'],'proof_only_exports':sorted(added),
          'baseline_report_sha256':sha(args.baseline_report),'baseline_abi_sha256':sha(baseline_abi),'fixture_module_sha256':sha(driver/'main.mpl'),
          'legacy_fixture_module_sha256':sha(driver/'fixture/legacy.mpl') if (driver/'fixture/legacy.mpl').exists() else None,'plaintext_sites':site_count,
          'artifacts':{p.name:sha(p) for p in output.iterdir() if p.is_file() and p.name!='build.json'}}
        if args.verify_only:
            for name in ['compiler_sha256','runtime_sha256']:
                assert record[name]==previous[name]
            for name,digest in previous['artifacts'].items():
                assert sha(output/name)==digest,(name,'built artifact changed')
            record['seconds']=previous['seconds']
            record['artifacts']=previous['artifacts']
            record['verification_strengthened_after_build']=True
        (output/'build.json').write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps({'target':target,'seconds':record['seconds'],'exports':len(actual)}),flush=True)
        return record
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        records=list(pool.map(build,targets))
    (args.work/'builds.json').write_text(json.dumps(records,indent=2)+'\n')
    (args.work/'settings.json').write_text(json.dumps({'closure':str(args.closure),'toolchain':str(args.toolchain),'work':str(args.work),'driver_sha256':sha(driver/'main.mpl'),'legacy_fixture_sha256':sha(driver/'fixture/legacy.mpl') if (driver/'fixture/legacy.mpl').exists() else None,**selected},indent=2)+'\n')
if __name__=='__main__':main()
