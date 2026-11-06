#!/usr/bin/env python3
"""Prepare isolated real Swift/JNI hosts; never overwrite installed production libs."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess
from wire_profile import work_selection, record_selection, unique_exports
PRODUCT=Path(__file__).resolve().parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def checked_native_inputs(work,selected):
    targets=['aarch64-apple-ios-sim','aarch64-linux-android']
    if (work/'builds.json').exists():
        rows=json.loads((work/'builds.json').read_text())
        assert len(rows)==2 and {row['target'] for row in rows}==set(targets),'incomplete proof builds'
        for row in rows:
            assert record_selection(row)==selected,'proof build selection differs'
            output=work/row['target']
            for name,digest in row['artifacts'].items():
                relative=Path(name);assert len(relative.parts)==1 and not relative.is_absolute()
                assert sha(output/relative)==digest,'proof artifact changed before preparation'
            unique_exports(json.loads((output/'libmessenger_mobile.abi.json').read_text()),selected['production_exports']+6)
        return
    if (work/'qualification.json').exists():
        q=json.loads((work/'qualification.json').read_text());ref=q['native_manifest'];path=Path(ref['path'])
        assert path.is_absolute() and sha(path)==ref['sha256'],'native manifest pin differs'
        native=json.loads(path.read_text())
        for target in targets:
            required={target+'/'+name for name in ['libmessenger_mobile.a','libmessenger_mobile.abi.json','libmessenger_mobile.a.plaintext.json']}
            assert required<=set(native['file_manifest']),'incomplete qualified native target'
            for name,digest in native['file_manifest'].items():
                if not name.startswith(target+'/'):continue
                relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts
                assert sha(work/relative)==digest,'qualified native artifact differs before preparation'
            unique_exports(json.loads((work/target/'libmessenger_mobile.abi.json').read_text()),selected['production_exports'])
        return
    raise ValueError('prepare requires recorded proof builds or pinned funded qualification')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,default=PRODUCT.parent/'.morse/witness-proof/ach3-native-87085')
    parser.add_argument('--wire-profile',type=int,choices=[3,4]);parser.add_argument('--expected-production-exports',type=int,choices=[162,163]);args=parser.parse_args()
    selected=work_selection(args.work,args.wire_profile,args.expected_production_exports)
    checked_native_inputs(args.work,selected)
    module=PRODUCT/'apps/mobile/modules/mesh-messenger';native=args.work/'native-product/apps/mobile/modules/mesh-messenger'
    selection_paths=[Path(__file__).with_name('wire_profile.py'),*[args.work/name for name in ['settings.json','qualification.json'] if (args.work/name).exists()]]
    inputs={str(path):sha(path) for path in selection_paths}
    def copy(source,target):
        target.parent.mkdir(parents=True,exist_ok=True);before=sha(source)
        subprocess.run(['cp','-c',str(source),str(target)],check=True)
        assert sha(source)==before and sha(target)==before
        inputs[str(source)]=before
    for name in ['ios/MeshMessengerSecureStore.h','ios/MeshMessengerSecureStore.m','native/include/morse_wallet_core.h','native/android/arm64-v8a/libmorse_wallet_core.a']:
        copy(module/name,native/name)
    for folder in ['android/src/main/cpp','android/src/main/java/expo/modules/meshmessenger']:
        for path in sorted((module/folder).rglob('*')):
            if path.is_file():copy(path,native/path.relative_to(module))
    for ext in ['h','swift','kt','jni.c','ts']:
        source=args.work/'aarch64-apple-ios-sim'/('libmessenger_mobile.'+ext)
        assert source.read_bytes()==(args.work/'aarch64-linux-android'/source.name).read_bytes()
        copy(source,native/'generated'/source.name)
    copy(args.work/'aarch64-apple-ios-sim/libmessenger_mobile.a',native/'native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a')
    copy(args.work/'aarch64-linux-android/libmessenger_mobile.a',native/'native/android/arm64-v8a/libmessenger_mobile.a')
    cmake='/opt/homebrew/share/android-commandlinetools/cmake/3.22.1/bin/cmake';ndk='/opt/homebrew/share/android-commandlinetools/ndk/28.2.13676358';output=native/'android/build/ach3-proof/arm64-v8a'
    commands=[[cmake,'-S',str(native/'android/src/main/cpp'),'-B',str(output),'-G','Ninja','-DCMAKE_MAKE_PROGRAM=/opt/homebrew/share/android-commandlinetools/cmake/3.22.1/bin/ninja','-DCMAKE_TOOLCHAIN_FILE='+ndk+'/build/cmake/android.toolchain.cmake','-DANDROID_ABI=arm64-v8a','-DANDROID_PLATFORM=android-26','-DCMAKE_BUILD_TYPE=Debug'],[cmake,'--build',str(output),'-j2']]
    with (args.work/'android-host-build.log').open('w') as log:
        for command in commands:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    # Preserve exact bodies of every host input, including currently dirty files.
    bodies=args.work/'host-inputs';bodies.mkdir(exist_ok=True)
    for source,digest in inputs.items():
        target=bodies/digest
        if not target.exists():shutil.copyfile(source,target)
        assert sha(target)==digest
    (args.work/'host-build.json').write_text(json.dumps({'commands':commands,'inputs':inputs,'library_sha256':sha(output/'libmessenger_mobile.so'),**selected,'selection_inputs':{str(path):sha(path) for path in selection_paths}},indent=2)+'\n')
    print('Prepared isolated ACH3 native hosts; production native modules unchanged.')
if __name__=='__main__':main()
