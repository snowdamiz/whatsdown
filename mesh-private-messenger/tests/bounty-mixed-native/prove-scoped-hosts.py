#!/usr/bin/env python3
"""Run real scoped bounty validators without full Tauri/Expo builds.

Rust excludes only the Tauri binary-body adapter and its two unrelated tests.
Swift/Kotlin compile the exact receiving module bounty branch with the production
BountyBridge and existing focused proof cases. This does not qualify native owner
retirement, Core serialization, device UI or actual SDK signing.

Supply installed compiler paths; this script never installs or copies toolchains.
Every generated source, binary and log goes to a new explicit output directory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, required=True)
parser.add_argument('--rustc', default=os.environ.get('RUSTC') or shutil.which('rustc'))
parser.add_argument('--swiftc', default=os.environ.get('SWIFTC') or shutil.which('swiftc'))
parser.add_argument('--java', default=os.environ.get('JAVA') or shutil.which('java'))
parser.add_argument('--kotlin-lib-dir', type=Path, required=True,
                    help='Existing directory containing compiler, stdlib and dependencies as jars')
args = parser.parse_args()
for name in ('rustc', 'swiftc', 'java'):
    if not getattr(args, name):
        parser.error(f'--{name} must identify an installed executable')
product = Path(__file__).resolve().parents[2]
mobile = product / 'apps/mobile/modules/mesh-messenger'
work = args.output_dir.resolve()
work.mkdir(parents=True, exist_ok=False)
source_paths = [
    product / 'apps/desktop/src-tauri/src/request.rs',
    mobile / 'generated/libmessenger_mobile.h',
    mobile / 'ios/MeshMessengerModule.swift',
    mobile / 'ios/MeshMessengerBountyBridge.swift',
    mobile / 'ios/bounty-proof/Proof.swift',
    mobile / 'android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt',
    mobile / 'android/src/main/java/expo/modules/meshmessenger/MeshMessengerBountyBridge.kt',
    mobile / 'android/bounty-proof/Proof.kt',
]
def source_hashes():
    return {str(path.relative_to(product)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_paths}
before = source_hashes()
(work / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')

def block(source,marker):
    start=source.index(marker);begin=source.index('{',start);level=1;at=begin+1
    while level:
        if source[at]=='{':level+=1
        elif source[at]=='}':level-=1
        at+=1
    return source[start:at]

def run(name,command):
    result=subprocess.run([str(x) for x in command],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (work/(name+'.log')).write_bytes(result.stdout)
    print(name,'exit',result.returncode)
    if result.returncode:print(result.stdout.decode(errors='replace')[-4500:])
    return result.returncode

request=(product/'apps/desktop/src-tauri/src/request.rs').read_text()
begin=request.index('pub fn binary_body(');end=request.index('// Header values are ASCII')
request=request[:begin]+request[end:]
header=mobile/'generated/libmessenger_mobile.h'
request=request.replace('"../../../mobile/modules/mesh-messenger/generated/libmessenger_mobile.h"',json.dumps(str(header)))
(work/'request.rs').write_text(request)
rustc=args.rustc
results={}
if not run('rust-build',[rustc,'--edition=2021','--test',work/'request.rs','-o',work/'rust-request']):
    results['rust']=run('rust-request',[work/'rust-request','--nocapture'])

swift=(mobile/'ios/MeshMessengerModule.swift').read_text()
branch=block(swift,'if symbol.hasPrefix("mesh_messenger_bounty_transfer_")')
wallet=block(swift,'private func walletFields(')
proof=block((mobile/'ios/bounty-proof/Proof.swift').read_text(),'func observationScopeProof(')
swift_probe='''import Foundation
struct DatabaseDirectory {let path:String;func appendingPathComponent(_ name:String)->Self {self}}
struct ProbeConfig {let documentDirectory:DatabaseDirectory?}
struct ProbeContext {let config:ProbeConfig}
final class ModuleScopeProbe {
  let appContext:ProbeContext?
  init(_ db:Data) {appContext=ProbeContext(config:ProbeConfig(documentDirectory:DatabaseDirectory(path:String(data:db,encoding:.utf8)!)))}
  func validate(_ symbol:String,_ request:Data) throws {
'''+branch+'\n  }\n'+wallet+'\n}\n'+proof+'''
@main struct ScopeMain {
  static func main() {
    do {try observationScopeProof {symbol,input,db in try ModuleScopeProbe(db).validate(symbol,input)}}
    catch {print(error);exit(1)}
  }
}
'''
(work/'SwiftScope.swift').write_text(swift_probe)
if not run('swift-build',[args.swiftc,mobile/'ios/MeshMessengerBountyBridge.swift',work/'SwiftScope.swift','-o',work/'swift-scope']):
    results['swift']=run('swift-scope',[work/'swift-scope'])

kotlin=(mobile/'android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt').read_text()
branch=block(kotlin,'if (symbol.startsWith("mesh_messenger_bounty_transfer_"))')
wallet=block(kotlin,'private fun walletFields(')
proof=block((mobile/'android/bounty-proof/Proof.kt').read_text(),'fun observationScopeProof(')
kotlin_probe='''package expo.modules.meshmessenger
import java.nio.ByteBuffer
class ProbeContext(val persistentFilesDirectory:java.io.File)
class ModuleScopeProbe(db:ByteArray) {
  val appContext=ProbeContext(java.io.File(String(db,Charsets.UTF_8)).parentFile)
  fun validate(symbol:String,request:ByteArray) {
'''+branch+'\n  }\n'+wallet+'\n}\n'+proof+'''
fun main() {observationScopeProof {symbol,input,db->ModuleScopeProbe(db).validate(symbol,input)}}
'''
(work/'KotlinScope.kt').write_text(kotlin_probe)
lib=args.kotlin_lib_dir.resolve()
stdlib=next(lib.glob('kotlin-stdlib-*.jar'));annotations=next(lib.glob('annotations-*.jar'))
java=args.java
classpath=':'.join(str(x) for x in lib.glob('*.jar'))
command=[java,'-cp',classpath,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','1.8','-classpath',f'{stdlib}:{annotations}','-d',work/'kotlin',mobile/'android/src/main/java/expo/modules/meshmessenger/MeshMessengerBountyBridge.kt',work/'KotlinScope.kt']
if not run('kotlin-build',command):
    results['kotlin']=run('kotlin-scope',[java,'-cp',f'{work/"kotlin"}:{stdlib}','expo.modules.meshmessenger.KotlinScopeKt'])
(work/'results.json').write_text(json.dumps(results,indent=2)+'\n')
after = source_hashes()
(work / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
print(json.dumps(results))
if after != before:
    sys.exit('Source changed during scoped validator proof')
if set(results) != {'rust', 'swift', 'kotlin'} or any(results.values()):
    sys.exit('A scoped validator build or test failed; inspect the output directory')
