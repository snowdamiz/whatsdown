"""Owned iOS Simulator runner for the compiled credit journal (test only)."""
from pathlib import Path
import base64
import json
import hashlib
import os
import plistlib
import subprocess
import shutil
import time


def packet_fields(data):
    count = int.from_bytes(data[:4], 'big')
    assert len(data) >= 4 and count <= 16
    offset, fields = 4, []
    for _ in range(count):
        assert offset + 4 <= len(data)
        size = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        assert offset + size <= len(data)
        fields.append(data[offset:offset+size])
        offset += size
    assert offset == len(data)
    return fields


class CreditIOSProof:
    bundle = 'app.morse.credit.proof.ios'

    def __init__(self, product, work, security_config, issuer_tls_root=None, *, proof_source=None, network_config=None, push_config=None, artifact_dir=None):
        self.product, self.work, self.security_config = product, work/'ios-credit', security_config
        self.issuer_tls_root = issuer_tls_root
        self.proof_source = proof_source
        self.network_config = network_config
        self.push_config = push_config
        self.artifact_dir = artifact_dir
        self.device = os.environ.get('MORSE_MAILBOX_IOS_DEVICE', 'EC972953-AD12-4896-945A-5C5D2BD110D9')

    def run(self, *command, check=True):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True)
        if check and result.returncode:
            raise RuntimeError('iOS proof tool failed: '+result.stdout[-1000:]+result.stderr[-5000:])
        return result

    def __enter__(self):
        self.work.mkdir()
        app = self.work/'CreditProof.app'
        app.mkdir()
        module = Path(os.environ.get('MORSE_LIGHTNING_IOS_MODULE', self.product/'apps/mobile/modules/mesh-messenger'))
        inputs = ['generated/libmessenger_mobile.h','generated/libmessenger_mobile.swift',
            'ios/MeshMessengerSecureStore.h','ios/MeshMessengerSecureStore.m',
            'native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a']
        self.input_hashes = {name: hashlib.sha256((module/name).read_bytes()).hexdigest() for name in inputs}
        proof_source = self.proof_source or self.product/'apps/mobile/modules/mesh-messenger/ios/credit-proof/CreditProof.swift'
        self.input_hashes['proof/'+proof_source.name] = hashlib.sha256(proof_source.read_bytes()).hexdigest()
        entitlements = {'application-identifier': 'MORSEPROOF.'+self.bundle, 'keychain-access-groups': ['MORSEPROOF.'+self.bundle]}
        ent = self.work/'entitlements.plist'
        ent.write_bytes(plistlib.dumps(entitlements))
        info = {
            'CFBundleExecutable':'CreditProof', 'CFBundleIdentifier':self.bundle, 'CFBundleName':'CreditProof',
            'CFBundleVersion':'1', 'CFBundleShortVersionString':'1.0','CFBundlePackageType':'APPL',
            'MinimumOSVersion':'16.4','UIDeviceFamily':[1],'LSRequiresIPhoneOS':True,
            'MeshMessengerSecurityConfig':self.security_config,'MeshMessengerCreditPurpose':'test',
            'MeshMessengerLightningNetwork':'regtest'}
        if self.issuer_tls_root is not None:
            info['MeshMessengerIssuerTLSRoot'] = base64.b64encode(self.issuer_tls_root).decode('ascii')
        if self.push_config is not None:
            info['MeshMessengerExpoProjectID'], info['MeshMessengerPushBrokerPublicKeyHex'] = self.push_config
        if self.network_config is not None:
            info['MeshMessengerNetworkConfig'] = self.network_config
        (app/'Info.plist').write_bytes(plistlib.dumps(info))
        bridge = self.work/'bridge.h'
        bridge.write_text('#include "libmessenger_mobile.h"\n#include "MeshMessengerSecureStore.h"\n')
        sdk = self.run('xcrun','--sdk','iphonesimulator','--show-sdk-path').stdout.strip()
        self.run('xcrun','--sdk','iphonesimulator','clang','-c','-fobjc-arc','-isysroot',sdk,'-target','arm64-apple-ios16.4-simulator',
            '-I',module/'generated',module/'ios/MeshMessengerSecureStore.m','-o',self.work/'host.o')
        self.run('xcrun','--sdk','iphonesimulator','swiftc','-parse-as-library','-sdk',sdk,'-target','arm64-apple-ios16.4-simulator',
            '-I',module/'generated','-I',module/'ios','-import-objc-header',bridge,
            module/'generated/libmessenger_mobile.swift',proof_source,self.work/'host.o',
            module/'native/ios/MeshMessengerCore.xcframework/ios-arm64-simulator/libmessenger_mobile.a',
            '-framework','Foundation','-framework','UIKit','-framework','Security','-framework','CoreFoundation',
            '-lc++','-lresolv','-lz','-lm','-Xlinker','-sectcreate','-Xlinker','__TEXT','-Xlinker','__entitlements','-Xlinker',ent,'-o',app/'CreditProof')
        self.run('codesign','--force','--sign','-',app)
        self.run('xcrun','simctl','boot',self.device,check=False)
        self.run('xcrun','simctl','bootstatus',self.device,'-b')
        self.run('xcrun','simctl','uninstall',self.device,self.bundle,check=False)
        self.run('xcrun','simctl','install',self.device,app)
        self.directory = Path(self.run('xcrun','simctl','get_app_container',self.device,self.bundle,'data').stdout.strip())/'Documents'
        self.restart()
        return self

    def await_file(self, name, timeout=60):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline:
            fatal = self.directory/'fatal.json'
            if fatal.exists(): raise AssertionError(fatal.read_text())
            file = self.directory/name
            if file.exists(): return file
            time.sleep(.02)
        raise TimeoutError('native iOS proof did not produce '+name)

    def restart(self):
        self.run('xcrun','simctl','terminate',self.device,self.bundle,check=False)
        (self.directory/'ready').unlink(missing_ok=True)
        self.run('xcrun','simctl','launch',self.device,self.bundle)
        self.await_file('ready')

    def invoke(self, operation, id=b'', body=b'', rejected=False):
        response = self.directory/'response.json'
        response.unlink(missing_ok=True)
        temp = self.directory/'command.tmp'
        temp.write_text(json.dumps({'operation':operation,'id':id.hex(),'body':body.hex()}))
        temp.rename(self.directory/'command.json')
        value = json.loads(self.await_file('response.json').read_text())
        assert value['result']==('rejected' if rejected else 'passed'), value
        return value.get('error') if rejected else bytes.fromhex(value['body'])

    def __exit__(self, *_):
        if self.artifact_dir is not None:
            self.artifact_dir.mkdir(parents=True,exist_ok=True)
            for name in ['Info.plist','CreditProof']:
                shutil.copyfile(self.work/'CreditProof.app'/name,self.artifact_dir/name)
            (self.artifact_dir/'inputs.json').write_text(json.dumps(self.input_hashes,indent=2)+'\n')
        self.run('xcrun','simctl','terminate',self.device,self.bundle,check=False)
        self.run('xcrun','simctl','uninstall',self.device,self.bundle,check=False)
