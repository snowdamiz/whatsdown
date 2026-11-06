"""Owned Android emulator harness using production JNI and OS secure storage."""
from pathlib import Path
from xml.sax.saxutils import escape
import hashlib
import json
import os
import shutil
import subprocess
import time
from urllib.parse import urlsplit


class AttachmentAndroidProof:
    bundle = 'app.morse.attachment.proof.android'
    instrumentation_class = 'AttachmentProofTest'

    def __init__(self, product, work, security_config, *, proof_source=None, network_config=None, push_config=None,
                 credit_purpose=None, lightning_network=None, issuer_tls_root=None, artifact_dir=None):
        self.product, self.work = product, work/'android-attachment'
        self.security_config = security_config
        self.network_config = network_config
        self.push_config = push_config
        self.credit_purpose = credit_purpose
        self.lightning_network = lightning_network
        self.issuer_tls_root = issuer_tls_root
        self.artifact_dir = artifact_dir
        self.proof_source = proof_source if proof_source is not None and Path(proof_source).suffix == ".kt" else None
        self.port = urlsplit(network_config.splitlines()[4]).port
        self.serial = os.environ.get('MORSE_ATTACHMENT_ANDROID_SERIAL', 'emulator-5554')
        self.sdk = Path(os.environ.get('ANDROID_HOME', '/opt/homebrew/share/android-commandlinetools'))
        self.java = Path(os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home'))
        self.adb = self.sdk/'platform-tools/adb'

    def run(self, *command, check=True, input=None, timeout=180):
        env = dict(os.environ, JAVA_HOME=str(self.java), PATH=str(self.java/'bin')+':'+os.environ['PATH'])
        result = subprocess.run(list(map(str, command)), input=input, capture_output=True, text=True, timeout=timeout, env=env)
        if check and result.returncode:
            raise RuntimeError('Android proof tool failed: '+result.stdout[-1000:]+result.stderr[-5000:])
        return result

    def device(self, *command, **kwargs):
        return self.run(self.adb, '-s', self.serial, *command, **kwargs)

    def __enter__(self):
        self.work.mkdir()
        for directory in ['classes','dex','lib/arm64-v8a']:
            (self.work/directory).mkdir(parents=True)
        module = self.product/'apps/mobile/modules/mesh-messenger'
        host = module/'android/src/main/java/expo/modules/meshmessenger'
        source = (host/'MeshMessengerModule.kt').read_text()
        (self.work/'HostObjects.kt').write_text('package expo.modules.meshmessenger\nimport java.nio.ByteBuffer\n'+source[source.index('internal object MeshMessengerHost {'):])
        inputs = [module/'generated/libmessenger_mobile.kt',host/'MeshMessengerSecureStore.kt',host/'MeshMessengerIssuerTLS.kt',host/'MeshMessengerModule.kt',self.proof_source or module/'android/attachment-proof/AttachmentProof.kt']
        libraries = list((module/'android/build').rglob('arm64-v8a/libmessenger_mobile.so'))
        assert libraries, 'build the real Android native module first'
        library = Path(os.environ['MORSE_ATTACHMENT_ANDROID_LIBRARY']) if 'MORSE_ATTACHMENT_ANDROID_LIBRARY' in os.environ else max(libraries, key=lambda p:p.stat().st_mtime)
        inputs.append(library)
        self.input_hashes = {str(p.relative_to(module)) if p.is_relative_to(module) else str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
        self.input_hashes['network_config'] = hashlib.sha256(self.network_config.encode()).hexdigest()
        self.input_hashes['security_config'] = hashlib.sha256(self.security_config.encode()).hexdigest()
        shutil.copyfile(library,self.work/'lib/arm64-v8a/libmessenger_mobile.so')
        cache = Path.home()/'.gradle/caches/modules-2/files-2.1'
        def jar(name): return next((cache/name).rglob('*.jar'))
        stdlib = jar('org.jetbrains.kotlin/kotlin-stdlib/2.1.20')
        annotations = jar('org.jetbrains/annotations/13.0')
        compiler = [jar('org.jetbrains.kotlin/kotlin-compiler-embeddable/2.1.20'),stdlib,jar('org.jetbrains.kotlin/kotlin-daemon-embeddable/2.1.20'),jar('org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm/1.8.1'),annotations,jar('org.jetbrains.intellij.deps/trove4j')]
        android = self.sdk/'platforms/android-36/android.jar'
        classpath = [android,self.sdk/'platforms/android-36/optional/android.test.runner.jar',self.sdk/'platforms/android-36/optional/android.test.base.jar',stdlib,annotations]
        self.run(self.java/'bin/java','-cp',':'.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','1.8','-classpath',':'.join(map(str,classpath)),'-d',self.work/'classes',*inputs[:3],self.work/'HostObjects.kt',inputs[4])
        self.run(self.java/'bin/jar','cf',self.work/'proof.jar','-C',self.work/'classes','.')
        build = self.sdk/'build-tools/36.0.0'
        self.run(build/'d8','--min-api','26','--lib',android,'--output',self.work/'dex',self.work/'proof.jar',stdlib)
        manifest = self.work/'AndroidManifest.xml'
        pins = escape(self.network_config, {'"':'&quot;'}).replace('\n','&#10;')
        security_metadata = '' if not self.security_config else (
            '<meta-data android:name="app.morse.mesh.SECURITY_CONFIG" android:value="'+
            escape(self.security_config, {'"': '&quot;'}).replace('\n','&#10;')+'"/>')
        push_metadata = '' if self.push_config is None else ''.join(
            f'<meta-data android:name="app.morse.mesh.{name}" android:value="{escape(value, {chr(34): "&quot;"})}"/>'
            for name, value in zip(['EXPO_PROJECT_ID', 'PUSH_BROKER_PUBLIC_KEY_HEX'], self.push_config))
        credit_metadata = ''.join(
            f'<meta-data android:name="app.morse.mesh.{name}" android:value="{escape(value, {chr(34): "&quot;"})}"/>'
            for name, value in [('CREDIT_PURPOSE', self.credit_purpose), ('LIGHTNING_NETWORK', self.lightning_network)] if value is not None)
        manifest.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{self.bundle}" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36"/><uses-permission android:name="android.permission.INTERNET"/><application android:label="Morse native proof" android:allowBackup="false" android:debuggable="true" android:usesCleartextTraffic="true"><uses-library android:name="android.test.runner"/><meta-data android:name="app.morse.mesh.NETWORK_CONFIG" android:value="{pins}"/>{security_metadata}{push_metadata}{credit_metadata}</application><instrumentation android:name="android.test.InstrumentationTestRunner" android:targetPackage="{self.bundle}"/></manifest>')
        self.run(build/'aapt2','link','-I',android,'--manifest',manifest,'-o',self.work/'proof.apk')
        shutil.copyfile(self.work/'dex/classes.dex',self.work/'classes.dex')
        subprocess.run(['zip','-q','proof.apk','classes.dex','lib/arm64-v8a/libmessenger_mobile.so'],cwd=self.work,check=True)
        if self.issuer_tls_root is not None:
            asset = self.work/'assets/morse-issuer-tls-root-v1.bin'
            asset.parent.mkdir()
            asset.write_bytes(self.issuer_tls_root)
            self.input_hashes['issuer_tls_root'] = hashlib.sha256(self.issuer_tls_root).hexdigest()
            subprocess.run(['zip','-q','proof.apk',str(asset.relative_to(self.work))],cwd=self.work,check=True)
        self.run(self.java/'bin/keytool','-genkeypair','-keystore',self.work/'test-key.p12','-storepass','android','-keypass','android','-alias','proof','-dname','CN=MorseAttachmentProof','-keyalg','RSA','-validity','1')
        self.run(build/'apksigner','sign','--ks',self.work/'test-key.p12','--ks-pass','pass:android',self.work/'proof.apk')
        self.device('uninstall',self.bundle,check=False)
        self.device('install',self.work/'proof.apk')
        self.device('reverse',f'tcp:{self.port}',f'tcp:{self.port}')
        self.device('shell','run-as',self.bundle,'mkdir','-p','files')
        self.sequence = 0
        return self

    def restart(self):
        self.device('shell','am','force-stop',self.bundle)
        deadline = time.monotonic() + 5
        while self.device('shell','pidof',self.bundle,check=False).stdout.strip():
            if time.monotonic() >= deadline:
                raise TimeoutError('owned Android proof process did not stop')
            time.sleep(.05)

    def invoke(self, operation, id=b'', body=b'', rejected=False):
        self.restart()
        self.device('shell','run-as',self.bundle,'rm','-f','files/response.json')
        self.device('shell','run-as',self.bundle,'sh','-c',"'cat > files/command.json'",input=json.dumps({'operation':operation,'id':id.hex(),'body':body.hex()}))
        command=('shell','am','instrument','-w','-e','class',f'expo.modules.meshmessenger.{self.instrumentation_class}#testCommand',self.bundle+'/android.test.InstrumentationTestRunner')
        result=self.device(*command)
        if 'failed to attach' in result.stdout:
            # Only retry a framework launch that never consumed the command.
            # Never replay an unknown native result or conceal an app crash.
            untouched=self.device('shell','run-as',self.bundle,'test','-f','files/command.json',check=False).returncode==0
            no_response=self.device('shell','run-as',self.bundle,'test','-f','files/response.json',check=False).returncode!=0
            if untouched and no_response:
                (self.work/f'{self.sequence+1}-{operation}-launch-failed.log').write_text(result.stdout+result.stderr)
                self.restart()
                result=self.device(*command)
        self.sequence += 1
        (self.work/f'{self.sequence}-{operation}.log').write_text(result.stdout+result.stderr)
        assert 'OK (1 test)' in result.stdout, result.stdout+result.stderr
        value=json.loads(self.device('exec-out','run-as',self.bundle,'cat','files/response.json').stdout)
        (self.work/f'{self.sequence}-{operation}.json').write_text(json.dumps(value,indent=2)+'\n')
        assert value['result']==('rejected' if rejected else 'passed'),value
        return value.get('error') if rejected else bytes.fromhex(value['body'])

    def __exit__(self, *_):
        if self.artifact_dir is not None:
            self.artifact_dir.mkdir(parents=True,exist_ok=True)
            for name in ['AndroidManifest.xml','proof.apk','assets/morse-issuer-tls-root-v1.bin']:
                source=self.work/name
                if source.is_file():
                    target=self.artifact_dir/name
                    target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(source,target)
            (self.artifact_dir/'inputs.json').write_text(json.dumps(self.input_hashes,indent=2)+'\n')
            for source in self.work.glob('*-launch-failed.log'):
                shutil.copyfile(source,self.artifact_dir/source.name)
        self.device('shell','am','force-stop',self.bundle,check=False)
        self.device('reverse','--remove',f'tcp:{self.port}',check=False)
        self.device('uninstall',self.bundle,check=False)
