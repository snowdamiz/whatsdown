"""Owned React Native -> production openCreditPayment -> OS receiver proof.

No screen, accessibility tree, recording, or screenshot is captured. Receiver
callbacks contain only the URI digest, length and invocation count; no payment.
"""
from contextlib import ExitStack
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode
import base64
import hashlib
import http.client
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from credit_tls_ingress import CreditTLSIngress


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(*args, cwd=None, input=None, check=True, timeout=240):
    env=dict(os.environ)
    env.setdefault('JAVA_HOME','/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home')
    result = subprocess.run(list(map(str, args)), cwd=cwd, input=input, capture_output=True, text=True, timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError('proof command failed: '+shlex.join(list(map(str,args)))+'\n'+result.stdout[-1000:]+result.stderr[-4000:])
    return result


class Metro:
    def __init__(self, mobile, work): self.mobile, self.work = mobile, work
    def __enter__(self):
        self.log = (self.work/'metro.log').open('w')
        self.child = subprocess.Popen(['node','node_modules/expo/bin/cli','start','--port','25389','--offline'], cwd=self.mobile, stdout=self.log, stderr=subprocess.STDOUT)
        class Proxy(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed=urlsplit(self.path)
                query=parse_qs(parsed.query)
                path=parsed.path
                if path.endswith('.bundle'):
                    path='/scripts/credit-handoff-proof.bundle'
                    query.update(dev=['false'],hot=['false'],minify=['false'])
                try:
                    peer=http.client.HTTPConnection('127.0.0.1',25389,timeout=180)
                    peer.request('GET',path+('?' + urlencode(query,doseq=True) if query else ''))
                    result=peer.getresponse(); data=result.read()
                    self.send_response(result.status)
                    for key,value in result.getheaders():
                        if key.lower() not in ['connection','transfer-encoding','content-length']: self.send_header(key,value)
                    self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); peer.close()
                except (ConnectionRefusedError, OSError): self.send_error(503)
            def log_message(self,*_): pass
        self.server=ThreadingHTTPServer(('127.0.0.1',8088),Proxy)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            try:
                peer=http.client.HTTPConnection('127.0.0.1',25389,timeout=2); peer.request('GET','/status')
                if peer.getresponse().read()==b'packager-status:running': return self
            except OSError: pass
            if self.child.poll() is not None: raise RuntimeError('Metro exited')
            time.sleep(.2)
        raise TimeoutError('Metro not ready')
    def __exit__(self,*_):
        self.server.shutdown(); self.server.server_close()
        self.child.terminate()
        try: self.child.wait(timeout=10)
        except subprocess.TimeoutExpired: self.child.kill(); self.child.wait()
        self.log.close()


class RNProof:
    ios_bundle='io.morseapp.networkproof'
    android_bundle='com.snowdamiz.morse.networkproof'
    receiver='app.morse.handoff.receiver'
    def __init__(self,product,work,platform,trust,ca):
        self.product,self.work,self.platform,self.trust,self.ca=product,work,platform,trust,ca
        self.mobile=product/'apps/mobile'; self.outer=product.parent
        self.device=os.environ.get('MORSE_MAILBOX_IOS_DEVICE','EC972953-AD12-4896-945A-5C5D2BD110D9')
        self.sdk=Path(os.environ.get('ANDROID_HOME','/opt/homebrew/share/android-commandlinetools'))
        self.adb=self.sdk/'platform-tools/adb'
        self.java=Path(os.environ.get('JAVA_HOME','/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home'))
        self.serial=os.environ.get('MORSE_ATTACHMENT_ANDROID_SERIAL','emulator-5554')
        self.sequence=0; self.records=[]
    def android(self,*args,**kw): return run(self.adb,'-s',self.serial,*args,**kw)
    def ios(self,*args,**kw): return run('xcrun','simctl',*args,**kw)
    def __enter__(self):
        self.work.mkdir(parents=True)
        (self.work/'public-security-config.txt').write_text(self.trust)
        (self.work/'issuer-tls-root.bin').write_bytes(self.ca)
        self.inputs={str(p.relative_to(self.product)):sha(p) for p in [self.mobile/'scripts/credit-handoff-proof.ts', self.mobile/'src/credit-payment-link.ts',self.mobile/'src/credits.ts',self.mobile/'modules/mesh-messenger/index.ts', self.product/'scripts/credit_handoff_proof.py', self.product/'scripts/prove-credit-os-handoff.py', self.product/('scripts/credit-handoff-proof/Receiver.swift' if self.platform=='ios' else 'scripts/credit-handoff-proof/Receiver.java')]}
        if self.platform=='ios': self.setup_ios()
        else: self.setup_android()
        self.restart()
        self.ready=self.await_json('credit-handoff-ready.json',timeout=180)
        assert self.ready['fetchBlocked'] is True
        self.database=self.ready['database']
        return self
    def setup_ios(self):
        original=Path(os.environ.get('MORSE_HANDOFF_IOS_APP',self.mobile/'ios/build-phase6-mailbox/Build/Products/Debug-iphonesimulator/Morse.app'))
        self.app=self.work/'MorseNetworkProof.app'; shutil.copytree(original,self.app,symlinks=True)
        info=plistlib.loads((self.app/'Info.plist').read_bytes()); info.update(CFBundleIdentifier=self.ios_bundle,MeshMessengerSecurityConfig=self.trust,MeshMessengerCreditPurpose='test',MeshMessengerLightningNetwork='regtest',MeshMessengerIssuerTLSRoot=base64.b64encode(self.ca).decode())
        info.setdefault('CFBundleURLTypes',[]).append({'CFBundleURLName':'Owned proof resume','CFBundleURLSchemes':['morse-handoff-proof']})
        (self.app/'Info.plist').write_bytes(plistlib.dumps(info))
        self.inputs['ios-host/Morse.debug.dylib']=sha(self.app/'Morse.debug.dylib')
        # Only the standard debug launcher is relinked for simulator Keychain
        # entitlements; the actual production Expo host dylib is unchanged.
        argv=json.loads((self.outer/'.morse/js-network-closure/ios/main-link-argv.json').read_text())
        argv[argv.index('-o')+1]=str(self.app/'Morse')
        for index,arg in enumerate(argv):
            if arg.endswith('/Morse.app/Morse.debug.dylib'): argv[index]=str(self.app/'Morse.debug.dylib')
        ent=self.work/'entitlements.plist'; ent.write_bytes(plistlib.dumps({'application-identifier':'MORSEPROOF.'+self.ios_bundle,'keychain-access-groups':['MORSEPROOF.'+self.ios_bundle]}))
        # The saved argv already contains the earlier entitlement section.
        if '__entitlements' in argv: argv[argv.index('__entitlements')+2]=str(ent)
        else: argv.extend(['-Xlinker','-sectcreate','-Xlinker','__TEXT','-Xlinker','__entitlements','-Xlinker',str(ent)])
        run(*argv)
        run('codesign','--force','--sign','-',self.app)
        self.ios('terminate',self.device,self.ios_bundle,check=False)
        self.ios('uninstall',self.device,self.ios_bundle,check=False)
        self.ios('install',self.device,self.app)
        self.container=Path(self.ios('get_app_container',self.device,self.ios_bundle,'data').stdout.strip())
        self.documents=self.container/'Documents'; self.documents.mkdir(exist_ok=True)
        prefs=self.container/'Library/Preferences'/f'{self.ios_bundle}.plist'; prefs.parent.mkdir(parents=True,exist_ok=True)
        prefs.write_bytes(plistlib.dumps({'RCT_jsLocation':'127.0.0.1:8088','RCT_enableDev':False}))
        self.ios('uninstall',self.device,self.receiver,check=False)
    def setup_android(self):
        # Reuse the separately compiled full RN app workbench, never production
        # application IDs or its build directory.
        root=self.outer/'.morse/js-network-closure/android-root'
        self.android_root=root/'android'
        manifest=self.android_root/'app/src/main/AndroidManifest.xml'
        ns='{http://schemas.android.com/apk/res/android}'
        ET.register_namespace('android','http://schemas.android.com/apk/res/android')
        tree=ET.parse(manifest); application=tree.getroot().find('application')
        values={'app.morse.mesh.SECURITY_CONFIG':self.trust,'app.morse.mesh.CREDIT_PURPOSE':'test','app.morse.mesh.LIGHTNING_NETWORK':'regtest','expo.modules.updates.ENABLED':'false'}
        for key,value in values.items():
            current=next((node for node in application.findall('meta-data') if node.get(ns+'name')==key),None)
            if current is None: current=ET.SubElement(application,'meta-data',{ns+'name':key})
            current.set(ns+'value',value)
        tree.write(manifest,encoding='unicode')
        assets=self.android_root/'app/src/main/assets'; assets.mkdir(exist_ok=True); (assets/'morse-issuer-tls-root-v1.bin').write_bytes(self.ca)
        env=dict(os.environ,JAVA_HOME=str(self.java),ANDROID_HOME=str(self.sdk),PATH=str(self.java/'bin')+':'+os.environ['PATH'])
        result=subprocess.run(['./gradlew',':app:assembleDebug','-PreactNativeArchitectures=arm64-v8a','--offline'],cwd=self.android_root,env=env,capture_output=True,text=True,timeout=420)
        (self.work/'android-build.log').write_text(result.stdout+result.stderr)
        assert result.returncode==0,'isolated full RN Android build failed'
        self.apk=self.android_root/'app/build/outputs/apk/debug/app-debug.apk'
        self.inputs['android-host/app-debug.apk']=sha(self.apk)
        self.android('uninstall',self.android_bundle,check=False); self.android('install',self.apk)
        self.android('reverse','tcp:8088','tcp:8088')
        origin=urlsplit(self.trust.splitlines()[9]); self.tls_port=origin.port
        self.android('reverse',f'tcp:{self.tls_port}',f'tcp:{self.tls_port}')
        self.android('shell','run-as',self.android_bundle,'mkdir','-p','shared_prefs','files')
        text=f'<map><string name="debug_http_host">127.0.0.1:8088</string></map>'
        self.write_android('shared_prefs/'+self.android_bundle+'_preferences.xml',text)
        # Only this owned debug package gets local-LAN permission.
        self.android('shell','pm','grant',self.android_bundle,'android.permission.ACCESS_LOCAL_NETWORK',check=False)
        self.android('uninstall',self.receiver,check=False)
    def write_android(self,path,text):
        return self.android('shell',shlex.join(['run-as',self.android_bundle,'sh','-c','cat > '+shlex.quote(path)]),input=text)
    def read_json(self,name):
        if self.platform=='ios':
            p=self.documents/name
            return json.loads(p.read_text()) if p.exists() else None
        result=self.android('exec-out','run-as',self.android_bundle,'cat','files/'+name,check=False)
        return json.loads(result.stdout) if result.returncode==0 and result.stdout.strip().startswith('{') else None
    def await_json(self,name,timeout=60):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            fatal=self.read_json('credit-handoff-fatal.json')
            if fatal: raise AssertionError(fatal)
            value=self.read_json(name)
            if value is not None: return value
            time.sleep(.1)
        raise TimeoutError('RN proof did not produce '+name)
    def remove(self,name):
        if self.platform=='ios': (self.documents/name).unlink(missing_ok=True)
        else: self.android('shell','run-as',self.android_bundle,'rm','-f','files/'+name)
    def restart(self):
        self.remove('credit-handoff-ready.json')
        if self.platform=='ios':
            self.ios('terminate',self.device,self.ios_bundle,check=False); self.ios('launch',self.device,self.ios_bundle)
            self.foreground()
        else:
            self.android('shell','am','force-stop',self.android_bundle)
            self.android('shell','am','start','-n',self.android_bundle+'/com.snowdamiz.morse.MainActivity')
    def foreground(self):
        if self.platform=='ios': self.ios('openurl',self.device,'morse-handoff-proof://resume')
        else: self.android('shell','am','start','-n',self.android_bundle+'/com.snowdamiz.morse.MainActivity')
    def invoke(self,operation,id='',rejected=False):
        self.foreground(); self.remove('credit-handoff-response.json')
        text=json.dumps({'operation':operation,'id':id})
        if self.platform=='ios':
            tmp=self.documents/'handoff-command.tmp'; tmp.write_text(text); tmp.rename(self.documents/'credit-handoff-command.json')
        else:
            self.write_android('files/credit-handoff-command.tmp',text)
            self.android('shell','run-as',self.android_bundle,'mv','files/credit-handoff-command.tmp','files/credit-handoff-command.json')
        if operation=='open' and not rejected:
            # iOS can suspend JS immediately after a successful OS launch. Use
            # the receiver callback as authority, then resume the sender so its
            # existing Promise can write its local test result.
            deadline=time.monotonic()+15
            previous=getattr(self,'last_receiver_count',0)
            while time.monotonic()<deadline:
                delivered=self.receiver_value()
                if delivered and delivered['count']>previous:
                    self.last_receiver_count=delivered['count']; break
                time.sleep(.1)
            self.foreground()
        value=self.await_json('credit-handoff-response.json')
        self.sequence+=1; self.records.append({'operation':operation,**value})
        (self.work/f'{self.sequence:02}-{operation}.json').write_text(json.dumps(value,indent=2)+'\n')
        assert value['passed'] is (not rejected),value
        return value.get('error') if rejected else value.get('value')
    def install_receiver(self):
        directory=self.work/'receiver'; directory.mkdir()
        if self.platform=='ios':
            app=directory/'Receiver.app'; app.mkdir()
            info={'CFBundleExecutable':'Receiver','CFBundleIdentifier':self.receiver,'CFBundleName':'Morse Owned Wallet Receiver','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','CFBundlePackageType':'APPL','MinimumOSVersion':'16.4','UIDeviceFamily':[1], 'LSRequiresIPhoneOS':True,'UIApplicationSceneManifest':{'UIApplicationSupportsMultipleScenes':False,'UISceneConfigurations':{'UIWindowSceneSessionRoleApplication':[{'UISceneConfigurationName':'Default Configuration','UISceneDelegateClassName':'MorseHandoffReceiverScene'}]}},'CFBundleURLTypes':[{'CFBundleURLName':'Owned unpaid Lightning receiver','CFBundleURLSchemes':['lightning']} ]}
            (app/'Info.plist').write_bytes(plistlib.dumps(info))
            sdk=run('xcrun','--sdk','iphonesimulator','--show-sdk-path').stdout.strip()
            run('xcrun','--sdk','iphonesimulator','swiftc','-parse-as-library','-sdk',sdk,'-target','arm64-apple-ios16.4-simulator',self.product/'scripts/credit-handoff-proof/Receiver.swift','-framework','UIKit','-framework','CryptoKit','-o',app/'Receiver')
            run('codesign','--force','--sign','-',app); self.ios('install',self.device,app)
            self.receiver_file=Path(self.ios('get_app_container',self.device,self.receiver,'data').stdout.strip())/'Documents/received.json'
        else:
            android=self.sdk/'platforms/android-36/android.jar'; build=self.sdk/'build-tools/36.0.0'
            classes=directory/'classes'; classes.mkdir(); dex=directory/'dex'; dex.mkdir()
            run(self.java/'bin/javac','-source','8','-target','8','-classpath',android,'-d',classes,self.product/'scripts/credit-handoff-proof/Receiver.java')
            run(self.java/'bin/jar','cf',directory/'receiver.jar','-C',classes,'.')
            run(build/'d8','--min-api','26','--lib',android,'--output',dex,directory/'receiver.jar')
            manifest=directory/'AndroidManifest.xml'
            manifest.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{self.receiver}" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36"/><application android:debuggable="true" android:allowBackup="false" android:label="Morse Owned Wallet Receiver"><activity android:name=".Receiver" android:exported="true" android:theme="@android:style/Theme.Material.Light.NoActionBar"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="lightning"/></intent-filter></activity></application></manifest>')
            run(build/'aapt2','link','-I',android,'--manifest',manifest,'-o',directory/'receiver.apk')
            shutil.copyfile(dex/'classes.dex',directory/'classes.dex'); run('zip','-q','receiver.apk','classes.dex',cwd=directory)
            run(build/'apksigner','sign','--ks',Path.home()/'.android/debug.keystore','--ks-key-alias','androiddebugkey','--ks-pass','pass:android',directory/'receiver.apk')
            self.android('install',directory/'receiver.apk')
    def receiver_value(self):
        if self.platform=='ios': return json.loads(self.receiver_file.read_text()) if self.receiver_file.exists() else None
        exists=self.android('shell','run-as',self.receiver,'test','-f','files/received.json',check=False)
        if exists.returncode==1 and not exists.stdout.strip() and not exists.stderr.strip(): return None
        assert exists.returncode==0, 'receiver file observation failed'
        result=self.android('exec-out','run-as',self.receiver,'cat','files/received.json')
        return json.loads(result.stdout)
    def received(self,count):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            result=self.receiver_value()
            if result and result['count']==count: return result
            time.sleep(.1)
        raise TimeoutError('OS receiver did not record exact invocation count')
    def __exit__(self,*_):
        (self.work/'inputs.json').write_text(json.dumps(self.inputs,indent=2)+'\n')
        if self.platform=='ios':
            self.ios('terminate',self.device,self.ios_bundle,check=False); self.ios('terminate',self.device,self.receiver,check=False)
        else:
            self.android('shell','am','force-stop',self.android_bundle,check=False); self.android('shell','am','force-stop',self.receiver,check=False)
            for port in [8088,self.tls_port]: self.android('reverse','--remove',f'tcp:{port}',check=False)


def prove_os_handoff(product,work,seed,lnd,issuer_origin,set_mode,platform):
    work.mkdir(parents=True,exist_ok=True)
    with CreditTLSIngress(work,issuer_origin,seed) as ingress:
        witness='outside '+seed['witness_key']+' Test'
        trust='\n'.join(['3',seed['service_key'],'22'*32,'16','1','1',witness,'-','0',ingress.origin,'2','1','1',witness])
        with Metro(product/'apps/mobile',work), RNProof(product,work/'rn',platform,trust,ingress.resource()) as app:
            quote_waits=0; cancellation_waits=0
            app.invoke('create'); app.invoke('discover')
            prepared=app.invoke('prepare'); id=prepared['id']
            try: quoted=app.invoke('continue',id)
            except AssertionError as error:
                if 'lightning_quote_request_mismatch' not in str(error): raise
                quote_waits+=1
                time.sleep(1.1); quoted=app.invoke('continue',id)
            assert quoted['stage']==1 and quoted['asset']==2
            # MCP exposes the authenticated public LQT view; signatures stay in
            # the sealed native journal and are rechecked by the host launcher.
            quote=bytes.fromhex(quoted['quote']); assert quote[:4]==b'\x01LQT'
            size=int.from_bytes(quote[193:195],'big'); invoice=quote[195:].decode()
            assert len(invoice)==size and invoice.startswith('lnbcrt')
            digest=hashlib.sha256(('lightning:'+invoice).encode()).hexdigest()
            # A missing receiver is an actual failing launch, not a fake UI flag.
            missing=app.invoke('open',id,rejected=True); assert 'external_wallet_unavailable' in missing,missing
            print(platform+': real production wrapper refused missing receiver',flush=True)
            app.install_receiver()
            app.invoke('wrong-database',id,rejected=True)
            app.invoke('open','99'*32,rejected=True)
            assert app.receiver_value() is None
            app.invoke('open',id); received=app.received(1)
            assert received=={'count':1,'sha256':digest,'scheme':'lightning','length':len(invoice)+10},received
            saved=app.invoke('recover',id); assert saved['stage']==2
            claim=bytes.fromhex(saved['body']); payment_hash=claim[36:68].hex()
            assert claim[:4]==b'\x01LIR' and lnd.lnd('issuer','/v1/invoice/'+payment_hash)['state']=='OPEN'
            app.restart(); app.await_json('credit-handoff-ready.json',timeout=90)
            assert app.invoke('recover',id)['body']==saved['body']
            app.invoke('open',id); again=app.received(2); assert again['sha256']==digest
            # Cancel with the real issuer/LND, authenticate LCN natively, then
            # prove the same production launcher cannot reopen it.
            lnd.lnd('issuer','/v2/invoices/cancel',{'payment_hash':base64.b64encode(bytes.fromhex(payment_hash)).decode()})
            try: canceled=app.invoke('continue',id)
            except AssertionError as error:
                if 'invalid_credit_cancellation' not in str(error): raise
                # The issuer persists one signed LCN. A native future-time
                # refusal must retain the same claim; wait once for the owned
                # emulator clock and retry that immutable claim unchanged.
                pending=app.invoke('recover',id)
                assert pending['stage']==2 and pending['body']==saved['body']
                cancellation_waits+=1
                time.sleep(1.1)
                canceled=app.invoke('continue',id)
            assert canceled['stage']==4
            app.invoke('open',id,rejected=True)
            time.sleep(.3); assert app.receiver_value()==again
            assert ingress.errors==[],ingress.errors
            evidence={'platform':platform,'passed':True,'production_js_wrapper':'apps/mobile/src/credit-payment-link.ts::openCreditPayment','native_http':True,'screen_capture':False,'live_funds':False,'invoice_state':'CANCELED','quote_wait_retries':quote_waits,'cancellation_wait_retries':cancellation_waits,'receiver':again,'missing_receiver_error':missing,'input_hashes':app.inputs,'requests':ingress.requests,'canceled_payment_hash':payment_hash,'cases':['production RN entry and locked JS network globals','native witnessed issuer discovery and signed Lightning quote','missing OS receiver rejected','wrong database and unknown purchase do not launch','real OS receiver gets exact verified invoice','app restart reopens same durable invoice without payment','native authenticated cancellation prevents further OS launch'],'limits':'Owned simulator/emulator receiver acknowledges URI delivery only; no third-party wallet or live payment compatibility claim.'}
            (work/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
            print(platform+': production wrapper OS handoff/restart/cancellation GREEN',flush=True)
            return evidence
