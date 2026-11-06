const { withAndroidManifest, withMainApplication, withMainActivity, withInfoPlist, withAppDelegate } = require('@expo/config-plugins');
const receiver='expo.modules.meshmessenger.MeshMessengerNotificationsService';
const stock='expo.modules.notifications.service.NotificationsService';
const actions=['expo.modules.notifications.NOTIFICATION_EVENT','android.intent.action.BOOT_COMPLETED','android.intent.action.REBOOT',
  'android.intent.action.QUICKBOOT_POWERON','com.htc.intent.action.QUICKBOOT_POWERON','android.intent.action.MY_PACKAGE_REPLACED'];
module.exports = function withAppLock(config) {
  config=withAndroidManifest(config, result => {
    const manifest=result.modResults.manifest;manifest.$['xmlns:tools']='http://schemas.android.com/tools';
    const application=manifest.application[0];
    const firebase='expo.modules.meshmessenger.MeshMessengerFirebaseMessagingService';
    const stockFirebase='expo.modules.notifications.service.ExpoFirebaseMessagingService';
    const messaging='com.google.firebase.MESSAGING_EVENT';
    const services=application.service??[];
    for(const service of services) {
      const handles=(service['intent-filter']??[]).some(filter=>(filter.action??[]).some(action=>action.$['android:name']===messaging));
      if(handles&&![firebase,stockFirebase].includes(service.$['android:name']))throw Error('Conflicting Firebase messaging service');
    }
    application.service=services.filter(service=>![firebase,stockFirebase].includes(service.$['android:name']));
    application.service.push({$:{'android:name':stockFirebase,'tools:node':'remove'}},
      {$:{'android:name':firebase,'android:enabled':'true','android:exported':'false'},
       'intent-filter':[{$:{'android:priority':'0'},action:[{$:{'android:name':messaging}}]}]});
    const delegation='firebase_messaging_notification_delegation_enabled';
    application['meta-data']=(application['meta-data']??[]).filter(item=>item.$['android:name']!==delegation);
    application['meta-data'].push({$:{'android:name':delegation,'android:value':'false','tools:replace':'android:value'}});
    application.receiver=(application.receiver??[]).filter(item=>![receiver,stock].includes(item.$['android:name']));
    application.receiver.push({$:{'android:name':stock,'tools:node':'remove'}},{$:{'android:name':receiver,'android:enabled':'true','android:exported':'false'},
      'intent-filter':[{$:{'android:priority':'-1'},action:actions.map(name=>({$:{'android:name':name}}))}]});
    manifest['uses-permission']??=[];
    if(!manifest['uses-permission'].some(item=>item.$['android:name']==='android.permission.USE_BIOMETRIC'))manifest['uses-permission'].push({$:{'android:name':'android.permission.USE_BIOMETRIC'}});
    return result;
  });
  config=withMainApplication(config,result=>{
    const call='expo.modules.meshmessenger.MeshMessengerAppLock.install(this)';
    if(!result.modResults.contents.includes(call)) {
      if(result.modResults.language!=='kt'||!result.modResults.contents.includes('super.onCreate()'))throw Error('Unsupported app-lock application template');
      result.modResults.contents=result.modResults.contents.replace('super.onCreate()',`super.onCreate()\n    ${call}`);
    }
    return result;
  });
  config=withMainActivity(config,result=>{
    const opening='override fun onCreate(savedInstanceState: Bundle?) {';
    const call='expo.modules.meshmessenger.MeshMessengerNotificationIntents.consumeBeforeReact(this, intent)';
    const cold=`${opening}\n    ${call}`;
    const warm=`  override fun onNewIntent(intent: android.content.Intent) {\n    ${call}\n    setIntent(intent)\n    super.onNewIntent(intent)\n  }\n`;
    const source=result.modResults.contents;
    const count=value=>source.split(value).length-1;
    const refuse=()=>{throw Error('Unsupported app-lock activity template');};
    if(result.modResults.language!=='kt'||count(opening)!==1||count('super.onCreate(null)')!==1)refuse();
    if(source.includes(call)) {
      if(count(call)!==2||!source.includes(cold)||!source.includes(warm)||count('override fun onNewIntent')!==1)refuse();
      return result;
    }
    if(source.includes('onNewIntent(')||!source.trimEnd().endsWith('}'))refuse();
    const changed=source.replace(opening,cold);
    const closing=changed.lastIndexOf('}');
    result.modResults.contents=changed.slice(0,closing)+warm+changed.slice(closing);
    return result;
  });
  config=withAppDelegate(config,result=>{
    if(result.modResults.language!=='swift')throw Error('Unsupported iOS app-lock AppDelegate template');
    result.modResults.contents=preserveNativeAppLock(result.modResults.contents);
    return result;
  });
  return withInfoPlist(config,result=>{result.modResults.NSFaceIDUsageDescription='Use Face ID or your device passcode to unlock Morse.';return result;});
};

function preserveNativeAppLock(contents) {
  const app='class AppDelegate: ExpoAppDelegate, ExpoReactNativeFactoryProvider {';
  const native='class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {';
  const factory='    let factory = ExpoReactNativeFactory(delegate: delegate)';
  const source='  override func sourceURL(for bridge: RCTBridge) -> URL? {';
  if(![app,native,factory,source,'  var window: UIWindow?\n'].every(anchor=>contents.includes(anchor))) {
    throw Error('Unsupported iOS app-lock AppDelegate template');
  }
  const meshImport='internal import MeshMessenger';
  let text=contents.replace(/^import MeshMessenger[ \t]*$/gm,meshImport);
  if(!text.includes(meshImport))text=text.replace('import ReactAppDependencyProvider',`import ReactAppDependencyProvider\n${meshImport}`);
  if(!text.includes('MeshMessengerDataProtection.installAtLaunch()')) {
    if(/\boverride\s+(?:public\s+)?init\s*\(/.test(text))throw Error('Unsupported iOS app-lock AppDelegate initializer');
    text=text.replace('  var window: UIWindow?\n',`  var window: UIWindow?

  override init() {
    super.init()
    MeshMessengerDataProtection.installAtLaunch()
  }
`);
  }
  const boundFactory='    delegate.rootFactory = factory';
  if(!text.includes(boundFactory))text=text.replace(factory,`${factory}\n${boundFactory}`);
  const currentFactory='    delegate.currentFactory = { [weak self] in self?.reactNativeFactory }';
  if(!text.includes(currentFactory))text=text.replace(boundFactory,`${boundFactory}\n${currentFactory}`);
  const weakFactory='  weak var rootFactory: RCTReactNativeFactory?';
  if(!text.includes(weakFactory))text=text.replace(native,`${native}\n${weakFactory}`);
  const factoryResolver='  var currentFactory: (() -> NSObject?)?';
  if(!text.includes(factoryResolver))text=text.replace(weakFactory,`${weakFactory}\n${factoryResolver}`);
  if(!text.includes('MeshMessengerDataProtection.bindReactNativeRoot(rootView, factory: factory, currentFactory: currentFactory)')) {
    if(/override\s+func\s+customize\s*\(/.test(text))throw Error('Unsupported iOS app-lock root customizer');
    text=text.replace(source,`  override func customize(_ rootView: UIView) {
    if let factory = rootFactory, let currentFactory {
      MeshMessengerDataProtection.bindReactNativeRoot(rootView, factory: factory, currentFactory: currentFactory)
    }
    super.customize(rootView)
  }

${source}`);
  }
  const installed=/\boverride\s+(?:public\s+)?init\(\)\s*\{\s*super\.init\(\)\s*MeshMessengerDataProtection\.installAtLaunch\(\)\s*\}/;
  if(!/^internal import MeshMessenger\s*$/m.test(text)||!installed.test(text)||
      ![boundFactory,currentFactory,weakFactory,factoryResolver,
        'MeshMessengerDataProtection.bindReactNativeRoot(rootView, factory: factory, currentFactory: currentFactory)'].every(anchor=>text.includes(anchor))) {
    throw Error('Unsupported iOS app-lock AppDelegate wiring');
  }
  return text;
}
