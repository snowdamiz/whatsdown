import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
// Use the installed real Expo mod hooks; no fake plugin framework.
const plugin = require('../plugins/with-app-lock.cjs');

const appDelegate = `internal import Expo
import React
import ReactAppDependencyProvider

@main
class AppDelegate: ExpoAppDelegate, ExpoReactNativeFactoryProvider {
  var window: UIWindow?

  var reactNativeDelegate: ExpoReactNativeFactoryDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  public override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    let factory = ExpoReactNativeFactory(delegate: delegate)
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory

    // The window is created and React Native is started by \`SceneDelegate\` under the
    // scene-based life cycle (required by the iOS 27 SDK).
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}

class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {
  // Extension point for config-plugins

  override func sourceURL(for bridge: RCTBridge) -> URL? {
    // needed to return the correct URL for expo-dev-client.
    bridge.bundleURL ?? bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    return RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: ".expo/.virtual-metro-entry")
#else
    return Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
`;

const legacyDelegate = `internal import Expo
import React
import ReactAppDependencyProvider
import MeshMessenger

@main
class AppDelegate: ExpoAppDelegate, ExpoReactNativeFactoryProvider {
  var window: UIWindow?

  override init() {
    super.init()
    MeshMessengerDataProtection.installAtLaunch()
  }

  var reactNativeDelegate: ExpoReactNativeFactoryDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  public override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    let factory = ExpoReactNativeFactory(delegate: delegate)
    delegate.rootFactory = factory
    delegate.currentFactory = { [weak self] in self?.reactNativeFactory }
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory

    // The window is created and React Native is started by \`SceneDelegate\` under the
    // scene-based life cycle (required by the iOS 27 SDK).
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}

class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {
  weak var rootFactory: RCTReactNativeFactory?
  var currentFactory: (() -> NSObject?)?
  // Extension point for config-plugins

  override func customize(_ rootView: UIView) {
    if let factory = rootFactory, let currentFactory {
      MeshMessengerDataProtection.bindReactNativeRoot(rootView, factory: factory, currentFactory: currentFactory)
    }
    super.customize(rootView)
  }

  override func sourceURL(for bridge: RCTBridge) -> URL? {
    // needed to return the correct URL for expo-dev-client.
    bridge.bundleURL ?? bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    return RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: ".expo/.virtual-metro-entry")
#else
    return Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
`;

const mainActivity = `package com.snowdamiz.morse
import expo.modules.splashscreen.SplashScreenManager

import android.os.Build
import android.os.Bundle

import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

import expo.modules.ReactActivityDelegateWrapper

class MainActivity : ReactActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // Set the theme to AppTheme BEFORE onCreate to support
    // coloring the background, status bar, and navigation bar.
    // This is required for expo-splash-screen.
    // setTheme(R.style.AppTheme);
    // @generated begin expo-splashscreen - expo prebuild (DO NOT MODIFY) sync-f3ff59a738c56c9a6119210cb55f0b613eb8b6af
    SplashScreenManager.registerOnActivity(this)
    // @generated end expo-splashscreen
    super.onCreate(null)
  }

  /**
   * Returns the name of the main component registered from JavaScript. This is used to schedule
   * rendering of the component.
   */
  override fun getMainComponentName(): String = "main"

  /**
   * Returns the instance of the [ReactActivityDelegate]. We use [DefaultReactActivityDelegate]
   * which allows you to enable New Architecture with a single boolean flags [fabricEnabled]
   */
  override fun createReactActivityDelegate(): ReactActivityDelegate {
    return ReactActivityDelegateWrapper(
          this,
          BuildConfig.IS_NEW_ARCHITECTURE_ENABLED,
          object : DefaultReactActivityDelegate(
              this,
              mainComponentName,
              fabricEnabled
          ){})
  }

  /**
    * Align the back button behavior with Android S
    * where moving root activities to background instead of finishing activities.
    * @see <a href="https://developer.android.com/reference/android/app/Activity#onBackPressed()">onBackPressed</a>
    */
  override fun invokeDefaultOnBackPressed() {
      if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
          if (!moveTaskToBack(false)) {
              // For non-root activities, use the default implementation to finish them.
              super.invokeDefaultOnBackPressed()
          }
          return
      }

      // Use the default back button implementation on Android S
      // because it's doing more than [Activity.moveTaskToBack] in fact.
      super.invokeDefaultOnBackPressed()
  }
}
`;

const mainApplication = `package com.snowdamiz.morse

import android.app.Application
import android.content.res.Configuration

import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.ReactPackage
import com.facebook.react.ReactHost
import com.facebook.react.common.ReleaseLevel
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint

import expo.modules.ApplicationLifecycleDispatcher
import expo.modules.ExpoReactHostFactory

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    ExpoReactHostFactory.getDefaultReactHost(
      context = applicationContext,
      packageList =
        PackageList(this).packages.apply {
          // Packages that cannot be autolinked yet can be added manually here, for example:
          // add(MyReactNativePackage())
        }
    )
  }

  override fun onCreate() {
    super.onCreate()
    DefaultNewArchitectureEntryPoint.releaseLevel = try {
      ReleaseLevel.valueOf(BuildConfig.REACT_NATIVE_RELEASE_LEVEL.uppercase())
    } catch (e: IllegalArgumentException) {
      ReleaseLevel.STABLE
    }
    loadReactNative(this)
    ApplicationLifecycleDispatcher.onApplicationCreate(this)
  }

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    ApplicationLifecycleDispatcher.onConfigurationChanged(this, newConfig)
  }
}
`;

function config(twice = false) {
  const once = plugin({ name: 'Morse', slug: 'morse' });
  return twice ? plugin(once) : once;
}
async function apply(mod, contents, language, twice = false) {
  const value = config(twice), [platform, name] = mod.split('.');
  assert.equal(typeof value.mods[platform][name], 'function');
  return (await value.mods[platform][name]({ ...value, modRequest: {}, modResults: { contents, language } })).modResults.contents;
}
const ios = (contents, language = 'swift', twice = false) => apply('ios.appDelegate', contents, language, twice);
const activity = (contents, language = 'kt', twice = false) => apply('android.mainActivity', contents, language, twice);
const rootBinding = 'MeshMessengerDataProtection.bindReactNativeRoot(rootView, factory: factory, currentFactory: currentFactory)';
const startup = 'MeshMessengerDataProtection.installAtLaunch()';

test('fresh real Expo iOS template emits one internal MeshMessenger import and preserves startup/current-factory wiring idempotently', async () => {
  const output = await ios(appDelegate);
  assert.equal(output.split('\n').filter(line => line === 'internal import MeshMessenger').length, 1);
  assert.doesNotMatch(output, /^import MeshMessenger\s*$/m);
  assert.match(output, /override init\(\)\s*\{\s*super\.init\(\)\s*MeshMessengerDataProtection\.installAtLaunch\(\)/);
  for (const anchor of ['delegate.rootFactory = factory', 'delegate.currentFactory = { [weak self] in self?.reactNativeFactory }',
    'weak var rootFactory: RCTReactNativeFactory?', 'var currentFactory: (() -> NSObject?)?', rootBinding, 'super.customize(rootView)']) assert.ok(output.includes(anchor), anchor);
  assert.equal(output.split(startup).length - 1, 1); assert.equal(output.split(rootBinding).length - 1, 1);
  assert.equal(await ios(output), output); assert.equal(await ios(appDelegate, 'swift', true), output);
});

test('unsupported iOS templates refuse instead of returning a partial startup edit', async () => {
  await assert.rejects(ios('import Expo\n'), /Unsupported/);
  await assert.rejects(ios(appDelegate, 'objc'), /Unsupported/);
  await assert.rejects(ios(appDelegate.replace('  var window: UIWindow?\n', '  var window: UIWindow?\n  override init() { super.init() }\n')), /Unsupported/);
  await assert.rejects(ios(appDelegate.replace('class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {',
    'class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {\n  override func customize(_ rootView: UIView) {}')), /Unsupported/);
});

test('real Expo privacy mod retains the exact native authentication description', async () => {
  const value = config();
  const result = await value.mods.ios.infoPlist({ ...value, modRequest: {}, modResults: { retained: 'value' } });
  assert.equal(result.modResults.NSFaceIDUsageDescription, 'Use Face ID or your device passcode to unlock Morse.');
  assert.equal(result.modResults.retained, 'value');
});

test('partial factory assignment is independently repaired without losing the current native resolver', async () => {
  const output = await ios(appDelegate), partial = output.replace('    delegate.rootFactory = factory\n', '');
  assert.notEqual(partial, output); assert.equal(await ios(partial), output);
});

test('missing iOS import or initializer insertion anchors fail closed', async () => {
  for (const contents of [appDelegate.replace('import ReactAppDependencyProvider\n', ''),
    appDelegate.replace('  var window: UIWindow?\n', '  var window: UIWindow? // unsupported layout\n')]) await assert.rejects(ios(contents), /Unsupported/);
});

test('the actual already-wired bare-import AppDelegate migrates only its import line', async () => {
  assert.match(legacyDelegate, /^import MeshMessenger$/m);
  const expected = legacyDelegate.replace(/^import MeshMessenger$/m, 'internal import MeshMessenger');
  assert.equal(await ios(legacyDelegate), expected);
  assert.equal(await ios(expected), expected);
});

test('an already-internal AppDelegate remains byte-identical after single and composed real Expo mods', async () => {
  const current = legacyDelegate.replace(/^import MeshMessenger$/m, 'internal import MeshMessenger');
  assert.equal(await ios(current), current);
  assert.equal(await ios(current, 'swift', true), current);
});

const coldCall = 'expo.modules.meshmessenger.MeshMessengerNotificationIntents.consumeBeforeReact';
test('actual Android Activity cold and warm ingress precede React startup and intent dispatch', async () => {
  const output = await activity(mainActivity), warm = output.slice(output.indexOf('override fun onNewIntent'));
  assert.ok(output.indexOf(`${coldCall}(this, intent)`) < output.indexOf('SplashScreenManager.registerOnActivity(this)'));
  assert.ok(warm.indexOf(`${coldCall}(this, intent)`) < warm.indexOf('setIntent(intent)'));
  assert.ok(warm.indexOf(`${coldCall}(this, intent)`) < warm.indexOf('super.onNewIntent(intent)'));
  assert.equal(output.split(`${coldCall}(this, intent)`).length - 1, 2);
  assert.ok(output.includes('super.onCreate(null)')); assert.ok(output.includes('moveTaskToBack(false)'));
});

test('Android real composed hooks remain idempotent and install after super before React load', async () => {
  const once = await activity(mainActivity);
  assert.equal(await activity(once), once); assert.equal(await activity(mainActivity, 'kt', true), once);
  const output = await apply('android.mainApplication', mainApplication, 'kt');
  const call = 'expo.modules.meshmessenger.MeshMessengerAppLock.install(this)';
  assert.equal(output, mainApplication.replace('super.onCreate()', `super.onCreate()\n    ${call}`));
  assert.ok(output.indexOf('super.onCreate()') < output.indexOf(call)); assert.ok(output.indexOf(call) < output.indexOf('loadReactNative(this)'));
  assert.equal(await apply('android.mainApplication', output, 'kt'), output);
});

test('unsupported or conflicting Android templates refuse without omitting early hooks', async () => {
  await assert.rejects(activity(mainActivity, 'java'), /Unsupported app-lock activity template/);
  await assert.rejects(activity(mainActivity.replace('super.onCreate(null)', 'unrecognizedCreate()')), /Unsupported app-lock activity template/);
  await assert.rejects(activity(mainActivity.replace('class MainActivity : ReactActivity() {',
    'class MainActivity : ReactActivity() {\n override fun onNewIntent(intent: android.content.Intent) { super.onNewIntent(intent) }')), /Unsupported app-lock activity template/);
  await assert.rejects(apply('android.mainApplication', mainApplication.replace('super.onCreate()', 'unrecognizedCreate()'), 'kt'), /Unsupported/);
});

const stockFirebase = 'expo.modules.notifications.service.ExpoFirebaseMessagingService';
const ownedFirebase = 'expo.modules.meshmessenger.MeshMessengerFirebaseMessagingService';
const event = 'com.google.firebase.MESSAGING_EVENT', delegation = 'firebase_messaging_notification_delegation_enabled';
const service = name => ({ $: { 'android:name': name, 'android:exported': 'false' }, 'intent-filter': [{ $: { 'android:priority': '-1' }, action: [{ $: { 'android:name': event } }] }] });
const manifest = () => ({ manifest: { $: {}, application: [{ $: {}, service: [service(stockFirebase), { $: { 'android:name': 'app.UnrelatedService' } }],
  'meta-data': [{ $: { 'android:name': delegation, 'android:value': 'true' } }, { $: { 'android:name': 'retained', 'android:value': '42' } }] }] } });
async function androidManifest(input, twice = false) {
  const value = config(twice);
  return (await value.mods.android.manifest({ ...value, modRequest: {}, modResults: structuredClone(input) })).modResults;
}
test('Android manifest selects only the owned nonexported Firebase service and removes stock ingress', async () => {
  const result = await androidManifest(manifest()), app = result.manifest.application[0];
  assert.deepEqual(app.service.filter(s => s.$['android:name'] === stockFirebase), [{ $: { 'android:name': stockFirebase, 'tools:node': 'remove' } }]);
  const selected = app.service.filter(s => s.$['android:name'] === ownedFirebase); assert.equal(selected.length, 1);
  assert.equal(selected[0].$['android:exported'], 'false'); assert.equal(selected[0].$['android:enabled'], 'true');
  assert.equal(selected[0]['intent-filter'][0].action[0].$['android:name'], event); assert.ok(Number(selected[0]['intent-filter'][0].$['android:priority']) > -1);
  assert.equal(app.service.filter(s => s.$['android:name'] === 'app.UnrelatedService').length, 1);
  assert.equal(app.receiver.find(r => r.$['android:name'] === 'expo.modules.notifications.service.NotificationsService').$['tools:node'], 'remove');
  assert.equal(app.receiver.find(r => r.$['android:name'] === 'expo.modules.meshmessenger.MeshMessengerNotificationsService').$['android:exported'], 'false');
  assert.equal(result.manifest['uses-permission'].filter(p => p.$['android:name'] === 'android.permission.USE_BIOMETRIC').length, 1);
});
test('Firebase OS proxy delegation is disabled without duplicating hooks or unrelated metadata', async () => {
  const original = manifest(), once = await androidManifest(original);
  assert.deepEqual(await androidManifest(once), once); assert.deepEqual(await androidManifest(original, true), once);
  const values = once.manifest.application[0]['meta-data'];
  assert.equal(values.filter(v => v.$['android:name'] === delegation).length, 1);
  assert.equal(values.find(v => v.$['android:name'] === delegation).$['android:value'], 'false');
  assert.equal(values.find(v => v.$['android:name'] === 'retained').$['android:value'], '42');
});
test('a competing unowned Firebase messaging service is refused', async () => {
  const input = manifest(); input.manifest.application[0].service.push(service('app.CompetingFirebaseService'));
  await assert.rejects(androidManifest(input), /Conflicting Firebase messaging service/);
});
