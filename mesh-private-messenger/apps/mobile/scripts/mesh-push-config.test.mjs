import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const {
  AndroidConfig,
  compileModsAsync,
  withAndroidManifest,
} = require('@expo/config-plugins');
const withMeshPushConfig = require('../plugins/with-mesh-push-config.cjs');

const projectID = '01234567-89ab-cdef-0123-456789abcdef';
const brokerPublicKeyHex = 'ab'.repeat(32);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

async function inspect(environment, seeded = false) {
  const base = {
    name: 'Whatsdown',
    slug: 'whatsdown',
    ios: {
      bundleIdentifier: 'com.snowdamiz.whatsdown',
      infoPlist: seeded
        ? {
            MeshMessengerExpoProjectID: projectID,
            MeshMessengerPushBrokerPublicKeyHex: brokerPublicKeyHex,
          }
        : {},
    },
    android: { package: 'com.snowdamiz.whatsdown' },
  };
  let configured = withMeshPushConfig(base, environment);
  if (seeded) {
    configured = withAndroidManifest(configured, (current) => {
      const application = AndroidConfig.Manifest.getMainApplicationOrThrow(
        current.modResults,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.whatsdown.mesh.EXPO_PROJECT_ID',
        projectID,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.whatsdown.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
        brokerPublicKeyHex,
      );
      return current;
    });
  }
  return compileModsAsync(configured, {
    projectRoot,
    introspect: true,
    platforms: ['ios', 'android'],
    ignoreExistingNativeFiles: true,
  });
}

test('canonical push pins land in signed iOS and Android resources', async () => {
  const config = await inspect({
    MESSENGER_EXPO_PROJECT_ID: projectID,
    MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX: brokerPublicKeyHex,
  });

  assert.equal(config.ios.infoPlist.MeshMessengerExpoProjectID, projectID);
  assert.equal(
    config.ios.infoPlist.MeshMessengerPushBrokerPublicKeyHex,
    brokerPublicKeyHex,
  );
  const manifest = config._internal.modResults.android.manifest;
  assert.equal(
    AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      manifest,
      'app.whatsdown.mesh.EXPO_PROJECT_ID',
    ),
    projectID,
  );
  assert.equal(
    AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      manifest,
      'app.whatsdown.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
    ),
    brokerPublicKeyHex,
  );
  const expectedFrame = `1\n${projectID}\n${brokerPublicKeyHex}`;
  const iosFrame = `1\n${config.ios.infoPlist.MeshMessengerExpoProjectID}\n${config.ios.infoPlist.MeshMessengerPushBrokerPublicKeyHex}`;
  const androidFrame = `1\n${AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    manifest,
    'app.whatsdown.mesh.EXPO_PROJECT_ID',
  )}\n${AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    manifest,
    'app.whatsdown.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
  )}`;
  assert.equal(Buffer.byteLength(expectedFrame), 103);
  assert.equal(iosFrame, expectedFrame);
  assert.equal(androidFrame, expectedFrame);
});

test('an absent push-pin pair removes stale native resource values', async () => {
  const config = await inspect({}, true);

  assert.equal('MeshMessengerExpoProjectID' in config.ios.infoPlist, false);
  assert.equal(
    'MeshMessengerPushBrokerPublicKeyHex' in config.ios.infoPlist,
    false,
  );
  const manifest = config._internal.modResults.android.manifest;
  const application = AndroidConfig.Manifest.getMainApplicationOrThrow(manifest);
  assert.equal(
    AndroidConfig.Manifest.findMetaDataItem(
      application,
      'app.whatsdown.mesh.EXPO_PROJECT_ID',
    ),
    -1,
  );
  assert.equal(
    AndroidConfig.Manifest.findMetaDataItem(
      application,
      'app.whatsdown.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
    ),
    -1,
  );
});

test('partial or malformed push pins fail native config evaluation', async () => {
  const invalidEnvironments = [
    { MESSENGER_EXPO_PROJECT_ID: projectID },
    { MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX: brokerPublicKeyHex },
    {
      MESSENGER_EXPO_PROJECT_ID: projectID.toUpperCase(),
      MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX: brokerPublicKeyHex,
    },
    {
      MESSENGER_EXPO_PROJECT_ID: projectID,
      MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX: 'ab'.repeat(31),
    },
    {
      MESSENGER_EXPO_PROJECT_ID: projectID,
      MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX: brokerPublicKeyHex.toUpperCase(),
    },
  ];

  for (const environment of invalidEnvironments) {
    await assert.rejects(
      inspect(environment),
      /MESSENGER_(EXPO_PROJECT_ID|PUSH_BROKER_PUBLIC_KEY_HEX)/,
    );
  }
});
