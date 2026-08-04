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
const transparencyPublicKeyHex = '11'.repeat(32);
const witnessAPublicKeyHex = '22'.repeat(32);
const witnessBPublicKeyHex = '33'.repeat(32);
const deliveryPublicKeyHex = '44'.repeat(32);
const securityFields = [
  ['MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX', transparencyPublicKeyHex],
  ['MESSENGER_WITNESS_A_PUBLIC_KEY_HEX', witnessAPublicKeyHex],
  ['MESSENGER_WITNESS_B_PUBLIC_KEY_HEX', witnessBPublicKeyHex],
  ['MESSENGER_DELIVERY_PUBLIC_KEY_HEX', deliveryPublicKeyHex],
  ['MESSENGER_ABUSE_DIFFICULTY', '8'],
];
const securityFrame = `1\n${securityFields.map(([, value]) => value).join('\n')}`;
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
            MeshMessengerSecurityConfig: securityFrame,
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
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.whatsdown.mesh.SECURITY_CONFIG',
        securityFrame,
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

test('messenger security policy lands in one canonical signed native frame', async () => {
  const config = await inspect({
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: transparencyPublicKeyHex,
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: witnessAPublicKeyHex,
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: witnessBPublicKeyHex,
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: deliveryPublicKeyHex,
    MESSENGER_ABUSE_DIFFICULTY: '8',
  });
  const manifest = config._internal.modResults.android.manifest;
  assert.equal(config.ios.infoPlist.MeshMessengerSecurityConfig, securityFrame);
  assert.equal(
    AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      manifest,
      'app.whatsdown.mesh.SECURITY_CONFIG',
    ),
    securityFrame,
  );
});

test('absent native configuration removes stale signed resource values', async () => {
  const config = await inspect({}, true);

  assert.equal('MeshMessengerExpoProjectID' in config.ios.infoPlist, false);
  assert.equal(
    'MeshMessengerPushBrokerPublicKeyHex' in config.ios.infoPlist,
    false,
  );
  assert.equal('MeshMessengerSecurityConfig' in config.ios.infoPlist, false);
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
  assert.equal(
    AndroidConfig.Manifest.findMetaDataItem(
      application,
      'app.whatsdown.mesh.SECURITY_CONFIG',
    ),
    -1,
  );
});

test('partial or malformed native configuration fails evaluation', async () => {
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

  invalidEnvironments.push(
    { MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: transparencyPublicKeyHex },
    Object.fromEntries(
      securityFields.map(([name, value]) => [
        name,
        name === 'MESSENGER_ABUSE_DIFFICULTY' ? '08' : value,
      ]),
    ),
    Object.fromEntries(
      securityFields.map(([name, value]) => [
        name,
        name === 'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX'
          ? witnessAPublicKeyHex
          : value,
      ]),
    ),
  );

  for (const environment of invalidEnvironments) {
    await assert.rejects(inspect(environment), /MESSENGER/);
  }
});
