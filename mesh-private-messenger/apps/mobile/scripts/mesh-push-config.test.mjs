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
const securityConfig = require('../plugins/security-config.cjs');

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

test('network destinations are signed native resources on both platforms', async () => {
  const environment = {
    EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
    EXPO_PUBLIC_MESSENGER_OBJECT_URL: 'https://objects.example',
    EXPO_PUBLIC_MESSENGER_STREAM_URL: 'wss://stream.example/v1/mailbox/stream',
  };
  const frame = '2\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16';
  const configured = await inspect(environment);
  assert.equal(configured.ios.infoPlist.MeshMessengerNetworkConfig, frame);
  assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    configured._internal.modResults.android.manifest, 'app.morse.mesh.NETWORK_CONFIG'), frame);
  const absent = await inspect({});
  assert.equal(absent.ios.infoPlist.MeshMessengerNetworkConfig, undefined);
  assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    absent._internal.modResults.android.manifest, 'app.morse.mesh.NETWORK_CONFIG'), null);
});

test('credit purpose reaches both signed native resources and is absent by default', async () => {
  const pins = JSON.stringify([{ id: 'outside', publicKey: '01'.repeat(32), operator: 'Outside' }]);
  const environment = {
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: transparencyPublicKeyHex,
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: deliveryPublicKeyHex,
    MESSENGER_ABUSE_DIFFICULTY: '8', MESSENGER_WITNESS_SET_JSON: pins, MESSENGER_WITNESS_THRESHOLD: '1',
    MESSENGER_LEGACY_WITNESS_SET_JSON: pins, MESSENGER_LEGACY_WITNESS_THRESHOLD: '1',
    MESSENGER_TRANSPARENCY_LOG_VERSION: '2', MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://edge.example',
  };
  for (const purpose of ['live', 'test', undefined]) {
    const config = await inspect({ ...environment, ...(purpose ? { MESSENGER_CREDIT_PURPOSE: purpose } : {}) });
    assert.equal(config.ios.infoPlist.MeshMessengerCreditPurpose, purpose);
    assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      config._internal.modResults.android.manifest, 'app.morse.mesh.CREDIT_PURPOSE'), purpose ?? null);
  }
  for (const purpose of ['live', 'test']) for (const origin of [undefined, '-']) {
    const env = { ...environment, MESSENGER_CREDIT_PURPOSE: purpose, MESSENGER_CREDIT_ISSUER_ORIGIN: origin,
      MESSENGER_CREDIT_USDC_MINT_ADDRESS: '1'.repeat(31) + '2' };
    const config = await inspect(env);
    assert.equal(config.ios.infoPlist.MeshMessengerCreditPurpose, purpose);
    assert.equal(config.ios.infoPlist.MeshMessengerCreditUSDCMintHex, '00'.repeat(31) + '01');
    assert.ok(config.ios.infoPlist.MeshMessengerSecurityConfig.includes('\n-\n'));
    assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      config._internal.modResults.android.manifest, 'app.morse.mesh.CREDIT_PURPOSE'), purpose);
    assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      config._internal.modResults.android.manifest, 'app.morse.mesh.CREDIT_USDC_MINT_HEX'), '00'.repeat(31) + '01');
  }
});

test('v4 and v5 pins reach both signed native resources; canaries require development', async () => {
  const pins = JSON.stringify([
    { id: 'a', publicKey: '01'.repeat(32), operator: 'Morse' },
    { id: 'b', publicKey: '02'.repeat(32), operator: 'Outside' },
  ]);
  const env = {
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: transparencyPublicKeyHex,
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: deliveryPublicKeyHex,
    MESSENGER_ABUSE_DIFFICULTY: '16',
    MESSENGER_WITNESS_SET_JSON: pins, MESSENGER_WITNESS_THRESHOLD: '2',
    MESSENGER_LEGACY_WITNESS_SET_JSON: pins, MESSENGER_LEGACY_WITNESS_THRESHOLD: '2',
    MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
    MESSENGER_ANCHOR_RING_ADDRESS: '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: '1'.repeat(32), MESSENGER_ANCHOR_LOG_NAME: 'morse-main',
    MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://two.example', 'https://three.example']),
  };
  for (const relayPins of [{}, {
    MESSENGER_RELAY_URLS: JSON.stringify(['https://relay.example']),
    MESSENGER_SLASH_MINT_ADDRESS: 'cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN',
  }]) for (const development of [false, true]) {
    const native = { ...env, ...relayPins };
    const configured = development ? { ...native, EAS_BUILD_PROFILE: 'development',
      MESSENGER_ANCHOR_RING_ADDRESS: 'D9mWiuuEDxC1CXJQMXgiB4zAj8yviMwwZQ3mvLUW5MD',
      MESSENGER_ANCHOR_LOG_NAME: 'morse-canary' } : native;
    const config = await inspect(configured);
    const expected = securityConfig(configured, { development });
    assert.equal(config.ios.infoPlist.MeshMessengerSecurityConfig, expected);
    assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      config._internal.modResults.android.manifest, 'app.morse.mesh.SECURITY_CONFIG'), expected);
  }
  await assert.rejects(() => inspect({ ...env, MESSENGER_ANCHOR_LOG_NAME: 'morse-canary' }), /morse-main/);
});

async function inspect(environment, seeded = false) {
  // These older tests isolate individual resources. Supply coherent unused
  // parents now required by the bound OHTTP companion; keep their assertions.
  const fixtureNetwork = {
    EXPO_PUBLIC_MESSENGER_BASE_URL: 'https://core.example',
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: 'https://edge.example',
  };
  const hasSecurity = securityFields.some(([name]) => environment[name] !== undefined);
  const hasNetwork = Object.keys(fixtureNetwork).some(name => environment[name] !== undefined) || environment.EAS_BUILD_PROFILE === 'development';
  environment = { ...(hasSecurity && !hasNetwork ? fixtureNetwork : {}),
    ...(hasNetwork && !hasSecurity ? Object.fromEntries(securityFields) : {}), ...environment };
  const base = {
    name: 'Morse',
    slug: 'morse',
    ios: {
      bundleIdentifier: 'com.snowdamiz.morse',
      infoPlist: seeded
        ? {
            MeshMessengerExpoProjectID: projectID,
            MeshMessengerPushBrokerPublicKeyHex: brokerPublicKeyHex,
            MeshMessengerSecurityConfig: securityFrame,
          }
        : {},
    },
    android: { package: 'com.snowdamiz.morse' },
  };
  let configured = withMeshPushConfig(base, environment);
  if (seeded) {
    configured = withAndroidManifest(configured, (current) => {
      const application = AndroidConfig.Manifest.getMainApplicationOrThrow(
        current.modResults,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.morse.mesh.EXPO_PROJECT_ID',
        projectID,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
        brokerPublicKeyHex,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        'app.morse.mesh.SECURITY_CONFIG',
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
      'app.morse.mesh.EXPO_PROJECT_ID',
    ),
    projectID,
  );
  assert.equal(
    AndroidConfig.Manifest.getMainApplicationMetaDataValue(
      manifest,
      'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
    ),
    brokerPublicKeyHex,
  );
  const expectedFrame = `1\n${projectID}\n${brokerPublicKeyHex}`;
  const iosFrame = `1\n${config.ios.infoPlist.MeshMessengerExpoProjectID}\n${config.ios.infoPlist.MeshMessengerPushBrokerPublicKeyHex}`;
  const androidFrame = `1\n${AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    manifest,
    'app.morse.mesh.EXPO_PROJECT_ID',
  )}\n${AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    manifest,
    'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
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
      'app.morse.mesh.SECURITY_CONFIG',
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
      'app.morse.mesh.EXPO_PROJECT_ID',
    ),
    -1,
  );
  assert.equal(
    AndroidConfig.Manifest.findMetaDataItem(
      application,
      'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX',
    ),
    -1,
  );
  assert.equal(
    AndroidConfig.Manifest.findMetaDataItem(
      application,
      'app.morse.mesh.SECURITY_CONFIG',
    ),
    -1,
  );
});

test('majority witness sets are identical in signed iOS and Android resources', async () => {
  const environment = {
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: transparencyPublicKeyHex,
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: deliveryPublicKeyHex,
    MESSENGER_ABUSE_DIFFICULTY: '8',
    MESSENGER_WITNESS_THRESHOLD: '2',
    MESSENGER_WITNESS_SET_JSON: JSON.stringify([
      { id: 'witness-c', publicKey: '55'.repeat(32), operator: 'Outside' },
      { id: 'witness-b', publicKey: witnessBPublicKeyHex, operator: 'Morse' },
      { id: 'witness-a', publicKey: witnessAPublicKeyHex, operator: 'Morse' },
    ]),
  };
  const config = await inspect(environment);
  const expected = require('../plugins/security-config.cjs')(environment);
  assert.equal(config.ios.infoPlist.MeshMessengerSecurityConfig, expected);
  assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    config._internal.modResults.android.manifest, 'app.morse.mesh.SECURITY_CONFIG'), expected);
  assert.equal(config.extra?.MESSENGER_WITNESS_SET_JSON, undefined);
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


test('v6 suite floor reaches actual iOS and Android native security resources', async () => {
  const environment = Object.fromEntries(securityFields);
  const configured = await inspect({ ...environment, MESSENGER_MINIMUM_SESSION_SUITE: '2' });
  const expected = `6\n2\n${securityFrame}`;
  assert.equal(configured.ios.infoPlist.MeshMessengerSecurityConfig, expected);
  assert.equal(AndroidConfig.Manifest.getMainApplicationMetaDataValue(
    configured._internal.modResults.android.manifest, 'app.morse.mesh.SECURITY_CONFIG'), expected);
});
