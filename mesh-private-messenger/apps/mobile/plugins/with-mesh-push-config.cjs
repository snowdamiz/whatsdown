const {
  AndroidConfig,
  withAndroidManifest,
  withInfoPlist,
  withDangerousMod,
} = require('@expo/config-plugins');

const IOS_PROJECT_ID = 'MeshMessengerExpoProjectID';
const IOS_BROKER_KEY = 'MeshMessengerPushBrokerPublicKeyHex';
const IOS_SECURITY_CONFIG = 'MeshMessengerSecurityConfig';
const IOS_CREDIT_PURPOSE = 'MeshMessengerCreditPurpose';
const IOS_LIGHTNING_NETWORK = 'MeshMessengerLightningNetwork';
const ANDROID_LIGHTNING_NETWORK = 'app.morse.mesh.LIGHTNING_NETWORK';
const IOS_CREDIT_MINT = 'MeshMessengerCreditUSDCMintHex';
const ANDROID_PROJECT_ID = 'app.morse.mesh.EXPO_PROJECT_ID';
const ANDROID_BROKER_KEY = 'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX';
const ANDROID_SECURITY_CONFIG = 'app.morse.mesh.SECURITY_CONFIG';
const ANDROID_CREDIT_PURPOSE = 'app.morse.mesh.CREDIT_PURPOSE';
const ANDROID_CREDIT_MINT = 'app.morse.mesh.CREDIT_USDC_MINT_HEX';
const IOS_NETWORK_CONFIG = 'MeshMessengerNetworkConfig';
const ANDROID_NETWORK_CONFIG = 'app.morse.mesh.NETWORK_CONFIG';
const securityConfig = require('./security-config.cjs');
const networkCounterConfig = require('./network-counter-config.cjs');
const creditPurpose = require('./credits-config.cjs');
const networkConfig = require('./network-config.cjs');
const issuerTLSRoot = require('./issuer-tls-root.cjs');
const ohttpConfig = require('./ohttp-config.cjs');

module.exports = function withMeshPushConfig(config, environment = process.env) {
  const projectID = environment.MESSENGER_EXPO_PROJECT_ID;
  const brokerPublicKeyHex = environment.MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX;
  const provisioned = projectID !== undefined || brokerPublicKeyHex !== undefined;
  const securityFrame = securityConfig(environment, { development: environment.EAS_BUILD_PROFILE === 'development' });
  const counterFrame = networkCounterConfig(environment, securityFrame);
  const issuerRoot = issuerTLSRoot(environment);
  const purpose = creditPurpose(environment);
  const walletMint = creditPurpose.walletMint(environment);
  const lightningNetwork = creditPurpose.lightningNetwork(environment);
  const networkFrame = networkConfig(environment, { development: environment.EAS_BUILD_PROFILE === 'development' });
  const ohttpFrame = ohttpConfig(environment, networkFrame, securityFrame);
  if (
    provisioned &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      projectID ?? '',
    )
  ) {
    throw new Error('MESSENGER_EXPO_PROJECT_ID must be a canonical lowercase UUID');
  }
  if (provisioned && !/^[0-9a-f]{64}$/.test(brokerPublicKeyHex ?? '')) {
    throw new Error(
      'MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX must be a 32-byte lowercase-hex key',
    );
  }

  config = withInfoPlist(config, (current) => {
    if (provisioned) {
      current.modResults[IOS_PROJECT_ID] = projectID;
      current.modResults[IOS_BROKER_KEY] = brokerPublicKeyHex;
    } else {
      delete current.modResults[IOS_PROJECT_ID];
      delete current.modResults[IOS_BROKER_KEY];
    }
    if (securityFrame) {
      current.modResults[IOS_SECURITY_CONFIG] = securityFrame;
    } else {
      delete current.modResults[IOS_SECURITY_CONFIG];
    }
    if (counterFrame) current.modResults.MeshMessengerNetworkCounterConfig = counterFrame;
    else delete current.modResults.MeshMessengerNetworkCounterConfig;
    if (issuerRoot) current.modResults.MeshMessengerIssuerTLSRoot = issuerRoot.toString('base64');
    else delete current.modResults.MeshMessengerIssuerTLSRoot;
    if (purpose) current.modResults[IOS_CREDIT_PURPOSE] = purpose;
    else delete current.modResults[IOS_CREDIT_PURPOSE];
    if (lightningNetwork) current.modResults[IOS_LIGHTNING_NETWORK] = lightningNetwork;
    else delete current.modResults[IOS_LIGHTNING_NETWORK];
    if (walletMint) current.modResults[IOS_CREDIT_MINT] = walletMint;
    else delete current.modResults[IOS_CREDIT_MINT];
    if (ohttpFrame !== undefined) current.modResults.MeshMessengerOhttpConfig = ohttpFrame;
    else delete current.modResults.MeshMessengerOhttpConfig;
    if (networkFrame) current.modResults[IOS_NETWORK_CONFIG] = networkFrame;
    else delete current.modResults[IOS_NETWORK_CONFIG];
    return current;
  });
  config = withDangerousMod(config, ['android', async current => {
    issuerTLSRoot.writeAndroid(current.modRequest.platformProjectRoot, environment);
    return current;
  }]);
  return withAndroidManifest(config, (current) => {
    const application = AndroidConfig.Manifest.getMainApplicationOrThrow(
      current.modResults,
    );
    if (provisioned) {
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        ANDROID_PROJECT_ID,
        projectID,
      );
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        ANDROID_BROKER_KEY,
        brokerPublicKeyHex,
      );
    } else {
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(
        application,
        ANDROID_PROJECT_ID,
      );
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(
        application,
        ANDROID_BROKER_KEY,
      );
    }
    if (securityFrame) {
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(
        application,
        ANDROID_SECURITY_CONFIG,
        securityFrame,
      );
    } else {
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(
        application,
        ANDROID_SECURITY_CONFIG,
      );
    }
    if (counterFrame) AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, 'app.morse.mesh.NETWORK_COUNTER_CONFIG', counterFrame);
    else AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, 'app.morse.mesh.NETWORK_COUNTER_CONFIG');
    if (purpose) {
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, ANDROID_CREDIT_PURPOSE, purpose);
    } else {
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, ANDROID_CREDIT_PURPOSE);
    }
    if (lightningNetwork) AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, ANDROID_LIGHTNING_NETWORK, lightningNetwork);
    else AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, ANDROID_LIGHTNING_NETWORK);
    if (walletMint) {
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, ANDROID_CREDIT_MINT, walletMint);
    } else {
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, ANDROID_CREDIT_MINT);
    }
    if (ohttpFrame !== undefined) AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, 'app.morse.mesh.OHTTP_CONFIG', ohttpFrame);
    else AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, 'app.morse.mesh.OHTTP_CONFIG');
    if (networkFrame) {
      AndroidConfig.Manifest.addMetaDataItemToMainApplication(application, ANDROID_NETWORK_CONFIG, networkFrame);
    } else {
      AndroidConfig.Manifest.removeMetaDataItemFromMainApplication(application, ANDROID_NETWORK_CONFIG);
    }
    return current;
  });
};
