const {
  AndroidConfig,
  withAndroidManifest,
  withInfoPlist,
} = require('@expo/config-plugins');

const IOS_PROJECT_ID = 'MeshMessengerExpoProjectID';
const IOS_BROKER_KEY = 'MeshMessengerPushBrokerPublicKeyHex';
const IOS_SECURITY_CONFIG = 'MeshMessengerSecurityConfig';
const ANDROID_PROJECT_ID = 'app.morse.mesh.EXPO_PROJECT_ID';
const ANDROID_BROKER_KEY = 'app.morse.mesh.PUSH_BROKER_PUBLIC_KEY_HEX';
const ANDROID_SECURITY_CONFIG = 'app.morse.mesh.SECURITY_CONFIG';
const securityConfig = require('./security-config.cjs');

module.exports = function withMeshPushConfig(config, environment = process.env) {
  const projectID = environment.MESSENGER_EXPO_PROJECT_ID;
  const brokerPublicKeyHex = environment.MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX;
  const provisioned = projectID !== undefined || brokerPublicKeyHex !== undefined;
  const securityFrame = securityConfig(environment);
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
    return current;
  });
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
    return current;
  });
};
