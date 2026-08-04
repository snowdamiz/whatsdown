export default {
  expo: {
    name: 'Whatsdown',
    slug: 'whatsdown',
    version: '0.1.0',
    orientation: 'portrait',
    scheme: 'whatsdown',
    userInterfaceStyle: 'dark',
    ios: {
      supportsTablet: true,
      bundleIdentifier: 'com.snowdamiz.whatsdown',
    },
    android: {
      package: 'com.snowdamiz.whatsdown',
      predictiveBackGestureEnabled: true,
    },
    plugins: [
      [
        'expo-camera',
        {
          cameraPermission: 'Allow Whatsdown to scan a contact QR code.',
        },
      ],
      [
        'expo-notifications',
        {
          defaultChannel: 'encrypted-wakeups',
        },
      ],
      'expo-font',
      './plugins/with-mesh-push-config.cjs',
    ],
  },
};
