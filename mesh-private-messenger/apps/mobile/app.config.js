const projectId = process.env.EXPO_PROJECT_ID ?? 'f41ebb5b-47f4-4c55-8f02-aab6bfeb96a8';
const updateCertificate = process.env.MORSE_OTA_CERTIFICATE ?? './certs/certificate.pem';

export default {
  expo: {
    name: 'Morse',
    slug: 'morse',
    owner: '120356aa-user',
    version: '0.1.0',
    orientation: 'portrait',
    scheme: 'morse',
    icon: './assets/icon.png',
    userInterfaceStyle: 'automatic',
    runtimeVersion: { policy: 'fingerprint' },
    updates: {
      enabled: Boolean(projectId && updateCertificate),
      ...(projectId && { url: `https://u.expo.dev/${projectId}` }),
      ...(updateCertificate && {
        codeSigningCertificate: updateCertificate,
        codeSigningMetadata: { keyid: 'morse-ota-v1', alg: 'rsa-v1_5-sha256' },
      }),
    },
    extra: {
      eas: { projectId },
    },
    ios: {
      supportsTablet: true,
      bundleIdentifier: 'io.morseapp',
      icon: {
        light: './assets/icon.png',
        dark: './assets/icon-dark.png',
        tinted: './assets/icon-tinted.png',
      },
    },
    android: {
      package: 'com.snowdamiz.morse',
      predictiveBackGestureEnabled: true,
      adaptiveIcon: {
        foregroundImage: './assets/adaptive-icon.png',
        backgroundImage: './assets/adaptive-icon-background.png',
        monochromeImage: './assets/adaptive-icon.png',
      },
    },
    plugins: [
      ['expo-splash-screen', {
        backgroundColor: '#FFFFFF',
        image: './assets/splash.png',
        imageWidth: 200,
        resizeMode: 'contain',
        dark: { backgroundColor: '#0A0A0C', image: './assets/splash.png' },
      }],
      [
        'expo-camera',
        {
          cameraPermission: 'Allow Morse to scan a contact QR code.',
          microphonePermission: false,
          recordAudioAndroid: false,
        },
      ],
      [
        'expo-notifications',
        {
          defaultChannel: 'encrypted-wakeups',
          enableBackgroundRemoteNotifications: true,
        },
      ],
      ['expo-image-picker', { photosPermission: 'Choose a profile or group photo.', cameraPermission: 'Allow Morse to scan a contact QR code.', microphonePermission: false }],
      'expo-font',
      './plugins/with-mesh-push-config.cjs',
      './plugins/with-data-protection.cjs',
    ],
  },
};
