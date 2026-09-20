module.exports = {
  // Hash the sources, not archives that only exist on the native build worker.
  ignorePaths: ['modules/mesh-messenger/native/**/*'],
  extraSources: [
    {
      type: 'contents',
      id: 'meshNativeBuildPins',
      reasons: ['meshNativeBuildPins'],
      contents: JSON.stringify(Object.fromEntries([
        'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX',
        'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX',
        'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
        'MESSENGER_DELIVERY_PUBLIC_KEY_HEX',
        'MESSENGER_ABUSE_DIFFICULTY',
        'MESSENGER_EXPO_PROJECT_ID',
        'MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX',
      ].map((name) => [name, process.env[name] ?? null]))),
    },
    ...['modules/mesh-messenger', '../../packages/mobile-core', '../../packages/messenger-protocol'].map(
      (filePath) => ({ type: 'dir', filePath, reasons: ['meshNativeSources'] }),
    ),
    ...['../../mesh-revision', '../../scripts/eas-build-native.sh', '../../scripts/build-mobile-native.sh'].map(
      (filePath) => ({ type: 'file', filePath, reasons: ['meshNativeToolchain'] }),
    ),
  ],
};
