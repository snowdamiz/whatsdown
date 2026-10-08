module.exports = {
  // Hash the sources, not archives that only exist on the native build worker.
  ignorePaths: ['modules/mesh-messenger/native/**/*'],
  extraSources: [
    {
      type: 'contents',
      id: 'meshNativeBuildPins',
      reasons: ['meshNativeBuildPins'],
      contents: JSON.stringify(Object.fromEntries([
        // Every variable that feeds the native security config frame.
        ...require('./plugins/security-config.cjs').variables,
        'MESSENGER_EXPO_PROJECT_ID',
        'MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX',
        // The Mesh commit the native core is compiled with (eas-build-native.sh).
        'MESH_LANG_REVISION',
      ].map((name) => [name, process.env[name] ?? null]))),
    },
    ...['modules/mesh-messenger', '../../packages/mobile-core', '../../packages/messenger-protocol', '../../packages/messenger-credits',
      '../../packages/messenger-ohttp'].map(
      (filePath) => ({ type: 'dir', filePath, reasons: ['meshNativeSources'] }),
    ),
    // The wallet core's sources and pins, not its target/ build output.
    ...['../../packages/wallet-core/src', '../../packages/wallet-core/include'].map(
      (filePath) => ({ type: 'dir', filePath, reasons: ['walletNativeSources'] }),
    ),
    ...['../../packages/wallet-core/Cargo.toml', '../../packages/wallet-core/Cargo.lock'].map(
      (filePath) => ({ type: 'file', filePath, reasons: ['walletNativeSources'] }),
    ),
    ...['../../scripts/eas-build-native.sh', '../../scripts/build-mobile-native.sh'].map(
      (filePath) => ({ type: 'file', filePath, reasons: ['meshNativeToolchain'] }),
    ),
  ],
};
