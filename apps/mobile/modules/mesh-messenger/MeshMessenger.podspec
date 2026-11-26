Pod::Spec.new do |s|
  s.name = 'MeshMessenger'
  s.version = '0.1.0'
  s.summary = 'Expo bridge for the compiled Mesh messenger core'
  s.description = 'A narrow binary bridge with native secure-storage adapters.'
  s.author = 'Morse'
  s.homepage = 'https://github.com/snowdamiz/whatsdown'
  s.platforms = { :ios => '16.4' }
  s.source = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.dependency 'ExpoNotifications', '57.0.15'
  s.dependency 'EXApplication', '57.0.2'
  s.frameworks = 'Security', 'CoreFoundation', 'LocalAuthentication'
  s.libraries = 'm'
  # The Mesh core and the wallet core (packages/wallet-core), both built by
  # scripts/build-mobile-native.sh.
  s.vendored_frameworks = 'native/ios/MeshMessengerCore.xcframework', 'native/ios/MorseWalletCore.xcframework'
  s.source_files = 'ios/*.{h,m,swift}', 'generated/*.{h,swift}'
  s.public_header_files = 'ios/MeshMessengerSecureStore.h', 'generated/libmessenger_mobile.h', 'generated/morse_wallet.h'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
