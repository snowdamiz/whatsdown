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

  s.dependency 'React-RCTAppDelegate'
  s.dependency 'ExpoModulesCore'
  s.dependency 'ExpoNotifications', '58.1.5'
  s.dependency 'ExpoApplication', '58.1.2'
  s.frameworks = 'Security', 'CoreFoundation'
  s.libraries = 'm'
  s.vendored_frameworks = 'native/ios/MeshMessengerCore.xcframework', 'native/ios/MorseWalletCore.xcframework'
  s.source_files = 'ios/*.{h,m,mm,swift}', 'generated/*.{h,swift}', 'apple/*.{h,m}', 'native/include/*.h'
  s.public_header_files = 'ios/MeshMessengerCurrentMount.h', 'ios/MeshMessengerSecureStore.h', 'ios/MeshMessengerWallet.h', 'generated/libmessenger_mobile.h'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'HEADER_SEARCH_PATHS' => '$(inherited) "${PODS_TARGET_SRCROOT}/apple" "${PODS_TARGET_SRCROOT}/native/include"' }
end
