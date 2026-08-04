Pod::Spec.new do |s|
  s.name = 'MeshMessenger'
  s.version = '0.1.0'
  s.summary = 'Expo bridge for the compiled Mesh messenger core'
  s.description = 'A narrow binary bridge with native secure-storage adapters.'
  s.author = 'Whatsdown'
  s.homepage = 'https://github.com/snowdamiz/whatsdown'
  s.platforms = { :ios => '16.4' }
  s.source = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.dependency 'ExpoNotifications', '57.0.8'
  s.dependency 'EXApplication', '57.0.2'
  s.frameworks = 'Security', 'CoreFoundation'
  s.libraries = 'm'
  s.vendored_frameworks = 'native/ios/MeshMessengerCore.xcframework'
  s.source_files = 'ios/*.{h,m,swift}', 'generated/*.{h,swift}'
  s.public_header_files = 'ios/MeshMessengerSecureStore.h', 'generated/libmessenger_mobile.h'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
