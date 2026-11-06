require 'xcodeproj'
require 'pathname'
proof = File.realpath(__dir__)
product = File.realpath(File.join(proof, '../../../../../..'))
work = ENV.fetch('MORSE_WALLET_IOS_PROOF_DIR')
archive = ENV.fetch('MORSE_WALLET_IOS_ARCHIVE', File.join(product, 'packages/wallet-core/target/aarch64-apple-ios-sim/debug/libmorse_wallet_core.a'))
project = Xcodeproj::Project.new(File.join(work, 'WalletProof.xcodeproj'))
app = project.new_target(:application, 'WalletProof', :ios, '16.4')
test = project.new_target(:ui_test_bundle, 'WalletProofUITests', :ios, '16.4')
app.add_file_references([project.main_group.new_file(File.join(proof, 'ios.m'))])
test.add_file_references([project.main_group.new_file(File.join(proof, 'WalletProofUITests.swift'))])
test.add_dependency(app)
app.build_configurations.each do |config|
  config.build_settings.merge!({
    'PRODUCT_BUNDLE_IDENTIFIER' => 'app.morse.wallet.disposable-ios-proof',
    'ENABLE_DEBUG_DYLIB' => 'NO',
    'INFOPLIST_FILE' => File.join(work, 'WalletProof.app/Info.plist'),
    'HEADER_SEARCH_PATHS' => File.join(product, 'packages/wallet-core/include'),
    'CLANG_ENABLE_OBJC_ARC' => 'YES',
    'CLANG_ENABLE_MODULES' => 'YES',
    'TARGETED_DEVICE_FAMILY' => '1,2',
    'OTHER_LDFLAGS' => [archive, '-framework', 'Security', '-framework', 'UIKit', '-framework', 'Foundation', '-sectcreate', '__TEXT', '__entitlements', File.join(work, 'entitlements.plist')]
  })
end
test.build_configurations.each do |config|
  config.build_settings.merge!({
    'PRODUCT_BUNDLE_IDENTIFIER' => 'app.morse.wallet.disposable-ios-proof-uitests',
    'GENERATE_INFOPLIST_FILE' => 'YES',
    'TEST_TARGET_NAME' => 'WalletProof',
    'SWIFT_VERSION' => '5.0'
  })
end
project.save
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(app)
scheme.add_test_target(test)
scheme.set_launch_target(app)
scheme.save_as(project.path, 'WalletProof')
