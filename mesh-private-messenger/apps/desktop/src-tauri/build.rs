fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // The unchanged shared wallet host remains linked for existing internal
        // SDK compatibility. Protected macOS receiving handlers call only the
        // separate captured desktop host below.
        let source = "../../mobile/modules/mesh-messenger/apple/MorseWalletApple.m";
        cc::Build::new().file(source).include("../../../packages/wallet-core/include")
            .flag("-fobjc-arc").flag("-fmodules").compile("morse_wallet_apple");
        println!("cargo:rerun-if-changed={source}");
        println!("cargo:rerun-if-changed=../../mobile/modules/mesh-messenger/apple/MorseWalletApple.h");
        println!(
            "cargo:rerun-if-changed=../../../packages/wallet-core/include/morse_wallet_core.h"
        );
        for framework in ["Foundation", "Security", "AppKit"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
        let native = "src/desktop_lock/native";
        let mut lock = cc::Build::new();
        lock.include(native).include("../../../packages/wallet-core/include").flag("-fobjc-arc").flag("-fblocks").flag("-fmodules");
        for name in ["Policy", "Storage", "ProcessOwner", "PolicyBridge", "Protection", "ProtectionBridge", "LegacyStorage", "PrivatePreview", "NativeFilePanels", "FilePanelBridge", "AvatarCodec", "NativeNotifications", "NativeNotificationsBridge", "NativeNoticeBroker", "NativeNoticeBrokerBridge", "IncomingFiles", "Wallet"] {
            let source = format!("{native}/{name}.m");
            println!("cargo:rerun-if-changed={source}"); lock.file(source);
        }
        if std::env::var_os("CARGO_FEATURE_NATIVE_BOUNDARY_TESTS").is_some() {
            lock.define("MD_NATIVE_TEST_PORTS", "1").file("src/desktop_lock/tests/policy_fixture.m");
            println!("cargo:rerun-if-changed=src/desktop_lock/tests/policy_fixture.m");
        }
        lock.compile("morse_desktop_app_lock");
        let intents=format!("{native}/NativeNoticeIntents.c");
        println!("cargo:rerun-if-changed={intents}");
        cc::Build::new().file(intents).include(native).flag("-std=c11").compile("morse_desktop_notice_intents");
        for name in ["Policy", "PolicyPorts", "ProcessOwner", "PolicyBridge", "Protection", "ProtectionBridge", "LegacyStorage", "PrivatePreview", "NativeFilePanels", "FilePanelBridge", "AvatarCodec", "NativeNoticeReceipt", "NativeNotifications", "NativeNotificationsBridge", "NativeNoticeBroker", "NativeNoticeBrokerBridge", "NativeNoticeIntents", "IncomingFiles", "PrivateJob", "Wallet"] {
            println!("cargo:rerun-if-changed={native}/{name}.h");
        }
        println!("cargo:rerun-if-changed={native}/ProcessOwnerRetirementLink.h");
        println!("cargo:rerun-if-changed={native}/ProcessOwnerRetirementLink.inc");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=WebKit");
        println!("cargo:rustc-link-lib=framework=UniformTypeIdentifiers");
        println!("cargo:rustc-link-lib=framework=ImageIO");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=UserNotifications");
    }
    tauri_build::build();
}
