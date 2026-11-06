fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let source = "../../mobile/modules/mesh-messenger/apple/MorseWalletApple.m";
        cc::Build::new()
            .file(source)
            .include("../../../packages/wallet-core/include")
            .flag("-fobjc-arc")
            .flag("-fmodules")
            .compile("morse_wallet_apple");
        println!("cargo:rerun-if-changed={source}");
        println!(
            "cargo:rerun-if-changed=../../mobile/modules/mesh-messenger/apple/MorseWalletApple.h"
        );
        println!(
            "cargo:rerun-if-changed=../../../packages/wallet-core/include/morse_wallet_core.h"
        );
        for framework in ["Foundation", "Security", "AppKit"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
    tauri_build::build();
}
