The proof uses the production Apple custody/confirmation host and the actual
custom Rust wallet SDK. It never obtains a blockhash, sends a transaction or
contacts an RPC provider. Test quotes and OS credential namespaces are disposable.

From the product root, `apple/wallet-proof/prove.sh` under this module runs real
macOS Keychain custody checks with 16 peer processes. Set
`MORSE_WALLET_UI_PROOF=1` to also open the native AppKit dialog fixture. Follow
Cancel/Create/Address/Sign, then bring another app forward during the final
confirmation and finish the proof. The final step requires an observed real
application deactivation; clicking Cancel alone does not pass it.

`apple/wallet-proof/ios-prove.sh` runs the reproducible XCTest on the one booted
iOS simulator (or `MORSE_WALLET_IOS_SERIAL`). It checks real native buttons,
exact U64 amount presentation, persistent address, offline SDK signing and
hardware Home cancellation. The fixture requires the actual UIApplication
lifecycle notification; waiting for timeout cannot pass. Xcode's debug dylib is
disabled only in this disposable fixture so simulated Keychain entitlements stay
in its executable. Failed artifacts remain in the printed temporary directory.

Both runners accept an explicit SDK archive override. They exercise platform
custody, confirmation and cancellation; Mesh CSQ admission/journal authentication
has separate mobile-core tests. They do not establish physical-device behavior,
Windows runtime behavior, network submission, funded settlement or release
approval. No feature flag is enabled by the proof.
