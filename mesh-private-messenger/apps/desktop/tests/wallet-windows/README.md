# Windows wallet host proof

This crate compiles the production Windows host directly, including Credential
Manager, native confirmation, the kernel mutex, and the purchase orchestration.
The tests check that two threads serialize without a shared app file and that
recovery never signs or bypasses journal identity checks. It requires Windows to
execute; a cross-compiled executable is only compilation and linking evidence.

On Windows, from this directory:

```sh
cargo test
```

On a host with the MinGW linker and Rust Windows target installed:

```sh
cargo test --target x86_64-pc-windows-gnu --no-run
```

The native mutex name includes the authenticated process user SID and the
bundled wallet service. The global namespace serializes the same user across
sessions. App filesystem replacement cannot create a second lock domain.
[Microsoft documents the kernel object namespaces here](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces).

Actual Windows dialog cancellation, Credential Manager persistence, cross-process
reservation, and full app execution still require a Windows machine. This crate
does not establish those gates on macOS or Linux.
