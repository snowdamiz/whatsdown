use libloading::Library;
use std::{ffi::c_void, path::Path, ptr, slice};
use zeroize::Zeroizing;

#[repr(C)]
struct Bytes {
    data: *mut u8,
    len: u64,
}
type Export = unsafe extern "C" fn(*const u8, u64, *mut Bytes) -> i32;
type Callback = unsafe extern "C" fn(*mut c_void, *const u8, u64, *mut u8, u64, *mut u64) -> i32;
#[repr(C)]
struct Callbacks {
    abi_version: u32,
    struct_size: u32,
    context: *mut c_void,
    callbacks: [Option<Callback>; 9],
}

struct Host {
    config: String,
    counter_config: String,
    network_config: String,
    ohttp_config: String,
    credit_purpose: String,
    credit_mint: String,
    lightning_network: String,
    issuer_tls_root: String,
    rpc_tls_roots: super::resources::RpcTlsRoots,
    service: String,
}

// The Box keeps the callback context at a stable address for the library's lifetime.
pub struct Mesh {
    library: Library,
    _host: Box<Host>,
}

impl Mesh {
    pub fn load(
        path: &Path,
        config: String,
        counter_config: String,
        network_config: String,
        ohttp_config: String,
        credit_purpose: String,
        credit_mint: String,
        lightning_network: String,
        issuer_tls_root: String,
        rpc_tls_roots: super::resources::RpcTlsRoots,
        service: String,
    ) -> Result<Self, String> {
        // SAFETY: only the bundled library, built from our pinned Mesh toolchain, is loaded.
        unsafe {
            let library = Library::new(path).map_err(|e| e.to_string())?;
            let init = library
                .get::<unsafe extern "C" fn() -> i32>(b"mesh_library_init")
                .map_err(|e| e.to_string())?;
            if init() != 0 {
                return Err("mesh_initialization_failed".into());
            }
            let mut context = Box::new(Host {
                config,
                counter_config,
                network_config,
                ohttp_config,
                credit_purpose,
                credit_mint,
                lightning_network,
                issuer_tls_root,
                rpc_tls_roots,
                service,
            });
            let callbacks = Callbacks {
                abi_version: 1,
                struct_size: size_of::<Callbacks>() as u32,
                context: (&mut *context as *mut Host).cast(),
                callbacks: [
                    Some(host::<1>),
                    Some(host::<2>),
                    Some(host::<3>),
                    Some(host::<4>),
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            };
            let mesh = Self {
                library,
                _host: context,
            };
            let register = mesh
                .library
                .get::<unsafe extern "C" fn(*const Callbacks) -> i32>(
                    b"mesh_library_register_host_callbacks",
                )
                .map_err(|e| e.to_string())?;
            if register(&callbacks) != 0 {
                return Err("mesh_callback_registration_failed".into());
            }
            // Fail on an ABI mismatch at startup, rather than during a later user action.
            for line in include_str!(
                "../../../mobile/modules/mesh-messenger/generated/libmessenger_mobile.h"
            )
            .lines()
            {
                if let Some(declaration) = line.strip_prefix("int32_t mesh_messenger_") {
                    let name = format!(
                        "mesh_messenger_{}",
                        declaration.split('(').next().ok_or("invalid_abi")?
                    );
                    mesh.library
                        .get::<Export>(name.as_bytes())
                        .map_err(|e| e.to_string())?;
                }
            }
            Ok(mesh)
        }
    }

    pub fn invoke(&self, symbol: &str, request: &[u8], database: &str) -> Result<Vec<u8>, String> {
        super::request::validate(symbol, request, database.as_bytes())?;
        // SAFETY: the allowlist above and the C header define the signatures and owned response.
        // Calls run under the app's one native mutex; response memory is always returned to Mesh.
        unsafe {
            let invoke = self
                .library
                .get::<Export>(symbol.as_bytes())
                .map_err(|e| e.to_string())?;
            let free = self
                .library
                .get::<unsafe extern "C" fn(*mut Bytes)>(b"mesh_library_free_returned_bytes")
                .map_err(|e| e.to_string())?;
            let mut response = Bytes {
                data: ptr::null_mut(),
                len: 0,
            };
            let status = invoke(request.as_ptr(), request.len() as u64, &mut response);
            let bytes = if response.len == 0 {
                Vec::new()
            } else if response.data.is_null()
                || response.len > super::request::maximum_response(symbol) as u64
            {
                free(&mut response);
                return Err("invalid_native_response".into());
            } else {
                slice::from_raw_parts(response.data, response.len as usize).to_vec()
            };
            free(&mut response);
            if status == 0 {
                Ok(bytes)
            } else {
                Err(format!(
                    "Mesh {status}: {}",
                    String::from_utf8_lossy(&bytes)
                ))
            }
        }
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        // SAFETY: shutdown is called before the library and callback context are dropped.
        unsafe {
            if let Ok(shutdown) = self
                .library
                .get::<unsafe extern "C" fn() -> i32>(b"mesh_library_shutdown")
            {
                shutdown();
            }
        }
    }
}

fn issuer_tls_resource(encoded: &str) -> Result<Vec<u8>, ()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    if encoded.is_empty() {
        return Ok(vec![1, 0, 0, 0, 0, 0, 0]);
    }
    if encoded.len() > 90124 {
        return Err(());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| ())?;
    if !(7..=67591).contains(&bytes.len()) || STANDARD.encode(&bytes) != encoded {
        return Err(());
    }
    Ok(bytes)
}

unsafe extern "C" fn host<const OP: u8>(
    context: *mut c_void,
    input: *const u8,
    len: u64,
    output: *mut u8,
    capacity: u64,
    written: *mut u64,
) -> i32 {
    // SAFETY: Mesh owns all buffers for the duration of this callback. Never unwind across C.
    if context.is_null() || input.is_null() || written.is_null() || len > 65_536 {
        return 1;
    }
    unsafe {
        *written = 0;
    }
    std::panic::catch_unwind(|| {
        let input = unsafe { slice::from_raw_parts(input, len as usize) };
        let host = unsafe { &*context.cast::<Host>() };
        let result = if OP == 4 {
            if input == b"messenger/rpc-tls-roots/v1" {
                host.rpc_tls_roots.bytes().map(<[u8]>::to_vec)
            } else if input == b"messenger/issuer-tls-root/v1" {
                match issuer_tls_resource(&host.issuer_tls_root) {
                    Ok(bytes) => Ok(bytes),
                    Err(_) => return 3,
                }
            } else if input == b"messenger/ohttp/v1" {
                if host.ohttp_config.is_empty() {
                    return 2;
                }
                if host.ohttp_config.len() > 600 {
                    return 1;
                }
                Ok(host.ohttp_config.as_bytes().to_vec())
            } else if input == b"messenger/network/v1" {
                if host.network_config.is_empty() {
                    return 2;
                }
                Ok(host.network_config.as_bytes().to_vec())
            } else if input == b"messenger/wallet/v1" {
                match super::wallet::pins(&host.credit_purpose, &host.credit_mint) {
                    Ok(frame) => Ok(frame.to_vec()),
                    Err(_) => return 2,
                }
            } else if input == b"messenger/lightning/v1" {
                match host.lightning_network.as_str() {
                    "mainnet" => Ok(vec![1, 0]),
                    "testnet" => Ok(vec![1, 1]),
                    "regtest" => Ok(vec![1, 2]),
                    "signet" => Ok(vec![1, 3]),
                    "simnet" => Ok(vec![1, 4]),
                    _ => return 2,
                }
            } else if input == b"messenger/network-counter/v1" {
                if host.counter_config.is_empty() {
                    return 2;
                }
                if host.counter_config.len() > 24576 {
                    return 1;
                }
                Ok(host.counter_config.as_bytes().to_vec())
            } else if input == b"messenger/credits/v1" {
                match host.credit_purpose.as_str() {
                    "live" => Ok(vec![1, 0]),
                    "test" => Ok(vec![1, 1]),
                    _ => return 2,
                }
            } else {
                if input != b"messenger/config/v1" {
                    return 2;
                }
                let config = &host.config;
                if config.is_empty() {
                    return 2;
                }
                Ok(config.as_bytes().to_vec())
            }
        } else {
            secure_store(&host.service, OP, input)
        };
        match result {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                if bytes.len() as u64 > capacity || (!bytes.is_empty() && output.is_null()) {
                    return 4;
                }
                unsafe {
                    if !bytes.is_empty() {
                        ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
                    }
                    *written = bytes.len() as u64;
                }
                0
            }
            Err(code) => code,
        }
    })
    .unwrap_or(3)
}

fn secure_store(service: &str, operation: u8, input: &[u8]) -> Result<Vec<u8>, i32> {
    let (key, value) = if operation == 1 {
        let length =
            u32::from_be_bytes(input.get(..4).ok_or(1)?.try_into().map_err(|_| 1)?) as usize;
        (
            input.get(4..4 + length).ok_or(1)?,
            input.get(4 + length..).ok_or(1)?,
        )
    } else {
        (input, &[][..])
    };
    if key.is_empty() || key.len() > 4096 || (operation == 1 && value.is_empty()) {
        return Err(1);
    }
    let name: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    let entry = keyring::Entry::new(service, &name).map_err(|_| 3)?;
    match operation {
        1 => entry.set_secret(value).map(|()| Vec::new()),
        2 => entry.get_secret(),
        3 => match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(error) => Err(error),
        },
        _ => return Err(1),
    }
    .map_err(|error| {
        if matches!(error, keyring::Error::NoEntry) {
            2
        } else {
            3
        }
    })
}

#[cfg(test)]
mod tests {
    fn read_rpc_tls(
        roots: super::super::resources::RpcTlsRoots,
        selector: &[u8],
        capacity: usize,
        null_output: bool,
    ) -> (i32, u64, Vec<u8>) {
        let mut context = super::Host {
            config: "security must not substitute".into(),
            counter_config: String::new(),
            network_config: String::new(),
            ohttp_config: String::new(),
            credit_purpose: String::new(),
            credit_mint: String::new(),
            lightning_network: String::new(),
            issuer_tls_root: String::new(),
            rpc_tls_roots: roots,
            service: "unused-rpc-tls-callback-test".into(),
        };
        let mut output = vec![0xcc; 82_003];
        let mut written = 99;
        let status = unsafe {
            super::host::<4>(
                (&mut context as *mut super::Host).cast(),
                selector.as_ptr(), selector.len() as u64,
                if null_output { std::ptr::null_mut() } else { output.as_mut_ptr() },
                capacity as u64, &mut written,
            )
        };
        (status, written, output)
    }

    fn rpc_tls_config(value: Option<serde_json::Value>) -> super::super::resources::RpcTlsRoots {
        let mut config = serde_json::json!({ "securityFrame": "native security", "development": true });
        if let Some(value) = value { config["rpcTlsRoots"] = value; }
        serde_json::from_value::<super::super::resources::Config>(config).unwrap().rpc_tls_roots
    }

    #[test]
    fn rpc_tls_selector_returns_the_exact_absence_frame() {
        for roots in [rpc_tls_config(None)] {
            let (status, written, output) = read_rpc_tls(roots, b"messenger/rpc-tls-roots/v1", 2, false);
            assert_eq!((status, written), (0, 2));
            assert_eq!(&output[..2], &[1, 0]);
            assert!(output[2..].iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn rpc_tls_selector_delivers_bounded_opaque_bytes() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        // Only the byte envelope is checked here; frame semantics belong to Mesh.
        for bytes in [vec![0xff, 0], vec![1, 0], vec![0xa5; 82_002]] {
            let encoded = STANDARD.encode(&bytes);
            let roots = rpc_tls_config(Some(serde_json::json!(encoded)));
            let (status, written, output) = read_rpc_tls(roots, b"messenger/rpc-tls-roots/v1", bytes.len(), false);
            assert_eq!((status, written), (0, bytes.len() as u64));
            assert_eq!(&output[..bytes.len()], &bytes);
            assert!(output[bytes.len()..].iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn rpc_tls_selector_refuses_wrong_json_types_and_encoding() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let mut invalid = vec![serde_json::Value::Null, serde_json::json!(false),
            serde_json::json!(7), serde_json::json!([]), serde_json::json!({})];
        invalid.extend(["", "!", "AQI", "AQ==", "AQJ=", "AA-_", "====", "AQI=\n", " AQI=", "é"].map(serde_json::Value::from));
        invalid.extend(["A".repeat(109_337), STANDARD.encode(vec![1; 82_003])].map(serde_json::Value::from));
        for value in invalid {
            let roots = rpc_tls_config(Some(value.clone()));
            let (status, written, output) = read_rpc_tls(roots, b"messenger/rpc-tls-roots/v1", 82_002, false);
            assert_eq!((status, written), (3, 0), "{value}");
            assert!(output.iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn rpc_tls_selector_refuses_empty_present_and_failed_reads() {
        use std::io::Read;
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("resource unavailable"))
            }
        }
        for roots in [
            super::super::resources::RpcTlsRoots::read_present(std::io::empty()),
            super::super::resources::RpcTlsRoots::read_present(FailedRead),
            super::super::resources::RpcTlsRoots::read_present(std::io::Cursor::new(b"AQI=").chain(FailedRead)),
        ] {
            let (status, written, output) = read_rpc_tls(roots, b"messenger/rpc-tls-roots/v1", 82_002, false);
            assert_eq!((status, written), (3, 0));
            assert!(output.iter().all(|byte| *byte == 0xcc));
        }
    }

    #[test]
    fn rpc_tls_selector_enforces_output_capacity_and_exact_selector() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        for (bytes, capacity, null_output) in [(vec![1, 0], 1, false),
            (vec![2; 82_002], 82_001, false), (vec![1, 0], 2, true)] {
            let roots = rpc_tls_config(Some(serde_json::json!(STANDARD.encode(bytes))));
            let (status, written, output) = read_rpc_tls(roots, b"messenger/rpc-tls-roots/v1", capacity, null_output);
            assert_eq!((status, written), (4, 0));
            assert!(output.iter().all(|byte| *byte == 0xcc));
        }
        let (status, written, output) = read_rpc_tls(rpc_tls_config(None), b"messenger/rpc-tls-roots/v1/", 2, false);
        assert_eq!((status, written), (2, 0));
        assert!(output.iter().all(|byte| *byte == 0xcc));
    }

    #[test]
    fn ohttp_selector_reads_only_the_bounded_release_resource() {
        fn read(frame: &str, selector: &[u8], capacity: usize) -> (i32, u64, Vec<u8>) {
            let mut context = super::Host {
                config: "legacy config must not substitute".into(),
                counter_config: "counter must not substitute".into(),
                network_config: "network must not substitute".into(),
                ohttp_config: frame.into(),
                credit_purpose: String::new(),
                credit_mint: String::new(),
                lightning_network: String::new(),
                issuer_tls_root: String::new(),
                rpc_tls_roots: Default::default(),
                service: "unused-ohttp-callback-test".into(),
            };
            let mut output = vec![0xcc; 601];
            let mut written = 99;
            let status = unsafe {
                super::host::<4>(
                    (&mut context as *mut super::Host).cast(),
                    selector.as_ptr(),
                    selector.len() as u64,
                    output.as_mut_ptr(),
                    capacity as u64,
                    &mut written,
                )
            };
            (status, written, output)
        }
        let selector = b"messenger/ohttp/v1";
        let frame = format!("1\n{}\n{}\n1\noff\n0", "11".repeat(32), "22".repeat(32));
        let (status, written, output) = read(&frame, selector, frame.len());
        assert_eq!((status, written), (0, frame.len() as u64));
        assert_eq!(&output[..frame.len()], frame.as_bytes());
        assert!(output[frame.len()..].iter().all(|byte| *byte == 0xcc));
        for frame in ["a".repeat(600), "é".repeat(300)] {
            let (status, written, output) = read(&frame, selector, 600);
            assert_eq!((status, written), (0, 600));
            assert_eq!(&output[..600], frame.as_bytes());
        }
        for (frame, selector, capacity, expected) in [
            (String::new(), selector.as_slice(), 600, 2),
            ("a".repeat(601), selector.as_slice(), 601, 1),
            ("é".repeat(301), selector.as_slice(), 601, 1),
            (frame.clone(), selector.as_slice(), frame.len() - 1, 4),
            (frame.clone(), b"messenger/ohttp/v1/", 600, 2),
        ] {
            let (status, written, output) = read(&frame, selector, capacity);
            assert_eq!((status, written), (expected, 0));
            assert!(output.iter().all(|byte| *byte == 0xcc));
        }
    }
    #[test]
    fn issuer_tls_native_resource_is_explicit_and_canonical() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        assert_eq!(
            super::issuer_tls_resource("").unwrap(),
            [1, 0, 0, 0, 0, 0, 0]
        );
        let maximum = vec![7; 67591];
        assert_eq!(
            super::issuer_tls_resource(&STANDARD.encode(&maximum)).unwrap(),
            maximum
        );
        for bad in [
            "bad-base64!".to_owned(),
            STANDARD.encode([1; 6]),
            STANDARD.encode(vec![1; 67592]),
            format!("{}\n", STANDARD.encode([1; 7])),
        ] {
            assert!(super::issuer_tls_resource(&bad).is_err());
        }
    }
    use super::*;
    static NATIVE_CORE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[test]
    fn platform_credentials_round_trip_binary_secrets_and_delete() {
        let service = format!("io.morseapp.desktop.tests.{}", std::process::id());
        let other = format!("{service}.dev");
        let key = format!("desktop-credential-test-{}", std::process::id()).into_bytes();
        let mut frame = (key.len() as u32).to_be_bytes().to_vec();
        frame.extend(&key);
        frame.extend([0, 255, 17, 0, 42]);
        let result = (|| {
            secure_store(&service, 1, &frame)?;
            assert_eq!(secure_store(&other, 2, &key), Err(2));
            let mut other_frame = frame.clone();
            *other_frame.last_mut().unwrap() = 99;
            secure_store(&other, 1, &other_frame)?;
            let value = secure_store(&service, 2, &key)?;
            assert_eq!(value, [0, 255, 17, 0, 42]);
            assert_eq!(secure_store(&other, 2, &key)?, [0, 255, 17, 0, 99]);
            secure_store(&other, 3, &key)?;
            assert_eq!(secure_store(&service, 2, &key)?, value);
            Ok::<(), i32>(())
        })();
        let removed = secure_store(&service, 3, &key);
        let other_removed = secure_store(&other, 3, &key);
        assert_eq!(result, Ok(()));
        assert_eq!(removed, Ok(Vec::new()));
        assert_eq!(other_removed, Ok(Vec::new()));
        assert_eq!(secure_store(&service, 2, &key), Err(2));
    }

    #[test]
    fn bundled_core_opens_storage_and_rejects_invalid_wire() {
        let _serial = NATIVE_CORE_TEST_LOCK.lock().unwrap();
        let extension = if cfg!(windows) { "dll" } else { "dylib" };
        let library = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("native/libmessenger_mobile.{extension}"));
        let service = format!("io.morseapp.desktop.tests.{}.core", std::process::id());
        let mesh = Mesh::load(
            &library,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Default::default(),
            service.clone(),
        )
        .unwrap();
        let directory =
            std::env::temp_dir().join(format!("morse-native-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let database = directory.join("morse.db").to_string_lossy().into_owned();
        assert_eq!(
            mesh.invoke("mesh_messenger_initialize", database.as_bytes(), &database)
                .unwrap(),
            b"mesh-messenger-mobile-v1"
        );
        assert!(mesh
            .invoke("mesh_messenger_validate_outer", b"invalid", &database)
            .is_err());
        assert!(mesh
            .invoke(
                "mesh_messenger_load_profile",
                database.as_bytes(),
                &database
            )
            .is_err());
        drop(mesh);
        for key in [b"mesh/storage-key/v2".as_slice()] {
            assert!(secure_store(&service, 2, key).is_ok());
            assert_eq!(secure_store(&service, 3, key), Ok(Vec::new()));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bundled_mailbox_authenticates_to_owned_peer_and_fences_sessions() {
        use std::{net::TcpListener, process::Command, thread, time::Duration};
        // The bundled runtime intentionally initializes once per process. Keep
        // this real scheduler/network proof separate from the storage test.
        if std::env::var("MORSE_DESKTOP_MAILBOX_CHILD").as_deref() != Ok("1") {
            let proof = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mesh::tests::bundled_mailbox_authenticates_to_owned_peer_and_fences_sessions",
                    "--nocapture",
                ])
                .env("MORSE_DESKTOP_MAILBOX_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                proof.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&proof.stdout),
                String::from_utf8_lossy(&proof.stderr)
            );
            return;
        }
        let _serial = NATIVE_CORE_TEST_LOCK.lock().unwrap();
        let product = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let directory =
            std::env::temp_dir().join(format!("morse-mailbox-desktop-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let service = format!("io.morseapp.desktop.tests.{}.mailbox", std::process::id());
        struct Cleanup(std::path::PathBuf, String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = secure_store(&self.1, 3, b"mesh/storage-key/v2");
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone(), service.clone());
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let frame = format!("1\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:{port}/v1/mailbox/stream");
        let mesh = Mesh::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("native/libmessenger_mobile.dylib"),
            String::new(),
            String::new(),
            frame,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            Default::default(),
            service,
        )
        .unwrap();
        let database = directory.join("mailbox.db").to_string_lossy().into_owned();
        let db = database.as_bytes();
        let vector = |value: &[u8]| {
            let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
            bytes.extend(value);
            bytes
        };
        let packet = |ticket: &[u8]| {
            let mut bytes = 2u32.to_be_bytes().to_vec();
            bytes.extend(vector(db));
            bytes.extend(vector(ticket));
            bytes
        };
        let mut account = vector(db);
        account.extend(vector(b"alice"));
        mesh.invoke("mesh_messenger_create_account", &account, &database)
            .unwrap();
        let entry = mesh
            .invoke("mesh_messenger_directory_entry", db, &database)
            .unwrap();
        std::fs::write(
            directory.join("entry.hex"),
            entry
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let keys = Command::new("node")
            .arg(product.join("scripts/mailbox-proof-keys.mjs"))
            .arg(directory.join("entry.hex"))
            .arg(directory.join("keys.json"))
            .arg(port.to_string())
            .output()
            .unwrap();
        assert!(
            keys.status.success(),
            "{}",
            String::from_utf8_lossy(&keys.stderr)
        );
        struct Peer(std::process::Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut peer = Peer(
            Command::new("node")
                .arg(product.join("scripts/mailbox-proof-peer.mjs"))
                .arg(directory.join("keys.json"))
                .arg(directory.join("ready"))
                .arg(directory.join("peer.json"))
                .spawn()
                .unwrap(),
        );
        for _ in 0..100 {
            if directory.join("ready").exists() {
                break;
            }
            assert!(peer.0.try_wait().unwrap().is_none(), "owned peer exited");
            thread::sleep(Duration::from_millis(20));
        }
        assert!(directory.join("ready").exists());
        let first = mesh
            .invoke("mesh_messenger_mailbox_stream_open", db, &database)
            .unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(
            mesh.invoke(
                "mesh_messenger_mailbox_stream_poll",
                &packet(&first),
                &database
            )
            .unwrap(),
            b"ready"
        );
        assert_eq!(
            mesh.invoke(
                "mesh_messenger_mailbox_stream_poll",
                &packet(&first),
                &database
            )
            .unwrap(),
            b"encrypted-wakeup"
        );
        let second = mesh
            .invoke("mesh_messenger_mailbox_stream_open", db, &database)
            .unwrap();
        assert_ne!(first, second);
        assert!(mesh
            .invoke(
                "mesh_messenger_mailbox_stream_poll",
                &packet(&first),
                &database
            )
            .is_err());
        let mut trailing = packet(&second);
        trailing.push(1);
        assert!(mesh
            .invoke("mesh_messenger_mailbox_stream_poll", &trailing, &database)
            .is_err());
        let mut other = 2u32.to_be_bytes().to_vec();
        other.extend(vector(b"other.db"));
        other.extend(vector(&second));
        assert!(mesh
            .invoke("mesh_messenger_mailbox_stream_poll", &other, &database)
            .is_err());
        mesh.invoke(
            "mesh_messenger_mailbox_stream_close",
            &packet(&second),
            &database,
        )
        .unwrap();
        assert!(mesh
            .invoke(
                "mesh_messenger_mailbox_stream_poll",
                &packet(&second),
                &database
            )
            .is_err());
        let erased = mesh
            .invoke("mesh_messenger_mailbox_stream_open", db, &database)
            .unwrap();
        mesh.invoke("mesh_messenger_erase_account", db, &database)
            .unwrap();
        assert!(mesh
            .invoke(
                "mesh_messenger_mailbox_stream_poll",
                &packet(&erased),
                &database
            )
            .is_err());
        assert!(Command::new("kill")
            .args(["-TERM", &peer.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        assert!(peer.0.wait().unwrap().success());
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("peer.json")).unwrap()).unwrap();
        assert_eq!(report["accepted"], 3);
        assert_eq!(report["rejected"], 0);
        if let Ok(evidence) = std::env::var("MORSE_MAILBOX_EVIDENCE_DIR") {
            std::fs::create_dir_all(&evidence).unwrap();
            std::fs::write(
                Path::new(&evidence).join("phase6-mailbox-desktop-peer.json"),
                serde_json::to_vec_pretty(&report).unwrap(),
            )
            .unwrap();
        }
    }
}
