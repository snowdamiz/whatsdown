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
    service: String,
}

// The Box keeps the callback context at a stable address for the library's lifetime.
pub struct Mesh {
    library: Library,
    _host: Box<Host>,
}

impl Mesh {
    pub fn load(path: &Path, config: String, service: String) -> Result<Self, String> {
        // SAFETY: only the bundled library, built from our pinned Mesh toolchain, is loaded.
        unsafe {
            let library = Library::new(path).map_err(|e| e.to_string())?;
            let init = library
                .get::<unsafe extern "C" fn() -> i32>(b"mesh_library_init")
                .map_err(|e| e.to_string())?;
            if init() != 0 {
                return Err("mesh_initialization_failed".into());
            }
            let mut context = Box::new(Host { config, service });
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
            } else if response.data.is_null() || response.len > super::request::MAX_REQUEST as u64 {
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
            if input != b"messenger/config/v1" {
                return 2;
            }
            let config = &host.config;
            if config.is_empty() {
                return 2;
            }
            Ok(config.as_bytes().to_vec())
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
    use super::*;
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
        let extension = if cfg!(windows) { "dll" } else { "dylib" };
        let library = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("native/libmessenger_mobile.{extension}"));
        let service = format!("io.morseapp.desktop.tests.{}.core", std::process::id());
        let mesh = Mesh::load(&library, String::new(), service.clone()).unwrap();
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
}
