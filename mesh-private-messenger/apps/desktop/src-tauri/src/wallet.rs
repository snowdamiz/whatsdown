#[cfg(not(windows))]
use std::path::Path;

pub fn pins(purpose: &str, mint: &str) -> Result<[u8; 34], String> {
    let mut output = [0; 34];
    output[0] = 1;
    output[1] = match purpose {
        "live" => 0,
        "test" => 1,
        _ => return Err("wallet_purpose_missing".into()),
    };
    if mint.len() != 64
        || !mint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("wallet_mint_missing".into());
    }
    for (index, pair) in mint.as_bytes().chunks_exact(2).enumerate() {
        fn digit(byte: u8) -> u8 {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        }
        output[2 + index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    if output[2..].iter().all(|byte| *byte == 0) {
        return Err("wallet_mint_invalid".into());
    }
    Ok(output)
}

fn fields(input: &[u8], count: usize, maximum: usize) -> Result<Vec<&[u8]>, String> {
    if input.len() > maximum {
        return Err("invalid_wallet_request".into());
    }
    let mut cursor = 0;
    let mut number = || {
        let bytes = input
            .get(cursor..cursor + 4)
            .ok_or("invalid_wallet_request")?;
        cursor += 4;
        Ok::<_, String>(
            u32::from_be_bytes(bytes.try_into().map_err(|_| "invalid_wallet_request")?) as usize,
        )
    };
    if number()? != count {
        return Err("invalid_wallet_request".into());
    }
    let mut output = Vec::new();
    for _ in 0..count {
        let bytes = input
            .get(cursor..cursor + 4)
            .ok_or("invalid_wallet_request")?;
        let size =
            u32::from_be_bytes(bytes.try_into().map_err(|_| "invalid_wallet_request")?) as usize;
        cursor += 4;
        let end = cursor.checked_add(size).ok_or("invalid_wallet_request")?;
        output.push(input.get(cursor..end).ok_or("invalid_wallet_request")?);
        cursor = end;
    }
    if cursor != input.len() {
        return Err("invalid_wallet_request".into());
    }
    Ok(output)
}
fn counted(values: &[&[u8]]) -> Vec<u8> {
    let mut output = (values.len() as u32).to_be_bytes().to_vec();
    for value in values {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }
    output
}
pub fn journal(input: &[u8], database: &[u8]) -> Result<Vec<u8>, String> {
    let value = fields(input, 2, 8192)?;
    if value[0] != database || value[1].len() != 32 {
        return Err("invalid_wallet_request".into());
    }
    Ok(counted(&value))
}
fn checked_result(input: Vec<u8>, id: &[u8]) -> Result<Vec<u8>, String> {
    let value = fields(&input, 4, 2048)?;
    if value[0] != b"\x01MWR"
        || value[1] != id
        || value[2].len() != 1
        || value[2][0] > 1
        || value[3].len() != 64
    {
        return Err("invalid_wallet_response".into());
    }
    Ok(input)
}
pub fn network_payment(
    operation: u32,
    input: &[u8],
    database: &[u8],
    mut mesh: impl FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    mut sdk: impl FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let request = journal(input, database)?;
    let original = fields(&request, 2, 8192)?;
    let id = original[1];
    if operation == 5 {
        let payer = sdk(2, &[])?;
        if payer.len() != 32 {
            return Err("invalid_wallet_address".into());
        }
        let response = mesh(
            "mesh_messenger_credit_wallet_prepare",
            &counted(&[database, id, &payer]),
        )?;
        let plan = fields(&response, 6, 2048)?;
        if plan[0] != b"\x01MWP"
            || plan[1] != id
            || plan[2].len() != 1
            || plan[2][0] > 1
            || plan[3].len() != 224
            || plan[4].len() != 32
            || (plan[2][0] == 0 && !plan[5].is_empty())
            || (plan[2][0] == 1 && plan[5].len() != 64)
        {
            return Err("invalid_wallet_response".into());
        }
        if plan[2][0] == 0 {
            let payload = [plan[3], plan[4]].concat();
            let wire = sdk(3, &payload)?;
            if !(64..=1232).contains(&wire.len()) {
                return Err("invalid_wallet_packet".into());
            }
            checked_result(
                mesh(
                    "mesh_messenger_credit_wallet_commit",
                    &counted(&[database, id, &wire]),
                )?,
                id,
            )?;
        }
    } else if operation != 6 {
        return Err("invalid_wallet_request".into());
    }
    checked_result(mesh("mesh_messenger_credit_wallet_submit", &request)?, id)
}

fn valid_payment_url(url: &str) -> bool {
    if url.chars().any(char::is_control) {
        return false;
    }
    if let Some(invoice) = url.strip_prefix("lightning:") {
        return (1..=7089).contains(&invoice.len())
            && invoice.to_ascii_lowercase().starts_with("ln")
            && invoice.bytes().all(|byte| byte.is_ascii_alphanumeric());
    }
    url.starts_with("solana:") && url.len() <= 4096
}

pub fn open_payment_url(url: &str) -> Result<(), String> {
    if !valid_payment_url(url) {
        return Err("invalid_payment_url".into());
    }
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("/usr/bin/open")
            .arg(url)
            .status()
            .map_err(|_| "external_wallet_unavailable")?
            .success()
            .then_some(())
            .ok_or("external_wallet_unavailable".into());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        let operation: Vec<u16> = "open\0".encode_utf16().collect();
        let address: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
        let status = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                address.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        return if status as isize > 32 {
            Ok(())
        } else {
            Err("external_wallet_unavailable".into())
        };
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    Err("external_wallet_unavailable".into())
}

pub fn payload(operation: u32, input: &[u8]) -> Result<Vec<u8>, String> {
    if matches!(operation, 1 | 2) && input.is_empty() {
        Ok(Vec::new())
    } else {
        Err("invalid_wallet_request".into())
    }
}

#[cfg(target_os = "macos")]
pub fn invoke(
    service: &str,
    directory: &Path,
    pins: &[u8; 34],
    _parent: isize,
    operation: u32,
    input: &[u8],
) -> Result<Vec<u8>, String> {
    use std::ffi::{c_char, CString};
    unsafe extern "C" {
        fn MorseWalletAppleCall(
            service: *const c_char,
            directory: *const c_char,
            pins: *const u8,
            operation: u32,
            input: *const u8,
            input_length: u64,
            output: *mut u8,
            capacity: u64,
            written: *mut u64,
        ) -> i32;
    }
    // Force the SDK entry point into the link alongside the native host shim.
    std::hint::black_box(morse_wallet_core::morse_wallet_call as *const () as usize);
    let service = CString::new(service).map_err(|_| "invalid_wallet_service")?;
    let directory = CString::new(directory.to_str().ok_or("invalid_wallet_directory")?)
        .map_err(|_| "invalid_wallet_directory")?;
    let mut output = vec![0; 1232];
    let mut written = 0;
    let status = unsafe {
        MorseWalletAppleCall(
            service.as_ptr(),
            directory.as_ptr(),
            pins.as_ptr(),
            operation,
            input.as_ptr(),
            input.len() as u64,
            output.as_mut_ptr(),
            output.len() as u64,
            &mut written,
        )
    };
    if status != 0 || written > 1232 {
        return Err(format!("wallet_status_{status}"));
    }
    output.truncate(written as usize);
    Ok(output)
}

#[cfg(windows)]
#[path = "wallet_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::invoke;

#[cfg(not(any(target_os = "macos", windows)))]
pub fn invoke(
    _service: &str,
    _directory: &Path,
    _pins: &[u8; 34],
    _parent: isize,
    _operation: u32,
    _input: &[u8],
) -> Result<Vec<u8>, String> {
    Err("wallet_unsupported_target".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(fields: &[&[u8]]) -> Vec<u8> {
        let mut output = (fields.len() as u32).to_be_bytes().to_vec();
        for field in fields {
            output.extend_from_slice(&(field.len() as u32).to_be_bytes());
            output.extend_from_slice(field);
        }
        output
    }
    #[test]
    fn public_wallet_operations_cannot_supply_a_quote_or_blockhash() {
        assert!(payload(3, &[5; 256]).is_err());
        assert!(payload(4, &[]).is_err());
        assert!(payload(1, &[1]).is_err());
        for operation in [1, 2] {
            assert_eq!(payload(operation, &[]).unwrap(), Vec::<u8>::new());
        }
    }
    #[test]
    fn wallet_requires_bundled_nonzero_mint_and_explicit_purpose() {
        assert!(pins("", &"07".repeat(32)).is_err());
        assert!(pins("test", "").is_err());
        assert!(pins("live", &"00".repeat(32)).is_err());
        assert!(pins("test", &"AF".repeat(32)).is_err());
        let value = pins("test", &"07".repeat(32)).unwrap();
        assert_eq!(&value[..2], &[1, 1]);
        assert_eq!(&value[2..], &[7; 32]);
    }
    #[test]
    fn external_wallet_accepts_only_bounded_payment_schemes() {
        assert!(valid_payment_url("solana:verified?amount=5.000000"));
        assert!(valid_payment_url("lightning:lnbcrt50u1verified"));
        assert!(valid_payment_url("lightning:LNBC50U1VERIFIED"));
        for value in [
            "https://example.com",
            "lightning:",
            "lightning:lnbc1?callback=https://x",
            "lightning:lnbc1#x",
            "lightning:lnbc1\n",
            "lightning:lnbc💸",
            "file:///tmp/x",
        ] {
            assert!(!valid_payment_url(value));
        }
        assert!(!valid_payment_url(&format!(
            "lightning:ln{}",
            "a".repeat(7088)
        )));
    }
    #[test]
    fn network_payment_recovers_without_signing_and_commits_before_submission() {
        let db = b"/app/morse.db";
        let id = [7; 32];
        let request = packet(&[db, &id]);
        let response = packet(&[b"\x01MWR", &id, &[0], &[8; 64]]);
        let mut steps = Vec::new();
        let result = network_payment(
            5,
            &request,
            db,
            |name, body| {
                steps.push(name.to_owned());
                match name {
                    "mesh_messenger_credit_wallet_prepare" => {
                        assert_eq!(body, packet(&[db, &id, &[12; 32]]));
                        Ok(packet(&[b"\x01MWP", &id, &[0], &[9; 224], &[10; 32], &[]]))
                    }
                    "mesh_messenger_credit_wallet_commit" => {
                        assert_eq!(body, packet(&[db, &id, &[11; 200]]));
                        Ok(response.clone())
                    }
                    "mesh_messenger_credit_wallet_submit" => Ok(response.clone()),
                    _ => panic!("unknown call"),
                }
            },
            |operation, payload| {
                if operation == 2 {
                    assert!(payload.is_empty());
                    return Ok(vec![12; 32]);
                }
                assert_eq!(operation, 3);
                assert_eq!(payload, [&[9; 224][..], &[10; 32][..]].concat());
                Ok(vec![11; 200])
            },
        )
        .unwrap();
        assert_eq!(result, response);
        assert_eq!(
            steps,
            [
                "mesh_messenger_credit_wallet_prepare",
                "mesh_messenger_credit_wallet_commit",
                "mesh_messenger_credit_wallet_submit"
            ]
        );
        let mut calls = 0;
        network_payment(
            6,
            &request,
            db,
            |name, body| {
                assert_eq!(name, "mesh_messenger_credit_wallet_submit");
                assert_eq!(body, request);
                calls += 1;
                Ok(response.clone())
            },
            |_, _| panic!("recovery cannot use SDK"),
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert!(network_payment(
            5,
            &packet(&[b"/other.db", &id]),
            db,
            |_, _| panic!("foreign DB"),
            |_, _| panic!("foreign DB")
        )
        .is_err());
        assert!(network_payment(
            5,
            &request,
            db,
            |_, _| Ok(packet(&[
                b"\x01MWP",
                &[1; 32],
                &[0],
                &[9; 224],
                &[10; 32],
                &[]
            ])),
            |operation, _| {
                assert_eq!(operation, 2);
                Ok(vec![12; 32])
            }
        )
        .is_err());
    }
}
