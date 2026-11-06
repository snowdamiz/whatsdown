//! Test-only bridge using a published deterministic seed and synthetic native
//! callbacks. Never use its addresses with funds. Production has no seed API.
use morse_wallet_core::{
    morse_wallet_authorization_text, morse_wallet_call, MorseWalletCallbacksV1,
};
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    io::{self, Read},
};
use zeroize::Zeroizing;
struct Host {
    record: Zeroizing<Vec<u8>>,
    locked: bool,
    text: String,
}
unsafe fn host<'a>(p: *mut c_void) -> &'a mut Host {
    unsafe { &mut *p.cast::<Host>() }
}
unsafe extern "C" fn acquire(p: *mut c_void) -> i32 {
    let h = unsafe { host(p) };
    if h.locked {
        return 3;
    }
    h.locked = true;
    0
}
unsafe extern "C" fn release(p: *mut c_void) -> i32 {
    let h = unsafe { host(p) };
    if !h.locked {
        return 3;
    }
    h.locked = false;
    0
}
unsafe extern "C" fn load(p: *mut c_void, out: *mut u8, cap: u64, written: *mut u64) -> i32 {
    let h = unsafe { host(p) };
    if !h.locked || cap < h.record.len() as u64 {
        return 3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(h.record.as_ptr(), out, h.record.len());
        written.write(h.record.len() as u64)
    };
    0
}
unsafe extern "C" fn replace(p: *mut c_void, input: *const u8, len: u64) -> i32 {
    let h = unsafe { host(p) };
    if !h.locked || len != 44 {
        return 3;
    }
    h.record = Zeroizing::new(unsafe { std::slice::from_raw_parts(input, len as usize) }.to_vec());
    0
}
unsafe extern "C" fn authorize(p: *mut c_void, op: u32, input: *const u8, len: u64) -> i32 {
    let h = unsafe { host(p) };
    if h.locked {
        return 3;
    }
    let mut text = [0; 2048];
    let mut written = 0;
    let status = unsafe {
        morse_wallet_authorization_text(
            op,
            input,
            len,
            text.as_mut_ptr(),
            text.len() as u64,
            &mut written,
        )
    };
    if status != 0 {
        return status;
    }
    h.text = String::from_utf8(text[..written as usize].to_vec()).unwrap();
    0
}
fn call(callbacks: &MorseWalletCallbacksV1, op: u32, input: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 1232];
    let mut written = 0;
    let status = unsafe {
        morse_wallet_call(
            callbacks,
            op,
            input.as_ptr(),
            input.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
        )
    };
    assert_eq!(status, 0, "local fixture SDK status");
    out.truncate(written as usize);
    out
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let value: Value = serde_json::from_str(&input).unwrap();
    let mut record = b"MWL1".to_vec();
    let seed_tag = value["seed_tag"].as_u64().unwrap_or(1);
    assert!((1..=255).contains(&seed_tag));
    record.extend_from_slice(&[seed_tag as u8; 32]);
    record.extend_from_slice(&0u64.to_le_bytes());
    let mut state = Host {
        record: Zeroizing::new(record),
        locked: false,
        text: String::new(),
    };
    let fixture_mint = value["usdc_mint_hex"]
        .as_str()
        .map(|hex| hex::decode(hex).unwrap().try_into().unwrap())
        .unwrap_or([7; 32]);
    let callbacks = MorseWalletCallbacksV1 {
        abi_version: 1,
        struct_size: std::mem::size_of::<MorseWalletCallbacksV1>() as u32,
        context: (&mut state as *mut Host).cast(),
        acquire: Some(acquire),
        load: Some(load),
        replace: Some(replace),
        release: Some(release),
        authorize: Some(authorize),
        usdc_mint: fixture_mint,
        purpose: 1,
        reserved: [0; 7],
    };
    let address = call(&callbacks, 2, &[]);
    let mut output = json!({"address_hex":hex::encode(address)});
    if let Some(quote) = value["quote_hex"].as_str() {
        let mut input = hex::decode(quote).unwrap();
        let hash = value["blockhash_hex"]
            .as_str()
            .map(|text| hex::decode(text).unwrap())
            .unwrap_or(vec![4; 32]);
        assert_eq!(hash.len(), 32);
        input.extend_from_slice(&hash);
        output["wire_hex"] = json!(hex::encode(call(&callbacks, 3, &input)));
        output["authorization_text"] = json!(state.text);
    }
    let count = value["bounty_count"].as_u64().unwrap_or(0);
    assert!(count <= 1024);
    let mut rows = Vec::new();
    for _ in 0..count {
        let row = call(&callbacks, 4, &[]);
        rows.push(json!({"index":u64::from_le_bytes(row[..8].try_into().unwrap()),"address_hex":hex::encode(&row[8..])}));
    }
    output["bounties"] = json!(rows);
    if let Some(transfer) = value["bounty_transfer_hex"].as_str() {
        let input = hex::decode(transfer).unwrap();
        output["wire_hex"] = json!(hex::encode(call(&callbacks, 5, &input)));
        output["authorization_text"] = json!(state.text);
    }
    println!("{output}");
}
