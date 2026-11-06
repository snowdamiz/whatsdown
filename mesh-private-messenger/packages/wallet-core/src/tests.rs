use super::*;

#[derive(Default)]
struct Host {
    record: Option<Vec<u8>>,
    locked: bool,
    approved: bool,
    fail_write: bool,
    approvals: usize,
    swap_on_approve: bool,
    intent: Vec<u8>,
}
unsafe fn host<'a>(context: *mut c_void) -> &'a mut Host {
    unsafe { &mut *context.cast::<Host>() }
}
unsafe extern "C" fn acquire(context: *mut c_void) -> i32 {
    let state = unsafe { host(context) };
    assert!(!state.locked);
    state.locked = true;
    0
}
unsafe extern "C" fn release(context: *mut c_void) -> i32 {
    let state = unsafe { host(context) };
    assert!(state.locked);
    state.locked = false;
    0
}
unsafe extern "C" fn load(context: *mut c_void, out: *mut u8, cap: u64, written: *mut u64) -> i32 {
    let state = unsafe { host(context) };
    assert!(state.locked);
    unsafe { written.write(0) };
    match &state.record {
        None => 2,
        Some(record) => {
            if cap < record.len() as u64 {
                unsafe { written.write(record.len() as u64) };
                return 0;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(record.as_ptr(), out, record.len());
                written.write(record.len() as u64)
            };
            0
        }
    }
}
unsafe extern "C" fn replace(context: *mut c_void, input: *const u8, len: u64) -> i32 {
    let state = unsafe { host(context) };
    assert!(state.locked);
    if state.fail_write {
        return 3;
    }
    state.record = Some(unsafe { std::slice::from_raw_parts(input, len as usize) }.to_vec());
    0
}
unsafe extern "C" fn authorize(context: *mut c_void, op: u32, input: *const u8, len: u64) -> i32 {
    let state = unsafe { host(context) };
    assert!(!state.locked);
    state.approvals += 1;
    assert_eq!(
        len,
        match op {
            1 => 32,
            3 => 288,
            5 => 198,
            _ => panic!("unexpected confirmation"),
        }
    );
    state.intent = unsafe { std::slice::from_raw_parts(input, len as usize) }.to_vec();
    if state.swap_on_approve {
        state.record.as_mut().unwrap()[4] ^= 1;
    }
    if state.approved {
        0
    } else {
        1
    }
}
fn callbacks(state: &mut Host) -> MorseWalletCallbacksV1 {
    MorseWalletCallbacksV1 {
        abi_version: 1,
        struct_size: std::mem::size_of::<MorseWalletCallbacksV1>() as u32,
        context: (state as *mut Host).cast(),
        acquire: Some(acquire),
        load: Some(load),
        replace: Some(replace),
        release: Some(release),
        authorize: Some(authorize),
        usdc_mint: [7; 32],
        purpose: 1,
        reserved: [0; 7],
    }
}
fn call(host: &mut Host, op: u32, input: &[u8]) -> (i32, Vec<u8>) {
    let callbacks = callbacks(host);
    let mut out = vec![0xAA; 1232];
    let mut written = 99;
    let status = unsafe {
        morse_wallet_call(
            &callbacks,
            op,
            input.as_ptr(),
            input.len() as u64,
            out.as_mut_ptr(),
            out.len() as u64,
            &mut written,
        )
    };
    if status != 0 {
        assert_eq!(written, 0);
        assert!(out.iter().all(|value| *value == 0xAA));
    }
    out.truncate(written as usize);
    (status, out)
}

#[test]
fn durable_reservation_precedes_bounty_output_and_survives_new_calls() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    assert_eq!(call(&mut state, 1, &[]).0, 0);
    let first = call(&mut state, 4, &[]);
    assert_eq!(first.0, 0);
    assert_eq!(u64::from_le_bytes(first.1[..8].try_into().unwrap()), 0);
    state.fail_write = true;
    assert_eq!(call(&mut state, 4, &[]).0, Error::Storage as i32);
    state.fail_write = false;
    let next = call(&mut state, 4, &[]);
    assert_eq!(next.0, 0);
    assert_eq!(u64::from_le_bytes(next.1[..8].try_into().unwrap()), 1);
    assert_ne!(&first.1[8..], &next.1[8..]);
    assert!(!state.locked);
}

fn quote(state: &mut Host, asset: u8) -> Vec<u8> {
    use solana_address::Address;
    let mut quote = vec![0; 224];
    quote[..4].copy_from_slice(b"\x01CQT");
    quote[4..36].fill(3);
    quote[36..68].fill(2);
    let deposit = Address::new_from_array([2; 32]);
    let destination = if asset == 0 {
        payment::associated(&deposit, &Address::new_from_array([7; 32])).to_bytes()
    } else {
        [2; 32]
    };
    quote[68..100].copy_from_slice(&destination);
    if asset == 0 {
        quote[100..132].fill(7)
    }
    quote[132] = asset;
    quote[133..141].copy_from_slice(&5_000_000u64.to_be_bytes());
    quote[141] = 1;
    quote[142..144].copy_from_slice(&100u16.to_be_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    quote[144..152].copy_from_slice(&now.to_be_bytes());
    quote[152..160].copy_from_slice(&(now + 900).to_be_bytes());
    quote[160..192].fill(8);
    quote[192..224].fill(9);
    assert!(state.record.is_some());
    quote
}
fn input(quote: &[u8]) -> Vec<u8> {
    let mut value = quote.to_vec();
    value.extend_from_slice(&[4; 32]);
    value
}

fn bounty_input(state: &mut Host) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let payer = call(state, 1, &[]).1;
    let reservation = call(state, 4, &[]).1;
    let finder = reservation[8..].to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut input = vec![0; 166];
    input[..4].copy_from_slice(b"\x01BWT");
    input[4..12]
        .copy_from_slice(&u64::from_le_bytes(reservation[..8].try_into().unwrap()).to_be_bytes());
    input[12..44].copy_from_slice(&finder);
    input[44..76].copy_from_slice(&payer);
    input[76..108].fill(7);
    input[108..116].copy_from_slice(&9_007_199_254_740_993u64.to_be_bytes());
    input[116..148].fill(4);
    input[148..156].copy_from_slice(&now.to_be_bytes());
    input[156..164].copy_from_slice(&(now + 300).to_be_bytes());
    input[164] = 1;
    input[165] = 6;
    (input, payer, finder)
}

#[test]
fn bounty_move_requires_confirmation_and_two_owned_signatures() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let (input, payer, finder) = bounty_input(&mut state);
    state.approved = false;
    assert_eq!(call(&mut state, 5, &input).0, Error::Cancelled as i32);
    assert_eq!(&state.intent[..166], &input);
    assert_eq!(&state.intent[166..], &payer);
    state.approved = true;
    let (status, packet) = call(&mut state, 5, &input);
    assert_eq!(status, 0);
    assert_eq!(packet[0], 2);
    let message = &packet[129..];
    assert_eq!(message[0], 2);
    assert_eq!(&message[4..36], &payer);
    assert_eq!(&message[36..68], &finder);
    for (index, key) in [&payer, &finder].iter().enumerate() {
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(key.as_slice().try_into().unwrap()).unwrap();
        let signature =
            ed25519_dalek::Signature::from_slice(&packet[1 + index * 64..65 + index * 64]).unwrap();
        public.verify_strict(message, &signature).unwrap();
    }
    let text = payment::authorization_text(5, &state.intent).unwrap();
    assert!(text.contains("9007199254.740993"));
    assert!(text.contains("links"));
    assert!(text.contains("fee-paying wallet"));
    state.swap_on_approve = true;
    assert_eq!(call(&mut state, 5, &input).0, Error::Storage as i32);
    assert!(!state.locked);
}

#[test]
fn bounty_move_rejects_unreserved_keys_bad_fields_and_expiry_before_prompt() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let (input, _, finder) = bounty_input(&mut state);
    let approvals = state.approvals;
    let mut invalid = Vec::new();
    for offset in [0, 11, 12, 156, 164, 165] {
        let mut value = input.clone();
        value[offset] ^= 1;
        invalid.push(value);
    }
    for (offset, width) in [(44, 32), (76, 32), (108, 8), (116, 32)] {
        let mut value = input.clone();
        value[offset..offset + width].fill(0);
        invalid.push(value);
    }
    let mut self_transfer = input.clone();
    self_transfer[44..76].copy_from_slice(&finder);
    invalid.push(self_transfer);
    let mut expired = input.clone();
    let now = u64::from_be_bytes(input[148..156].try_into().unwrap());
    expired[148..156].copy_from_slice(&(now - 300).to_be_bytes());
    expired[156..164].copy_from_slice(&now.to_be_bytes());
    invalid.push(expired);
    let mut future = input.clone();
    future[148..156].copy_from_slice(&(now + 300).to_be_bytes());
    future[156..164].copy_from_slice(&(now + 600).to_be_bytes());
    invalid.push(future);
    for value in invalid {
        assert_eq!(call(&mut state, 5, &value).0, Error::Invalid as i32);
        assert_eq!(state.approvals, approvals);
    }
    for length in [0, 165, 167, 257] {
        assert_eq!(
            call(&mut state, 5, &vec![0; length]).0,
            Error::Invalid as i32
        );
        assert_eq!(state.approvals, approvals);
    }
}

#[test]
fn bounty_move_rechecks_expiry_after_confirmation_and_formats_full_u64() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let (mut input, _, _) = bounty_input(&mut state);
    let issued = u64::from_be_bytes(input[148..156].try_into().unwrap());
    let mut reads = 0;
    let result = bounty_transfer::sign_with_clock(&callbacks(&mut state), &input, || {
        reads += 1;
        Ok(if reads == 1 { issued } else { issued + 300 })
    });
    assert_eq!(result, Err(Error::Invalid));
    assert_eq!(reads, 2);
    input[76..108].fill(11);
    input[108..116].copy_from_slice(&u64::MAX.to_be_bytes());
    input[165] = 0;
    assert_eq!(call(&mut state, 5, &input).0, 0);
    let text = payment::authorization_text(5, &state.intent).unwrap();
    assert!(text.contains("18446744073709551615 tokens"));
    assert!(text.contains("Token decimals: 0"));
    assert!(!text.contains("USDC"));
}

#[test]
fn creation_is_explicit_cancellable_and_never_replaces_existing_seed() {
    let mut state = Host::default();
    assert_eq!(call(&mut state, 2, &[]).0, 2);
    assert_eq!(call(&mut state, 1, &[]).0, 4);
    assert!(state.record.is_none());
    assert_eq!(state.approvals, 1);
    state.approved = true;
    let first = call(&mut state, 1, &[]);
    assert_eq!(first.0, 0);
    assert_eq!(state.record.as_ref().unwrap().len(), 44);
    let approvals = state.approvals;
    assert_eq!(call(&mut state, 1, &[]), first);
    assert_eq!(call(&mut state, 2, &[]), first);
    assert_eq!(state.approvals, approvals);
}

#[test]
fn quote_signing_requires_confirmation_and_checks_seed_after_prompt() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let address = call(&mut state, 1, &[]).1;
    for asset in [0, 1] {
        let quote = quote(&mut state, asset);
        state.approved = false;
        assert_eq!(call(&mut state, 3, &input(&quote)).0, 4);
        assert!(state.intent[..224] == quote);
        assert!(state.intent[224..256] == address);
        state.approved = true;
        let result = call(&mut state, 3, &input(&quote));
        assert_eq!(result.0, 0);
        assert_eq!(result.1[0], 1);
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(address.as_slice().try_into().unwrap())
                .unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&result.1[1..65]).unwrap();
        assert!(public.verify_strict(&result.1[65..], &signature).is_ok());
    }
    let quote = quote(&mut state, 1);
    state.swap_on_approve = true;
    assert_eq!(call(&mut state, 3, &input(&quote)).0, 3);
    assert!(!state.locked);
}

#[test]
fn noncanonical_quotes_and_roles_are_refused_before_any_prompt() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let address = call(&mut state, 1, &[]).1;
    for asset in [0, 1] {
        let base = quote(&mut state, asset);
        let approvals = state.approvals;
        let mut invalid = Vec::new();
        for offset in [0, 141, 142, 143, 152] {
            let mut value = base.clone();
            value[offset] ^= 1;
            invalid.push(value);
        }
        for (offset, width) in [(4, 32), (36, 32), (68, 32), (133, 8), (160, 32), (192, 32)] {
            let mut value = base.clone();
            value[offset..offset + width].fill(0);
            invalid.push(value);
        }
        let mut aliased = base.clone();
        aliased[4..36].copy_from_slice(&address);
        invalid.push(aliased);
        let mut wrong_asset = base.clone();
        wrong_asset[132] = 2;
        invalid.push(wrong_asset);
        let mut future = base.clone();
        let current = u64::from_be_bytes(base[144..152].try_into().unwrap());
        future[144..152].copy_from_slice(&(current + 1000).to_be_bytes());
        future[152..160].copy_from_slice(&(current + 1900).to_be_bytes());
        invalid.push(future);
        let mut expired = base.clone();
        expired[144..152].copy_from_slice(&(current - 900).to_be_bytes());
        expired[152..160].copy_from_slice(&current.to_be_bytes());
        invalid.push(expired);
        if asset == 0 {
            let mut price = base.clone();
            price[140] ^= 1;
            invalid.push(price);
            let mut mint = base.clone();
            mint[100] ^= 1;
            invalid.push(mint);
        } else {
            let mut mint = base.clone();
            mint[100] = 1;
            invalid.push(mint);
        }
        for quote in invalid {
            assert_eq!(call(&mut state, 3, &input(&quote)).0, 1);
            assert_eq!(state.approvals, approvals);
        }
        let mut zero_hash = input(&base);
        zero_hash[224..].fill(0);
        assert_eq!(call(&mut state, 3, &zero_hash).0, 1);
    }
}

#[test]
fn malformed_state_and_exhaustion_never_reset_the_wallet() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    assert_eq!(call(&mut state, 1, &[]).0, 0);
    let original = state.record.clone().unwrap();
    for length in [0, 1, 35, 43, 45] {
        state.record = Some(vec![0; length]);
        assert_eq!(call(&mut state, 1, &[]).0, 3);
        assert_eq!(call(&mut state, 4, &[]).0, 3);
    }
    state.record = Some(original);
    state.record.as_mut().unwrap()[36..44].copy_from_slice(&(1u64 << 31).to_le_bytes());
    assert_eq!(call(&mut state, 4, &[]).0, 5);
    let mut public_keys = std::collections::HashSet::new();
    state.record.as_mut().unwrap()[36..44].fill(0);
    for index in 0..128 {
        let result = call(&mut state, 4, &[]);
        assert_eq!(result.0, 0);
        assert_eq!(u64::from_le_bytes(result.1[..8].try_into().unwrap()), index);
        assert!(public_keys.insert(result.1[8..].to_vec()));
    }
}

#[test]
fn abi_validation_and_output_capacity_have_no_side_effects() {
    assert_eq!(std::mem::size_of::<MorseWalletCallbacksV1>(), 96);
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let mut callbacks = callbacks(&mut state);
    let mut out = [0xAA; 1232];
    let mut written = 99;
    for length in [0, 1, 31] {
        let status = unsafe {
            morse_wallet_call(
                &callbacks,
                1,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                length,
                &mut written,
            )
        };
        assert_eq!(status, 7);
        assert_eq!(written, 0);
        assert!(state.record.is_none());
    }
    callbacks.reserved[0] = 1;
    let status = unsafe {
        morse_wallet_call(
            &callbacks,
            1,
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            1232,
            &mut written,
        )
    };
    assert_eq!(status, 1);
    assert!(state.record.is_none());
    assert!(out.iter().all(|value| *value == 0xAA));
    assert_eq!(state.approvals, 0);
}

fn text(operation: u32, intent: &[u8], capacity: usize) -> (i32, String) {
    let mut output = vec![0xa5; capacity];
    let mut written = 99;
    let status = unsafe {
        morse_wallet_authorization_text(
            operation,
            intent.as_ptr(),
            intent.len() as u64,
            output.as_mut_ptr(),
            capacity as u64,
            &mut written,
        )
    };
    if status != 0 {
        assert_eq!(written, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }
    (
        status,
        String::from_utf8(output[..written as usize].to_vec()).unwrap(),
    )
}
#[test]
fn native_confirmation_text_displays_exact_quote_without_floating_point() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let address = call(&mut state, 1, &[]).1;
    let created = text(1, &address, 2048);
    assert_eq!(created.0, 0);
    assert!(created.1.contains("device-local"));
    assert!(created.1.contains("no seed export or recovery"));
    for asset in [0, 1] {
        let quote = quote(&mut state, asset);
        let mut intent = quote.clone();
        intent.extend_from_slice(&address);
        intent.extend_from_slice(&[4; 32]);
        let result = text(3, &intent, 2048);
        assert_eq!(result.0, 0);
        assert!(result.1.contains(if asset == 0 {
            "5.000000 USDC"
        } else {
            "0.005000000 SOL"
        }));
        assert!(result.1.contains("Purpose: test credits"));
        assert!(result.1.contains("Credits: 100"));
        assert!(result.1.contains("payment is public"));
        for key in [
            &quote[4..36],
            &quote[36..68],
            &quote[68..100],
            address.as_slice(),
        ] {
            assert!(result.1.contains(
                &solana_address::Address::new_from_array(key.try_into().unwrap()).to_string()
            ));
        }
        let expiry = u64::from_be_bytes(quote[152..160].try_into().unwrap());
        assert!(result
            .1
            .contains(&format!("Expires at Unix seconds: {expiry}")));
        assert_eq!(text(3, &intent, 1).0, 7);
        intent[141] = 9;
        assert_eq!(text(3, &intent, 2048).0, 1);
    }
    assert_eq!(text(4, &[], 2048).0, 1);
    assert_eq!(text(3, &[0; 287], 2048).0, 1);
}

#[test]
fn quote_expiry_is_rechecked_after_native_confirmation() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    assert_eq!(call(&mut state, 1, &[]).0, 0);
    let quote = quote(&mut state, 1);
    let issued = u64::from_be_bytes(quote[144..152].try_into().unwrap());
    let approvals = state.approvals;
    let callbacks = callbacks(&mut state);
    let mut times = [issued, issued + 900].into_iter();
    assert_eq!(
        payment::sign_with_clock(&callbacks, &input(&quote), || Ok(times.next().unwrap()))
            .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(state.approvals, approvals + 1);
}

#[test]
fn native_confirmation_preserves_all_u64_amount_digits() {
    let mut state = Host {
        approved: true,
        ..Host::default()
    };
    let address = call(&mut state, 1, &[]).1;
    let mut quote = quote(&mut state, 1);
    quote[133..141].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut intent = quote;
    intent.extend_from_slice(&address);
    intent.extend_from_slice(&[4; 32]);
    let result = text(3, &intent, 2048);
    assert_eq!(result.0, 0);
    assert!(result.1.contains("18446744073.709551615 SOL"));
}
