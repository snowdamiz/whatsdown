//! Typed transfer from a previously reserved bounty key. No raw signing API.
use crate::{
    payment::{associated, now, ATA, SYSTEM, TOKEN},
    store, Error, MorseWalletCallbacksV1,
};
use ed25519_dalek::Signer;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::legacy::Message;
use subtle::ConstantTimeEq;

fn wide(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed transfer field"),
    )
}
fn key(input: &[u8], offset: usize) -> Address {
    Address::new_from_array(
        input[offset..offset + 32]
            .try_into()
            .expect("fixed transfer field"),
    )
}
fn current(input: &[u8], timestamp: u64) -> Result<(), Error> {
    let issued = wide(input, 148);
    let expires = wide(input, 156);
    if issued.checked_add(300) != Some(expires) || timestamp < issued || timestamp >= expires {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn message(
    input: &[u8],
    payer: Address,
    purpose: u8,
    usdc: [u8; 32],
    timestamp: u64,
) -> Result<Vec<u8>, Error> {
    if input.len() != 166
        || &input[..4] != b"\x01BWT"
        || input[164] != purpose
        || purpose > 1
        || input[165] > 18
        || wide(input, 4) >= store::INDEX_LIMIT
    {
        return Err(Error::Invalid);
    }
    current(input, timestamp)?;
    let finder = key(input, 12);
    let recipient = key(input, 44);
    let mint = key(input, 76);
    let amount = wide(input, 108);
    let hash: [u8; 32] = input[116..148].try_into().expect("fixed hash");
    if amount == 0
        || hash == [0; 32]
        || recipient == finder
        || [payer, finder, recipient, mint]
            .iter()
            .any(|address| address.to_bytes() == [0; 32])
        || (mint.to_bytes() == usdc && input[165] != 6)
    {
        return Err(Error::Invalid);
    }
    let source = associated(&finder, &mint);
    let destination = associated(&recipient, &mint);
    let roles = [payer, finder, mint, source, destination, SYSTEM, TOKEN, ATA];
    for (index, value) in roles.iter().enumerate() {
        if roles[..index].contains(value) {
            return Err(Error::Invalid);
        }
    }
    if recipient != payer && roles.contains(&recipient) {
        return Err(Error::Invalid);
    }
    let create = Instruction {
        program_id: ATA,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(recipient, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(TOKEN, false),
        ],
        data: vec![1],
    };
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(input[165]);
    let transfer = Instruction {
        program_id: TOKEN,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(finder, true),
        ],
        data,
    };
    let message = Message::new_with_blockhash(
        &[create, transfer],
        Some(&payer),
        &Hash::new_from_array(hash),
    );
    if message.header.num_required_signatures != 2 || message.account_keys[..2] != [payer, finder] {
        return Err(Error::Internal);
    }
    let wire = message.serialize();
    if wire.len() + 129 > 1232 {
        return Err(Error::Invalid);
    }
    Ok(wire)
}

pub(crate) fn sign(host: &MorseWalletCallbacksV1, input: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_clock(host, input, now)
}
pub(crate) fn sign_with_clock(
    host: &MorseWalletCallbacksV1,
    input: &[u8],
    mut clock: impl FnMut() -> Result<u64, Error>,
) -> Result<Vec<u8>, Error> {
    if input.len() != 166 {
        return Err(Error::Invalid);
    }
    let record = store::read(host)?;
    let finder = record.bounty_key(wide(input, 4))?;
    if finder.verifying_key().to_bytes() != input[12..44] {
        return Err(Error::Invalid);
    }
    let payer = record.address();
    let wire = message(
        input,
        Address::new_from_array(payer),
        host.purpose,
        host.usdc_mint,
        clock()?,
    )?;
    let mut intent = input.to_vec();
    intent.extend_from_slice(&payer);
    if unsafe {
        (host.authorize.expect("validated callback"))(
            host.context,
            5,
            intent.as_ptr(),
            intent.len() as u64,
        )
    } != 0
    {
        return Err(Error::Cancelled);
    }
    current(input, clock()?)?;
    let after = store::read(host)?;
    if !bool::from(record.seed.as_slice().ct_eq(after.seed.as_slice()))
        || after.bounty_key(wide(input, 4)).is_err()
    {
        return Err(Error::Storage);
    }
    let payment = record.payment_key();
    let mut packet = vec![2];
    for secret in [&payment, &finder] {
        let signature = secret.sign(&wire);
        secret
            .verifying_key()
            .verify_strict(&wire, &signature)
            .map_err(|_| Error::Internal)?;
        packet.extend_from_slice(&signature.to_bytes());
    }
    packet.extend_from_slice(&wire);
    Ok(packet)
}

pub(crate) fn authorization_text(intent: &[u8]) -> Result<String, Error> {
    if intent.len() != 198 {
        return Err(Error::Invalid);
    }
    let input = &intent[..166];
    let payer = key(intent, 166);
    // This formatter has no wallet access and cannot attest a token symbol.
    // Show the exact mint, decimals and quantity from the signer's intent.
    message(input, payer, input[164], [0; 32], wide(input, 148))?;
    let amount = wide(input, 108);
    let decimals = input[165] as usize;
    let scale = 10u64.pow(decimals as u32);
    let exact = if decimals == 0 {
        amount.to_string()
    } else {
        format!(
            "{}.{:0width$}",
            amount / scale,
            amount % scale,
            width = decimals
        )
    };
    Ok(format!("Move fork bounty\nThis transfer is public and links the one-time bounty address to the destination and fee-paying wallet.\nNetwork fees and any destination token-account rent are additional.\nAmount: {exact} tokens\nToken mint: {}\nToken decimals: {decimals}\nBounty address: {}\nDestination owner: {}\nDestination token account: {}\nFee-paying wallet: {payer}\nExpires at Unix seconds: {}",key(input,76),key(input,12),key(input,44),associated(&key(input,44),&key(input,76)),wide(input,156)))
}
