use crate::{store, Error, MorseWalletCallbacksV1};
use ed25519_dalek::Signer;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::legacy::Message;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub(crate) const SYSTEM: Address = Address::from_str_const("11111111111111111111111111111111");
pub(crate) const TOKEN: Address =
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub(crate) const ATA: Address =
    Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
fn key(value: &[u8]) -> Address {
    Address::new_from_array(value.try_into().expect("fixed quote field"))
}
fn nonzero(value: &[u8]) -> bool {
    value.iter().any(|byte| *byte != 0)
}
pub(crate) fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Invalid)
}
fn wide(quote: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        quote[offset..offset + 8]
            .try_into()
            .expect("fixed quote field"),
    )
}
fn current(quote: &[u8], now: u64) -> Result<(), Error> {
    let issued = wide(quote, 144);
    let expires = wide(quote, 152);
    if issued.checked_add(900) != Some(expires) || now < issued || now >= expires {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
pub(crate) fn associated(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}

fn message(
    host: &MorseWalletCallbacksV1,
    quote: &[u8],
    payer: Address,
    blockhash: [u8; 32],
    timestamp: u64,
) -> Result<Vec<u8>, Error> {
    if quote.len() != 224
        || &quote[..4] != b"\x01CQT"
        || quote[141] != host.purpose
        || !nonzero(&blockhash)
    {
        return Err(Error::Invalid);
    }
    current(quote, timestamp)?;
    let credits = u16::from_be_bytes(quote[142..144].try_into().expect("fixed quote field"));
    if !matches!(credits, 100 | 500 | 2000) {
        return Err(Error::Invalid);
    }
    let reference = key(&quote[4..36]);
    let deposit = key(&quote[36..68]);
    let destination = key(&quote[68..100]);
    let mint = key(&quote[100..132]);
    let amount = wide(quote, 133);
    if amount == 0
        || ![
            &quote[4..36],
            &quote[36..68],
            &quote[68..100],
            &quote[160..192],
            &quote[192..224],
        ]
        .iter()
        .all(|value| nonzero(value))
    {
        return Err(Error::Invalid);
    }
    let mut instructions = Vec::new();
    let keys = match quote[132] {
        0 => {
            if amount != u64::from(credits) * 50_000
                || mint.to_bytes() != host.usdc_mint
                || associated(&deposit, &mint) != destination
            {
                return Err(Error::Invalid);
            }
            let source = associated(&payer, &mint);
            instructions.push(Instruction {
                program_id: ATA,
                accounts: vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(destination, false),
                    AccountMeta::new_readonly(deposit, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(SYSTEM, false),
                    AccountMeta::new_readonly(TOKEN, false),
                ],
                data: vec![1],
            });
            let mut data = vec![12];
            data.extend_from_slice(&amount.to_le_bytes());
            data.push(6);
            instructions.push(Instruction {
                program_id: TOKEN,
                accounts: vec![
                    AccountMeta::new(source, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new(destination, false),
                    AccountMeta::new_readonly(payer, true),
                    AccountMeta::new_readonly(reference, false),
                ],
                data,
            });
            vec![
                payer,
                source,
                destination,
                deposit,
                mint,
                SYSTEM,
                TOKEN,
                ATA,
                reference,
            ]
        }
        1 => {
            if nonzero(mint.as_ref()) || destination != deposit {
                return Err(Error::Invalid);
            }
            let mut data = 2u32.to_le_bytes().to_vec();
            data.extend_from_slice(&amount.to_le_bytes());
            instructions.push(Instruction {
                program_id: SYSTEM,
                accounts: vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(destination, false),
                    AccountMeta::new_readonly(reference, false),
                ],
                data,
            });
            vec![payer, destination, SYSTEM, reference]
        }
        _ => return Err(Error::Invalid),
    };
    for (index, value) in keys.iter().enumerate() {
        if keys[..index].contains(value) {
            return Err(Error::Invalid);
        }
    }
    let message = Message::new_with_blockhash(
        &instructions,
        Some(&payer),
        &Hash::new_from_array(blockhash),
    )
    .serialize();
    if message.len() + 65 > 1232 {
        return Err(Error::Invalid);
    }
    Ok(message)
}

pub(crate) fn sign(host: &MorseWalletCallbacksV1, input: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_clock(host, input, now)
}
pub(crate) fn sign_with_clock(
    host: &MorseWalletCallbacksV1,
    input: &[u8],
    mut clock: impl FnMut() -> Result<u64, Error>,
) -> Result<Vec<u8>, Error> {
    if input.len() != 256 {
        return Err(Error::Invalid);
    }
    let quote = &input[..224];
    let blockhash = input[224..].try_into().expect("checked input");
    let record = store::read(host)?;
    let payer = record.address();
    let message = message(
        host,
        quote,
        Address::new_from_array(payer),
        blockhash,
        clock()?,
    )?;
    let mut intent = Vec::with_capacity(288);
    intent.extend_from_slice(quote);
    intent.extend_from_slice(&payer);
    intent.extend_from_slice(&blockhash);
    if unsafe {
        (host.authorize.expect("validated callback"))(
            host.context,
            3,
            intent.as_ptr(),
            intent.len() as u64,
        )
    } != 0
    {
        return Err(Error::Cancelled);
    }
    current(quote, clock()?)?;
    let after = store::read(host)?;
    if !bool::from(record.seed.as_slice().ct_eq(after.seed.as_slice())) {
        return Err(Error::Storage);
    }
    let secret = record.payment_key();
    let signature = secret.sign(&message);
    secret
        .verifying_key()
        .verify_strict(&message, &signature)
        .map_err(|_| Error::Internal)?;
    let mut packet = Vec::with_capacity(message.len() + 65);
    packet.push(1);
    packet.extend_from_slice(&signature.to_bytes());
    packet.extend_from_slice(&message);
    Ok(packet)
}

pub(crate) fn authorization_text(operation: u32, intent: &[u8]) -> Result<String, Error> {
    if operation == 5 {
        return crate::bounty_transfer::authorization_text(intent);
    }
    if operation == 1 {
        if intent.len() != 32 || !nonzero(intent) {
            return Err(Error::Invalid);
        }
        return Ok(format!("Create device-local wallet\nPayment address: {}\nThere is no seed export or recovery option. Losing this device or access to its secure storage can permanently lose funds.",key(intent)));
    }
    if operation != 3 || intent.len() != 288 {
        return Err(Error::Invalid);
    }
    let quote = &intent[..224];
    let payer = key(&intent[224..256]);
    if quote[141] > 1 || !nonzero(payer.as_ref()) || (quote[132] == 0 && !nonzero(&quote[100..132]))
    {
        return Err(Error::Invalid);
    }
    // The signer has already checked native release pins before invoking the
    // callback. This pure formatter repeats canonical quote/message validation
    // using that intent's fields; it neither approves nor signs anything.
    let host = MorseWalletCallbacksV1 {
        abi_version: 1,
        struct_size: 0,
        context: std::ptr::null_mut(),
        acquire: None,
        load: None,
        replace: None,
        release: None,
        authorize: None,
        usdc_mint: quote[100..132].try_into().expect("checked quote"),
        purpose: quote[141],
        reserved: [0; 7],
    };
    message(
        &host,
        quote,
        payer,
        intent[256..].try_into().expect("checked intent"),
        wide(quote, 144),
    )?;
    let amount = wide(quote, 133);
    let (asset, decimals, scale) = if quote[132] == 0 {
        ("USDC", 6, 1_000_000)
    } else {
        ("SOL", 9, 1_000_000_000)
    };
    let exact = format!(
        "{}.{:0width$}",
        amount / scale,
        amount % scale,
        width = decimals
    );
    let purpose = if quote[141] == 0 {
        "live credits"
    } else {
        "test credits"
    };
    Ok(format!("Public Solana payment\nThis payment is public on Solana and can reveal this wallet address.\nNetwork fees and any token-account rent are additional.\nPurpose: {purpose}\nCredits: {}\nAmount: {exact} {asset}\nPayer: {payer}\nDestination: {}\nDeposit owner: {}\nQuote reference: {}\nIssuer key: {}\nBatch commitment: {}\nExpires at Unix seconds: {}",u16::from_be_bytes(quote[142..144].try_into().expect("quote")),key(&quote[68..100]),key(&quote[36..68]),key(&quote[4..36]),key(&quote[160..192]),key(&quote[192..224]),wide(quote,152)))
}
