//! Signed Solana transfers in the legacy message format: SOL system transfers and SPL
//! `TransferChecked`, laid out the way Solana Pay expects (compute budget first, then the
//! optional recipient token account, then the memo, then the transfer with its references).

use crate::Error;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Pubkey = [u8; 32];

const fn b58(s: &str) -> Pubkey {
    bs58::decode(s.as_bytes()).into_array_const_unwrap()
}

const SYSTEM_PROGRAM: Pubkey = [0; 32];
const TOKEN_PROGRAM: Pubkey = b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = b58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const MEMO_PROGRAM: Pubkey = b58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const COMPUTE_BUDGET_PROGRAM: Pubkey = b58("ComputeBudget111111111111111111111111111111");
pub const USDC_MINT: Pubkey = b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
/// Largest serialized transaction a Solana packet carries.
const MAX_TRANSACTION: usize = 1232;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset {
    Sol,
    Spl { mint: Pubkey, decimals: u8 },
}

pub struct Transfer<'a> {
    pub asset: Asset,
    /// Base units: lamports, or the mint's smallest unit.
    pub amount: u64,
    /// A wallet address. For SPL assets the tokens go to its associated token account.
    pub recipient: Pubkey,
    /// SPL only: create the recipient's associated token account if it doesn't exist.
    pub create_recipient_account: bool,
    /// Solana Pay references, added in order as read-only non-signers on the transfer.
    pub references: &'a [Pubkey],
    pub memo: Option<&'a str>,
    pub compute_unit_limit: Option<u32>,
    /// Priority fee in micro-lamports per compute unit.
    pub compute_unit_price: Option<u64>,
    pub recent_blockhash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Ready for `sendTransaction` with `encoding: "base64"`.
    pub transaction_base64: String,
    /// The fee payer's signature: the transaction ID.
    pub signature_base58: String,
}

/// The associated token account of `owner` for `mint` (SPL Token program).
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    // find_program_address: the first bump from 255 down whose hash is off the curve.
    for bump in (0..=255u8).rev() {
        let hash: Pubkey = Sha256::new()
            .chain_update(owner)
            .chain_update(TOKEN_PROGRAM)
            .chain_update(mint)
            .chain_update([bump])
            .chain_update(ATA_PROGRAM)
            .chain_update(b"ProgramDerivedAddress")
            .finalize()
            .into();
        if CompressedEdwardsY(hash).decompress().is_none() {
            return hash;
        }
    }
    unreachable!("no bump seed gives an off-curve address")
}

struct Account {
    key: Pubkey,
    signer: bool,
    writable: bool,
}

fn account(key: Pubkey, signer: bool, writable: bool) -> Account {
    Account {
        key,
        signer,
        writable,
    }
}

struct Instruction {
    program: Pubkey,
    accounts: Vec<Account>,
    data: Vec<u8>,
}

/// Signs a transfer from `owner` (the SOL sender or the token account owner), with the fee paid
/// by `fee_payer`. Pass the same key twice when the owner pays its own fee.
pub fn sign_transfer(
    owner: &SigningKey,
    fee_payer: &SigningKey,
    transfer: &Transfer,
) -> Result<Signed, Error> {
    if transfer.amount == 0 {
        return Err(Error::Amount);
    }
    let from = owner.verifying_key().to_bytes();
    let payer = fee_payer.verifying_key().to_bytes();
    let amount = transfer.amount.to_le_bytes();
    let mut instructions = Vec::new();
    if let Some(units) = transfer.compute_unit_limit {
        let data = [&[2u8][..], &units.to_le_bytes()].concat();
        instructions.push(Instruction {
            program: COMPUTE_BUDGET_PROGRAM,
            accounts: vec![],
            data,
        });
    }
    if let Some(price) = transfer.compute_unit_price {
        let data = [&[3u8][..], &price.to_le_bytes()].concat();
        instructions.push(Instruction {
            program: COMPUTE_BUDGET_PROGRAM,
            accounts: vec![],
            data,
        });
    }
    let mut last = match transfer.asset {
        Asset::Sol if transfer.create_recipient_account => return Err(Error::NotSpl),
        Asset::Sol => Instruction {
            program: SYSTEM_PROGRAM,
            accounts: vec![
                account(from, true, true),
                account(transfer.recipient, false, true),
            ],
            data: [&2u32.to_le_bytes()[..], &amount].concat(),
        },
        Asset::Spl { mint, decimals } => {
            let destination = associated_token_address(&transfer.recipient, &mint);
            if transfer.create_recipient_account {
                instructions.push(Instruction {
                    program: ATA_PROGRAM,
                    accounts: vec![
                        account(payer, true, true),
                        account(destination, false, true),
                        account(transfer.recipient, false, false),
                        account(mint, false, false),
                        account(SYSTEM_PROGRAM, false, false),
                        account(TOKEN_PROGRAM, false, false),
                    ],
                    data: vec![1], // CreateIdempotent
                });
            }
            Instruction {
                program: TOKEN_PROGRAM,
                accounts: vec![
                    account(associated_token_address(&from, &mint), false, true),
                    account(mint, false, false),
                    account(destination, false, true),
                    account(from, true, false),
                ],
                data: [&[12u8][..], &amount, &[decimals]].concat(), // TransferChecked
            }
        }
    };
    for reference in transfer.references {
        if *reference == payer || last.accounts.iter().any(|a| a.key == *reference) {
            return Err(Error::Reference);
        }
        last.accounts.push(account(*reference, false, false));
    }
    if let Some(memo) = transfer.memo {
        let data = memo.as_bytes().to_vec();
        instructions.push(Instruction {
            program: MEMO_PROGRAM,
            accounts: vec![],
            data,
        });
    }
    instructions.push(last);

    let (message, signers) = compile(payer, &instructions, &transfer.recent_blockhash)?;
    let mut wire = vec![signers as u8];
    for key in [fee_payer, owner].into_iter().take(signers) {
        wire.extend_from_slice(&key.sign(&message).to_bytes());
    }
    let signature_base58 = bs58::encode(&wire[1..65]).into_string();
    wire.extend_from_slice(&message);
    if wire.len() > MAX_TRANSACTION {
        return Err(Error::TooLarge);
    }
    let transaction_base64 = base64::engine::general_purpose::STANDARD.encode(&wire);
    Ok(Signed {
        transaction_base64,
        signature_base58,
    })
}

/// A legacy message, with accounts ordered as the Solana SDK orders them: the fee payer, then
/// writable signers, read-only signers, writable and read-only non-signers, each group sorted
/// by key bytes. Returns the message and the number of signatures it needs (1 or 2).
fn compile(
    payer: Pubkey,
    instructions: &[Instruction],
    blockhash: &[u8; 32],
) -> Result<(Vec<u8>, usize), Error> {
    let mut flags: BTreeMap<Pubkey, (bool, bool)> = BTreeMap::new();
    for instruction in instructions {
        flags.entry(instruction.program).or_default();
        for a in &instruction.accounts {
            let f = flags.entry(a.key).or_default();
            f.0 |= a.signer;
            f.1 |= a.writable;
        }
    }
    flags.remove(&payer);
    let group = |flag: (bool, bool)| {
        flags
            .iter()
            .filter(move |(_, f)| **f == flag)
            .map(|(k, _)| *k)
    };
    let keys: Vec<Pubkey> = std::iter::once(payer)
        .chain(group((true, true)))
        .chain(group((true, false)))
        .chain(group((false, true)))
        .chain(group((false, false)))
        .collect();
    if keys.len() * 32 > MAX_TRANSACTION {
        return Err(Error::TooLarge); // also keeps every index within a u8
    }
    let signers = 1 + group((true, true)).count() + group((true, false)).count();
    let index = |key: &Pubkey| keys.iter().position(|k| k == key).expect("compiled key") as u8;

    let mut out = vec![
        signers as u8,
        group((true, false)).count() as u8,
        group((false, false)).count() as u8,
    ];
    shortvec(&mut out, keys.len());
    keys.iter().for_each(|k| out.extend_from_slice(k));
    out.extend_from_slice(blockhash);
    shortvec(&mut out, instructions.len());
    for instruction in instructions {
        out.push(index(&instruction.program));
        shortvec(&mut out, instruction.accounts.len());
        out.extend(instruction.accounts.iter().map(|a| index(&a.key)));
        shortvec(&mut out, instruction.data.len());
        out.extend_from_slice(&instruction.data);
    }
    Ok((out, signers))
}

/// Solana's compact-u16 length prefix.
fn shortvec(out: &mut Vec<u8>, mut n: usize) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive::keypair, seed::Seed, KeyPath};
    use base64::{engine::general_purpose::STANDARD, Engine};

    const BLOCKHASH: &str = "4PG9L5JD4KUbqTamRMG8s8muqgUiQH5QrfcKPjmLLR48";

    fn key(path: KeyPath) -> SigningKey {
        keypair(&Seed::from_entropy(&[0; 16]).unwrap(), path).unwrap()
    }

    fn transfer(asset: Asset, amount: u64, recipient: &str) -> Transfer<'static> {
        Transfer {
            asset,
            amount,
            recipient: b58_runtime(recipient),
            create_recipient_account: false,
            references: &[],
            memo: None,
            compute_unit_limit: None,
            compute_unit_price: None,
            recent_blockhash: b58_runtime(BLOCKHASH),
        }
    }

    fn b58_runtime(s: &str) -> Pubkey {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }

    const USDC: Asset = Asset::Spl {
        mint: USDC_MINT,
        decimals: 6,
    };

    /// Compares with `solana`/`spl-token` `--sign-only --dump-transaction-message` output:
    /// the transaction is the signature list followed by the message.
    fn assert_cli(signed: &Signed, message_b64: &str, signatures: &[&str]) {
        let mut expected = vec![signatures.len() as u8];
        for s in signatures {
            expected.extend(bs58::decode(s).into_vec().unwrap());
        }
        expected.extend(STANDARD.decode(message_b64).unwrap());
        assert_eq!(
            STANDARD.decode(&signed.transaction_base64).unwrap(),
            expected
        );
        assert_eq!(signed.signature_base58, signatures[0]);
    }

    // Vectors from solana-cli 4.1.1 / spl-token-cli 5.6.1, keypairs from `solana-keygen recover`
    // of "abandon ×11 about" (account 0 = HAgk…, account 1 = Hh8Q…, bounty 0 = DZJc…,
    // bounty 7 = H6wH…), all with `--sign-only --blockhash 4PG9L5… --dump-transaction-message`:
    //   solana transfer --keypair acct0.json --fee-payer acct0.json DZJc… 0.0015 --allow-unfunded-recipient
    //   solana transfer --keypair acct1.json --fee-payer acct1.json 9WzD… 2.000000001 --allow-unfunded-recipient
    //   spl-token transfer --owner acct0.json --fee-payer acct0.json --mint-decimals 6 \
    //     --transfer-hook-account H6wH…:readonly EPjF… 12.5 5tVJ… (DZJc…'s USDC account)
    //   spl-token transfer --owner bounty0.json --fee-payer acct0.json --mint-decimals 6 \
    //     EPjF… 3.25 5N3f… (HAgk…'s USDC account)

    #[test]
    fn sol_transfer_matches_solana_cli() {
        let owner = key(KeyPath::Account(0));
        let signed = sign_transfer(
            &owner,
            &owner,
            &transfer(
                Asset::Sol,
                1_500_000,
                "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
            ),
        )
        .unwrap();
        assert_cli(&signed, "AQABA/A2J2JGp1ud4zSe1CsV4jL2UY/CD1/NTx1k6B+b0lj3upK9OneMmP4x8XnaBj0GLGJTOTSPamH3ScYCh76V2uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADJG9iUQa+kTS+ASOE/NxyCXhZ4UsNCPE7kbLgXY1zo9AQICAAEMAgAAAGDjFgAAAAAA", &["wtHkzcVbBw9hz6PvxGSYiPvvy3WRJmt5g7HgrWoDfmcYKD3cXPeKi4DSe3zVH1ZiHyAaCA4CxVUdwByjXeV9QF1"]);

        let owner = key(KeyPath::Account(1));
        let signed = sign_transfer(
            &owner,
            &owner,
            &transfer(
                Asset::Sol,
                2_000_000_001,
                "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            ),
        )
        .unwrap();
        assert_cli(&signed, "AQABA/gCms9cvL3VrEbsFH87eKPfblAi7wQR2yurZQ0ymkzUfowIh2C/3h3dzzLBfyCbgkLuUqrxMfrNiNDqLG0LBvIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADJG9iUQa+kTS+ASOE/NxyCXhZ4UsNCPE7kbLgXY1zo9AQICAAEMAgAAAAGUNXcAAAAA", &["xtEP3XfW7oKg94X44EKvYURuBTn2yngksWKBsQVb6r8pNY3Sk4Lqy54QNx8uk7PyWYu1LQQDMnRHJy24CxVpBJM"]);
    }

    #[test]
    fn usdc_transfer_with_reference_matches_spl_token_cli() {
        let owner = key(KeyPath::Account(0));
        let reference = [b58_runtime("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5")];
        let mut t = transfer(
            USDC,
            12_500_000,
            "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
        );
        t.references = &reference;
        let signed = sign_transfer(&owner, &owner, &t).unwrap();
        assert_cli(&signed, "AQADBvA2J2JGp1ud4zSe1CsV4jL2UY/CD1/NTx1k6B+b0lj3QNLyfEYfKen+uhq4rNOUlqnGWwrmKnE/AflBqZO/Ve1In11bvaU8vbHShRMrsP3xcmA01uebHouqXgxKHd5kyAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpxvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWHvQERIbPiGenhxMmmj9CUYbddTGlfK7GFsIjNIyw9UMjJG9iUQa+kTS+ASOE/NxyCXhZ4UsNCPE7kbLgXY1zo9AQMFAQQCAAUKDCC8vgAAAAAABg==", &["RJ5Gv7DP9q3M233NDgEt1sUqYHM524d7pvqqnc1o6vfnWTSyYPse4AVRw5j5WezrAX1s2VEXw8QkT1Wf61EZ6FY"]);
    }

    #[test]
    fn bounty_move_with_a_separate_fee_payer_matches_spl_token_cli() {
        let bounty = key(KeyPath::Bounty(0));
        let payer = key(KeyPath::Account(0));
        let signed = sign_transfer(
            &bounty,
            &payer,
            &transfer(
                USDC,
                3_250_000,
                "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
            ),
        )
        .unwrap();
        assert_cli(&signed, "AgECBvA2J2JGp1ud4zSe1CsV4jL2UY/CD1/NTx1k6B+b0lj3upK9OneMmP4x8XnaBj0GLGJTOTSPamH3ScYCh76V2uBA0vJ8Rh8p6f66Gris05SWqcZbCuYqcT8B+UGpk79V7UifXVu9pTy9sdKFEyuw/fFyYDTW55sei6peDEod3mTIBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnG+nrzvtutOj1l82qryXQxsbvkwtL24OR8pgIDRS9dYTJG9iUQa+kTS+ASOE/NxyCXhZ4UsNCPE7kbLgXY1zo9AQQEAwUCAQoMUJcxAAAAAAAG", &[
            "4eQ2MS3PLxwRYC3FFnk37Z7v98BNSNJUUtEfn8tCg9LxRsgLYm9yx8wqP8ZPEGxBQ6d5CcMDu2bhsEqNuAZH8Awu",
            "MS4cDfsWM1LQanrhEseNhDa1XV9XCKjPwmGWPp9tdubn5ysVQtyxCo4xtp4n8igBLJjDAdwtTpeYityXZPAPFFW",
        ]);
    }

    #[test]
    fn full_quote_payment_matches_the_solana_rust_sdk() {
        // solana-sdk 5.0 `Message::new_with_blockhash` + `Transaction::new` over
        // [set_compute_unit_limit(20000), set_compute_unit_price(50000),
        //  create_associated_token_account_idempotent(payer, DZJc…, USDC),
        //  memo "Morse credits: 100 pack", transfer_checked(5 USDC) + references H6wH…, Hh8Q…].
        let owner = key(KeyPath::Account(0));
        let references = [
            b58_runtime("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5"),
            b58_runtime("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"),
        ];
        let mut t = transfer(
            USDC,
            5_000_000,
            "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
        );
        t.create_recipient_account = true;
        t.references = &references;
        t.memo = Some("Morse credits: 100 pack");
        t.compute_unit_limit = Some(20_000);
        t.compute_unit_price = Some(50_000);
        let signed = sign_transfer(&owner, &owner, &t).unwrap();
        assert_eq!(signed.signature_base58, "2McUeZRpszHVNGm98BrMYyfmZDSMQatmrTHcRSJgXGWjiyKiLzXQGcTnnpXWB6KtxV5wWke1qCrXSwzbEWJhq6kz");
        assert_eq!(signed.transaction_base64, "AUPKrgBj5L3ewWMHJ9fUGE21VRtiDZrnB3pPmywzIQMrquljPAnMLH4iDRO44XFWCK6l6ZJ7PkqyUxrTvZpGFwsBAAkM8DYnYkanW53jNJ7UKxXiMvZRj8IPX81PHWToH5vSWPdA0vJ8Rh8p6f66Gris05SWqcZbCuYqcT8B+UGpk79V7UifXVu9pTy9sdKFEyuw/fFyYDTW55sei6peDEod3mTIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAVKU1qZKSEGTSTocWDaOHx8NbXdvJK7geQfqEBBBUSNBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKmMlyWPTiSJ8bs9ECkUjg2DC1oTmdr/EIQEjnvY2+n4WbqSvTp3jJj+MfF52gY9BixiUzk0j2ph90nGAoe+ldrgxvp6877brTo9ZfNqq8l0MbG75MLS9uDkfKYCA0UvXWHvQERIbPiGenhxMmmj9CUYbddTGlfK7GFsIjNIyw9UMvgCms9cvL3VrEbsFH87eKPfblAi7wQR2yurZQ0ymkzUMkb2JRBr6RNL4BI4T83HIJeFnhSw0I8TuRsuBdjXOj0FBAAFAiBOAAAEAAkDUMMAAAAAAAAHBgACCAkDBgEBBQAXTW9yc2UgY3JlZGl0czogMTAwIHBhY2sGBgEJAgAKCwoMQEtMAAAAAAAG");
    }

    #[test]
    fn associated_token_addresses_match_spl_token_cli() {
        for (owner, ata) in [
            (
                "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
                "5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt",
            ),
            (
                "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
                "5tVJEgZZc8d2eAXDTUc9UZWFZdzRNH4fFD5WxTF25sUs",
            ),
        ] {
            assert_eq!(
                associated_token_address(&b58_runtime(owner), &USDC_MINT),
                b58_runtime(ata)
            );
        }
    }

    #[test]
    fn rejects_a_zero_amount() {
        let owner = key(KeyPath::Account(0));
        let t = transfer(
            Asset::Sol,
            0,
            "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
        );
        assert_eq!(sign_transfer(&owner, &owner, &t), Err(Error::Amount));
    }

    #[test]
    fn account_creation_is_for_spl_only() {
        let owner = key(KeyPath::Account(0));
        let mut t = transfer(
            Asset::Sol,
            1,
            "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
        );
        t.create_recipient_account = true;
        assert_eq!(sign_transfer(&owner, &owner, &t), Err(Error::NotSpl));
    }

    #[test]
    fn references_must_be_fresh_read_only_keys() {
        let owner = key(KeyPath::Account(0));
        let payer = key(KeyPath::Account(1));
        let recipient = "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo";
        let r = b58_runtime("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5");
        for refs in [
            vec![r, r],
            vec![b58_runtime(recipient)],
            vec![owner.verifying_key().to_bytes()],
            vec![payer.verifying_key().to_bytes()],
        ] {
            let mut t = transfer(Asset::Sol, 1, recipient);
            t.references = &refs;
            assert_eq!(sign_transfer(&owner, &payer, &t), Err(Error::Reference));
        }
    }

    #[test]
    fn refuses_transactions_over_1232_bytes() {
        let owner = key(KeyPath::Account(0));
        let memo = "m".repeat(1000);
        let mut t = transfer(USDC, 1, "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo");
        t.memo = Some(&memo);
        assert_eq!(sign_transfer(&owner, &owner, &t), Err(Error::TooLarge));
        let many: Vec<Pubkey> = (1..=40u8).map(|i| [i; 32]).collect();
        let mut t = transfer(USDC, 1, "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo");
        t.references = &many;
        assert_eq!(sign_transfer(&owner, &owner, &t), Err(Error::TooLarge));
    }
}
