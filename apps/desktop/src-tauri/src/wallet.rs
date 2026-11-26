//! The in-app wallet's host (plan §6.13): packages/wallet-core, linked into this binary,
//! with its seed (the BIP39 entropy) in the OS credential store beside the Mesh keys.
//! The seed never reaches the web view; the recovery phrase (for display), public keys,
//! parsed pay requests and signed transactions do. Every request frame that held the
//! seed is wiped when the call returns.

use morse_wallet_core::{morse_wallet_call, morse_wallet_free_bytes, MorseWalletBytes};
use std::{ptr, slice, sync::Mutex};
use tauri::ipc::{InvokeBody, Request, Response};
use zeroize::Zeroizing;

const ENTROPY: &str = "wallet/entropy/v1";
const BOUNTY_INDEX: &str = "wallet/bounty-index/v1";

pub struct Wallet {
    service: String,
    // Creating, wiping and handing out bounty indexes are read-modify-write.
    lock: Mutex<()>,
}

// One wallet-core call; the response is wiped when dropped.
fn core(request: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut response = MorseWalletBytes {
        data: ptr::null_mut(),
        len: 0,
    };
    // SAFETY: `request` is a live slice; `response` is released by morse_wallet_free_bytes.
    let status =
        unsafe { morse_wallet_call(request.as_ptr(), request.len() as u64, &mut response) };
    let bytes = Zeroizing::new(if response.data.is_null() {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(response.data, response.len as usize) }.to_vec()
    });
    unsafe { morse_wallet_free_bytes(&mut response) };
    match status {
        0 => Ok(bytes),
        9 => Err(String::from_utf8_lossy(&bytes).into_owned()),
        _ => Err("wallet_failed".into()),
    }
}

fn frame(op: u8, parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut request = Zeroizing::new(Vec::with_capacity(4096));
    request.extend_from_slice(&[1, op]);
    for part in parts {
        request.extend_from_slice(part);
    }
    request
}

fn vec32(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new((bytes.len() as u32).to_be_bytes().to_vec());
    out.extend_from_slice(bytes);
    out
}

// Op 1's answer: vec32(entropy) || vec32(phrase).
fn split_generated(answer: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let take = |at: usize| -> Result<(&[u8], usize), String> {
        let length = u32::from_be_bytes(
            answer
                .get(at..at + 4)
                .ok_or("bad_frame")?
                .try_into()
                .map_err(|_| "bad_frame")?,
        ) as usize;
        Ok((
            answer.get(at + 4..at + 4 + length).ok_or("bad_frame")?,
            at + 4 + length,
        ))
    };
    let (entropy, next) = take(0)?;
    let (phrase, end) = take(next)?;
    if end != answer.len() {
        return Err("bad_frame".into());
    }
    Ok((entropy, phrase))
}

impl Wallet {
    pub fn new(service: String) -> Self {
        Self {
            service,
            lock: Mutex::new(()),
        }
    }

    fn entry(&self, name: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(&self.service, name).map_err(|_| "wallet_store_failed".into())
    }

    fn read(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match self.entry(name)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err("wallet_store_failed".into()),
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.entry(name)?
            .set_secret(bytes)
            .map_err(|_| "wallet_store_failed".into())
    }

    fn entropy(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        self.read(ENTROPY)?.ok_or_else(|| "wallet_missing".into())
    }

    fn issued(&self) -> Result<u32, String> {
        Ok(match self.read(BOUNTY_INDEX)? {
            None => 0,
            Some(bytes) => u32::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "wallet_store_failed")?,
            ),
        })
    }

    fn store_new(&self, entropy: &[u8]) -> Result<(), String> {
        if self.read(ENTROPY)?.is_some() {
            return Err("wallet_exists".into());
        }
        self.write(BOUNTY_INDEX, &0u32.to_be_bytes())?;
        self.write(ENTROPY, entropy)
    }

    pub fn exists(&self) -> Result<bool, String> {
        Ok(self.read(ENTROPY)?.is_some())
    }

    pub fn create(&self, words: u8) -> Result<Zeroizing<String>, String> {
        let _guard = self.lock.lock().map_err(|_| "wallet_lock_failed")?;
        let answer = core(&frame(1, &[&[words]]))?;
        let (entropy, phrase) = split_generated(&answer)?;
        self.store_new(entropy)?;
        Ok(Zeroizing::new(
            String::from_utf8(phrase.to_vec()).map_err(|_| "bad_frame")?,
        ))
    }

    pub fn restore(&self, phrase: &str) -> Result<(), String> {
        let _guard = self.lock.lock().map_err(|_| "wallet_lock_failed")?;
        let entropy = core(&frame(2, &[&vec32(phrase.as_bytes())]))?;
        self.store_new(&entropy)
    }

    // ponytail: no device-owner prompt on the desktop (none without a new dependency);
    // the phones ask for it (Face ID / passcode, BiometricPrompt).
    pub fn phrase(&self) -> Result<Zeroizing<String>, String> {
        let phrase = core(&frame(3, &[&vec32(&self.entropy()?)]))?;
        Ok(Zeroizing::new(
            String::from_utf8(phrase.to_vec()).map_err(|_| "bad_frame")?,
        ))
    }

    pub fn wipe(&self) -> Result<(), String> {
        let _guard = self.lock.lock().map_err(|_| "wallet_lock_failed")?;
        for name in [ENTROPY, BOUNTY_INDEX] {
            match self.entry(name)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(_) => return Err("wallet_store_failed".into()),
            }
        }
        Ok(())
    }

    // Ops 4 (address), 5 (transfer) and 6 (parse a Solana Pay URL); `body` is the frame
    // after the seed. A bounty key must be one already handed out, and a transfer's
    // fee payer must be an account key.
    pub fn call(&self, op: u8, body: &[u8]) -> Result<Vec<u8>, String> {
        if op == 6 {
            return Ok(core(&frame(6, &[body]))?.to_vec());
        }
        let keys = match op {
            4 => 1,
            5 => 2,
            _ => return Err("bad_op".into()),
        };
        let issued = self.issued()?;
        for key in (0..keys).map(|index| body.get(index * 5..index * 5 + 5)) {
            let key = key.ok_or("bad_frame")?;
            if key[0] == 2 && u32::from_be_bytes([key[1], key[2], key[3], key[4]]) >= issued {
                return Err("bounty_not_issued".into());
            }
        }
        if op == 5 && body[5] != 1 {
            return Err("fee_payer_not_account".into());
        }
        Ok(core(&frame(op, &[&vec32(&self.entropy()?), body]))?.to_vec())
    }

    // u32 index || public key. The next index is persisted before the address exists.
    pub fn next_bounty_address(&self) -> Result<Vec<u8>, String> {
        let _guard = self.lock.lock().map_err(|_| "wallet_lock_failed")?;
        let entropy = self.entropy()?;
        let index = self.issued()?;
        self.write(
            BOUNTY_INDEX,
            &index.checked_add(1).ok_or("bad_index")?.to_be_bytes(),
        )?;
        let key = [&[2u8][..], &index.to_be_bytes()].concat();
        let address = core(&frame(4, &[&vec32(&entropy), &key]))?;
        Ok([&index.to_be_bytes()[..], &address].concat())
    }

    pub fn bounty_index(&self, at_least: u32) -> Result<u32, String> {
        let _guard = self.lock.lock().map_err(|_| "wallet_lock_failed")?;
        self.entropy()?;
        let issued = self.issued()?;
        if at_least > issued {
            self.write(BOUNTY_INDEX, &at_least.to_be_bytes())?;
            return Ok(at_least);
        }
        Ok(issued)
    }
}

// Tauri commands (apps/mobile/modules/mesh-messenger/wallet.web.ts). They run off the
// main thread: keychain reads and PBKDF2 must not stall the window.

#[tauri::command(async)]
pub fn wallet_exists(wallet: tauri::State<Wallet>) -> Result<bool, String> {
    wallet.exists()
}

#[tauri::command(async)]
pub fn wallet_create(wallet: tauri::State<Wallet>, words: u8) -> Result<String, String> {
    Ok(wallet.create(words)?.to_string())
}

#[tauri::command(async)]
pub fn wallet_restore(wallet: tauri::State<Wallet>, phrase: String) -> Result<(), String> {
    let phrase = Zeroizing::new(phrase);
    wallet.restore(&phrase)
}

#[tauri::command(async)]
pub fn wallet_phrase(wallet: tauri::State<Wallet>) -> Result<String, String> {
    Ok(wallet.phrase()?.to_string())
}

#[tauri::command(async)]
pub fn wallet_wipe(wallet: tauri::State<Wallet>) -> Result<(), String> {
    wallet.wipe()
}

// The op rides in a header and the body is the raw IPC body, as for mesh_invoke.
#[tauri::command(async)]
pub fn wallet_call(wallet: tauri::State<Wallet>, request: Request<'_>) -> Result<Response, String> {
    let op = request
        .headers()
        .get("X-Wallet-Op")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or("bad_op")?;
    match request.body() {
        InvokeBody::Raw(body) if body.len() <= 65_000 => wallet.call(op, body).map(Response::new),
        _ => Err("bad_frame".into()),
    }
}

#[tauri::command(async)]
pub fn wallet_next_bounty_address(wallet: tauri::State<Wallet>) -> Result<Response, String> {
    wallet.next_bounty_address().map(Response::new)
}

#[tauri::command(async)]
pub fn wallet_bounty_index(wallet: tauri::State<Wallet>, at_least: u32) -> Result<u32, String> {
    wallet.bounty_index(at_least)
}

#[cfg(test)]
mod tests {
    use super::*;

    // "abandon ×11 about": wallet-core's solana-keygen known answers (src/derive.rs).
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ACCOUNT_0: &str = "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7";
    const BOUNTY_0: &str = "ba92bd3a778c98fe31f179da063d062c625339348f6a61f749c60287be95dae0";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // A wallet in a credential-store service of its own, deleted when the test ends.
    struct Scratch(Wallet);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = self.0.wipe();
        }
    }
    fn scratch(name: &str) -> Scratch {
        Scratch(Wallet::new(format!(
            "io.morseapp.desktop.tests.{}.wallet-{name}",
            std::process::id()
        )))
    }

    #[test]
    fn a_restored_wallet_derives_the_known_addresses_and_refuses_a_second_seed() {
        let wallet = scratch("restore");
        assert!(!wallet.0.exists().unwrap());
        assert_eq!(
            wallet.0.call(4, &[1, 0, 0, 0, 0]),
            Err("wallet_missing".into())
        );
        wallet.0.restore(PHRASE).unwrap();
        assert!(wallet.0.exists().unwrap());
        assert_eq!(hex(&wallet.0.call(4, &[1, 0, 0, 0, 0]).unwrap()), ACCOUNT_0);
        assert_eq!(*wallet.0.phrase().unwrap(), PHRASE);
        assert_eq!(wallet.0.restore(PHRASE), Err("wallet_exists".into()));
        assert_eq!(wallet.0.create(12).map(|_| ()), Err("wallet_exists".into()));
        wallet.0.wipe().unwrap();
        assert!(!wallet.0.exists().unwrap());
        // Twelve words whose checksum is wrong.
        let typo = PHRASE.replace("about", "abandon");
        assert_eq!(scratch("typo").0.restore(&typo), Err("bad_mnemonic".into()));
    }

    #[test]
    fn a_created_wallet_shows_its_phrase_once_and_again_on_request() {
        let wallet = scratch("create");
        let phrase = wallet.0.create(24).unwrap();
        assert_eq!(phrase.split(' ').count(), 24);
        assert_eq!(*wallet.0.phrase().unwrap(), *phrase);
        assert_eq!(
            scratch("words").0.create(13).map(|_| ()),
            Err("bad_word_count".into())
        );
    }

    #[test]
    fn bounty_addresses_are_issued_in_order_and_never_twice() {
        let wallet = scratch("bounty");
        wallet.0.restore(PHRASE).unwrap();
        // Nothing is issued yet: deriving bounty 0 is refused.
        assert_eq!(
            wallet.0.call(4, &[2, 0, 0, 0, 0]),
            Err("bounty_not_issued".into())
        );
        let first = wallet.0.next_bounty_address().unwrap();
        assert_eq!(hex(&first), format!("00000000{BOUNTY_0}"));
        assert_eq!(wallet.0.bounty_index(0).unwrap(), 1);
        assert_eq!(hex(&wallet.0.call(4, &[2, 0, 0, 0, 0]).unwrap()), BOUNTY_0);
        let second = wallet.0.next_bounty_address().unwrap();
        assert_eq!(second[..4], [0, 0, 0, 1]);
        assert_ne!(second[4..], first[4..]);
        // Raising never lowers.
        assert_eq!(wallet.0.bounty_index(9).unwrap(), 9);
        assert_eq!(wallet.0.bounty_index(3).unwrap(), 9);
        assert_eq!(wallet.0.next_bounty_address().unwrap()[..4], [0, 0, 0, 9]);
    }

    #[test]
    fn transfers_need_an_account_fee_payer_and_an_issued_bounty_owner() {
        let wallet = scratch("transfer");
        wallet.0.restore(PHRASE).unwrap();
        wallet.0.next_bounty_address().unwrap();
        let body = |owner: [u8; 5], fee_payer: [u8; 5]| {
            let mut body = [owner, fee_payer].concat();
            body.push(1); // SOL
            body.extend(5_000u64.to_be_bytes());
            body.extend([9; 32]); // recipient
            body.extend([0, 0]); // no account creation, no references
            body.extend([0, 0, 0, 0]); // no memo
            body.extend([0; 12]); // no compute budget
            body.extend([3; 32]); // blockhash
            body
        };
        let signed = wallet
            .0
            .call(5, &body([2, 0, 0, 0, 0], [1, 0, 0, 0, 0]))
            .unwrap();
        let signature = u32::from_be_bytes(signed[..4].try_into().unwrap()) as usize;
        assert!((64..=88).contains(&signature));
        assert_eq!(
            wallet.0.call(5, &body([2, 0, 0, 0, 1], [1, 0, 0, 0, 0])),
            Err("bounty_not_issued".into())
        );
        assert_eq!(
            wallet.0.call(5, &body([1, 0, 0, 0, 0], [2, 0, 0, 0, 0])),
            Err("fee_payer_not_account".into())
        );
        assert_eq!(wallet.0.call(3, &[]), Err("bad_op".into()));
    }

    #[test]
    fn pay_urls_parse_without_a_wallet() {
        let wallet = scratch("pay");
        let url = "solana:HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk?amount=1.5";
        let parsed = wallet.0.call(6, &vec32(url.as_bytes())).unwrap();
        assert_eq!(hex(&parsed[..32]), ACCOUNT_0);
        assert_eq!(parsed[32..42], [1, 0, 0, 0, 0, 0, 0, 0, 15, 1]);
        assert_eq!(
            wallet.0.call(6, &vec32(b"https://example.com")),
            Err("bad_url".into())
        );
    }
}
