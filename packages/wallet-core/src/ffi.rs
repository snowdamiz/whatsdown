//! The C ABI: one entry point taking a request frame and returning a response frame, in the
//! style of the Mesh mobile library boundary. The frame format is in README.md ("C ABI").

use crate::{
    derive::keypair, entropy_from_phrase, generate_entropy, parse_pay_url, phrase, sign_transfer,
    Asset, Error, KeyPath, Pubkey, Seed, Transfer,
};
use std::{panic, ptr, slice};
use zeroize::{Zeroize, Zeroizing};

/// Bytes returned to the host. Release with `morse_wallet_free_bytes`, which wipes them.
#[repr(C)]
pub struct MorseWalletBytes {
    pub data: *mut u8,
    pub len: u64,
}

const OK: i32 = 0;
const ERR_INVALID_ARGUMENT: i32 = 1;
const ERR_PANIC: i32 = 4;
const ERR_APPLICATION: i32 = 9;
const MAX_REQUEST: u64 = 65_536;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Frame);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn vec32(&mut self) -> Result<&'a [u8], Error> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(len as usize)
    }

    fn text(&mut self) -> Result<&'a str, Error> {
        std::str::from_utf8(self.vec32()?).map_err(|_| Error::Frame)
    }

    fn path(&mut self) -> Result<KeyPath, Error> {
        let kind = self.u8()?;
        let index = u32::from_be_bytes(self.array()?);
        match kind {
            1 => Ok(KeyPath::Account(index)),
            2 => Ok(KeyPath::Bounty(index)),
            _ => Err(Error::Frame),
        }
    }

    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Frame)
        }
    }
}

fn put_vec32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn dispatch(request: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut r = Reader(request);
    if r.u8()? != 1 {
        return Err(Error::Frame);
    }
    // Sized up front so secret responses never leave copies behind in reallocations.
    let mut out = Zeroizing::new(Vec::with_capacity(4096));
    match r.u8()? {
        1 => {
            let words = r.u8()?;
            r.end()?;
            let entropy = generate_entropy(words)?;
            put_vec32(&mut out, &entropy);
            put_vec32(&mut out, phrase(&entropy)?.as_bytes());
        }
        2 => {
            let typed = r.text()?;
            r.end()?;
            out.extend_from_slice(&entropy_from_phrase(typed)?);
        }
        3 => {
            let entropy = r.vec32()?;
            r.end()?;
            out.extend_from_slice(phrase(entropy)?.as_bytes());
        }
        4 => {
            let (entropy, path) = (r.vec32()?, r.path()?);
            r.end()?;
            let key = keypair(&Seed::from_entropy(entropy)?, path)?;
            out.extend_from_slice(key.verifying_key().as_bytes());
        }
        5 => transfer(&mut r, &mut out)?,
        6 => {
            let url = r.text()?;
            r.end()?;
            let request = parse_pay_url(url)?;
            out.extend_from_slice(&request.recipient);
            match request.amount {
                Some(amount) => {
                    out.push(1);
                    out.extend_from_slice(&amount.mantissa.to_be_bytes());
                    out.push(amount.scale);
                }
                None => out.push(0),
            }
            match request.spl_token {
                Some(mint) => {
                    out.push(1);
                    out.extend_from_slice(&mint);
                }
                None => out.push(0),
            }
            out.push(u8::try_from(request.references.len()).map_err(|_| Error::Url)?);
            request
                .references
                .iter()
                .for_each(|k| out.extend_from_slice(k));
            for text in [request.label, request.message, request.memo] {
                put_vec32(&mut out, text.unwrap_or_default().as_bytes());
            }
        }
        _ => return Err(Error::Frame),
    }
    Ok(out)
}

fn transfer(r: &mut Reader, out: &mut Vec<u8>) -> Result<(), Error> {
    let entropy = r.vec32()?;
    let (owner, fee_payer) = (r.path()?, r.path()?);
    let asset = match r.u8()? {
        1 => Asset::Sol,
        2 => Asset::Spl {
            mint: r.array()?,
            decimals: r.u8()?,
        },
        _ => return Err(Error::Frame),
    };
    let amount = u64::from_be_bytes(r.array()?);
    let recipient = r.array()?;
    let create_recipient_account = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::Frame),
    };
    let count = r.u8()? as usize;
    let references: Vec<Pubkey> = (0..count).map(|_| r.array()).collect::<Result<_, _>>()?;
    let memo = r.text()?;
    let compute_unit_limit = u32::from_be_bytes(r.array()?);
    let compute_unit_price = u64::from_be_bytes(r.array()?);
    let recent_blockhash = r.array()?;
    r.end()?;

    let seed = Seed::from_entropy(entropy)?;
    let signed = sign_transfer(
        &keypair(&seed, owner)?,
        &keypair(&seed, fee_payer)?,
        &Transfer {
            asset,
            amount,
            recipient,
            create_recipient_account,
            references: &references,
            memo: (!memo.is_empty()).then_some(memo),
            compute_unit_limit: (compute_unit_limit != 0).then_some(compute_unit_limit),
            compute_unit_price: (compute_unit_price != 0).then_some(compute_unit_price),
            recent_blockhash,
        },
    )?;
    put_vec32(out, signed.signature_base58.as_bytes());
    put_vec32(out, signed.transaction_base64.as_bytes());
    Ok(())
}

/// Runs one request frame. On return `*response` holds the response frame (status 0) or a
/// UTF-8 error code (status 9), and must be released with `morse_wallet_free_bytes`.
///
/// # Safety
/// `request` must point to `request_len` readable bytes (it may be null when the length is 0)
/// and `response` to writable memory for one `MorseWalletBytes`.
#[no_mangle]
pub unsafe extern "C" fn morse_wallet_call(
    request: *const u8,
    request_len: u64,
    response: *mut MorseWalletBytes,
) -> i32 {
    if response.is_null() || (request.is_null() && request_len != 0) || request_len > MAX_REQUEST {
        return ERR_INVALID_ARGUMENT;
    }
    let request = if request_len == 0 {
        &[][..]
    } else {
        // SAFETY: non-null, and the caller guarantees `request_len` readable bytes.
        unsafe { slice::from_raw_parts(request, request_len as usize) }
    };
    let (status, body) = match panic::catch_unwind(|| dispatch(request)) {
        Ok(Ok(body)) => (OK, body),
        Ok(Err(error)) => (
            ERR_APPLICATION,
            Zeroizing::new(error.code().as_bytes().to_vec()),
        ),
        Err(_) => (ERR_PANIC, Zeroizing::new(Vec::new())),
    };
    let bytes = if body.is_empty() {
        MorseWalletBytes {
            data: ptr::null_mut(),
            len: 0,
        }
    } else {
        let boxed: Box<[u8]> = Box::from(&body[..]);
        let len = boxed.len() as u64;
        MorseWalletBytes {
            data: Box::into_raw(boxed).cast(),
            len,
        }
    };
    // SAFETY: non-null, and the caller guarantees it is writable.
    unsafe { response.write(bytes) };
    status
}

/// Wipes and frees bytes returned by `morse_wallet_call`, then sets them to null/0.
/// Null, empty and already-freed values are ignored.
///
/// # Safety
/// `bytes` must be null or point to a `MorseWalletBytes` last filled by `morse_wallet_call`.
#[no_mangle]
pub unsafe extern "C" fn morse_wallet_free_bytes(bytes: *mut MorseWalletBytes) {
    // SAFETY: the caller guarantees a valid pointer or null.
    let Some(bytes) = (unsafe { bytes.as_mut() }) else {
        return;
    };
    if !bytes.data.is_null() && bytes.len > 0 {
        // SAFETY: `data`/`len` came from `Box<[u8]>::into_raw` in `morse_wallet_call`.
        let mut boxed = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                bytes.data,
                bytes.len as usize,
            ))
        };
        boxed.zeroize();
    }
    bytes.data = ptr::null_mut();
    bytes.len = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(request: &[u8]) -> (i32, Vec<u8>) {
        let mut out = MorseWalletBytes {
            data: ptr::null_mut(),
            len: 0,
        };
        let status = unsafe { morse_wallet_call(request.as_ptr(), request.len() as u64, &mut out) };
        let body = if out.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out.data, out.len as usize) }.to_vec()
        };
        unsafe { morse_wallet_free_bytes(&mut out) };
        assert!(out.data.is_null() && out.len == 0);
        (status, body)
    }

    fn vec32(bytes: &[u8]) -> Vec<u8> {
        [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat()
    }

    fn read_vec32(body: &mut &[u8]) -> Vec<u8> {
        let len = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
        let value = body[4..4 + len].to_vec();
        *body = &body[4 + len..];
        value
    }

    fn b58(s: &str) -> Vec<u8> {
        bs58::decode(s).into_vec().unwrap()
    }

    const ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn wallet_lifecycle_through_the_abi() {
        let (status, body) = call(&[1, 1, 24]);
        assert_eq!(status, OK);
        let mut rest = &body[..];
        let entropy = read_vec32(&mut rest);
        let words = read_vec32(&mut rest);
        assert!(rest.is_empty());
        assert_eq!(entropy.len(), 32);

        assert_eq!(
            call(&[&[1, 3][..], &vec32(&entropy)].concat()),
            (OK, words.clone())
        );
        assert_eq!(call(&[&[1, 2][..], &vec32(&words)].concat()), (OK, entropy));

        let restored = call(&[&[1, 2][..], &vec32(ABOUT.as_bytes())].concat());
        assert_eq!(restored, (OK, vec![0; 16]));
        let address = |kind: u8, index: u32| {
            call(&[&[1, 4][..], &vec32(&[0; 16]), &[kind], &index.to_be_bytes()].concat())
        };
        assert_eq!(
            address(1, 0),
            (OK, b58("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"))
        );
        assert_eq!(
            address(2, 7),
            (OK, b58("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5"))
        );
    }

    #[test]
    fn signs_a_quote_payment_through_the_abi() {
        // Same inputs as tx::full_quote_payment_matches_the_solana_rust_sdk.
        let request = [
            &[1u8, 5][..],
            &vec32(&[0; 16]),
            &[1],
            &0u32.to_be_bytes(), // owner: account 0
            &[1],
            &0u32.to_be_bytes(), // fee payer: account 0
            &[2],
            &b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            &[6],
            &5_000_000u64.to_be_bytes(),
            &b58("DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo"),
            &[1],
            &[2],
            &b58("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5"),
            &b58("Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"),
            &vec32(b"Morse credits: 100 pack"),
            &20_000u32.to_be_bytes(),
            &50_000u64.to_be_bytes(),
            &b58("4PG9L5JD4KUbqTamRMG8s8muqgUiQH5QrfcKPjmLLR48"),
        ]
        .concat();
        let (status, body) = call(&request);
        assert_eq!(status, OK, "{}", String::from_utf8_lossy(&body));
        let mut rest = &body[..];
        assert_eq!(read_vec32(&mut rest), b"2McUeZRpszHVNGm98BrMYyfmZDSMQatmrTHcRSJgXGWjiyKiLzXQGcTnnpXWB6KtxV5wWke1qCrXSwzbEWJhq6kz");
        assert!(read_vec32(&mut rest).starts_with(b"AUPKrgBj5L3ewWMHJ9fUGE21"));
        assert!(rest.is_empty());
    }

    #[test]
    fn parses_a_pay_url_through_the_abi() {
        let url = "solana:DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo?amount=12.5&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&reference=H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5&label=Morse&memo=q1";
        let expected = [
            &b58("DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo")[..],
            &[1],
            &125u64.to_be_bytes(),
            &[1],
            &[1],
            &b58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            &[1],
            &b58("H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5"),
            &vec32(b"Morse"),
            &vec32(b""),
            &vec32(b"q1"),
        ]
        .concat();
        assert_eq!(
            call(&[&[1, 6][..], &vec32(url.as_bytes())].concat()),
            (OK, expected)
        );

        let bare = "solana:DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo";
        let expected = [
            &b58(&bare[7..])[..],
            &[0, 0, 0],
            &vec32(b""),
            &vec32(b""),
            &vec32(b""),
        ]
        .concat();
        assert_eq!(
            call(&[&[1, 6][..], &vec32(bare.as_bytes())].concat()),
            (OK, expected)
        );
    }

    #[test]
    fn application_errors_return_their_code() {
        assert_eq!(
            call(&[1, 1, 15]),
            (ERR_APPLICATION, b"bad_word_count".to_vec())
        );
        assert_eq!(
            call(&[&[1, 6][..], &vec32(b"bitcoin:x")].concat()),
            (ERR_APPLICATION, b"bad_url".to_vec())
        );
    }

    #[test]
    fn rejects_malformed_frames() {
        let address = [&[1u8, 4][..], &vec32(&[0; 16]), &[1], &0u32.to_be_bytes()].concat();
        assert_eq!(call(&address).0, OK);
        let bad = |frame: &[u8]| {
            assert_eq!(
                call(frame),
                (ERR_APPLICATION, b"bad_frame".to_vec()),
                "{frame:?}"
            )
        };
        bad(&[]);
        bad(&[2, 1, 12]); // unknown version
        bad(&[1, 99]); // unknown op
        bad(&address[..address.len() - 1]); // truncated
        bad(&[&address[..], &[0]].concat()); // trailing byte
        bad(&[&address[..22], &[3], &address[23..]].concat()); // unknown key kind
        bad(&[&[1u8, 2][..], &u32::MAX.to_be_bytes()].concat()); // length past the end
        bad(&[&[1u8, 2][..], &vec32(&[0xff, 0xfe])].concat()); // phrase not UTF-8
    }

    #[test]
    fn rejects_bad_arguments() {
        let mut out = MorseWalletBytes {
            data: ptr::null_mut(),
            len: 0,
        };
        unsafe {
            assert_eq!(
                morse_wallet_call([1u8, 1, 12].as_ptr(), 3, ptr::null_mut()),
                ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                morse_wallet_call(ptr::null(), 3, &mut out),
                ERR_INVALID_ARGUMENT
            );
            let big = vec![0u8; MAX_REQUEST as usize + 1];
            assert_eq!(
                morse_wallet_call(big.as_ptr(), big.len() as u64, &mut out),
                ERR_INVALID_ARGUMENT
            );
            morse_wallet_free_bytes(ptr::null_mut());
            morse_wallet_free_bytes(&mut out);
        }
    }

    #[test]
    fn header_matches_the_exports() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/include");
        let source = "#include \"morse_wallet.h\"\n\
            int32_t (*call)(const uint8_t *, uint64_t, MorseWalletBytes *) = morse_wallet_call;\n\
            void (*release)(MorseWalletBytes *) = morse_wallet_free_bytes;\n\
            _Static_assert(MORSE_WALLET_OK == 0 && MORSE_WALLET_ERR_INVALID_ARGUMENT == 1 && MORSE_WALLET_ERR_PANIC == 4 && MORSE_WALLET_ERR_APPLICATION == 9, \"codes\");\n\
            _Static_assert(sizeof(MorseWalletBytes) == 16, \"layout\");\n";
        let mut cc = std::process::Command::new("cc")
            .args([
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsyntax-only",
                "-x",
                "c",
                "-",
                "-I",
                dir,
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut cc.stdin.take().unwrap(), source.as_bytes()).unwrap();
        assert!(cc.wait().unwrap().success());
    }
}
