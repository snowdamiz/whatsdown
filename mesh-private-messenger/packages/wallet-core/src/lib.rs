//! Morse's wallet core: holds the seed, derives keys and signs Solana transfers.
//!
//! Non-custodial and offline: no networking, no persistence, no global state. The host
//! stores the seed bytes in the platform keystore and passes them in on every call.
//! Blinding and unblinding of credits happen in mobile-core, never here.

mod derive;
mod ffi;
mod pay;
mod seed;
mod tx;

pub use derive::{keypair, KeyPath, BOUNTY_ACCOUNT};
pub use ffi::{morse_wallet_call, morse_wallet_free_bytes, MorseWalletBytes};
pub use pay::{parse_pay_url, Amount, PayRequest};
pub use seed::{entropy_from_phrase, generate_entropy, phrase, Seed};
pub use tx::{associated_token_address, sign_transfer, Asset, Pubkey, Signed, Transfer, USDC_MINT};

/// Every failure has a stable snake_case code; the C ABI returns it as the error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    WordCount,
    Entropy,
    Mnemonic,
    Random,
    Index,
    Amount,
    NotSpl,
    Reference,
    TooLarge,
    Url,
    UnknownParam,
    DuplicateParam,
    Base58,
    Decimals,
    Text,
    Frame,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Error::WordCount => "bad_word_count",
            Error::Entropy => "bad_entropy",
            Error::Mnemonic => "bad_mnemonic",
            Error::Random => "random_unavailable",
            Error::Index => "bad_index",
            Error::Amount => "bad_amount",
            Error::NotSpl => "account_creation_needs_spl",
            Error::Reference => "bad_reference",
            Error::TooLarge => "transaction_too_large",
            Error::Url => "bad_url",
            Error::UnknownParam => "unknown_param",
            Error::DuplicateParam => "duplicate_param",
            Error::Base58 => "bad_base58",
            Error::Decimals => "too_many_decimals",
            Error::Text => "bad_text",
            Error::Frame => "bad_frame",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
pub(crate) fn test_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
