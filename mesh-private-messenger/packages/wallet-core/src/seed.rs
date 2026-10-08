//! BIP39 (English, 12 or 24 words). The host stores the mnemonic's entropy (16 or 32 bytes)
//! in the platform keystore: it is the smallest form of the seed and still lets the app show
//! the recovery phrase again.

use crate::Error;
use bip39::{Language, Mnemonic};
use std::fmt::Write;
use zeroize::Zeroizing;

/// Fresh entropy from the OS for a 12- or 24-word wallet.
pub fn generate_entropy(words: u8) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(Error::WordCount),
    };
    let mut entropy = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut entropy).map_err(|_| Error::Random)?;
    Ok(entropy)
}

fn mnemonic(entropy: &[u8]) -> Result<Mnemonic, Error> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err(Error::Entropy);
    }
    Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| Error::Entropy)
}

/// The recovery phrase for stored entropy.
pub fn phrase(entropy: &[u8]) -> Result<Zeroizing<String>, Error> {
    // 24 words of at most 8 letters plus spaces fit, so the string never reallocates.
    let mut words = Zeroizing::new(String::with_capacity(24 * 9));
    write!(words, "{}", mnemonic(entropy)?).map_err(|_| Error::Entropy)?;
    Ok(words)
}

/// Entropy from a typed recovery phrase. Case and runs of whitespace are forgiven; the words,
/// their count (12 or 24) and the checksum are not.
pub fn entropy_from_phrase(phrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let typed = Zeroizing::new(phrase.to_ascii_lowercase());
    if !matches!(typed.split_whitespace().count(), 12 | 24) {
        return Err(Error::WordCount);
    }
    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &typed).map_err(|_| Error::Mnemonic)?;
    let (bytes, len) = mnemonic.to_entropy_array();
    let bytes = Zeroizing::new(bytes);
    Ok(Zeroizing::new(bytes[..len].to_vec()))
}

/// The 64-byte BIP39 seed (empty passphrase, as Phantom and Solflare use), wiped on drop.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        Ok(Seed(Zeroizing::new(
            mnemonic(entropy)?.to_seed_normalized(""),
        )))
    }

    pub(crate) fn bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_hex as hex;

    const ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TITLE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

    #[test]
    fn known_phrases_and_seeds() {
        // BIP39 reference vectors; seeds (empty passphrase) from Python's hashlib.pbkdf2_hmac.
        for (entropy, words, seed) in [
            (vec![0u8; 16], ABOUT, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"),
            (vec![0x7f; 32], TITLE, "761914478ebf6fe16185749372e91549361af22b386de46322cf8b1ba7e92e80c4af05196f742be1e63aab603899842ddadf4e7248d8e43870a4b6ff9bf16324"),
        ] {
            assert_eq!(phrase(&entropy).unwrap().as_str(), words);
            assert_eq!(*entropy_from_phrase(words).unwrap(), entropy);
            assert_eq!(Seed::from_entropy(&entropy).unwrap().bytes()[..], hex(seed)[..]);
        }
    }

    #[test]
    fn generated_entropy_is_fresh_and_restorable() {
        for (words, len) in [(12, 16), (24, 32)] {
            let a = generate_entropy(words).unwrap();
            let b = generate_entropy(words).unwrap();
            assert_eq!(a.len(), len);
            assert_ne!(a, b);
            let typed = phrase(&a).unwrap();
            assert_eq!(typed.split(' ').count(), words as usize);
            assert_eq!(entropy_from_phrase(&typed).unwrap(), a);
        }
    }

    #[test]
    fn typed_phrase_forgives_case_and_spacing() {
        let typed = format!("  Abandon\tABANDON {}\n", &ABOUT[16..]);
        assert_eq!(*entropy_from_phrase(&typed).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn only_12_or_24_words() {
        assert_eq!(generate_entropy(15).unwrap_err(), Error::WordCount);
        let fifteen = format!("{ABOUT} abandon abandon abandon");
        assert_eq!(entropy_from_phrase(&fifteen).unwrap_err(), Error::WordCount);
    }

    #[test]
    fn only_16_or_32_bytes_of_entropy() {
        for len in [0, 15, 20, 24, 33] {
            assert_eq!(phrase(&vec![1; len]).unwrap_err(), Error::Entropy);
            assert_eq!(
                Seed::from_entropy(&vec![1; len]).err(),
                Some(Error::Entropy)
            );
        }
    }

    #[test]
    fn rejects_bad_checksum_and_unknown_words() {
        let bad_checksum = ABOUT.replace("about", "abandon");
        let unknown = ABOUT.replace("about", "aboutt");
        for typed in [bad_checksum, unknown] {
            assert_eq!(entropy_from_phrase(&typed).unwrap_err(), Error::Mnemonic);
        }
    }
}
