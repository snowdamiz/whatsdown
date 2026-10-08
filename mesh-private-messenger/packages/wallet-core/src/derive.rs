//! SLIP-0010 Ed25519 derivation (hardened only) and Morse's two path families:
//!
//! - accounts `m/44'/501'/i'/0'`, what Phantom, Solflare and `solana-keygen` use;
//! - bounty addresses `m/44'/501'/2147483646'/n'`, one per fork proof, never reused.

use crate::{seed::Seed, Error};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

const HARDENED: u32 = 0x8000_0000;

/// The account-level index reserved for bounty addresses. Accounts below it are ordinary
/// wallet accounts; this one and 2^31 - 1 above it are never offered as accounts.
pub const BOUNTY_ACCOUNT: u32 = 0x7FFF_FFFE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPath {
    /// `m/44'/501'/i'/0'`, i < 2147483646.
    Account(u32),
    /// `m/44'/501'/2147483646'/n'`, n < 2^31.
    Bounty(u32),
}

impl KeyPath {
    fn indexes(self) -> Result<[u32; 4], Error> {
        match self {
            KeyPath::Account(i) if i < BOUNTY_ACCOUNT => Ok([44, 501, i, 0]),
            KeyPath::Bounty(n) if n < HARDENED => Ok([44, 501, BOUNTY_ACCOUNT, n]),
            _ => Err(Error::Index),
        }
    }
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// SLIP-0010 master key and hardened children (indexes below 2^31, hardened here): returns
/// (private key, chain code).
fn slip10(seed: &[u8], path: &[u32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    let mut i = hmac_sha512(b"ed25519 seed", &[seed]);
    for index in path {
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        i = hmac_sha512(
            &chain[..],
            &[&[0], &key[..], &(index | HARDENED).to_be_bytes()],
        );
    }
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    (key, chain)
}

/// The Ed25519 key at `path`. The key is wiped when dropped.
pub fn keypair(seed: &Seed, path: KeyPath) -> Result<SigningKey, Error> {
    let (key, _) = slip10(seed.bytes(), &path.indexes()?);
    Ok(SigningKey::from_bytes(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_hex as hex;

    fn check(seed: &str, chains: &[(&[u32], &str, &str, &str)]) {
        for (path, chain, private, public) in chains {
            let (key, code) = slip10(&hex(seed), path);
            assert_eq!(code[..], hex(chain)[..], "chain code {path:?}");
            assert_eq!(key[..], hex(private)[..], "private {path:?}");
            let verifying = SigningKey::from_bytes(&key).verifying_key();
            assert_eq!([&[0u8][..], verifying.as_bytes()].concat(), hex(public));
        }
    }

    #[test]
    fn slip10_ed25519_test_vector_1() {
        check(
            "000102030405060708090a0b0c0d0e0f",
            &[
                (
                    &[],
                    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                ),
                (
                    &[0],
                    "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                ),
                (
                    &[0, 1],
                    "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                ),
                (
                    &[0, 1, 2],
                    "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                ),
                (
                    &[0, 1, 2, 2],
                    "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                ),
                (
                    &[0, 1, 2, 2, 1_000_000_000],
                    "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                ),
            ],
        );
    }

    #[test]
    fn slip10_ed25519_test_vector_2() {
        check("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", &[
            (&[], "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"),
            (&[0], "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"),
            (&[0, 2147483647], "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"),
            (&[0, 2147483647, 1], "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90", "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c", "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"),
            (&[0, 2147483647, 1, 2147483646], "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a", "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72", "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"),
            (&[0, 2147483647, 1, 2147483646, 2], "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4", "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d", "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"),
        ]);
    }

    #[test]
    fn matches_solana_keygen_for_the_abandon_mnemonic() {
        // `solana-keygen recover 'prompt://?key=0/0'` (and `?full-path=m/44/501/2147483646/7`)
        // with "abandon ×11 about", no passphrase; solana-cli 4.1.1.
        let seed = Seed::from_entropy(&[0; 16]).unwrap();
        for (path, secret, address) in [
            (
                KeyPath::Account(0),
                "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
                "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
            ),
            (
                KeyPath::Account(1),
                "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4",
                "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb",
            ),
            (
                KeyPath::Bounty(0),
                "e7649bd07b9a9016937afc210bf4f49021552897ed4f44e1b8de5d412f9e8c72",
                "DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo",
            ),
            (
                KeyPath::Bounty(7),
                "57895c77b29d176442ee4575a3a1a7462e07faaf0bbadeb49a58793e1b76ef7a",
                "H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5",
            ),
        ] {
            let key = keypair(&seed, path).unwrap();
            assert_eq!(key.to_bytes()[..], hex(secret)[..], "{path:?}");
            assert_eq!(
                bs58::encode(key.verifying_key().as_bytes()).into_string(),
                address
            );
        }
    }

    #[test]
    fn account_indexes_stop_below_the_bounty_branch() {
        let seed = Seed::from_entropy(&[0; 16]).unwrap();
        assert!(keypair(&seed, KeyPath::Account(BOUNTY_ACCOUNT - 1)).is_ok());
        for i in [BOUNTY_ACCOUNT, BOUNTY_ACCOUNT + 1, u32::MAX] {
            assert_eq!(
                keypair(&seed, KeyPath::Account(i)).err(),
                Some(Error::Index)
            );
        }
    }

    #[test]
    fn bounty_indexes_are_below_2_pow_31() {
        let seed = Seed::from_entropy(&[0; 16]).unwrap();
        assert!(keypair(&seed, KeyPath::Bounty(HARDENED - 1)).is_ok());
        assert_eq!(
            keypair(&seed, KeyPath::Bounty(HARDENED)).err(),
            Some(Error::Index)
        );
    }
}
