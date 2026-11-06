use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let mut bytes = mac.finalize().into_bytes();
    let mut result = Zeroizing::new([0; 64]);
    result.copy_from_slice(&bytes);
    bytes.zeroize();
    result
}

/// SLIP0010 hardened Ed25519 derivation. Private, fixed wallet paths only;
/// callers supply the unhardened numeric index, and this sets the high bit.
pub(crate) fn derive(seed: &[u8], path: &[u32]) -> Zeroizing<[u8; 32]> {
    assert!((16..=64).contains(&seed.len()) && path.len() <= 8);
    let mut node = hmac(b"ed25519 seed", seed);
    for index in path {
        assert!(*index < 1 << 31);
        let mut input = Zeroizing::new([0; 37]);
        input[1..33].copy_from_slice(&node[..32]);
        input[33..].copy_from_slice(&(index | (1 << 31)).to_be_bytes());
        node = hmac(&node[32..], &*input);
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&node[..32]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slip10_ed25519_published_vector_master_and_hardened_child() {
        // Published test seed, never a funded wallet.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let expected =
            hex::decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
                .unwrap();
        assert!(
            derive(&seed, &[]).as_slice() == expected.as_slice(),
            "SLIP0010 master mismatch"
        );
        let paths = [
            vec![0],
            vec![0, 1],
            vec![0, 1, 2],
            vec![0, 1, 2, 2],
            vec![0, 1, 2, 2, 1000000000],
        ];
        let expected = [
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        ];
        for (path, expected) in paths.iter().zip(expected) {
            assert!(
                derive(&seed, path).as_slice() == hex::decode(expected).unwrap().as_slice(),
                "SLIP0010 child mismatch"
            );
        }
    }
}
