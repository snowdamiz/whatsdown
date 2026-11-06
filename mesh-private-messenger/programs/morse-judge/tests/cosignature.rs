use ed25519_dalek::{Signature, VerifyingKey};
use morse_judge::witness::c2sp_statement;

#[test]
fn c2sp_bytes_match_independent_openssl_and_mesh_at_full_u64_timestamp() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/fork-v1/anchor-checkpoints.json"
    ))
    .unwrap();
    let fixture = &fixtures[1];
    let wire = hex::decode(fixture["wire"].as_str().unwrap()).unwrap();
    let message = c2sp_statement(b"morseapp.io/log/main/v2", &wire, u64::MAX).unwrap();
    let expected = hex::decode(fixture["witness"]["c2spStatement"].as_str().unwrap()).unwrap();
    assert_eq!(message.as_slice(), expected);
    let key = hex::decode(fixture["witness"]["publicKey"].as_str().unwrap()).unwrap();
    let signature = hex::decode(fixture["witness"]["c2spSignature"].as_str().unwrap()).unwrap();
    VerifyingKey::from_bytes(&key.try_into().unwrap())
        .unwrap()
        .verify_strict(
            message.as_slice(),
            &Signature::from_slice(&signature[8..]).unwrap(),
        )
        .unwrap();
    let mut legacy = wire.clone();
    legacy[0] = 1;
    assert!(c2sp_statement(b"morseapp.io/log/main/v2", &legacy, 0).is_err());
    for origin in [b"".as_slice(), b"bad\norigin", b"bad+origin", &[b'a'; 129]] {
        assert!(c2sp_statement(origin, &wire, 0).is_err());
    }
    let mut too_large = wire.clone();
    too_large[12..20].copy_from_slice(&4294967296u64.to_be_bytes());
    assert!(c2sp_statement(b"morseapp.io/log/main/v2", &too_large, 0).is_err());
    let mut empty = wire.clone();
    empty[12..20].fill(0);
    assert!(c2sp_statement(b"morseapp.io/log/main/v2", &empty, 0).is_err());
    empty[20..52].copy_from_slice(&solana_sha256_hasher::hash(&[]).to_bytes());
    assert!(c2sp_statement(b"morseapp.io/log/main/v2", &empty, 0).is_ok());
    let mut largest = wire.clone();
    largest[12..20].copy_from_slice(&(u32::MAX as u64).to_be_bytes());
    assert!(
        c2sp_statement(&[b'a'; 128], &largest, u64::MAX)
            .unwrap()
            .as_slice()
            .len()
            <= 512
    );
}
