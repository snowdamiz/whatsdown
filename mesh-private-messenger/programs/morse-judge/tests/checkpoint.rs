use ed25519_dalek::{Signature, VerifyingKey};
use morse_judge::checkpoint::{matches_ed25519_instruction, Checkpoint};

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../tests/fixtures/fork-v1/vectors.json")).unwrap()
}

fn signed_instruction(key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut instruction = vec![1, 0];
    for value in [
        48,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        instruction.extend_from_slice(&value.to_le_bytes());
    }
    instruction.extend_from_slice(key);
    instruction.extend_from_slice(signature);
    instruction.extend_from_slice(message);
    instruction
}

#[test]
fn judge_reconstructs_mesh_statements_from_independent_signed_fork_vectors() {
    let data = fixtures();
    let mut checked = 0;
    for vector in data["cases"].as_array().unwrap() {
        if vector["valid"] != true || vector["decode"] != true {
            continue;
        }
        let wire = hex::decode(vector["wire_hex"].as_str().unwrap()).unwrap();
        let first = Checkpoint::parse(&wire[69..257]).unwrap();
        let key = VerifyingKey::from_bytes(&first.service_key).unwrap();
        key.verify_strict(&first.statement(), &Signature::from_bytes(&first.signature))
            .unwrap_or_else(|_| panic!("{}", vector["name"]));
        let instruction =
            signed_instruction(&first.service_key, &first.signature, &first.statement());
        assert!(matches_ed25519_instruction(
            &instruction,
            &first.service_key,
            &first.signature,
            &first.statement()
        ));
        checked += 1;
    }
    assert!(checked >= 10);
    let wire = hex::decode(data["cases"][0]["wire_hex"].as_str().unwrap()).unwrap();
    let first = Checkpoint::parse(&wire[69..257]).unwrap();
    assert_eq!(
        hex::encode(first.hash()),
        "d9716cab59fd613a865fa80ead34ace56e1e05d0b87a4cd647220ca1ee11fb38"
    );
    assert_eq!(
        (first.sequence, first.tree_size, first.timestamp),
        (10, 3, 1000)
    );
}

#[test]
fn both_log_versions_match_openssl_and_mesh_including_unsigned_maximum() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/fork-v1/anchor-checkpoints.json"
    ))
    .unwrap();
    let mut versions = [false; 2];
    for fixture in fixtures.as_array().unwrap() {
        let wire = hex::decode(fixture["wire"].as_str().unwrap()).unwrap();
        let checkpoint = Checkpoint::parse(&wire).unwrap();
        versions[checkpoint.version as usize - 1] = true;
        assert_eq!(checkpoint.sequence, u64::MAX);
        assert_eq!(hex::encode(checkpoint.statement()), fixture["statement"]);
        assert_eq!(hex::encode(checkpoint.hash()), fixture["hash"]);
        VerifyingKey::from_bytes(&checkpoint.service_key)
            .unwrap()
            .verify_strict(
                &checkpoint.statement(),
                &Signature::from_bytes(&checkpoint.signature),
            )
            .unwrap();
    }
    assert_eq!(versions, [true, true]);
}

#[test]
fn only_the_canonical_exact_precompile_statement_matches() {
    let wire = hex::decode(fixtures()["cases"][0]["wire_hex"].as_str().unwrap()).unwrap();
    let first = Checkpoint::parse(&wire[69..257]).unwrap();
    let valid = signed_instruction(&first.service_key, &first.signature, &first.statement());
    // Includes count, padding, every offset/index/length byte, key, signature,
    // and every signed field. No byte may be substituted or redirected.
    for position in 0..valid.len() {
        let mut attack = valid.clone();
        attack[position] ^= 1;
        assert!(
            !matches_ed25519_instruction(
                &attack,
                &first.service_key,
                &first.signature,
                &first.statement()
            ),
            "changed byte {position}"
        );
    }
    for length in 0..valid.len() {
        assert!(!matches_ed25519_instruction(
            &valid[..length],
            &first.service_key,
            &first.signature,
            &first.statement()
        ));
    }
    let mut trailing = valid;
    trailing.push(0);
    assert!(!matches_ed25519_instruction(
        &trailing,
        &first.service_key,
        &first.signature,
        &first.statement()
    ));
}

#[test]
fn checkpoints_require_exact_wire_version_and_length() {
    let wire = hex::decode(fixtures()["cases"][0]["wire_hex"].as_str().unwrap()).unwrap();
    let valid = &wire[69..257];
    for length in 0..valid.len() {
        assert!(Checkpoint::parse(&valid[..length]).is_err());
    }
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(Checkpoint::parse(&trailing).is_err());
    for offset in 0..4 {
        let mut attack = valid.to_vec();
        attack[offset] = 0;
        assert!(Checkpoint::parse(&attack).is_err());
    }
    let mut maximum = valid.to_vec();
    maximum[4..20].fill(255);
    let parsed = Checkpoint::parse(&maximum).unwrap();
    assert_eq!((parsed.sequence, parsed.tree_size), (u64::MAX, u64::MAX));
}
