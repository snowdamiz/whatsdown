use ed25519_dalek::{Signature, VerifyingKey};
use morse_judge::{
    checkpoint::Checkpoint,
    fork::{Fork, Position, Target},
};
use serde_json::Value;

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().unwrap()).unwrap()
}

fn signed(cp: &Checkpoint, key: &[u8]) -> bool {
    cp.service_key == key
        && VerifyingKey::from_bytes(&cp.service_key)
            .unwrap()
            .verify_strict(&cp.statement(), &Signature::from_bytes(&cp.signature))
            .is_ok()
}

#[test]
fn independent_mesh_oracle_agrees_on_framing_hashes_and_relations() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/fork-v1/vectors.json")).unwrap();
    let key = bytes(&fixture, "service_public_key");
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let wire = bytes(case, "wire_hex");
        let parsed = Fork::parse(&wire);
        assert_eq!(parsed.is_ok(), case["decode"].as_bool().unwrap(), "{name}");
        let Ok(proof) = parsed else { continue };
        assert_eq!(
            hex::encode(proof.hash()),
            case["proof_hash"].as_str().unwrap(),
            "{name}"
        );
        let first = Checkpoint::parse(proof.first).unwrap();
        let second = match proof.second {
            Target::Checkpoint(wire) => {
                let cp = Checkpoint::parse(wire).unwrap();
                (Position::from(&cp), signed(&cp, &key))
            }
            Target::Anchor(index) => {
                let anchor = &case["anchor"];
                if anchor.is_null() {
                    assert!(!case["valid"].as_bool().unwrap(), "{name}");
                    continue;
                }
                (
                    Position {
                        version: 1,
                        sequence: anchor["sequence"].as_str().unwrap().parse().unwrap(),
                        tree_size: anchor["tree_size"].as_str().unwrap().parse().unwrap(),
                        root: bytes(anchor, "tree_root").try_into().unwrap(),
                        hash: bytes(anchor, "checkpoint_hash").try_into().unwrap(),
                    },
                    index as u64 == anchor["ring_index"].as_u64().unwrap()
                        && bytes(anchor, "service_public_key") == key,
                )
            }
        };
        let valid = signed(&first, &key) && second.1 && proof.conflicts(&second.0).unwrap();
        assert_eq!(valid, case["valid"].as_bool().unwrap(), "{name}");
        // Every prefix of a valid frame must fail closed, including maximum
        // path/attestation framing. No parsing panics or implicit zero padding.
        for length in 0..wire.len() {
            assert!(Fork::parse(&wire[..length]).is_err(), "{name} at {length}");
        }
    }
}

#[test]
fn inclusion_requires_the_exact_path_under_each_hash_profile() {
    use morse_judge::fork::inclusion;
    use solana_sha256_hasher::hashv;
    let a = [3; 32];
    let b = [5; 32];
    let c = [7; 32];
    for version in [1, 2] {
        let prefix = if version == 1 {
            b"mesh-msg/v1/transparency-node".as_slice()
        } else {
            &[1]
        };
        let ab = hashv(&[prefix, &a, &b]).to_bytes();
        let root = hashv(&[prefix, &ab, &c]).to_bytes();
        assert!(inclusion(version, 2, 3, &c, &ab, &root));
        assert!(inclusion(version, 1, 3, &b, &[a, c].concat(), &root));
        assert!(!inclusion(version, 1, 3, &b, &a, &root));
        assert!(!inclusion(version, 2, 3, &c, &[ab, a].concat(), &root));
        assert!(!inclusion(version, 3, 3, &c, &ab, &root));
        assert!(!inclusion(version, 0, 0, &a, &[], &a));
        assert!(!inclusion(version, 0, u32::MAX as u64 + 1, &a, &[], &a));
    }
}
