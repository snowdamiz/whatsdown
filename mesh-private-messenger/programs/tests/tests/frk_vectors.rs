//! Replays the Mesh `FRK` vectors (`tests/fixtures/frk/*.json`, written by
//! `Transparency.Fork`) through the on-chain judge: every valid proof must
//! slash exactly the directory and the implicated witnesses, every invalid
//! one must be refused and change nothing, and the proof hash must match.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use morse_program_tests::*;
use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/frk");
const MIN: u64 = 1_000_000_000;
const DIR: u64 = 10_000_000_000;

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

type Entry = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Every signature the proof carries that verifies off-chain, as a relay
/// would collect them for Ed25519 instructions.
fn signatures(frk: &[u8], service: &[u8; 32], witness_keys: &[(String, [u8; 32])]) -> Vec<Entry> {
    let mut out = vec![];
    let mut push = |pk: &[u8; 32], msg: Vec<u8>, sig: &[u8]| {
        let ok = VerifyingKey::from_bytes(pk).ok().is_some_and(|k| k.verify_strict(&msg, &Signature::from_slice(sig).unwrap()).is_ok());
        if ok {
            out.push((pk.to_vec(), msg, sig.to_vec()));
        }
    };
    let ktk_at = |o: usize| -> [u8; KTK_LEN] { frk[o..o + KTK_LEN].try_into().unwrap() };
    let c1 = ktk_at(69);
    push(service, statement(&c1), &c1[124..188]);
    let mut at = 257;
    if frk[at] == 0 {
        let c2 = ktk_at(258);
        push(service, statement(&c2), &c2[124..188]);
        at += 1 + KTK_LEN;
    } else {
        at += 5;
    }
    let count = frk[at] as usize;
    at += 1;
    for _ in 0..count {
        let len = frk[at] as usize;
        let id = std::str::from_utf8(&frk[at + 1..at + 1 + len]).unwrap().to_string();
        let hash: [u8; 32] = frk[at + 1 + len..at + 33 + len].try_into().unwrap();
        let sig = &frk[at + 33 + len..at + 97 + len];
        if let Some((_, pk)) = witness_keys.iter().find(|(w, _)| *w == id) {
            push(pk, witness_msg(&id, &hash), sig);
        }
        at += 97 + len;
    }
    out
}

fn expected_refusal(name: &str) -> Option<u32> {
    match name {
        "tampered-signature" => Some(code::SIGNATURE_NOT_VERIFIED),
        "wrong-service-key" => Some(code::WRONG_LOG_KEY),
        n if n.starts_with("honest-") || n == "tampered-path" || n == "wrong-kind" => Some(code::NOT_A_FORK),
        _ => None,
    }
}

fn replay(v: &Value) {
    let name = v["name"].as_str().unwrap();
    let frk = hex::decode(v["frk"].as_str().unwrap()).unwrap();
    let kind = v["kind"].as_u64().unwrap() as u8;
    let mut env = Env::bare();
    // Checkpoint timestamps are in the vectors: judge them an hour later.
    let ts = if frk.len() >= 161 { u64::from_be_bytes(frk[153..161].try_into().unwrap()) } else { START as u64 * 1000 };
    env.set_clock((ts / 1000) as i64 + 3600, 50_000);
    assert_ok(env.initialize(MIN, MIN));
    let service = SigningKey::from_bytes(&hex32(&v["log"]["service_seed"]));
    assert_eq!(pubkey(&service), hex32(&v["log"]["service_public_key"]), "{name}: service key");
    assert_ok(env.register_log(MAIN, &service));
    env.grow_ring_full(MAIN);
    let usdc = env.usdc;
    assert_ok(env.bond_directory(MAIN, &usdc, DIR));
    let mut witnesses = vec![];
    for w in v["log"]["witnesses"].as_array().unwrap() {
        let id = w["witness_id"].as_str().unwrap();
        let mut wit = env.witness(MAIN, id, 0);
        wit.key = SigningKey::from_bytes(&hex32(&w["seed"]));
        assert_eq!(pubkey(&wit.key), hex32(&w["public_key"]), "{name}: key of {id}");
        assert_ok(env.register(MAIN, &wit, false));
        assert_ok(env.bond(MAIN, &wit, &usdc, MIN));
        witnesses.push(wit);
    }
    if let Some(r) = v["ring"].as_object() {
        // The anchored entry as post_anchor and cosign would have left it.
        let index = r["ring_index"].as_u64().unwrap() as u32;
        let ring = env.ring(MAIN);
        let mut acct = env.svm.get_account(&ring).unwrap();
        let o = layout::ring_entry(index);
        let d = &mut acct.data;
        d[o..o + 8].copy_from_slice(&r["sequence"].as_str().unwrap().parse::<u64>().unwrap().to_le_bytes());
        d[o + 8..o + 16].copy_from_slice(&r["tree_size"].as_str().unwrap().parse::<u64>().unwrap().to_le_bytes());
        d[o + 16..o + 48].copy_from_slice(&hex32(&r["root"]));
        d[o + 48..o + 80].copy_from_slice(&hex32(&r["checkpoint_hash"]));
        d[o + 80..o + 88].copy_from_slice(&ts.to_le_bytes());
        d[o + 88..o + 96].copy_from_slice(&env.slot.to_le_bytes());
        d[o + 96..o + 98].copy_from_slice(&(r["cosign_bitmap"].as_u64().unwrap() as u16).to_le_bytes());
        d[32..36].copy_from_slice(&(index + 1).to_le_bytes());
        d[36..40].copy_from_slice(&(index + 1).to_le_bytes());
        env.svm.set_account(ring, acct).unwrap();
    }

    let submitter = Keypair::new();
    env.svm.airdrop(&submitter.pubkey(), 100_000_000_000).unwrap();
    let finder = hex32(&v["finder"]);
    let payee = if finder == [0; 32] { submitter.pubkey() } else { Address::new_from_array(finder) };
    let payee_account = env.fund(&payee, &usdc, 0);
    let before = env.log_data(MAIN);

    if !v["decodes"].as_bool().unwrap() {
        let accounts = env.prove_accounts(MAIN, &submitter.pubkey(), &[0; 32], None, &payee_account, &payee_account, &[]);
        let p = env.prove_inline_ix(kind.clamp(1, 3), accounts, 0, &frk);
        assert_code(env.send(&[p], &[&submitter]), code::FRK_MALFORMED);
        return;
    }
    let hash = proof_hash(&frk);
    assert_eq!(hash, hex32(&v["proof_hash"]), "{name}: proof hash");
    let keys: Vec<(String, [u8; 32])> = witnesses.iter().map(|w| (w.id.clone(), pubkey(&w.key))).collect();
    let entries = signatures(&frk, &pubkey(&service), &keys);
    let stage = env.stage_proof(MAIN, &submitter, 0, &frk, &entries);
    let implicated: Vec<&str> = v["implicated"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let pairs: Vec<(Address, Address)> =
        witnesses.iter().filter(|w| implicated.contains(&w.id.as_str())).map(|w| (w.account(&env.judge), w.vault(&env.judge))).collect();
    let accounts = env.prove_accounts(MAIN, &submitter.pubkey(), &hash, Some(&stage), &payee_account, &payee_account, &pairs);
    let p = env.prove_staged_ix(kind, accounts);
    let res = env.send(&[compute_budget(1_400_000), p], &[&submitter]);
    if v["valid"].as_bool().unwrap() {
        assert_ok(res);
        assert_eq!(env.log_data(MAIN)[layout::LOG_SERVICE_SLASHED], 1, "{name}");
        for w in &witnesses {
            let want = if implicated.contains(&w.id.as_str()) { layout::SLASHED } else { layout::ACTIVE };
            assert_eq!(env.witness_status(w), want, "{name}: status of {}", w.id);
        }
        let paid = DIR / 10 + implicated.len() as u64 * (MIN / 10);
        assert_eq!(env.balance(&payee_account), paid, "{name}: finder share");
        assert!(env.exists(&env.proof(&hash)), "{name}: pay-once record");
    } else {
        match expected_refusal(name) {
            Some(c) => assert_code(res, c),
            None => assert!(res.is_err(), "{name}: invalid proof accepted"),
        }
        assert_eq!(env.log_data(MAIN), before, "{name}: refused proof changed the log");
    }
}

#[test]
fn mesh_frk_vectors_replay_on_chain() {
    let Ok(dir) = std::fs::read_dir(FIXTURES) else {
        eprintln!("no Mesh FRK vectors at {FIXTURES}; nothing to replay");
        return;
    };
    let mut paths: Vec<_> = dir.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    paths.sort();
    let (mut valid, mut refused) = (0, 0);
    for p in &paths {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        replay(&v);
        if v["valid"].as_bool().unwrap() {
            valid += 1;
        } else {
            refused += 1;
        }
    }
    eprintln!("replayed {} Mesh FRK vectors: {valid} valid, {refused} refused", paths.len());
    assert!(valid >= 1 && refused >= 1, "expected both valid and invalid vectors");
}
