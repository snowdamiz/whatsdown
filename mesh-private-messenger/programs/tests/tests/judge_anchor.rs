//! Config, timelock, logs, the ring, post_anchor, cosign and every Ed25519
//! introspection attack against them.

use morse_program_tests::*;

fn cp(env: &Env, service: &ed25519_dalek::SigningKey, seq: u64, size: u64, root_seed: u8) -> [u8; KTK_LEN] {
    ktk(service, seq, size, [root_seed; 32], env.now_ms())
}

#[test]
fn precompile_rejects_a_bad_signature() {
    // Sanity check of the harness: LiteSVM runs the Ed25519 precompile.
    let (mut env, service) = Env::new();
    let msg = b"hello".to_vec();
    let mut sig = [7u8; 64];
    sig[63] &= 0x0f;
    assert!(env.send(&[ed25519_ix(&[(&pubkey(&service), &msg, &sig)])], &[]).is_err());
}

#[test]
fn initialize_only_by_the_upgrade_authority_and_once() {
    let mut env = Env::bare();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let i = env.initialize_ix(&stranger.pubkey(), &env.gov.pubkey(), &[0; 32], 1, 1);
    assert_code(env.send(&[i], &[&stranger]), code::UNAUTHORIZED);
    assert_ok(env.initialize(1, 1));
    env.svm.expire_blockhash();
    assert!(env.initialize(1, 1).is_err());
    let d = env.data(&env.config());
    assert_eq!(d.len(), 192);
    assert_eq!(&d[8..40], env.gov.pubkey().as_ref());
    assert_eq!(&d[40..72], env.usdc.as_ref());
}

#[test]
fn parameter_changes_wait_fourteen_days() {
    let (mut env, _) = Env::new();
    let gov = env.gov.insecure_clone();
    let stranger = Keypair::new();
    let m = env.token_mint.to_bytes();
    assert_code(env.send(&[env.propose_ix(&stranger.pubkey(), 2, m)], &[&stranger]), code::UNAUTHORIZED);
    assert_code(env.send(&[env.apply_ix()], &[]), code::NO_PENDING_CHANGE);
    assert_ok(env.send(&[env.propose_ix(&gov.pubkey(), 2, m)], &[&gov]));
    env.advance(14 * DAY - 1, 10);
    assert_code(env.send(&[env.apply_ix()], &[]), code::TIMELOCK_ACTIVE);
    env.advance(1, 1);
    assert_ok(env.send(&[env.apply_ix()], &[]));
    assert_eq!(&env.data(&env.config())[72..104], env.token_mint.as_ref());
    // The token mint is set once.
    let other = Address::new_unique().to_bytes();
    assert_ok(env.send(&[env.propose_ix(&gov.pubkey(), 2, other)], &[&gov]));
    env.advance(14 * DAY, 10);
    assert_code(env.send(&[env.apply_ix()], &[]), code::INVALID_PARAMETER);
    // Minimum bond change, and cancel.
    let mut v = [0u8; 32];
    v[..8].copy_from_slice(&5u64.to_le_bytes());
    assert_ok(env.send(&[env.propose_ix(&gov.pubkey(), 4, v)], &[&gov]));
    assert_ok(env.send(&[env.propose_ix(&gov.pubkey(), 0, [0; 32])], &[&gov]));
    env.advance(15 * DAY, 10);
    assert_code(env.send(&[env.apply_ix()], &[]), code::NO_PENDING_CHANGE);
    env.govern(4, v);
    assert_eq!(u64le(&env.data(&env.config()), 136), 5);
}

#[test]
fn register_log_needs_governance_and_creates_the_locked_vault() {
    let mut env = Env::bare();
    assert_ok(env.initialize(1, 1));
    let stranger = Keypair::new();
    let i = env.register_log_ix(MAIN, &[9; 32], &env.anchor.pubkey(), &stranger.pubkey(), 0);
    assert_code(env.send(&[i], &[&stranger]), code::UNAUTHORIZED);
    assert_ok(env.register_log(MAIN, &key(9)));
    let l = env.log_data(MAIN);
    assert_eq!(l.len(), layout::LOG_LEN);
    assert_eq!(&l[16..48], &log_id(MAIN));
    assert_eq!(&l[112..144], env.ring(MAIN).as_ref());
    assert_eq!(&l[144..176], env.dir_vault(MAIN).as_ref());
    assert_eq!(&l[176..208], env.locked(MAIN).as_ref());
    let locked = env.data(&env.locked(MAIN));
    assert_eq!(&locked[0..32], env.usdc.as_ref());
    assert_eq!(&locked[32..64], env.locked(MAIN).as_ref(), "locked vault is its own authority");
}

#[test]
fn ring_grows_in_ten_kilobyte_steps_and_is_unusable_until_full() {
    let mut env = Env::bare();
    assert_ok(env.initialize(1, 1));
    let service = key(0x51);
    assert_ok(env.register_log(MAIN, &service));
    assert_ok(env.send(&[env.grow_ring_ix(MAIN)], &[]));
    assert_eq!(env.data(&env.ring(MAIN)).len(), 10_240);
    assert_eq!(&env.data(&env.ring(MAIN))[..32], &log_id(MAIN));
    let k = cp(&env, &service, 1, 1, 1);
    assert_code(env.post(MAIN, &service, &k), code::RING_NOT_READY);
    env.grow_ring_full(MAIN);
    assert_eq!(env.data(&env.ring(MAIN)).len(), layout::RING_LEN);
    assert_code(env.send(&[env.grow_ring_ix(MAIN)], &[]), code::RING_ALREADY_GROWN);
    let rent = env.svm.minimum_balance_for_rent_exemption(layout::RING_LEN);
    assert!(env.svm.get_account(&env.ring(MAIN)).unwrap().lamports >= rent);
    assert_ok(env.post(MAIN, &service, &k));
}

#[test]
fn post_anchor_writes_the_entry_and_header() {
    let (mut env, service) = Env::new();
    let k = cp(&env, &service, 7, 100, 3);
    assert_ok(env.post(MAIN, &service, &k));
    let r = env.data(&env.ring(MAIN));
    let e = layout::ring_entry(0);
    assert_eq!(u64le(&r, e), 7);
    assert_eq!(u64le(&r, e + 8), 100);
    assert_eq!(&r[e + 16..e + 48], &[3; 32]);
    assert_eq!(&r[e + 48..e + 80], &checkpoint_hash(&k));
    assert_eq!(u64le(&r, e + 80), env.now_ms());
    assert_eq!(u64le(&r, e + 88), env.slot);
    assert_eq!(r[e + 98], 0);
    assert_eq!(u32le(&r, e + 100) as i64, env.now / EPOCH);
    assert_eq!(u32le(&r, layout::RH_HEAD), 1);
    assert_eq!(u32le(&r, layout::RH_COUNT), 1);
    assert_eq!(u64le(&r, layout::RH_LAST_SEQUENCE), 7);
    assert_eq!(u64le(&r, layout::RH_LAST_SIZE), 100);
    assert_eq!(u64le(&r, layout::RH_LAST_SLOT), env.slot);
    let l = env.log_data(MAIN);
    let slot = layout::LOG_ANCHOR_COUNTS + ((env.now / EPOCH) % 4) as usize * 16;
    assert_eq!(u64le(&l, slot) as i64, env.now / EPOCH);
    assert_eq!(u64le(&l, slot + 8), 1);
}

#[test]
fn post_anchor_order_rules() {
    let (mut env, service) = Env::new();
    let first = cp(&env, &service, 10, 100, 1);
    assert_ok(env.post(MAIN, &service, &first));
    // Exact repost: refused (idempotent retry signal).
    assert_code(env.post(MAIN, &service, &first), code::DUPLICATE_ANCHOR);
    // Refresh: newer sequence, same size and root.
    env.advance(60, 150);
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 11, 100, 1)));
    // Stale: both older.
    assert_code(env.post(MAIN, &service, &cp(&env, &service, 9, 90, 9)), code::STALE_ANCHOR);
    // Rollback: newer sequence, smaller tree -> stored as F3 evidence.
    env.advance(60, 150);
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 12, 50, 2)));
    // Same sequence, other content -> F3 evidence.
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 11, 120, 4)));
    // Same size, other root -> F1 evidence.
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 13, 100, 5)));
    // Normal growth continues from the tip (seq 11, size 100).
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 14, 101, 6)));
    let r = env.data(&env.ring(MAIN));
    let flags: Vec<u8> = (0..6).map(|i| r[layout::ring_entry(i) + 98]).collect();
    assert_eq!(flags, vec![0, 0, 3, 3, 1, 0]);
    assert_eq!(u64le(&r, layout::RH_LAST_SEQUENCE), 14);
    assert_eq!(u64le(&r, layout::RH_LAST_SIZE), 101);
    let l = env.log_data(MAIN);
    let slot = layout::LOG_ANCHOR_COUNTS + ((env.now / EPOCH) % 4) as usize * 16;
    assert_eq!(u64le(&l, slot + 8), 3, "evidence entries are not counted as anchors");
}

#[test]
fn post_anchor_refuses_other_signers_and_keys() {
    let (mut env, service) = Env::new();
    let k = cp(&env, &service, 1, 1, 1);
    let stranger = Keypair::new();
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&k), &ktk_sig(&k))]);
    let post = env.post_anchor_ix(MAIN, &stranger.pubkey(), 0, &k);
    assert_code(env.send(&[ed, post], &[&stranger]), code::UNAUTHORIZED);
    // A checkpoint signed by another key.
    let other = key(0x77);
    let k2 = ktk(&other, 1, 1, [1; 32], env.now_ms());
    assert_code(env.post(MAIN, &other, &k2), code::INVALID_CHECKPOINT);
}

#[test]
fn anchor_authority_rotation_by_governance() {
    let (mut env, service) = Env::new();
    let new = Keypair::new();
    let gov = env.gov.insecure_clone();
    let i = env.set_anchor_authority_ix(MAIN, &gov.pubkey(), &new.pubkey());
    assert_ok(env.send(&[i], &[&gov]));
    assert_eq!(&env.log_data(MAIN)[80..112], new.pubkey().as_ref());
    let k = cp(&env, &service, 1, 1, 1);
    assert_code(env.post(MAIN, &service, &k), code::UNAUTHORIZED);
    env.anchor = new;
    assert_ok(env.post(MAIN, &service, &k));
}

// ------------------------------------------------ Ed25519 introspection attacks

fn anchored(env: &mut Env, service: &ed25519_dalek::SigningKey) -> [u8; KTK_LEN] {
    cp(env, service, 5, 50, 5)
}

#[test]
fn introspection_instruction_missing() {
    let (mut env, service) = Env::new();
    let k = anchored(&mut env, &service);
    let a = env.anchor.insecure_clone();
    // ed_ix points at the judge instruction itself.
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k);
    assert_code(env.send(&[post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
    // ed_ix out of range.
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 5, &k);
    assert_code(env.send(&[post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_instruction_in_another_transaction() {
    let (mut env, service) = Env::new();
    let k = anchored(&mut env, &service);
    let a = env.anchor.insecure_clone();
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&k), &ktk_sig(&k))]);
    assert_ok(env.send(&[ed], &[]));
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k);
    assert_code(env.send(&[post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_offsets_into_another_instruction() {
    let (mut env, service) = Env::new();
    let a = env.anchor.insecure_clone();
    // A checkpoint the service never signed, with made-up signature bytes.
    let mut forged = cp(&env, &service, 8, 80, 8);
    forged[124..188].copy_from_slice(&[0x42; 64]);
    // Instruction 1 genuinely verifies some other signed checkpoint. The entry
    // in instruction 0 points (instruction index 1) at those bytes, so the
    // precompile passes, while instruction 0's own data holds the forged
    // statement at the same offsets.
    let decoy = cp(&env, &service, 99, 999, 9);
    let genuine = ed25519_ix(&[(&pubkey(&service), &statement(&decoy), &ktk_sig(&decoy))]);
    let mut pointer = vec![1u8, 0];
    for v in [48u16, 1, 16, 1, 112, 146, 1] {
        pointer.extend_from_slice(&v.to_le_bytes());
    }
    pointer.extend_from_slice(&pubkey(&service));
    pointer.extend_from_slice(&ktk_sig(&forged));
    pointer.extend_from_slice(&statement(&forged));
    let pointer = Instruction { program_id: ED25519, accounts: vec![], data: pointer };
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &forged);
    assert_code(env.send(&[pointer, genuine, post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_instruction_of_another_program() {
    let (mut env, service) = Env::new();
    let a = env.anchor.insecure_clone();
    let mut forged = cp(&env, &service, 8, 80, 8);
    forged[124..188].copy_from_slice(&[0x42; 64]);
    // A successful instruction of another program (the judge's `apply`,
    // which ignores trailing data) laid out like an Ed25519 instruction
    // whose self-contained entry holds the forged statement.
    let gov = env.gov.insecure_clone();
    assert_ok(env.send(&[env.propose_ix(&gov.pubkey(), 3, [7; 32])], &[&gov]));
    env.advance(14 * DAY, 10);
    let mut mimic = vec![ix::APPLY, 0]; // count byte = 2 entries
    for v in [62u16, 0xFFFF, 30, 0xFFFF, 126, 146, 0xFFFF] {
        mimic.extend_from_slice(&v.to_le_bytes());
    }
    mimic.extend_from_slice(&[0; 14]);
    mimic.extend_from_slice(&pubkey(&service));
    mimic.extend_from_slice(&ktk_sig(&forged));
    mimic.extend_from_slice(&statement(&forged));
    let mut apply = env.apply_ix();
    apply.data = mimic;
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &forged);
    assert_code(env.send(&[apply, post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_offsets_pointing_at_other_data() {
    let (mut env, service) = Env::new();
    let k = anchored(&mut env, &service);
    let a = env.anchor.insecure_clone();
    // The entry verifies another checkpoint; the expected statement sits in
    // the same instruction data, but not where the entry points.
    let decoy = cp(&env, &service, 99, 999, 9);
    let mut ed = ed25519_ix(&[(&pubkey(&service), &statement(&decoy), &ktk_sig(&decoy))]);
    ed.data.extend_from_slice(&statement(&k));
    ed.data.extend_from_slice(&ktk_sig(&k));
    let post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k);
    assert_code(env.send(&[ed, post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_different_message_key_or_signature() {
    let (mut env, service) = Env::new();
    let k = anchored(&mut env, &service);
    let a = env.anchor.insecure_clone();
    let other_cp = cp(&env, &service, 6, 60, 6);
    // Different message (a valid signature over another statement).
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&other_cp), &ktk_sig(&other_cp))]);
    assert_code(env.send(&[ed, env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k)], &[&a]), code::SIGNATURE_NOT_VERIFIED);
    // Different key signing the right statement.
    let other = key(0x66);
    let ed = ed25519_sign(&other, &statement(&k));
    assert_code(env.send(&[ed, env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k)], &[&a]), code::SIGNATURE_NOT_VERIFIED);
    // KTK carries other signature bytes than the ones verified.
    let mut forged = k;
    forged[124..188].copy_from_slice(&ktk_sig(&other_cp));
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&k), &ktk_sig(&k))]);
    assert_code(env.send(&[ed, env.post_anchor_ix(MAIN, &a.pubkey(), 0, &forged)], &[&a]), code::SIGNATURE_NOT_VERIFIED);
    // A message that is a prefix of the statement (length must match).
    let st = statement(&k);
    let sig = ed25519_dalek::Signer::sign(&service, &st[..145]).to_bytes();
    let ed = ed25519_ix(&[(&pubkey(&service), &st[..145], &sig)]);
    assert_code(env.send(&[ed, env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k)], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

#[test]
fn introspection_fake_instructions_sysvar() {
    let (mut env, service) = Env::new();
    let k = anchored(&mut env, &service);
    let a = env.anchor.insecure_clone();
    let fake = Address::new_unique();
    env.svm
        .set_account(fake, solana_account::Account { lamports: 1_000_000, data: vec![0; 64], owner: SYSTEM, executable: false, rent_epoch: 0 })
        .unwrap();
    let mut post = env.post_anchor_ix(MAIN, &a.pubkey(), 0, &k);
    post.accounts[3] = AccountMeta::new_readonly(fake, false);
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&k), &ktk_sig(&k))]);
    assert_code(env.send(&[ed, post], &[&a]), code::SIGNATURE_NOT_VERIFIED);
}

// ------------------------------------------------ cosign

fn witnessed() -> (Env, ed25519_dalek::SigningKey, Witness, Witness) {
    let (mut env, service) = Env::new();
    let a = env.witness(MAIN, "witness-a", 0xA1);
    let b = env.witness(MAIN, "witness-b", 0xB2);
    assert_ok(env.register(MAIN, &a, false));
    assert_ok(env.register(MAIN, &b, false));
    (env, service, a, b)
}

#[test]
fn cosign_sets_the_bit_and_counts_attendance_once() {
    let (mut env, service, a, b) = witnessed();
    let k = cp(&env, &service, 1, 10, 1);
    assert_ok(env.post(MAIN, &service, &k));
    assert_ok(env.cosign(MAIN, 0, 1, &b));
    assert_ok(env.cosign(MAIN, 0, 0, &a));
    assert_ok(env.cosign(MAIN, 0, 1, &b)); // repeat is a no-op
    let r = env.data(&env.ring(MAIN));
    assert_eq!(u16::from_le_bytes([r[layout::ring_entry(0) + 96], r[layout::ring_entry(0) + 97]]), 0b11);
    let w = env.data(&b.account(&env.judge));
    let slot = layout::W_COSIGN_COUNTS + ((env.now / EPOCH) % 4) as usize * 16;
    assert_eq!(u64le(&w, slot) as i64, env.now / EPOCH);
    assert_eq!(u64le(&w, slot + 8), 1);
}

#[test]
fn cosign_outside_the_window_is_refused() {
    let (mut env, service, a, _) = witnessed();
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 1, 10, 1)));
    env.advance(600, 1_500);
    assert_ok(env.cosign(MAIN, 0, 0, &a)); // slot posted + 1,500: still on time
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 2, 11, 1)));
    env.advance(601, 1_501);
    assert_code(env.cosign(MAIN, 1, 0, &a), code::COSIGN_WINDOW_CLOSED);
}

#[test]
fn cosign_refuses_wrong_witness_signature_or_index() {
    let (mut env, service, a, b) = witnessed();
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 1, 10, 1)));
    let hash: [u8; 32] = env.data(&env.ring(MAIN))[layout::ring_entry(0) + 48..][..32].try_into().unwrap();
    // b's signature presented for a's slot.
    let sig = witness_sig(&b.key, &b.id, &hash);
    let ed = ed25519_ix(&[(&pubkey(&b.key), &witness_msg(&b.id, &hash), &sig)]);
    let c = env.cosign_ix(MAIN, 0, 0, &a.account(&env.judge), 0);
    assert_code(env.send(&[ed, c], &[]), code::SIGNATURE_NOT_VERIFIED);
    // a's key over a statement naming b's id.
    let sig = witness_sig(&a.key, &b.id, &hash);
    let ed = ed25519_ix(&[(&pubkey(&a.key), &witness_msg(&b.id, &hash), &sig)]);
    let c = env.cosign_ix(MAIN, 0, 0, &a.account(&env.judge), 0);
    assert_code(env.send(&[ed, c], &[]), code::SIGNATURE_NOT_VERIFIED);
    // Witness account that is not the one in the list slot.
    let sig = witness_sig(&a.key, &a.id, &hash);
    let ed = ed25519_ix(&[(&pubkey(&a.key), &witness_msg(&a.id, &hash), &sig)]);
    let c = env.cosign_ix(MAIN, 0, 0, &b.account(&env.judge), 0);
    assert_code(env.send(&[ed, c], &[]), code::WRONG_ACCOUNT);
    // Ring index never written.
    assert_code(env.cosign(MAIN, 7, 0, &a), code::RING_INDEX_INVALID);
}

#[test]
fn ring_wraps_after_4096_entries() {
    let (mut env, service) = Env::new();
    // Fast-forward the header to the last slot, as if 4,095 entries existed.
    let ring = env.ring(MAIN);
    let mut acct = env.svm.get_account(&ring).unwrap();
    acct.data[32..36].copy_from_slice(&4095u32.to_le_bytes());
    acct.data[36..40].copy_from_slice(&4095u32.to_le_bytes());
    env.svm.set_account(ring, acct).unwrap();
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 1, 1, 1)));
    env.advance(60, 150);
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 2, 2, 1)));
    let r = env.data(&ring);
    assert_eq!(u32le(&r, layout::RH_HEAD), 1);
    assert_eq!(u32le(&r, layout::RH_COUNT), 4096);
    assert_eq!(u64le(&r, layout::ring_entry(4095)), 1);
    assert_eq!(u64le(&r, layout::ring_entry(0)), 2);
}

#[test]
fn four_cosigns_fit_one_legacy_transaction() {
    let (mut env, service) = Env::new();
    let ws: Vec<Witness> = (0..4).map(|i| env.witness(MAIN, &format!("witness-{i}"), 0x30 + i as u8)).collect();
    for w in &ws {
        assert_ok(env.register(MAIN, w, false));
    }
    assert_ok(env.post(MAIN, &service, &cp(&env, &service, 1, 10, 1)));
    let hash: [u8; 32] = env.data(&env.ring(MAIN))[layout::ring_entry(0) + 48..][..32].try_into().unwrap();
    let msgs: Vec<Vec<u8>> = ws.iter().map(|w| witness_msg(&w.id, &hash)).collect();
    let sigs: Vec<[u8; 64]> = ws.iter().map(|w| witness_sig(&w.key, &w.id, &hash)).collect();
    let keys: Vec<[u8; 32]> = ws.iter().map(|w| pubkey(&w.key)).collect();
    let entries: Vec<(&[u8; 32], &[u8], &[u8; 64])> = (0..4).map(|i| (&keys[i], msgs[i].as_slice(), &sigs[i])).collect();
    let mut ixs = vec![ed25519_ix(&entries)];
    for (i, w) in ws.iter().enumerate() {
        ixs.push(env.cosign_ix(MAIN, 0, i as u8, &w.account(&env.judge), 0));
    }
    let size = env.wire_size(&ixs);
    assert!(size <= 1232, "{size} bytes");
    assert_ok(env.send(&ixs, &[]));
    let r = env.data(&env.ring(MAIN));
    assert_eq!(r[layout::ring_entry(0) + 96], 0b1111);
}
