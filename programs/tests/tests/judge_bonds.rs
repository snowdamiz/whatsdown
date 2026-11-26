//! Witness registration, bonds, unbonding and withdrawal.

use morse_program_tests::*;

const MIN: u64 = 1_000_000_000; // Env::new() minimum for new bonds (both mints)

#[test]
fn register_witness_records_the_witness_and_list_entry() {
    let (mut env, _) = Env::new();
    let w = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &w, true));
    let d = env.data(&w.account(&env.judge));
    assert_eq!(d.len(), 336);
    assert_eq!(d[0], 3);
    assert_eq!(d[layout::W_STATUS], layout::REGISTERED);
    assert_eq!(d[layout::W_EXCLUDED], 1);
    assert_eq!(d[7] as usize, w.id.len());
    assert_eq!(&d[8..8 + w.id.len()], w.id.as_bytes());
    assert_eq!(&d[72..104], env.log(MAIN).as_ref());
    assert_eq!(&d[104..136], &pubkey(&w.key));
    assert_eq!(&d[136..168], w.operator.pubkey().as_ref());
    assert_eq!(&d[168..200], w.payout.pubkey().as_ref());
    assert_eq!(&d[232..264], w.vault(&env.judge).as_ref());
    let l = env.log_data(MAIN);
    assert_eq!(l[layout::LOG_WITNESS_COUNT], 1);
    let e = layout::LOG_LIST;
    assert_eq!(l[e] as usize, w.id.len());
    assert_eq!(&l[e + 1..e + 1 + w.id.len()], w.id.as_bytes());
    assert_eq!(&l[e + 72..e + 104], &pubkey(&w.key));
    assert_eq!(&l[e + 104..e + 136], w.account(&env.judge).as_ref());
    assert_eq!(u64le(&l, e + 136), env.slot);
}

#[test]
fn register_witness_refusals() {
    let (mut env, _) = Env::new();
    let w = env.witness(MAIN, "witness-a", 0xA1);
    let op = w.operator.insecure_clone();
    // Proof of key control over another payout address.
    let mut other = Env::register_msg(&w);
    let n = other.len();
    other[n - 1] ^= 1;
    let ed = ed25519_sign(&w.key, &other);
    let r = env.register_witness_ix(MAIN, &w, 0, 0);
    assert_code(env.send(&[ed, r], &[&op]), code::SIGNATURE_NOT_VERIFIED);
    // Someone else's key (signed by the attacker's own key).
    let mut thief = env.witness(MAIN, "witness-t", 0x77);
    thief.key = key(0x77);
    let victim_key = pubkey(&w.key);
    let ed = ed25519_sign(&thief.key, &Env::register_msg(&thief));
    let mut r = env.register_witness_ix(MAIN, &thief, 0, 0);
    r.data[1..33].copy_from_slice(&victim_key);
    let top = thief.operator.insecure_clone();
    assert_code(env.send(&[ed, r], &[&top]), code::SIGNATURE_NOT_VERIFIED);
    // Bad IDs.
    let bad = env.witness(MAIN, "Witness_A", 0xA2);
    assert_code(env.register_only(MAIN, &bad, false), code::INVALID_WITNESS_ID);
    // Registered but not admitted: not in the list.
    assert_ok(env.register_only(MAIN, &w, false));
    assert_eq!(env.data(&w.account(&env.judge))[5], 0xFF);
    assert_eq!(env.log_data(MAIN)[layout::LOG_WITNESS_COUNT], 0);
    // The same ID twice.
    let again = Witness { id: w.id.clone(), key: key(0xA9), operator: Keypair::new(), payout: Keypair::new(), log: w.log };
    env.svm.airdrop(&again.operator.pubkey(), 10_000_000_000).unwrap();
    assert!(env.register_only(MAIN, &again, false).is_err());
}

#[test]
fn admission_is_governance_only_once_and_can_exclude() {
    let (mut env, _) = Env::new();
    let w = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register_only(MAIN, &w, false));
    let stranger = Keypair::new();
    let i = env.admit_witness_ix(MAIN, &w.account(&env.judge), &stranger.pubkey(), 0xFF, 0, &env.judge);
    assert_code(env.send(&[i], &[&stranger]), code::UNAUTHORIZED);
    assert_ok(env.admit(MAIN, &w, 0xFF, true, env.judge));
    let d = env.data(&w.account(&env.judge));
    assert_eq!((d[5], d[layout::W_EXCLUDED]), (0, 1), "listed at 0 and excluded by governance");
    assert_code(env.admit(MAIN, &w, 0xFF, false, env.judge), code::INVALID_STATUS);
    // A second ID with the same signing key cannot be listed.
    let dup = env.witness(MAIN, "witness-dup", 0xA1);
    assert_ok(env.register_only(MAIN, &dup, false));
    assert_code(env.admit(MAIN, &dup, 0xFF, false, env.judge), code::DUPLICATE_SIGNING_KEY);
    // A witness of another log cannot be listed here.
    let canary = key(0xCA);
    assert_ok(env.register_log(CANARY, &canary));
    let t = env.witness(CANARY, "t1", 0x11);
    assert_ok(env.register_only(CANARY, &t, false));
    let gov = env.gov.insecure_clone();
    let i = env.admit_witness_ix(MAIN, &t.account(&env.judge), &gov.pubkey(), 0xFF, 0, &env.judge);
    assert_code(env.send(&[i], &[&gov]), code::WRONG_ACCOUNT);
}

#[test]
fn list_holds_sixteen_and_slots_are_reused_only_after_exit() {
    let (mut env, service) = Env::new();
    let ws: Vec<Witness> = (0..16).map(|i| env.witness(MAIN, &format!("w{i}"), 10 + i as u8)).collect();
    for w in &ws {
        assert_ok(env.register(MAIN, w, false));
    }
    let extra = env.witness(MAIN, "w16", 99);
    assert_code(env.register(MAIN, &extra, false), code::WITNESS_LIST_FULL);
    let old = ws[3].account(&env.judge);
    assert_code(env.register_replacing(MAIN, &extra, false, 3, old), code::SLOT_NOT_REUSABLE);
    // An anchor posted before the replacement.
    assert_ok(env.post(MAIN, &service, &ktk(&service, 1, 1, [1; 32], env.now_ms())));
    assert_ok(env.bond(MAIN, &ws[3], &env.usdc.clone(), MIN));
    assert_ok(env.unbond_witness(MAIN, &ws[3]));
    env.advance(30 * DAY, 10);
    assert_ok(env.withdraw_witness(MAIN, &ws[3], &env.usdc.clone()));
    assert_ok(env.register_replacing(MAIN, &extra, false, 3, old));
    let l = env.log_data(MAIN);
    let e = layout::LOG_LIST + 3 * layout::ENTRY_LEN;
    assert_eq!(&l[e + 1..e + 4], b"w16");
    assert_eq!(l[e + 4], 0, "old id bytes cleared");
    assert_eq!(&l[e + 104..e + 136], extra.account(&env.judge).as_ref());
    assert_eq!(l[layout::LOG_WITNESS_COUNT], 16);
    assert_eq!(env.data(&old)[5], 0xFF, "replaced witness is no longer listed");
    assert_eq!(env.data(&extra.account(&env.judge))[5], 3);
    // The new occupant cannot cosign an entry posted before it arrived.
    assert_code(env.cosign(MAIN, 0, 3, &extra), code::RING_INDEX_INVALID);
}

#[test]
fn bond_reaches_the_minimum_then_tops_up() {
    let (mut env, _) = Env::new();
    let usdc = env.usdc;
    let w = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &w, false));
    assert_code(env.bond(MAIN, &w, &usdc, MIN - 1), code::BOND_BELOW_MINIMUM);
    assert_code(env.bond(MAIN, &w, &usdc, 0), code::AMOUNT_ZERO);
    assert_ok(env.bond(MAIN, &w, &usdc, MIN));
    assert_eq!(env.witness_status(&w), layout::ACTIVE);
    assert_ok(env.bond(MAIN, &w, &usdc, 5));
    let vault = env.data(&w.vault(&env.judge));
    assert_eq!(&vault[0..32], usdc.as_ref());
    assert_eq!(&vault[32..64], w.vault(&env.judge).as_ref(), "vault is its own authority");
    assert_eq!(env.balance(&w.vault(&env.judge)), MIN + 5);
    // The token is refused until governance sets it, then accepted for new bonds.
    let tm = env.token_mint;
    let t = env.witness(MAIN, "witness-t", 0xA3);
    assert_ok(env.register(MAIN, &t, false));
    assert_code(env.bond(MAIN, &t, &tm, MIN), code::MINT_NOT_ALLOWED);
    env.set_token_mint();
    assert_ok(env.bond(MAIN, &t, &tm, MIN));
    // A vault keeps its first mint.
    assert_code(env.bond(MAIN, &t, &usdc, 1), code::MINT_NOT_ALLOWED);
}

#[test]
fn only_the_operator_bonds_and_unbonds() {
    let (mut env, _) = Env::new();
    let usdc = env.usdc;
    let w = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &w, false));
    let mallory = Keypair::new();
    env.svm.airdrop(&mallory.pubkey(), 10_000_000_000).unwrap();
    env.fund(&mallory.pubkey(), &usdc, MIN);
    let mut i = env.bond_ix(MAIN, &w, &usdc, MIN);
    i.accounts[0] = AccountMeta::new(mallory.pubkey(), true);
    i.accounts[6] = AccountMeta::new(ata(&mallory.pubkey(), &usdc), false);
    assert_code(env.send(&[i], &[&mallory]), code::UNAUTHORIZED);
    assert_ok(env.bond(MAIN, &w, &usdc, MIN));
    let i = env.unbond_ix(MAIN, &mallory.pubkey(), 1, &w.account(&env.judge));
    assert_code(env.send(&[i], &[&mallory]), code::UNAUTHORIZED);
}

#[test]
fn withdraw_after_thirty_days_to_the_owner_only() {
    let (mut env, _) = Env::new();
    let usdc = env.usdc;
    let w = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &w, false));
    assert_ok(env.bond(MAIN, &w, &usdc, MIN));
    let dest = env.fund(&w.operator.pubkey(), &usdc, 0);
    let op = w.operator.insecure_clone();
    let i = env.withdraw_ix(MAIN, &op.pubkey(), 1, &w.account(&env.judge), &w.vault(&env.judge), &dest);
    assert_code(env.send(&[i.clone()], &[&op]), code::INVALID_STATUS);
    assert_ok(env.unbond_witness(MAIN, &w));
    assert_eq!(env.witness_status(&w), layout::UNBONDING);
    assert_code(env.bond(MAIN, &w, &usdc, 1), code::INVALID_STATUS);
    env.advance(30 * DAY - 1, 10);
    assert_code(env.send(&[i.clone()], &[&op]), code::UNBONDING_NOT_ELAPSED);
    env.advance(1, 1);
    // To a token account someone else owns.
    let other = Keypair::new();
    let theirs = env.fund(&other.pubkey(), &usdc, 0);
    let bad = env.withdraw_ix(MAIN, &op.pubkey(), 1, &w.account(&env.judge), &w.vault(&env.judge), &theirs);
    assert_code(env.send(&[bad], &[&op]), code::WRONG_DESTINATION);
    let before = env.balance(&dest);
    assert_ok(env.send(&[i.clone()], &[&op]));
    assert_eq!(env.balance(&dest), before + MIN);
    assert_eq!(env.balance(&w.vault(&env.judge)), 0);
    assert_eq!(env.witness_status(&w), layout::WITHDRAWN);
    assert_code(env.send(&[i], &[&op]), code::INVALID_STATUS);
}

#[test]
fn directory_bond_is_governance_posted_and_exits_like_a_witness_bond() {
    let (mut env, _) = Env::new();
    let usdc = env.usdc;
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    env.fund(&stranger.pubkey(), &usdc, 500);
    let i = env.bond_directory_ix(MAIN, &stranger.pubkey(), &usdc, 500);
    assert_code(env.send(&[i], &[&stranger]), code::UNAUTHORIZED);
    assert_ok(env.bond_directory(MAIN, &usdc, 50_000));
    assert_ok(env.bond_directory(MAIN, &usdc, 1));
    assert_eq!(env.balance(&env.dir_vault(MAIN)), 50_001);
    assert_eq!(env.log_data(MAIN)[layout::LOG_DIR_STATUS], layout::ACTIVE);
    let gov = env.gov.insecure_clone();
    let log = env.log(MAIN);
    let i = env.unbond_ix(MAIN, &stranger.pubkey(), 0, &log);
    assert_code(env.send(&[i], &[&stranger]), code::UNAUTHORIZED);
    assert_ok(env.send(&[env.unbond_ix(MAIN, &gov.pubkey(), 0, &log)], &[&gov]));
    let dest = ata(&gov.pubkey(), &usdc);
    let w = env.withdraw_ix(MAIN, &gov.pubkey(), 0, &log, &env.dir_vault(MAIN), &dest);
    assert_code(env.send(&[w.clone()], &[&gov]), code::UNBONDING_NOT_ELAPSED);
    env.advance(30 * DAY, 10);
    let before = env.balance(&dest);
    assert_ok(env.send(&[w], &[&gov]));
    assert_eq!(env.balance(&dest), before + 50_001);
    assert_eq!(env.log_data(MAIN)[layout::LOG_DIR_STATUS], layout::WITHDRAWN);
}
