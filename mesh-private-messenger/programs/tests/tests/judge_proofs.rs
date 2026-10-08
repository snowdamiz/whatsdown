//! Fork proofs, staging and slashing.

use ed25519_dalek::SigningKey;
use morse_program_tests::*;

const MIN: u64 = 1_000_000_000;
const DIR: u64 = 50_000_000_000;

type Entry = (Vec<u8>, Vec<u8>, Vec<u8>);

struct World {
    env: Env,
    service: SigningKey,
    a: Witness,
    b: Witness,
    c: Witness,
    submitter: Keypair,
}

fn world() -> World {
    let (mut env, service) = Env::new();
    let usdc = env.usdc;
    assert_ok(env.bond_directory(MAIN, &usdc, DIR));
    let a = env.witness(MAIN, "witness-a", 0xA1);
    let b = env.witness(MAIN, "witness-b", 0xB2);
    let c = env.witness(MAIN, "witness-c", 0xC3);
    for w in [&a, &b, &c] {
        assert_ok(env.register(MAIN, w, false));
        assert_ok(env.bond(MAIN, w, &usdc, MIN));
    }
    let submitter = Keypair::new();
    env.svm.airdrop(&submitter.pubkey(), 100_000_000_000).unwrap();
    env.fund(&submitter.pubkey(), &usdc, 0);
    World { env, service, a, b, c, submitter }
}

fn cp_entry(service: &SigningKey, k: &[u8; KTK_LEN]) -> Entry {
    (pubkey(service).to_vec(), statement(k), ktk_sig(k).to_vec())
}

fn att(w: &Witness, k: &[u8; KTK_LEN]) -> ((String, [u8; 32], [u8; 64]), Entry) {
    let h = checkpoint_hash(k);
    let sig = witness_sig(&w.key, &w.id, &h);
    ((w.id.clone(), h, sig), (pubkey(&w.key).to_vec(), witness_msg(&w.id, &h), sig.to_vec()))
}

/// F1: same size 100, two roots. a signs both, b only C1, c only C2.
fn f1(w: &World, finder: [u8; 32]) -> (Frk, Vec<Entry>, [u8; KTK_LEN], [u8; KTK_LEN]) {
    let t = w.env.now_ms();
    let c1 = ktk(&w.service, 10, 100, [1; 32], t);
    let c2 = ktk(&w.service, 11, 100, [2; 32], t + 1000);
    let mut atts = vec![];
    let mut entries = vec![cp_entry(&w.service, &c1), cp_entry(&w.service, &c2)];
    for (wit, k) in [(&w.a, &c1), (&w.a, &c2), (&w.b, &c1), (&w.c, &c2)] {
        let (a, e) = att(wit, k);
        atts.push(a);
        entries.push(e);
    }
    let frk = Frk { kind: 1, finder, log_key: pubkey(&w.service), c1, c2: C2::Inline(c2), attestations: atts, contradiction: None };
    (frk, entries, c1, c2)
}

fn ed(entries: &[Entry]) -> Instruction {
    let refs: Vec<(&[u8; 32], &[u8], &[u8; 64])> =
        entries.iter().map(|(p, m, s)| (p.as_slice().try_into().unwrap(), m.as_slice(), s.as_slice().try_into().unwrap())).collect();
    ed25519_ix(&refs)
}

fn pair(env: &Env, w: &Witness) -> (Address, Address) {
    (w.account(&env.judge), w.vault(&env.judge))
}

fn prove_inline(
    env: &mut Env,
    submitter: &Keypair,
    kind: u8,
    frk: &[u8],
    entries: &[Entry],
    finder_usdc: Address,
    pairs: &[(Address, Address)],
) -> litesvm::types::TransactionResult {
    let hash = proof_hash(frk);
    let accounts = env.prove_accounts(MAIN, &submitter.pubkey(), &hash, None, &finder_usdc, &finder_usdc, pairs);
    let p = env.prove_inline_ix(kind, accounts, 1, frk);
    env.send(&[compute_budget(1_400_000), ed(entries), p], &[submitter])
}

#[test]
fn f1_slashes_the_directory_and_the_double_signer_and_pays_the_submitter() {
    let mut w = world();
    let (frk, entries, _, _) = f1(&w, [0; 32]);
    let bytes = frk.encode();
    let mine = ata(&w.submitter.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    assert_ok(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs));
    let env = &w.env;
    assert_eq!(env.balance(&mine), DIR / 10 + MIN / 10);
    assert_eq!(env.balance(&env.locked(MAIN)), DIR - DIR / 10 + MIN - MIN / 10);
    assert_eq!(env.balance(&env.dir_vault(MAIN)), 0);
    assert_eq!(env.balance(&w.a.vault(&env.judge)), 0);
    assert_eq!(env.balance(&w.b.vault(&env.judge)), MIN);
    assert_eq!(env.balance(&w.c.vault(&env.judge)), MIN);
    assert_eq!(env.witness_status(&w.a), layout::SLASHED);
    assert_eq!(env.witness_status(&w.b), layout::ACTIVE);
    assert_eq!(env.witness_status(&w.c), layout::ACTIVE);
    let l = env.log_data(MAIN);
    assert_eq!(l[layout::LOG_SERVICE_SLASHED], 1);
    assert_eq!(l[layout::LOG_DIR_STATUS], layout::SLASHED);
    let p = env.data(&env.proof(&proof_hash(&bytes)));
    assert_eq!(p.len(), 112);
    assert_eq!(p[0], 5);
    assert_eq!(p[3], 1);
    assert_eq!(&p[8..40], env.log(MAIN).as_ref());
    assert_eq!(&p[40..72], &proof_hash(&bytes));
    assert_eq!(&p[layout::P_PAID_TO..layout::P_PAID_TO + 32], w.submitter.pubkey().as_ref());
}

#[test]
fn named_finder_is_paid_at_its_new_associated_token_account_and_once_only() {
    let mut w = world();
    let finder = Keypair::new().pubkey();
    let (frk, entries, _, _) = f1(&w, finder.to_bytes());
    let bytes = frk.encode();
    let (plain_frk, _, _, _) = f1(&w, [0; 32]);
    let plain = plain_frk.encode();
    assert_eq!(proof_hash(&bytes), proof_hash(&plain), "finder address is outside the proof hash");
    assert_ne!(bytes, plain);
    let usdc = w.env.usdc;
    let finder_ata = ata(&finder, &usdc);
    assert!(!w.env.exists(&finder_ata));
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    let hash = proof_hash(&bytes);
    let accounts = w.env.prove_accounts(MAIN, &s.pubkey(), &hash, None, &finder_ata, &finder_ata, &pairs);
    let create = create_ata_idempotent(&s.pubkey(), &finder, &usdc);
    let p = w.env.prove_inline_ix(1, accounts, 1, &bytes);
    assert_ok(w.env.send(&[compute_budget(1_400_000), ed(&entries), create, p], &[&s]));
    assert_eq!(w.env.balance(&finder_ata), DIR / 10 + MIN / 10);
    assert_eq!(w.env.balance(&ata(&s.pubkey(), &usdc)), 0);
    let p = w.env.data(&w.env.proof(&hash));
    assert_eq!(&p[layout::P_PAID_TO..layout::P_PAID_TO + 32], finder.as_ref());
    // The same fork again, naming nobody or someone else: already paid.
    let mine = ata(&s.pubkey(), &usdc);
    assert_code(prove_inline(&mut w.env, &s, 1, &plain, &entries, mine, &pairs), code::ALREADY_PROVEN);
    let other = Keypair::new().pubkey();
    let (again, _, _, _) = f1(&w, other.to_bytes());
    let other_ata = w.env.fund(&other, &usdc, 0);
    assert_code(prove_inline(&mut w.env, &s, 1, &again.encode(), &entries, other_ata, &pairs), code::ALREADY_PROVEN);
}

#[test]
fn finder_token_account_must_match() {
    let mut w = world();
    let usdc = w.env.usdc;
    let finder = Keypair::new().pubkey();
    let (frk, entries, _, _) = f1(&w, finder.to_bytes());
    let bytes = frk.encode();
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    // The submitter's account in place of the named finder's.
    let mine = ata(&s.pubkey(), &usdc);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs), code::FINDER_ACCOUNT_MISMATCH);
    // A token account the finder owns that is not its associated account.
    let side = Address::new_unique();
    w.env.set_token_account(side, &usdc, &finder, 0);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, side, &pairs), code::FINDER_ACCOUNT_MISMATCH);
    // The finder's associated account for another mint.
    let tm = w.env.token_mint;
    let wrong_mint = w.env.fund(&finder, &tm, 0);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, wrong_mint, &pairs), code::FINDER_ACCOUNT_MISMATCH);
    // No finder named: the account must belong to the submitter.
    let (plain, _, _, _) = f1(&w, [0; 32]);
    let someone = w.env.fund(&Keypair::new().pubkey(), &usdc, 0);
    assert_code(prove_inline(&mut w.env, &s, 1, &plain.encode(), &entries, someone, &pairs), code::FINDER_ACCOUNT_MISMATCH);
}

#[test]
fn every_listed_attestation_must_be_verified() {
    let mut w = world();
    let (frk, entries, _, _) = f1(&w, [0; 32]);
    let bytes = frk.encode();
    let mine = ata(&w.submitter.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    // Leaving out the Ed25519 entry for a's second attestation would shield a.
    let mut partial = entries.clone();
    partial.remove(3);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &partial, mine, &[]), code::ATTESTATION_NOT_VERIFIED);
    // A bogus attestation signature can never be verified.
    let (mut bad, _, _, _) = f1(&w, [0; 32]);
    bad.attestations[2].2 = [9; 64];
    let bad = bad.encode();
    let mut e = entries.clone();
    e.remove(4);
    assert_code(prove_inline(&mut w.env, &s, 1, &bad, &e, mine, &pairs), code::ATTESTATION_NOT_VERIFIED);
    // Service signature missing.
    let no_service: Vec<Entry> = entries[1..].to_vec();
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &no_service, mine, &pairs), code::SIGNATURE_NOT_VERIFIED);
    // Attestations from IDs the log never registered are ignored.
    let mut extra = f1(&w, [0; 32]).0;
    let stranger = Witness { id: "stranger".into(), key: key(0x99), operator: Keypair::new(), payout: Keypair::new(), log: log_id(MAIN) };
    let (a1, _) = att(&stranger, &extra.c1);
    extra.attestations.push(a1);
    assert_ok(prove_inline(&mut w.env, &s, 1, &extra.encode(), &entries, mine, &pairs));
}

#[test]
fn all_implicated_witness_accounts_must_be_passed() {
    let mut w = world();
    let (frk, entries, _, _) = f1(&w, [0; 32]);
    let bytes = frk.encode();
    let mine = ata(&w.submitter.pubkey(), &w.env.usdc);
    let s = w.submitter.insecure_clone();
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &[]), code::IMPLICATED_ACCOUNTS_MISMATCH);
    let wrong = [pair(&w.env, &w.b)];
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &wrong), code::IMPLICATED_ACCOUNTS_MISMATCH);
    let swapped = [(w.a.account(&w.env.judge), w.b.vault(&w.env.judge))];
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &swapped), code::IMPLICATED_ACCOUNTS_MISMATCH);
}

#[test]
fn honest_pairs_and_mismatched_proofs_are_refused() {
    let mut w = world();
    let t = w.env.now_ms();
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let c1 = ktk(&w.service, 10, 100, [1; 32], t);
    let c2 = ktk(&w.service, 11, 101, [2; 32], t);
    let entries = vec![cp_entry(&w.service, &c1), cp_entry(&w.service, &c2)];
    for kind in [1u8, 3] {
        let frk = Frk { kind, finder: [0; 32], log_key: pubkey(&w.service), c1, c2: C2::Inline(c2), attestations: vec![], contradiction: None };
        assert_code(prove_inline(&mut w.env, &s, kind, &frk.encode(), &entries, mine, &[]), code::NOT_A_FORK);
    }
    let (frk, entries, _, _) = f1(&w, [0; 32]);
    let pairs = [pair(&w.env, &w.a)];
    let bytes = frk.encode();
    assert_code(prove_inline(&mut w.env, &s, 3, &bytes, &entries, mine, &pairs), code::KIND_MISMATCH);
    let other = key(0x33);
    let mut foreign = f1(&w, [0; 32]).0;
    foreign.log_key = pubkey(&other);
    assert_code(prove_inline(&mut w.env, &s, 1, &foreign.encode(), &entries, mine, &pairs), code::WRONG_LOG_KEY);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_code(prove_inline(&mut w.env, &s, 1, &trailing, &entries, mine, &pairs), code::FRK_MALFORMED);
}

#[test]
fn proof_window_is_28_days_from_the_older_checkpoint() {
    let mut w = world();
    let (frk, entries, _, _) = f1(&w, [0; 32]);
    let bytes = frk.encode();
    let mine = ata(&w.submitter.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    w.env.advance(28 * DAY + 1, 10);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs), code::PROOF_WINDOW_CLOSED);
    w.env.advance(-1, 1);
    assert_ok(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs));
}

#[test]
fn double_slash_is_refused_and_a_slashed_bond_never_withdraws() {
    let mut w = world();
    let (frk, entries, c1, c2) = f1(&w, [0; 32]);
    let bytes = frk.encode();
    let mine = ata(&w.submitter.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a)];
    let s = w.submitter.insecure_clone();
    // a asked to leave first: a slash during unbonding still takes the bond.
    assert_ok(w.env.unbond_witness(MAIN, &w.a));
    assert_ok(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs));
    assert_eq!(w.env.witness_status(&w.a), layout::SLASHED);
    assert_eq!(w.env.balance(&w.a.vault(&w.env.judge)), 0);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &pairs), code::ALREADY_PROVEN);
    // The same fork encoded the other way round: nothing left to take.
    let swapped = Frk {
        kind: 1,
        finder: [0; 32],
        log_key: pubkey(&w.service),
        c1: c2,
        c2: C2::Inline(c1),
        attestations: frk.attestations.clone(),
        contradiction: None,
    };
    assert_code(prove_inline(&mut w.env, &s, 1, &swapped.encode(), &entries, mine, &pairs), code::NOTHING_TO_SLASH);
    w.env.advance(30 * DAY, 10);
    assert_code(w.env.withdraw_witness(MAIN, &w.a, &w.env.usdc.clone()), code::INVALID_STATUS);
}

#[test]
fn a_withdrawn_bond_cannot_be_slashed() {
    let mut w = world();
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    assert_ok(w.env.unbond_witness(MAIN, &w.a));
    w.env.advance(29 * DAY, 100);
    // Fork X (no attestations) takes the directory bond.
    let (mut x, entries, _, _) = f1(&w, [0; 32]);
    x.attestations.clear();
    assert_ok(prove_inline(&mut w.env, &s, 1, &x.encode(), &entries[..2], mine, &[]));
    // Fork Y was double-signed by a, which then withdraws.
    let t = w.env.now_ms();
    let y1 = ktk(&w.service, 20, 300, [7; 32], t);
    let y2 = ktk(&w.service, 21, 300, [8; 32], t);
    let (a1, e1) = att(&w.a, &y1);
    let (a2, e2) = att(&w.a, &y2);
    let y =
        Frk { kind: 1, finder: [0; 32], log_key: pubkey(&w.service), c1: y1, c2: C2::Inline(y2), attestations: vec![a1, a2], contradiction: None };
    w.env.advance(DAY, 100);
    assert_ok(w.env.withdraw_witness(MAIN, &w.a, &w.env.usdc.clone()));
    let e = vec![cp_entry(&w.service, &y1), cp_entry(&w.service, &y2), e1, e2];
    let pairs = [pair(&w.env, &w.a)];
    assert_code(prove_inline(&mut w.env, &s, 1, &y.encode(), &e, mine, &pairs), code::NOTHING_TO_SLASH);
    assert_eq!(w.env.witness_status(&w.a), layout::WITHDRAWN);
}

#[test]
fn f1_against_an_anchored_ring_entry_uses_the_cosign_bitmap() {
    let mut w = world();
    let t = w.env.now_ms();
    let service = w.service.clone();
    let public = ktk(&service, 10, 100, [1; 32], t);
    assert_ok(w.env.post(MAIN, &service, &public));
    assert_ok(w.env.cosign(MAIN, 0, 0, &w.a));
    assert_ok(w.env.cosign(MAIN, 0, 1, &w.b));
    // The version shown to a victim, signed by a and c.
    let shown = ktk(&service, 11, 100, [9; 32], t + 500);
    let (aa, ea) = att(&w.a, &shown);
    let (ac, ec) = att(&w.c, &shown);
    let frk =
        Frk { kind: 1, finder: [0; 32], log_key: pubkey(&service), c1: shown, c2: C2::Ring(0), attestations: vec![aa, ac], contradiction: None };
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let entries = vec![cp_entry(&service, &shown), ea, ec];
    let pairs = [pair(&w.env, &w.a)];
    assert_code(prove_inline(&mut w.env, &s, 1, &frk.encode(), &entries, mine, &[]), code::IMPLICATED_ACCOUNTS_MISMATCH);
    assert_ok(prove_inline(&mut w.env, &s, 1, &frk.encode(), &entries, mine, &pairs));
    assert_eq!(w.env.witness_status(&w.a), layout::SLASHED);
    assert_eq!(w.env.witness_status(&w.b), layout::ACTIVE);
    assert_eq!(w.env.witness_status(&w.c), layout::ACTIVE);
    // A ring index never written is refused.
    let mut bad = frk;
    bad.c2 = C2::Ring(9);
    assert_code(prove_inline(&mut w.env, &s, 1, &bad.encode(), &entries, mine, &pairs), code::RING_INDEX_INVALID);
}

#[test]
fn rollback_recorded_by_post_anchor_is_provable_from_the_ring() {
    let mut w = world();
    let t = w.env.now_ms();
    let service = w.service.clone();
    let tip = ktk(&service, 20, 200, [1; 32], t);
    assert_ok(w.env.post(MAIN, &service, &tip));
    w.env.advance(60, 150);
    let rollback = ktk(&service, 21, 150, [2; 32], t + 60_000);
    assert_ok(w.env.post(MAIN, &service, &rollback));
    assert_eq!(w.env.data(&w.env.ring(MAIN))[layout::ring_entry(1) + 98], 3);
    let frk = Frk { kind: 3, finder: [0; 32], log_key: pubkey(&service), c1: tip, c2: C2::Ring(1), attestations: vec![], contradiction: None };
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    assert_code(prove_inline(&mut w.env, &s, 1, &frk.encode(), &[cp_entry(&service, &tip)], mine, &[]), code::KIND_MISMATCH);
    assert_ok(prove_inline(&mut w.env, &s, 3, &frk.encode(), &[cp_entry(&service, &tip)], mine, &[]));
    assert_eq!(w.env.log_data(MAIN)[layout::LOG_SERVICE_SLASHED], 1);
}

#[test]
fn rollback_with_two_inline_checkpoints_and_equal_sequence() {
    let mut w = world();
    let t = w.env.now_ms();
    let service = w.service.clone();
    let c1 = ktk(&service, 30, 300, [1; 32], t);
    let c2 = ktk(&service, 30, 300, [1; 32], t + 1); // same sequence, other content
    let (a1, e1) = att(&w.b, &c1);
    let (a2, e2) = att(&w.b, &c2);
    let frk = Frk { kind: 3, finder: [0; 32], log_key: pubkey(&service), c1, c2: C2::Inline(c2), attestations: vec![a1, a2], contradiction: None };
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let entries = vec![cp_entry(&service, &c1), cp_entry(&service, &c2), e1, e2];
    let pairs = [pair(&w.env, &w.b)];
    assert_ok(prove_inline(&mut w.env, &s, 3, &frk.encode(), &entries, mine, &pairs));
    assert_eq!(w.env.witness_status(&w.b), layout::SLASHED);
}

// ------------------------------------------------ F2 and staging

struct Contra {
    frk: Frk,
    entries: Vec<Entry>,
}

/// Two logs sharing leaves 0-1 and 3-4 but differing at index 2.
fn contradiction(w: &World, finder: [u8; 32]) -> Contra {
    let base: Vec<[u8; 32]> = (0..7u8).map(|i| leaf_hash(&[i])).collect();
    let mut forked = base.clone();
    forked[2] = leaf_hash(b"evil");
    let (l1, l2) = (&base[..5], &forked[..7]);
    let t = w.env.now_ms();
    let c1 = ktk(&w.service, 40, 5, root(l1), t);
    let c2 = ktk(&w.service, 41, 7, root(l2), t);
    let mut atts = vec![];
    let mut entries = vec![cp_entry(&w.service, &c1), cp_entry(&w.service, &c2)];
    for (wit, k) in [(&w.a, &c1), (&w.a, &c2), (&w.b, &c1), (&w.b, &c2)] {
        let (a, e) = att(wit, k);
        atts.push(a);
        entries.push(e);
    }
    let contradiction = Some(Contradiction { index: 2, path1: path(2, l1), leaf1: l1[2], path2: path(2, l2), leaf2: l2[2] });
    Contra { frk: Frk { kind: 2, finder, log_key: pubkey(&w.service), c1, c2: C2::Inline(c2), attestations: atts, contradiction }, entries }
}

fn prove_staged(
    env: &mut Env,
    submitter: &Keypair,
    kind: u8,
    bytes: &[u8],
    stage: &Address,
    finder: Address,
    pairs: &[(Address, Address)],
) -> litesvm::types::TransactionResult {
    let hash = proof_hash(bytes);
    let accounts = env.prove_accounts(MAIN, &submitter.pubkey(), &hash, Some(stage), &finder, &finder, pairs);
    let p = env.prove_staged_ix(kind, accounts);
    env.send(&[compute_budget(1_400_000), p], &[submitter])
}

#[test]
fn contradiction_proof_staged_across_transactions() {
    let mut w = world();
    let Contra { frk, entries } = contradiction(&w, [0; 32]);
    let bytes = frk.encode();
    let s = w.submitter.insecure_clone();
    let lamports_before = w.env.svm.get_balance(&s.pubkey()).unwrap();
    let stage = w.env.stage_proof(MAIN, &s, 0, &bytes, &entries);
    assert_eq!(u32le(&w.env.data(&stage), layout::S_MARKS), 0b11_1111);
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a), pair(&w.env, &w.b)];
    assert_ok(prove_staged(&mut w.env, &s, 2, &bytes, &stage, mine, &pairs));
    assert!(!w.env.exists(&stage), "stage closed");
    assert_eq!(w.env.witness_status(&w.a), layout::SLASHED);
    assert_eq!(w.env.witness_status(&w.b), layout::SLASHED);
    assert_eq!(w.env.witness_status(&w.c), layout::ACTIVE);
    assert_eq!(w.env.balance(&mine), DIR / 10 + 2 * (MIN / 10));
    let proof_rent = w.env.svm.minimum_balance_for_rent_exemption(112);
    let spent = lamports_before - w.env.svm.get_balance(&s.pubkey()).unwrap();
    assert!(spent < proof_rent + 1_000_000, "stage rent refunded (spent {spent})");
}

#[test]
fn contradiction_needs_valid_paths_and_different_leaves() {
    let mut w = world();
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a), pair(&w.env, &w.b)];
    let mut bad_path = contradiction(&w, [0; 32]);
    bad_path.frk.contradiction.as_mut().unwrap().path1[0] = [0; 32];
    let mut same_leaf = contradiction(&w, [0; 32]);
    let c = same_leaf.frk.contradiction.as_mut().unwrap();
    c.leaf2 = c.leaf1;
    let mut out_of_range = contradiction(&w, [0; 32]);
    out_of_range.frk.contradiction.as_mut().unwrap().index = 5;
    for (n, bad) in [bad_path, same_leaf, out_of_range].into_iter().enumerate() {
        let bytes = bad.frk.encode();
        let stage = w.env.stage_proof(MAIN, &s, n as u64, &bytes, &bad.entries);
        assert_code(prove_staged(&mut w.env, &s, 2, &bytes, &stage, mine, &pairs), code::NOT_A_FORK);
    }
}

#[test]
fn staging_abuse_is_refused() {
    let mut w = world();
    let Contra { frk, entries } = contradiction(&w, [0; 32]);
    let bytes = frk.encode();
    let s = w.submitter.insecure_clone();
    let mallory = Keypair::new();
    w.env.svm.airdrop(&mallory.pubkey(), 10_000_000_000).unwrap();
    let st = w.env.stage(&s.pubkey(), 7);
    assert_code(w.env.send(&[w.env.stage_init_ix(MAIN, &s.pubkey(), 7, 8_193)], &[&s]), code::STAGE_INVALID);
    assert_ok(w.env.send(&[w.env.stage_init_ix(MAIN, &s.pubkey(), 7, bytes.len() as u16)], &[&s]));
    // Out-of-order write, foreign writer, verify before complete.
    assert_code(w.env.send(&[w.env.stage_write_ix(&s.pubkey(), &st, 10, &bytes[10..20])], &[&s]), code::STAGE_INVALID);
    let mut foreign = w.env.stage_write_ix(&mallory.pubkey(), &st, 0, &bytes[..10]);
    foreign.accounts[0] = AccountMeta::new_readonly(mallory.pubkey(), true);
    assert_code(w.env.send(&[foreign], &[&mallory]), code::UNAUTHORIZED);
    assert_ok(w.env.send(&[w.env.stage_write_ix(&s.pubkey(), &st, 0, &bytes[..900])], &[&s]));
    assert_code(w.env.send(&[ed(&entries[..1]), w.env.stage_verify_ix(MAIN, &st, 0)], &[]), code::STAGE_INVALID);
    // Overflow past the declared length.
    let mut long = bytes[900..].to_vec();
    long.push(0);
    assert_code(w.env.send(&[w.env.stage_write_ix(&s.pubkey(), &st, 900, &long)], &[&s]), code::STAGE_INVALID);
    assert_ok(w.env.send(&[w.env.stage_write_ix(&s.pubkey(), &st, 900, &bytes[900..])], &[&s]));
    // Complete: no more writes, so verified bytes can never change.
    let n = bytes.len() as u16;
    assert_code(w.env.send(&[w.env.stage_write_ix(&s.pubkey(), &st, n, &[0])], &[&s]), code::STAGE_INVALID);
    let mine = ata(&s.pubkey(), &w.env.usdc);
    let pairs = [pair(&w.env, &w.a), pair(&w.env, &w.b)];
    // Nothing verified yet.
    assert_code(prove_staged(&mut w.env, &s, 2, &bytes, &st, mine, &pairs), code::SIGNATURE_NOT_VERIFIED);
    for e in &entries {
        assert_ok(w.env.send(&[ed(std::slice::from_ref(e)), w.env.stage_verify_ix(MAIN, &st, 0)], &[]));
    }
    // Someone else's stage.
    let theirs = w.env.fund(&mallory.pubkey(), &w.env.usdc.clone(), 0);
    assert_code(prove_staged(&mut w.env, &mallory, 2, &bytes, &st, theirs, &pairs), code::UNAUTHORIZED);
    // A stage made for another log.
    let canary = key(0xCA);
    assert_ok(w.env.register_log(CANARY, &canary));
    assert_code(w.env.send(&[ed(&entries[..1]), w.env.stage_verify_ix(CANARY, &st, 0)], &[]), code::WRONG_ACCOUNT);
    // Close by someone else refused; the submitter may abandon it.
    let mut close = w.env.stage_close_ix(&mallory.pubkey(), &st);
    close.accounts[0] = AccountMeta::new(mallory.pubkey(), true);
    assert_code(w.env.send(&[close], &[&mallory]), code::UNAUTHORIZED);
    assert_ok(prove_staged(&mut w.env, &s, 2, &bytes, &st, mine, &pairs));
    // Abandon path.
    let st2 = w.env.stage(&s.pubkey(), 8);
    assert_ok(w.env.send(&[w.env.stage_init_ix(MAIN, &s.pubkey(), 8, 10)], &[&s]));
    assert_ok(w.env.send(&[w.env.stage_close_ix(&s.pubkey(), &st2)], &[&s]));
    assert!(!w.env.exists(&st2));
}

#[test]
fn canary_and_main_logs_are_isolated() {
    let mut w = world();
    let usdc = w.env.usdc;
    let canary_key = key(0xCA);
    assert_ok(w.env.register_log(CANARY, &canary_key));
    w.env.grow_ring_full(CANARY);
    assert_ok(w.env.bond_directory(CANARY, &usdc, 100));
    let t3 = w.env.witness(CANARY, "t3", 0x13);
    assert_ok(w.env.register(CANARY, &t3, true));
    assert_ok(w.env.bond(CANARY, &t3, &usdc, MIN));
    // A canary checkpoint cannot be anchored in the main ring.
    let ck = ktk(&canary_key, 1, 1, [1; 32], w.env.now_ms());
    assert_code(w.env.post(MAIN, &canary_key, &ck), code::INVALID_CHECKPOINT);
    assert_ok(w.env.post(CANARY, &canary_key, &ck));
    // A canary fork proof against main: wrong log key.
    let t = w.env.now_ms();
    let c1 = ktk(&canary_key, 5, 10, [1; 32], t);
    let c2 = ktk(&canary_key, 6, 10, [2; 32], t);
    let (a1, e1) = att(&t3, &c1);
    let (a2, e2) = att(&t3, &c2);
    let frk = Frk { kind: 1, finder: [0; 32], log_key: pubkey(&canary_key), c1, c2: C2::Inline(c2), attestations: vec![a1, a2], contradiction: None };
    let bytes = frk.encode();
    let entries = vec![cp_entry(&canary_key, &c1), cp_entry(&canary_key, &c2), e1, e2];
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &usdc);
    assert_code(prove_inline(&mut w.env, &s, 1, &bytes, &entries, mine, &[]), code::WRONG_LOG_KEY);
    // Against the canary log it slashes only canary bonds.
    let hash = proof_hash(&bytes);
    let pairs = [(t3.account(&w.env.judge), t3.vault(&w.env.judge))];
    let accounts = w.env.prove_accounts(CANARY, &s.pubkey(), &hash, None, &mine, &mine, &pairs);
    let p = w.env.prove_inline_ix(1, accounts, 1, &bytes);
    assert_ok(w.env.send(&[compute_budget(1_400_000), ed(&entries), p], &[&s]));
    assert_eq!(w.env.log_data(CANARY)[layout::LOG_SERVICE_SLASHED], 1);
    assert_eq!(w.env.log_data(MAIN)[layout::LOG_SERVICE_SLASHED], 0);
    assert_eq!(w.env.balance(&w.env.dir_vault(MAIN)), DIR);
    assert_eq!(w.env.balance(&w.env.locked(MAIN)), 0);
    assert_eq!(w.env.balance(&w.env.locked(CANARY)), 90 + MIN - MIN / 10);
    // Main's vaults cannot be passed for a canary proof.
    let (frk2, e2s, _, _) = f1(&w, [0; 32]);
    let b2 = frk2.encode();
    let mut accounts = w.env.prove_accounts(CANARY, &s.pubkey(), &proof_hash(&b2), None, &mine, &mine, &[]);
    accounts[13] = AccountMeta::new(w.env.dir_vault(MAIN), false);
    let p = w.env.prove_inline_ix(1, accounts, 1, &b2);
    assert_code(w.env.send(&[compute_budget(1_400_000), ed(&e2s), p], &[&s]), code::WRONG_ACCOUNT);
}

#[test]
fn token_bonds_are_burned_on_slash() {
    let (mut env, service) = Env::new();
    env.set_token_mint();
    let tm = env.token_mint;
    let usdc = env.usdc;
    assert_ok(env.bond_directory(MAIN, &usdc, DIR));
    let a = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &a, false));
    assert_ok(env.bond(MAIN, &a, &tm, MIN));
    let supply_before = u64le(&env.data(&tm), 36);
    let submitter = Keypair::new();
    env.svm.airdrop(&submitter.pubkey(), 10_000_000_000).unwrap();
    let mine_usdc = env.fund(&submitter.pubkey(), &usdc, 0);
    let mine_token = env.fund(&submitter.pubkey(), &tm, 0);
    let t = env.now_ms();
    let c1 = ktk(&service, 10, 100, [1; 32], t);
    let c2 = ktk(&service, 11, 100, [2; 32], t);
    let (a1, e1) = att(&a, &c1);
    let (a2, e2) = att(&a, &c2);
    let frk = Frk { kind: 1, finder: [0; 32], log_key: pubkey(&service), c1, c2: C2::Inline(c2), attestations: vec![a1, a2], contradiction: None };
    let bytes = frk.encode();
    let entries = vec![cp_entry(&service, &c1), cp_entry(&service, &c2), e1, e2];
    let pairs = [(a.account(&env.judge), a.vault(&env.judge))];
    let accounts = env.prove_accounts(MAIN, &submitter.pubkey(), &proof_hash(&bytes), None, &mine_usdc, &mine_token, &pairs);
    let p = env.prove_inline_ix(1, accounts, 1, &bytes);
    assert_ok(env.send(&[compute_budget(1_400_000), ed(&entries), p], &[&submitter]));
    assert_eq!(env.balance(&mine_token), MIN / 10);
    assert_eq!(env.balance(&mine_usdc), DIR / 10);
    assert_eq!(env.balance(&a.vault(&env.judge)), 0);
    assert_eq!(u64le(&env.data(&tm), 36), supply_before - (MIN - MIN / 10), "90% burned");
    assert_eq!(env.balance(&env.locked(MAIN)), DIR - DIR / 10, "only USDC is locked");
}

#[test]
fn an_unbonded_double_signer_loses_trust_even_with_nothing_to_take() {
    let (mut env, service) = Env::new();
    let a = env.witness(MAIN, "witness-a", 0xA1);
    assert_ok(env.register(MAIN, &a, false));
    let submitter = Keypair::new();
    env.svm.airdrop(&submitter.pubkey(), 10_000_000_000).unwrap();
    let mine = env.fund(&submitter.pubkey(), &env.usdc.clone(), 0);
    let t = env.now_ms();
    let c1 = ktk(&service, 10, 100, [1; 32], t);
    let c2 = ktk(&service, 11, 100, [2; 32], t);
    let (a1, e1) = att(&a, &c1);
    let (a2, e2) = att(&a, &c2);
    let frk = Frk { kind: 1, finder: [0; 32], log_key: pubkey(&service), c1, c2: C2::Inline(c2), attestations: vec![a1, a2], contradiction: None };
    let entries = vec![cp_entry(&service, &c1), cp_entry(&service, &c2), e1, e2];
    let pairs = [(a.account(&env.judge), a.vault(&env.judge))];
    assert_ok(prove_inline(&mut env, &submitter, 1, &frk.encode(), &entries, mine, &pairs));
    assert_eq!(env.witness_status(&a), layout::SLASHED);
    assert_eq!(env.log_data(MAIN)[layout::LOG_SERVICE_SLASHED], 1);
    assert_eq!(env.balance(&mine), 0);
}

#[test]
fn worst_case_proof_fits_one_transaction_budget() {
    // 16 witnesses, all of them double-signers through the ring bitmap:
    // 17 slashes (34 token transfers) in one prove instruction.
    let (mut env, service) = Env::new();
    let usdc = env.usdc;
    assert_ok(env.bond_directory(MAIN, &usdc, DIR));
    let ws: Vec<Witness> = (0..16).map(|i| env.witness(MAIN, &format!("witness-{i:02}"), 0x20 + i as u8)).collect();
    for w in &ws {
        assert_ok(env.register(MAIN, w, false));
        assert_ok(env.bond(MAIN, w, &usdc, MIN));
    }
    let t = env.now_ms();
    let public = ktk(&service, 10, 100, [1; 32], t);
    let post = env.post(MAIN, &service, &public);
    let post_cu = assert_ok(post).compute_units_consumed;
    let mut cosign_cu = 0;
    for (i, w) in ws.iter().enumerate() {
        cosign_cu = cosign_cu.max(assert_ok(env.cosign(MAIN, 0, i as u8, w)).compute_units_consumed);
    }
    let shown = ktk(&service, 11, 100, [9; 32], t);
    let mut atts = vec![];
    let mut entries = vec![cp_entry(&service, &shown)];
    for w in &ws {
        let (a, e) = att(w, &shown);
        atts.push(a);
        entries.push(e);
    }
    let frk = Frk { kind: 1, finder: [0; 32], log_key: pubkey(&service), c1: shown, c2: C2::Ring(0), attestations: atts, contradiction: None };
    let bytes = frk.encode();
    let submitter = Keypair::new();
    env.svm.airdrop(&submitter.pubkey(), 100_000_000_000).unwrap();
    let mine = env.fund(&submitter.pubkey(), &usdc, 0);
    let stage = env.stage_proof(MAIN, &submitter, 0, &bytes, &entries);
    let pairs: Vec<(Address, Address)> = ws.iter().map(|w| pair(&env, w)).collect();
    // A relay paying its own fees fits 9 implicated witnesses in a legacy
    // transaction; more need an address lookup table.
    let payer = env.payer.pubkey();
    let sized = |n: usize| {
        let accounts = env.prove_accounts(MAIN, &payer, &proof_hash(&bytes), Some(&stage), &mine, &mine, &pairs[..n]);
        env.wire_size(&[compute_budget(400_000), env.prove_staged_ix(1, accounts)])
    };
    assert!(sized(9) <= 1232 && sized(10) > 1232, "9: {}, 10: {}", sized(9), sized(10));
    let res = prove_staged(&mut env, &submitter, 1, &bytes, &stage, mine, &pairs);
    let prove_cu = assert_ok(res).compute_units_consumed;
    eprintln!("compute units: post_anchor {post_cu}, cosign {cosign_cu}, worst-case prove {prove_cu}");
    assert!(ws.iter().all(|w| env.witness_status(w) == layout::SLASHED));
    assert!(prove_cu < 1_400_000);
    assert!(post_cu < 200_000 && cosign_cu < 200_000);
}

// ------------------------------------------------ closing slashed canary logs

fn prove_on(
    env: &mut Env,
    log: &str,
    s: &Keypair,
    frk: &[u8],
    entries: &[Entry],
    finder: Address,
    pairs: &[(Address, Address)],
) -> litesvm::types::TransactionResult {
    let accounts = env.prove_accounts(log, &s.pubkey(), &proof_hash(frk), None, &finder, &finder, pairs);
    let p = env.prove_inline_ix(1, accounts, 1, frk);
    env.send(&[compute_budget(1_400_000), ed(entries), p], &[s])
}

/// An F1 fork of `log` under `service`, double-signed by `w`.
fn fork(env: &Env, service: &SigningKey, w: &Witness) -> (Vec<u8>, Vec<Entry>) {
    let t = env.now_ms();
    let c1 = ktk(service, 5, 10, [1; 32], t);
    let c2 = ktk(service, 6, 10, [2; 32], t);
    let (a1, e1) = att(w, &c1);
    let (a2, e2) = att(w, &c2);
    let frk = Frk { kind: 1, finder: [0; 32], log_key: pubkey(service), c1, c2: C2::Inline(c2), attestations: vec![a1, a2], contradiction: None };
    (frk.encode(), vec![cp_entry(service, &c1), cp_entry(service, &c2), e1, e2])
}

#[test]
fn a_slashed_canary_log_is_closed_after_28_days_and_its_rent_returned() {
    let mut w = world();
    let env = &mut w.env;
    let usdc = env.usdc;
    let canary = key(0xCA);
    assert_ok(env.register_log(CANARY, &canary));
    assert_eq!(env.log_data(CANARY)[6], 1, "canary kind");
    assert_eq!(env.log_data(MAIN)[6], 0, "main kind");
    env.grow_ring_full(CANARY);
    assert_ok(env.bond_directory(CANARY, &usdc, 100));
    let t1 = env.witness(CANARY, "t1", 0x11);
    let t3 = env.witness(CANARY, "t3", 0x13);
    for t in [&t1, &t3] {
        assert_ok(env.register(CANARY, t, true));
        assert_ok(env.bond(CANARY, t, &usdc, MIN));
    }
    // A stage someone left behind for the canary log, and one for main.
    let straggler = Keypair::new();
    env.svm.airdrop(&straggler.pubkey(), 10_000_000_000).unwrap();
    let left = env.stage(&straggler.pubkey(), 5);
    assert_ok(env.send(&[env.stage_init_ix(CANARY, &straggler.pubkey(), 5, 10)], &[&straggler]));
    let other = env.stage(&straggler.pubkey(), 6);
    assert_ok(env.send(&[env.stage_init_ix(MAIN, &straggler.pubkey(), 6, 10)], &[&straggler]));
    // The drill: T3 double-signs, the canary is slashed.
    let (frk, entries) = fork(env, &canary, &t3);
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &usdc);
    assert_ok(prove_on(env, CANARY, &s, &frk, &entries, mine, &[(t3.account(&env.judge), t3.vault(&env.judge))]));
    assert_eq!(u64le(&env.log_data(CANARY), 8) as i64, env.now, "slash time recorded");
    // Its ring is frozen from now on.
    let k = ktk(&canary, 7, 11, [3; 32], env.now_ms());
    assert_code(env.post(CANARY, &canary, &k), code::INVALID_STATUS);

    let gov = env.gov.insecure_clone();
    let dest = Keypair::new().pubkey();
    let close = |env: &Env, stages: &[(Address, Address)]| env.close_log_ix(CANARY, &gov.pubkey(), &dest, stages);
    env.advance(28 * DAY - 1, 100);
    assert_code(env.send(&[close(env, &[])], &[&gov]), code::CLOSE_TOO_EARLY);
    env.advance(1, 1);
    let mallory = Keypair::new();
    let mut theirs = close(env, &[]);
    theirs.accounts[0] = AccountMeta::new_readonly(mallory.pubkey(), true);
    assert_code(env.send(&[theirs], &[&mallory]), code::UNAUTHORIZED);
    assert_code(env.send(&[close(env, &[(other, straggler.pubkey())])], &[&gov]), code::WRONG_ACCOUNT);
    assert_code(env.send(&[close(env, &[(left, dest)])], &[&gov]), code::WRONG_ACCOUNT);

    let vaults = [env.dir_vault(CANARY), env.locked(CANARY), t1.vault(&env.judge), t3.vault(&env.judge)];
    let held: Vec<(u64, u64)> = vaults.iter().map(|v| (env.balance(v), env.svm.get_balance(v).unwrap())).collect();
    let ring_rent = env.svm.get_balance(&env.ring(CANARY)).unwrap();
    let stage_rent = env.svm.get_balance(&left).unwrap();
    let straggler_before = env.svm.get_balance(&straggler.pubkey()).unwrap();
    assert_ok(env.send(&[close(env, &[(left, straggler.pubkey())])], &[&gov]));
    assert_eq!(env.svm.get_balance(&dest).unwrap(), ring_rent, "ring rent to the named destination");
    assert!(!env.exists(&env.ring(CANARY)) && !env.exists(&left));
    assert_eq!(env.svm.get_balance(&straggler.pubkey()).unwrap(), straggler_before + stage_rent, "stage rent to its submitter");
    let after: Vec<(u64, u64)> = vaults.iter().map(|v| (env.balance(v), env.svm.get_balance(v).unwrap())).collect();
    assert_eq!(held, after, "vaults untouched");
    assert_eq!(env.balance(&t1.vault(&env.judge)), MIN);
    assert_eq!(env.log_data(CANARY)[layout::LOG_SERVICE_SLASHED], 1, "the Log stays as the public record");
    assert!(env.exists(&env.proof(&proof_hash(&frk))), "the pay-once record stays");
    assert!(env.exists(&other), "other logs' stages untouched");
}

#[test]
fn unslashed_and_main_logs_are_never_closed() {
    let mut w = world();
    let env = &mut w.env;
    let usdc = env.usdc;
    let canary = key(0xCA);
    assert_ok(env.register_log(CANARY, &canary));
    env.grow_ring_full(CANARY);
    let gov = env.gov.insecure_clone();
    let dest = Keypair::new().pubkey();
    env.advance(60 * DAY, 100);
    assert_code(env.send(&[env.close_log_ix(CANARY, &gov.pubkey(), &dest, &[])], &[&gov]), code::NOT_CLOSABLE);
    // Main, slashed and long past the window: still never closable.
    let (frk, entries) = fork(env, &w.service, &w.a);
    let s = w.submitter.insecure_clone();
    let mine = ata(&s.pubkey(), &usdc);
    assert_ok(prove_on(env, MAIN, &s, &frk, &entries, mine, &[(w.a.account(&env.judge), w.a.vault(&env.judge))]));
    env.advance(60 * DAY, 100);
    assert_code(env.send(&[env.close_log_ix(MAIN, &gov.pubkey(), &dest, &[])], &[&gov]), code::NOT_CLOSABLE);
    assert!(env.exists(&env.ring(MAIN)));
    // A slashed main log keeps accepting anchors.
    let k = ktk(&w.service, 50, 50, [5; 32], env.now_ms());
    assert_ok(env.post(MAIN, &w.service, &k));
}
