//! Real token CPIs and SBF execution; all wallets/mints are disposable fixtures.
#[path = "support/custody.rs"]
mod custody_support;
use custody_support::*;
use ed25519_dalek::SigningKey;
use morse_judge::state::TIMELOCK_SECONDS;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_sha256_hasher::hashv;
use solana_signer::Signer;

#[test]
fn witness_custody_holds_real_tokens_until_the_immutable_owner_delay_and_refuses_substitution() {
    let mut h = Harness::new();
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    assert!(
        !h.send(&[h.directory_deposit()], false),
        "configuration is timelocked"
    );
    h.clock(1000 + TIMELOCK_SECONDS);
    assert!(
        !h.send(&[h.deposit(100_000_000)], true),
        "directory collateral must cover witness principal"
    );
    h.fund_directory();
    assert!(!h.send(&[h.deposit(99_999_999)], true));
    let mut outsider = h.deposit(100_000_000);
    outsider.accounts[0] = signer(h.payer.pubkey());
    assert!(!h.send(&[outsider], false));
    assert_eq!(h.balance(h.source), 1_000_000_000);
    assert!(h.send(&[h.deposit(100_000_000)], true));
    assert_eq!(h.balance(h.vault), 100_000_000);
    assert_eq!(h.balance(h.source), 900_000_000);
    assert_eq!(h.svm.get_account(&h.witness).unwrap().data[5], 1);
    assert!(!h.send(&[h.withdraw(h.source)], true));
    // Even the operator cannot use the token program directly to bypass escrow.
    let bypass = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(h.vault), rw(h.source), signer(h.operator.pubkey())],
        data: [vec![3], 1u64.to_le_bytes().to_vec()].concat(),
    };
    assert!(!h.send(&[bypass], true));
    assert_eq!(h.balance(h.vault), 100_000_000);
    assert!(h.send(&[h.request()], true));
    let requested_at = 1000 + TIMELOCK_SECONDS;
    h.clock(requested_at + UNBOND - 1);
    assert!(!h.send(&[h.withdraw(h.source)], true));
    assert!(
        !h.send(&[h.deposit(1)], true),
        "cannot disguise unbonding as a top-up"
    );
    h.clock(requested_at + UNBOND);
    let wrong = ata(&h.payer.pubkey(), &h.mint);
    let create = Instruction {
        program_id: ATA,
        accounts: vec![
            signer(h.payer.pubkey()),
            rw(wrong),
            ro(h.payer.pubkey()),
            ro(h.mint),
            ro(Address::default()),
            ro(TOKEN),
        ],
        data: vec![1],
    };
    assert!(h.send(&[create], false));
    assert!(
        !h.send(&[h.withdraw(wrong)], true),
        "payout wallet is not the bond owner"
    );
    assert!(h.send(&[h.withdraw(h.source)], true));
    assert_eq!(h.balance(h.source), 1_000_000_000);
    assert_eq!(h.balance(h.vault), 0);
    assert_eq!(h.svm.get_account(&h.witness).unwrap().data[5], 4);
    assert!(!h.send(&[h.withdraw(h.source)], true));
}

#[test]
fn minimum_updates_wait_fourteen_days_and_only_apply_to_new_bonds() {
    let mut h = Harness::new();
    h.clock(1000);
    let mut unauthorized = h.configure();
    unauthorized.accounts[0] = signer(h.operator.pubkey());
    assert!(!h.send(&[unauthorized], true));
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    assert!(h.send(&[h.deposit(100_000_000)], true));
    let mut snapshots = vec![h.snapshot("active", serde_json::json!({
        "minimum_witness": "100000000", "minimum_directory": "500000000", "pending_witness": "0",
        "pending_directory": "0", "pending_ready": "0", "witness_principal": "100000000",
        "directory_principal": "500000000", "directory_status": 1, "status": 1,
        "principal": "100000000", "bonded_at": "1210600", "unbond_at": "0"
    }))];
    let immutable = h.svm.get_account(&h.economy).unwrap().data[4..100].to_vec();
    let change = h.ix(
        vec![
            signer(h.payer.pubkey()),
            ro(h.config),
            ro(h.log),
            rw(h.economy),
        ],
        [
            vec![16],
            200_000_000u64.to_le_bytes().to_vec(),
            600_000_000u64.to_le_bytes().to_vec(),
        ]
        .concat(),
    );
    let apply = h.ix(vec![ro(h.log), rw(h.economy)], vec![17]);
    let mut unauthorized = change.clone();
    unauthorized.accounts[0] = signer(h.operator.pubkey());
    assert!(!h.send(&[unauthorized], true));
    assert!(h.send(&[change], false));
    snapshots.push(h.snapshot("pending minimums", serde_json::json!({
        "minimum_witness": "100000000", "minimum_directory": "500000000", "pending_witness": "200000000",
        "pending_directory": "600000000", "pending_ready": "2420200", "witness_principal": "100000000",
        "directory_principal": "500000000", "directory_status": 1, "status": 1,
        "principal": "100000000", "bonded_at": "1210600", "unbond_at": "0"
    })));
    h.clock(1000 + TIMELOCK_SECONDS * 2 - 1);
    assert!(!h.send(std::slice::from_ref(&apply), false));
    h.clock(1000 + TIMELOCK_SECONDS * 2);
    assert!(h.send(&[apply], false));
    assert_eq!(
        &h.svm.get_account(&h.economy).unwrap().data[4..100],
        immutable.as_slice()
    );
    assert!(
        h.send(&[h.deposit(1)], true),
        "existing bonds are not retroactively subject to a higher minimum"
    );
    assert!(h.send(&[h.request()], true));
    snapshots.push(h.snapshot("unbonding after top-up", serde_json::json!({
        "minimum_witness": "200000000", "minimum_directory": "600000000", "pending_witness": "0",
        "pending_directory": "0", "pending_ready": "0", "witness_principal": "100000001",
        "directory_principal": "500000000", "directory_status": 1, "status": 2,
        "principal": "100000001", "bonded_at": "1210600", "unbond_at": "2420200"
    })));
    let requested = h.svm.get_account(&h.bond).unwrap().data[184..192].to_vec();
    h.clock(1000 + TIMELOCK_SECONDS * 2 + 1);
    assert!(h.send(&[h.request()], true));
    assert_eq!(
        &h.svm.get_account(&h.bond).unwrap().data[184..192],
        requested.as_slice()
    );
    h.clock(1000 + TIMELOCK_SECONDS * 2 + UNBOND);
    assert!(h.send(&[h.withdraw(h.source)], true));
    snapshots.push(h.snapshot("withdrawn", serde_json::json!({
        "minimum_witness": "200000000", "minimum_directory": "600000000", "pending_witness": "0",
        "pending_directory": "0", "pending_ready": "0", "witness_principal": "0",
        "directory_principal": "500000000", "directory_status": 1, "status": 4,
        "principal": "0", "bonded_at": "1210600", "unbond_at": "2420200"
    })));
    assert!(!h.send(&[h.deposit(100_000_000)], true));
    assert!(h.send(&[h.deposit(200_000_000)], true));
    assert_eq!(h.balance(h.vault), 200_000_000);
    if let Ok(path) = std::env::var("MORSE_CUSTODY_FIXTURES_PATH") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({"version": 1, "snapshots": snapshots}))
                .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn directory_cannot_exit_while_witness_principal_is_locked_and_an_exit_stops_new_witness_deposits()
{
    let mut h = Harness::new();
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    assert!(h.send(&[h.deposit(100_000_000)], true));
    let bond = Address::find_program_address(&[b"bond", &h.log_id, b"directory"], &h.program).0;
    let vault = ata(&bond, &h.mint);
    let owner_account = ata(&h.payer.pubkey(), &h.mint);
    let request = h.ix(
        vec![signer(h.payer.pubkey()), ro(h.log), rw(h.economy), rw(bond)],
        vec![20, 0],
    );
    let withdraw = h.ix(
        vec![
            signer(h.payer.pubkey()),
            ro(h.log),
            rw(h.economy),
            rw(bond),
            rw(vault),
            rw(owner_account),
            ro(h.mint),
            ro(TOKEN),
        ],
        vec![21, 0],
    );
    assert!(h.send(&[request], false));
    assert!(!h.send(&[h.deposit(1)], true));
    h.clock(1000 + TIMELOCK_SECONDS + UNBOND);
    assert!(!h.send(std::slice::from_ref(&withdraw), false));
    assert_eq!(h.balance(vault), 500_000_000);
    assert!(h.send(&[h.request()], true));
    h.clock(1000 + TIMELOCK_SECONDS + UNBOND * 2);
    assert!(h.send(&[h.withdraw(h.source)], true));
    assert!(h.send(&[withdraw], false));
    assert_eq!(h.balance(vault), 0);
    assert_eq!(h.balance(owner_account), 500_000_000);
}

#[test]
fn token_account_substitution_failed_transfers_and_rotated_keys_cannot_inherit_or_drain_bonds() {
    let mut h = Harness::new();
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    // A token transfer failure rolls back both newly created custody accounts
    // and principal counters, not just the token movement.
    let mut source = h.svm.get_account(&h.source).unwrap();
    let original = source.clone();
    source.data[64..72].copy_from_slice(&1u64.to_le_bytes());
    h.svm.set_account(h.source, source).unwrap();
    assert!(!h.send(&[h.deposit(100_000_000)], true));
    assert!(h.svm.get_account(&h.bond).is_none_or(|a| a.data.is_empty()));
    assert_eq!(
        &h.svm.get_account(&h.economy).unwrap().data[148..156],
        &[0; 8]
    );
    assert_eq!(h.svm.get_account(&h.witness).unwrap().data[5], 0);
    h.svm.set_account(h.source, original).unwrap();
    let mut wrong_program = h.deposit(100_000_000);
    wrong_program.accounts[8] = ro(Address::default());
    assert!(!h.send(&[wrong_program], true));
    let mut same_account = h.deposit(100_000_000);
    same_account.accounts[6] = rw(h.vault);
    assert!(!h.send(&[same_account], true));
    assert!(h.send(&[h.deposit(100_000_000)], true));
    let key = SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes();
    let id = b"outside";
    let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &key]);
    let replacement =
        Address::find_program_address(&[b"witness", &h.log_id, identity.as_ref()], &h.program).0;
    let mut record = h.svm.get_account(&h.witness).unwrap().data;
    record[5] = 0;
    record[72..104].copy_from_slice(&key);
    record[232..272].fill(0);
    Harness::account(&mut h.svm, replacement, h.program, record);
    let mut inherit = h.deposit(1);
    inherit.accounts[3] = rw(replacement);
    assert!(!h.send(&[inherit], true));
    assert_eq!(h.balance(h.vault), 100_000_000);
    // New key, same ID and operator: separate PDA, vault, principal and delay.
    let new_bond =
        Address::find_program_address(&[b"bond", &h.log_id, identity.as_ref()], &h.program).0;
    let new_vault = ata(&new_bond, &h.mint);
    let mut fresh = h.deposit(100_000_000);
    fresh.accounts[3] = rw(replacement);
    fresh.accounts[4] = rw(new_bond);
    fresh.accounts[5] = rw(new_vault);
    assert!(h.send(&[fresh], true));
    assert_ne!(h.bond, new_bond);
    assert_eq!(h.balance(new_vault), 100_000_000);
    assert_eq!(
        u64::from_le_bytes(
            h.svm.get_account(&h.economy).unwrap().data[148..156]
                .try_into()
                .unwrap()
        ),
        200_000_000
    );
    assert!(h.send(&[h.request()], true));
    h.clock(1000 + TIMELOCK_SECONDS + UNBOND);
    let mut wrong_vault = h.withdraw(h.source);
    wrong_vault.accounts[5] = rw(h.source);
    assert!(!h.send(&[wrong_vault], true));
    assert!(h.send(&[h.withdraw(h.source)], true));
    assert_eq!(h.balance(new_vault), 100_000_000);
}

#[test]
fn donated_tokens_do_not_inflate_principal_and_readonly_or_frozen_accounts_cannot_release_it() {
    let mut h = Harness::new();
    h.clock(1000);
    // Both the state PDA and ATA may be prefunded by arbitrary senders.
    let prefund = h.svm.minimum_balance_for_rent_exemption(0);
    h.svm.airdrop(&h.economy, prefund).unwrap();
    h.svm.airdrop(&h.bond, prefund).unwrap();
    h.svm.airdrop(&h.vault, prefund).unwrap();
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    for index in [2, 3, 4, 5, 6] {
        let mut readonly = h.deposit(100_000_000);
        readonly.accounts[index].is_writable = false;
        assert!(!h.send(&[readonly], true));
    }
    assert!(h.send(&[h.deposit(100_000_000)], true));
    let donation = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(h.source), rw(h.vault), signer(h.operator.pubkey())],
        data: [vec![3], 7u64.to_le_bytes().to_vec()].concat(),
    };
    assert!(h.send(&[donation], true));
    assert_eq!(h.balance(h.vault), 100_000_007);
    assert_eq!(
        &h.svm.get_account(&h.economy).unwrap().data[148..156],
        &100_000_000u64.to_le_bytes()
    );
    assert!(h.send(&[h.request()], true));
    h.clock(1000 + TIMELOCK_SECONDS + UNBOND);
    for index in [2, 3, 4, 5, 6] {
        let mut readonly = h.withdraw(h.source);
        readonly.accounts[index].is_writable = false;
        assert!(!h.send(&[readonly], true));
    }
    let original = h.svm.get_account(&h.vault).unwrap();
    for field in [108, 72, 129] {
        let mut changed = original.clone();
        changed.data[field] = if field == 108 { 2 } else { 1 };
        h.svm.set_account(h.vault, changed).unwrap();
        assert!(!h.send(&[h.withdraw(h.source)], true));
        assert_eq!(h.svm.get_account(&h.bond).unwrap().data[4], 2);
    }
    h.svm.set_account(h.vault, original).unwrap();
    assert!(h.send(&[h.withdraw(h.source)], true));
    assert_eq!(h.balance(h.source), 1_000_000_000);
    assert_eq!(h.balance(h.vault), 0);
    assert_eq!(
        &h.svm.get_account(&h.economy).unwrap().data[148..156],
        &[0; 8]
    );
}

#[test]
fn maximum_length_ids_and_a_witness_named_directory_have_distinct_custody_authorities() {
    let mut h = Harness::new();
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    for (id, seed) in [(vec![b'a'; 64], 14), (b"directory".to_vec(), 15)] {
        let key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], &id, &key]);
        let witness =
            Address::find_program_address(&[b"witness", &h.log_id, identity.as_ref()], &h.program)
                .0;
        let bond =
            Address::find_program_address(&[b"bond", &h.log_id, identity.as_ref()], &h.program).0;
        let vault = ata(&bond, &h.mint);
        let mut data = h.svm.get_account(&h.witness).unwrap().data;
        data[4] = id.len() as u8;
        data[8..72].fill(0);
        data[8..8 + id.len()].copy_from_slice(&id);
        data[72..104].copy_from_slice(&key);
        Harness::account(&mut h.svm, witness, h.program, data);
        let mut deposit = h.deposit(100_000_000);
        deposit.accounts[3] = rw(witness);
        deposit.accounts[4] = rw(bond);
        deposit.accounts[5] = rw(vault);
        assert!(h.send(&[deposit], true));
        assert_eq!(h.balance(vault), 100_000_000);
        let mut request = h.request();
        request.accounts[2] = rw(witness);
        request.accounts[3] = rw(bond);
        assert!(h.send(&[request], true));
    }
    let directory =
        Address::find_program_address(&[b"bond", &h.log_id, b"directory"], &h.program).0;
    assert_eq!(h.svm.get_account(&directory).unwrap().data[4], 1);
    assert_eq!(h.balance(ata(&directory, &h.mint)), 500_000_000);
    assert_eq!(
        &h.svm.get_account(&h.economy).unwrap().data[148..156],
        &200_000_000u64.to_le_bytes()
    );
}

#[test]
fn eligibility_revision_tracks_status_changes_but_not_an_active_topup() {
    let mut h = Harness::new();
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    let revision = |h: &Harness| {
        u64::from_le_bytes(
            h.svm.get_account(&h.economy).unwrap().data[168..176]
                .try_into()
                .unwrap(),
        )
    };
    assert_eq!(revision(&h), 0);
    assert!(h.send(&[h.deposit(100_000_000)], true));
    assert_eq!(revision(&h), 1);
    assert!(h.send(&[h.deposit(1)], true));
    assert_eq!(revision(&h), 1);
    assert!(h.send(&[h.request()], true));
    assert_eq!(revision(&h), 2);
    assert!(h.send(&[h.request()], true));
    assert_eq!(revision(&h), 2);
    h.clock(1000 + TIMELOCK_SECONDS + UNBOND);
    assert!(h.send(&[h.withdraw(h.source)], true));
    assert_eq!(revision(&h), 3);
    assert!(h.send(&[h.deposit(100_000_000)], true));
    assert_eq!(revision(&h), 4);
}
