//! Fund actual escrows, verify staged signatures with real precompiles, then
//! execute atomic settlement. Fixtures use no real wallets or external RPC.
#[allow(dead_code)]
#[path = "support/custody.rs"]
mod custody_support;
#[path = "support/public_history_index.rs"]
mod public_history_index;
use custody_support::*;
use ed25519_dalek::{Signer as _, SigningKey};
use morse_judge::{
    checkpoint::Checkpoint,
    fork::{Fork, Target},
    state::TIMELOCK_SECONDS,
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_sha256_hasher::{hash, hashv};
use solana_signer::Signer;

const ISSUED: i64 = 1_700_000_000;
const WINDOW: i64 = 28 * 24 * 60 * 60;

#[test]
#[ignore = "requires fresh Mesh admission plans; run scripts/prove-relay-admission.sh"]
fn mesh_admitted_settlements_execute_in_sbf() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use litesvm::LiteSVM;
    use serde_json::Value;
    use solana_account::Account;
    use solana_clock::Clock;
    use solana_instruction::AccountMeta;
    use solana_keypair::Keypair;
    use solana_message::Message;
    use solana_transaction::Transaction;
    use std::{path::PathBuf, str::FromStr};

    fn address(value: &Value) -> Address {
        Address::from_str(value.as_str().unwrap()).unwrap()
    }
    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }
    fn instruction(value: &Value) -> Instruction {
        assert_eq!(value["schemaVersion"], 1);
        let keys = value["accountKeys"].as_array().unwrap();
        assert_eq!(value["accountCount"].as_u64().unwrap() as usize, keys.len());
        Instruction {
            program_id: address(&value["programId"]),
            accounts: keys
                .iter()
                .map(|key| AccountMeta {
                    pubkey: address(key),
                    is_signer: value["signerKeys"].as_array().unwrap().contains(key),
                    is_writable: value["writableKeys"].as_array().unwrap().contains(key),
                })
                .collect(),
            data: STANDARD
                .decode(value["dataBase64"].as_str().unwrap())
                .unwrap(),
        }
    }
    fn send(svm: &mut LiteSVM, payer: &Keypair, instructions: &[Instruction]) -> bool {
        svm.expire_blockhash();
        let transaction = Transaction::new(
            &[payer],
            Message::new(instructions, Some(&payer.pubkey())),
            svm.latest_blockhash(),
        );
        assert!(bincode::serialize(&transaction).unwrap().len() <= 1232);
        match svm.send_transaction(transaction) {
            Ok(_) => true,
            Err(error) => {
                eprintln!("Mesh settlement refusal: {error:?}");
                false
            }
        }
    }
    fn balance(svm: &LiteSVM, key: &Address) -> u64 {
        u64::from_le_bytes(
            svm.get_account(key).unwrap().data[64..72]
                .try_into()
                .unwrap(),
        )
    }
    fn settle(
        svm: &mut LiteSVM,
        payer: &Keypair,
        ix: &Instruction,
        lookup: &Value,
        table: &mut Option<solana_message::AddressLookupTableAccount>,
    ) -> bool {
        if ix.accounts.len() < 60 {
            return send(svm, payer, std::slice::from_ref(ix));
        }
        use solana_compute_budget_interface::ComputeBudgetInstruction;
        use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
        use solana_transaction::versioned::VersionedTransaction;
        let addresses = lookup["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(address)
            .collect();
        if table.is_none() {
            let slot = svm.get_sysvar::<Clock>().slot;
            assert_eq!(lookup["recent_slot"].as_str().unwrap(), slot.to_string());
            let key = address(&lookup["address"]);
            assert!(send(svm, payer, &[instruction(&lookup["create"])]));
            for extension in lookup["extend"].as_array().unwrap() {
                assert!(send(svm, payer, &[instruction(extension)]));
            }
            svm.warp_to_slot(slot + 1);
            *table = Some(AddressLookupTableAccount { key, addresses });
        }
        // Reuse the same table on replay. A retry must not allocate another
        // table or confuse blockhash/lookup-table failures with paid-once refusal.
        svm.expire_blockhash();
        let message = v0::Message::try_compile(
            &payer.pubkey(),
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                ix.clone(),
            ],
            std::slice::from_ref(table.as_ref().unwrap()),
            svm.latest_blockhash(),
        )
        .unwrap();
        let locks = message.account_keys.len()
            + message
                .address_table_lookups
                .iter()
                .map(|table| table.writable_indexes.len() + table.readonly_indexes.len())
                .sum::<usize>();
        assert!(locks <= 64);
        let transaction =
            VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer]).unwrap();
        assert!(bincode::serialize(&transaction).unwrap().len() <= 1232);
        match svm.send_transaction(transaction) {
            Ok(meta) => {
                assert!(meta.compute_units_consumed <= 1_400_000);
                true
            }
            Err(error) => {
                eprintln!("Mesh maximum settlement refusal: {error:?}");
                false
            }
        }
    }
    let mut fixtures: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::env::var("MORSE_ADJUDICATION_FIXTURES_PATH").expect("custody fixtures"),
        )
        .unwrap(),
    )
    .unwrap();
    if let Ok(path) = std::env::var("MORSE_RELAY_ANCHORED_FIXTURES_PATH") {
        let anchored: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(anchored.as_array().unwrap().len(), 9);
        fixtures
            .as_array_mut()
            .unwrap()
            .extend(anchored.as_array().unwrap().iter().cloned());
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_MAXIMUM_FIXTURES_PATH") {
        let maximum: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(maximum.as_array().unwrap().len(), 4);
        fixtures
            .as_array_mut()
            .unwrap()
            .extend(maximum.as_array().unwrap().iter().cloned());
    }
    let plans = std::fs::read_to_string(
        std::env::var("MORSE_RELAY_SETTLEMENT_PLANS_PATH").expect("fresh Mesh admission plans"),
    )
    .unwrap();
    let plans: Vec<Value> = plans
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(plans.len(), fixtures.as_array().unwrap().len());
    assert!(plans.len() == 6 || plans.len() == 15 || plans.len() == 19);
    let mut completed = Vec::new();
    for (index, plan) in plans.iter().enumerate() {
        let fixture = &fixtures[index];
        assert_eq!(plan["program"], fixture["program"]);
        assert_eq!(plan["status"], "ready");
        let mut svm = LiteSVM::new();
        // Public test identity, never a deployed wallet; Mesh receives only its public key.
        let payer = Keypair::new_from_array([11; 32]);
        assert_eq!(payer.pubkey(), address(&plan["submitter"]));
        svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
        let program = address(&plan["program"]);
        let path = std::env::var_os("MORSE_JUDGE_SBF_PATH").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_judge.so"),
            PathBuf::from,
        );
        svm.add_program_from_file(program, path).unwrap();
        for account in fixture["before_accounts"].as_array().unwrap() {
            svm.set_account(
                address(&account["address"]),
                Account {
                    lamports: account["lamports"].as_str().unwrap().parse().unwrap(),
                    data: bytes(&account["data_hex"]),
                    owner: address(&account["owner"]),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        }
        svm.set_sysvar(
            &bincode::deserialize::<Clock>(&bytes(&fixture["clock"]["data_hex"])).unwrap(),
        );
        let log = address(&plan["log"]);
        let stage = address(&plan["stage"]["address"]);
        let stage_plan = &plan["stage"];
        let ix = |accounts, data| Instruction {
            program_id: program,
            accounts,
            data,
        };
        assert!(send(
            &mut svm,
            &payer,
            &[ix(
                vec![
                    signer(payer.pubkey()),
                    ro(log),
                    rw(stage),
                    ro(Address::default())
                ],
                bytes(&stage_plan["initialize_hex"])
            )]
        ));
        for chunk in stage_plan["append_hex"].as_array().unwrap() {
            assert!(send(
                &mut svm,
                &payer,
                &[ix(vec![signer(payer.pubkey()), rw(stage)], bytes(chunk))]
            ));
        }
        assert!(send(
            &mut svm,
            &payer,
            &[ix(
                vec![signer(payer.pubkey()), ro(log), rw(stage)],
                bytes(&stage_plan["seal_hex"])
            )]
        ));
        assert_eq!(
            &svm.get_account(&stage).unwrap().data[1152..],
            bytes(&plan["proof_hex"])
        );
        for step in stage_plan["signatures"].as_array().unwrap() {
            let precompile = Instruction {
                program_id: Address::from_str_const("Ed25519SigVerify111111111111111111111111111"),
                accounts: vec![],
                data: bytes(&step["ed25519_hex"]),
            };
            let mut accounts = vec![
                ro(log),
                rw(stage),
                ro(Address::from_str_const(
                    "Sysvar1nstructions1111111111111111111111111",
                )),
            ];
            if !step["witness"].is_null() {
                accounts.extend([ro(address(&step["witness"])), signer(payer.pubkey())]);
            }
            assert!(send(
                &mut svm,
                &payer,
                &[precompile, ix(accounts, bytes(&step["judge_hex"]))]
            ));
        }
        for setup in plan["setup"].as_array().unwrap() {
            assert!(send(&mut svm, &payer, &[instruction(setup)]));
        }
        let settlement = instruction(&plan["settlement"]);
        let mut table = None;
        assert!(settle(
            &mut svm,
            &payer,
            &settlement,
            &plan["lookup"],
            &mut table
        ));
        let expected: u64 = plan["estimate"]["finder_units"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let total: u64 = plan["estimate"]["total_slashed_units"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(balance(&svm, &settlement.accounts[7].pubkey), expected);
        assert_eq!(
            balance(&svm, &settlement.accounts[8].pubkey),
            total - expected
        );
        assert!(!settle(
            &mut svm,
            &payer,
            &settlement,
            &plan["lookup"],
            &mut table
        ));
        assert_eq!(balance(&svm, &settlement.accounts[7].pubkey), expected);
        assert!(send(
            &mut svm,
            &payer,
            &[ix(
                vec![signer(payer.pubkey()), rw(stage)],
                bytes(&stage_plan["close_hex"])
            )]
        ));
        if let Some(table) = table {
            assert!(send(
                &mut svm,
                &payer,
                &[instruction(&plan["lookup"]["deactivate"])]
            ));
            let rent = svm.get_account(&table.key).unwrap().lamports;
            assert!(!send(
                &mut svm,
                &payer,
                &[instruction(&plan["lookup"]["close"])]
            ));
            assert_eq!(svm.get_account(&table.key).unwrap().lamports, rent);
            // Model retirement from the validator's recent-slot history. Merely
            // advancing a local wall clock is not sufficient for rent recovery.
            let mut clock = svm.get_sysvar::<Clock>();
            clock.slot += 513;
            svm.set_sysvar(&clock);
            svm.set_sysvar(&solana_slot_hashes::SlotHashes::default());
            let before = svm.get_balance(&payer.pubkey()).unwrap();
            assert!(send(
                &mut svm,
                &payer,
                &[instruction(&plan["lookup"]["close"])]
            ));
            assert_eq!(
                svm.get_balance(&payer.pubkey()).unwrap(),
                before + rent - 5000
            );
            assert!(svm
                .get_account(&table.key)
                .is_none_or(|account| account.lamports == 0));
        }
        let mut result = fixture.clone();
        result["submitter"] = payer.pubkey().to_string().into();
        result["finder"] = plan["finder"].clone();
        result["receipt_hex"] =
            hex::encode(svm.get_account(&address(&plan["receipt"])).unwrap().data).into();
        for account in result["accounts"].as_array_mut().unwrap() {
            account["data_hex"] =
                hex::encode(svm.get_account(&address(&account["address"])).unwrap().data).into();
        }
        completed.push(result);
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_PAID_FIXTURES_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&completed[..6]).unwrap()).unwrap();
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_ANCHORED_PAID_FIXTURES_PATH") {
        assert!(completed.len() >= 15);
        std::fs::write(path, serde_json::to_vec_pretty(&completed[6..15]).unwrap()).unwrap();
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_MAXIMUM_PAID_FIXTURES_PATH") {
        assert_eq!(completed.len(), 19);
        std::fs::write(path, serde_json::to_vec_pretty(&completed[15..]).unwrap()).unwrap();
    }
}

fn checkpoint(cp: &Checkpoint) -> Vec<u8> {
    [
        vec![cp.version, b'K', b'T', b'K'],
        cp.sequence.to_be_bytes().to_vec(),
        cp.tree_size.to_be_bytes().to_vec(),
        cp.tree_root.to_vec(),
        cp.previous_hash.to_vec(),
        cp.timestamp.to_be_bytes().to_vec(),
        cp.service_key.to_vec(),
        cp.signature.to_vec(),
    ]
    .concat()
}
fn evidence(version: u8, kind: u8, finder: Address) -> Vec<u8> {
    let service = SigningKey::from_bytes(&[11; 32]);
    let mut first = Checkpoint {
        version,
        sequence: 1,
        tree_size: 1,
        tree_root: [3; 32],
        previous_hash: [0; 32],
        timestamp: ISSUED as u64 * 1000,
        service_key: service.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    first.signature = service.sign(&first.statement()).to_bytes();
    let mut second = first.clone();
    second.tree_root = [4; 32];
    second.timestamp += 1000;
    second.signature = service.sign(&second.statement()).to_bytes();
    let key = SigningKey::from_bytes(&[12; 32]);
    let mut wire = [
        vec![1, b'F', b'R', b'K', kind],
        finder.as_ref().to_vec(),
        first.service_key.to_vec(),
        checkpoint(&first),
        vec![0],
        checkpoint(&second),
        vec![2],
    ]
    .concat();
    for cp in [&first, &second] {
        let message = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            b"outside",
            &cp.hash(),
        ]
        .concat();
        wire.extend_from_slice(&[7]);
        wire.extend_from_slice(b"outside");
        wire.extend_from_slice(&cp.hash());
        wire.extend_from_slice(&key.sign(&message).to_bytes());
    }
    if kind == 2 {
        wire.extend_from_slice(&0u64.to_be_bytes());
        wire.push(0);
        wire.extend_from_slice(&first.tree_root);
        wire.push(0);
        wire.extend_from_slice(&second.tree_root);
    }
    wire
}
fn ed(key: &[u8], signature: &[u8], message: &[u8]) -> Instruction {
    let mut data = vec![1, 0];
    for n in [
        48u16,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&n.to_le_bytes());
    }
    data.extend_from_slice(key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction {
        program_id: Address::from_str_const("Ed25519SigVerify111111111111111111111111111"),
        accounts: vec![],
        data,
    }
}
fn stage(h: &mut Harness, wire: &[u8], attestations: bool) -> Address {
    let address = Address::find_program_address(
        &[b"stage", h.payer.pubkey().as_ref(), hash(wire).as_ref()],
        &h.program,
    )
    .0;
    assert!(h.send(
        &[h.ix(
            vec![
                signer(h.payer.pubkey()),
                ro(h.log),
                rw(address),
                ro(Address::default())
            ],
            [
                vec![10],
                (wire.len() as u16).to_le_bytes().to_vec(),
                hash(wire).as_ref().to_vec()
            ]
            .concat()
        )],
        false
    ));
    for (i, chunk) in wire.chunks(900).enumerate() {
        assert!(h.send(
            &[h.ix(
                vec![signer(h.payer.pubkey()), rw(address)],
                [
                    vec![11],
                    (i as u16 * 900).to_le_bytes().to_vec(),
                    chunk.to_vec()
                ]
                .concat()
            )],
            false
        ));
    }
    assert!(h.send(
        &[h.ix(
            vec![signer(h.payer.pubkey()), ro(h.log), rw(address)],
            vec![12]
        )],
        false
    ));
    let proof = Fork::parse(wire).unwrap();
    let mut checkpoints = vec![proof.first];
    if let Target::Checkpoint(cp) = proof.second {
        checkpoints.push(cp);
    }
    for (ordinal, bytes) in checkpoints.into_iter().enumerate() {
        let cp = Checkpoint::parse(bytes).unwrap();
        assert!(h.send(
            &[
                ed(&cp.service_key, &cp.signature, &cp.statement()),
                verify(h, address, ordinal as u8)
            ],
            false
        ));
    }
    if attestations {
        let key = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
        for index in 0..proof.attestation_count {
            let att = proof.attestation(index).unwrap();
            let statement = [
                b"mesh-msg/v1/transparency-witness".as_slice(),
                att.id,
                att.checkpoint_hash,
            ]
            .concat();
            assert!(h.send(
                &[
                    ed(&key, att.signature, &statement),
                    verify(h, address, index + 2)
                ],
                false
            ));
        }
    }
    address
}
fn verify(h: &Harness, stage: Address, ordinal: u8) -> Instruction {
    let mut accounts = vec![
        ro(h.log),
        rw(stage),
        ro(Address::from_str_const(
            "Sysvar1nstructions1111111111111111111111111",
        )),
    ];
    if ordinal >= 2 {
        accounts.push(ro(h.witness));
        accounts.push(signer(h.payer.pubkey()));
    }
    h.ix(accounts, vec![13, ordinal, 0, 0])
}
fn funded(version: u8) -> Harness {
    let mut h = Harness::new();
    if version == 2 {
        let mut account = h.svm.get_account(&h.log).unwrap();
        account.data[4] = 2;
        let origin = b"morseapp.io/log/main/v2";
        account.data[210..212].copy_from_slice(&(origin.len() as u16).to_le_bytes());
        account.data[212..212 + origin.len()].copy_from_slice(origin);
        h.svm.set_account(h.log, account).unwrap();
    }
    h.clock(1000);
    assert!(h.send(&[h.configure()], false));
    h.clock(1000 + TIMELOCK_SECONDS);
    h.fund_directory();
    assert!(h.send(&[h.deposit(100_000_000)], true));
    h.clock(ISSUED + 1);
    h
}
fn destinations(h: &mut Harness, finder: Address) -> (Address, Address) {
    let locked = Address::find_program_address(&[b"locked", &h.log_id], &h.program).0;
    for owner in [finder, locked] {
        assert!(h.send(
            &[Instruction {
                program_id: ATA,
                accounts: vec![
                    signer(h.payer.pubkey()),
                    rw(ata(&owner, &h.mint)),
                    ro(owner),
                    ro(h.mint),
                    ro(Address::default()),
                    ro(TOKEN)
                ],
                data: vec![1]
            }],
            false
        ));
    }
    (ata(&finder, &h.mint), ata(&locked, &h.mint))
}
fn instruction(
    h: &Harness,
    wire: &[u8],
    stage: Address,
    finder: Address,
    locked: Address,
) -> Instruction {
    let proof = Fork::parse(wire).unwrap();
    let second = match proof.second {
        Target::Checkpoint(cp) => Checkpoint::parse(cp).unwrap().hash(),
        _ => unreachable!(),
    };
    let receipt =
        Address::find_program_address(&[b"proof", &h.log_id, &proof.hash()], &h.program).0;
    let directory =
        Address::find_program_address(&[b"bond", &h.log_id, b"directory"], &h.program).0;
    h.ix(
        vec![
            signer(h.payer.pubkey()),
            rw(h.log),
            ro(stage),
            rw(h.economy),
            rw(receipt),
            rw(directory),
            rw(ata(&directory, &h.mint)),
            rw(finder),
            rw(locked),
            ro(h.mint),
            ro(TOKEN),
            ro(Address::default()),
            rw(h.witness),
            rw(h.bond),
            rw(h.vault),
        ],
        [vec![21 + proof.kind], second.to_vec()].concat(),
    )
}

#[test]
fn all_three_fork_kinds_atomically_pay_the_named_finder_and_lock_the_rest_for_both_log_profiles() {
    let mut fixtures = Vec::new();
    for version in [1, 2] {
        for kind in [1, 2, 3] {
            let mut h = funded(version);
            let named = Address::new_unique();
            let wire = evidence(version, kind, named);
            let before = h.snapshot("before settlement", serde_json::json!({}));
            if version == 2 && kind == 3
                && std::env::var_os("MORSE_PUBLIC_HISTORY_LEGACY_ACTIVE_EXPORT").is_some()
            {
                public_history_index::export(
                    &h.svm,
                    &[h.program],
                    before.clone(),
                    "MORSE_PUBLIC_HISTORY_LEGACY_ACTIVE_EXPORT",
                );
            }
            let clock_address =
                Address::from_str_const("SysvarC1ock11111111111111111111111111111111");
            let clock = h.svm.get_account(&clock_address).unwrap();
            let staged = stage(&mut h, &wire, true);
            let (finder, locked) = destinations(&mut h, named);
            let settle = instruction(&h, &wire, staged, finder, locked);
            assert!(
                h.send(std::slice::from_ref(&settle), false),
                "valid funded fork must settle"
            );
            assert_eq!(h.balance(finder), 60_000_000);
            assert_eq!(h.balance(locked), 540_000_000);
            assert_eq!(h.balance(h.vault), 0);
            assert_eq!(h.svm.get_account(&h.log).unwrap().data[5], 1);
            assert_eq!(h.svm.get_account(&h.witness).unwrap().data[5], 3);
            assert_eq!(h.svm.get_account(&h.bond).unwrap().data[4], 3);
            assert_eq!(
                &h.svm.get_account(&h.economy).unwrap().data[148..164],
                &[0; 16]
            );
            assert_eq!(h.svm.get_account(&h.economy).unwrap().data[164], 3);
            let receipt = h.svm.get_account(&settle.accounts[4].pubkey).unwrap();
            assert_eq!(&receipt.data[..4], b"MPR\x01");
            assert_eq!(receipt.data.len(), 384);
            assert_eq!(&receipt.data[72..104], named.as_ref());
            let mut fixture = h.snapshot("slashed", serde_json::json!({}));
            fixture["version"] = version.into();
            fixture["kind"] = kind.into();
            fixture["wire_hex"] = hex::encode(&wire).into();
            fixture["receipt_hex"] = hex::encode(&receipt.data).into();
            fixture["receipt_address"] = settle.accounts[4].pubkey.to_string().into();
            fixture["finder"] = named.to_string().into();
            fixture["submitter"] = h.payer.pubkey().to_string().into();
            fixture["before_accounts"] = before["accounts"].clone();
            fixture["clock"] = serde_json::json!({"address":clock_address.to_string(),
                "data_hex":hex::encode(clock.data),"owner":clock.owner.to_string(),
                "lamports":clock.lamports.to_string(),"executable":clock.executable});
            fixture["settlement_instruction_hex"] = hex::encode(&settle.data).into();
            fixture["settlement_accounts"] = settle.accounts.iter().map(|meta| serde_json::json!({
                "address":meta.pubkey.to_string(),"signer":meta.is_signer,"writable":meta.is_writable
            })).collect::<Vec<_>>().into();
            fixtures.push(fixture);
            assert!(!h.send(&[settle], false));
            assert_eq!(h.balance(finder), 60_000_000);
            assert_eq!(h.balance(locked), 540_000_000);
            assert!(!h.send(&[h.request()], true));
            assert!(!h.send(&[h.deposit(100_000_000)], true));
            if version == 2 && kind == 3
                && std::env::var_os("MORSE_PUBLIC_HISTORY_LEGACY_EXPORT").is_some()
            {
                public_history_index::export(
                    &h.svm,
                    &[h.program],
                    h.snapshot("public-history-legacy-final-bank", serde_json::json!({})),
                    "MORSE_PUBLIC_HISTORY_LEGACY_EXPORT",
                );
            }
        }
    }
    if let Ok(path) = std::env::var("MORSE_ADJUDICATION_FIXTURES_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
}

#[test]
fn age_window_and_atomic_refusals_preserve_every_bond_until_a_complete_verified_proof() {
    let mut h = funded(1);
    let wire = evidence(1, 1, Address::default());
    let staged = stage(&mut h, &wire, false);
    let owner = h.payer.pubkey();
    let (finder, locked) = destinations(&mut h, owner);
    let settle = instruction(&h, &wire, staged, finder, locked);
    assert!(
        !h.send(std::slice::from_ref(&settle), false),
        "unverified witnesses cannot be convicted"
    );
    let proof = Fork::parse(&wire).unwrap();
    let key = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
    for i in 0..2 {
        let att = proof.attestation(i).unwrap();
        let statement = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            att.id,
            att.checkpoint_hash,
        ]
        .concat();
        assert!(h.send(
            &[
                ed(&key, att.signature, &statement),
                verify(&h, staged, i + 2)
            ],
            false
        ));
    }
    h.clock(ISSUED);
    assert!(
        !h.send(std::slice::from_ref(&settle), false),
        "future checkpoint refused"
    );
    h.clock(ISSUED + WINDOW + 1);
    assert!(!h.send(std::slice::from_ref(&settle), false));
    h.clock(ISSUED + WINDOW);
    for index in [1, 3, 4, 5, 6, 7, 8, 12, 13, 14] {
        let mut readonly = settle.clone();
        readonly.accounts[index].is_writable = false;
        assert!(!h.send(&[readonly], false));
        assert_eq!(h.balance(h.vault), 100_000_000);
        assert_eq!(h.balance(finder), 0);
    }
    let mut wrong_finder = settle.clone();
    wrong_finder.accounts[7] = rw(h.source);
    assert!(!h.send(&[wrong_finder], false));
    let mut wrong_locked = settle.clone();
    wrong_locked.accounts[8] = rw(h.source);
    assert!(!h.send(&[wrong_locked], false));
    let original = h.svm.get_account(&h.vault).unwrap();
    let mut frozen = original.clone();
    frozen.data[108] = 2;
    h.svm.set_account(h.vault, frozen).unwrap();
    assert!(!h.send(std::slice::from_ref(&settle), false));
    assert_eq!(h.balance(finder), 0);
    assert_eq!(h.svm.get_account(&h.log).unwrap().data[5], 0);
    h.svm.set_account(h.vault, original).unwrap();
    assert!(h.send(&[h.request()], true));
    assert!(
        h.send(&[settle], false),
        "inclusive 28-day boundary can slash while unbonding"
    );
    h.clock(ISSUED + WINDOW + UNBOND);
    assert!(!h.send(&[h.withdraw(h.source)], true));
}

#[test]
fn finder_fallback_rounding_replay_and_late_cpi_rollback_do_not_divert_or_repeat_assets() {
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use solana_message::Message;
    use solana_transaction::Transaction;
    let mut h = funded(1);
    let wire = evidence(1, 1, Address::default());
    let staged = stage(&mut h, &wire, true);
    let payer = h.payer.pubkey();
    let (finder, locked) = destinations(&mut h, payer);
    let settle = instruction(&h, &wire, staged, finder, locked);
    let directory_vault = settle.accounts[6].pubkey;
    // Each vault rounds its own 10% down. Donations are escrow assets too.
    mint_to(&mut h, directory_vault, 9);
    let vault = h.vault;
    mint_to(&mut h, vault, 9);
    let before: Vec<_> = settle
        .accounts
        .iter()
        .skip(1)
        .filter(|a| a.is_writable)
        .map(|a| (a.pubkey, h.svm.get_account(&a.pubkey)))
        .collect();
    let transaction = |h: &Harness, budget| {
        Transaction::new(
            &[&h.payer],
            Message::new(
                &[
                    ComputeBudgetInstruction::set_compute_unit_limit(budget),
                    settle.clone(),
                ],
                Some(&payer),
            ),
            h.svm.latest_blockhash(),
        )
    };
    let simulated = h
        .svm
        .simulate_transaction(transaction(&h, 1_400_000))
        .unwrap();
    let budget = simulated.meta.compute_units_consumed as u32 - 10_000;
    let failure = h.svm.send_transaction(transaction(&h, budget)).unwrap_err();
    assert!(
        failure
            .meta
            .logs
            .iter()
            .any(|log| log == &format!("Program {TOKEN} success")),
        "the test must run transfers before exhausting compute"
    );
    for (address, account) in before {
        assert_eq!(h.svm.get_account(&address), account);
    }
    h.svm.expire_blockhash();
    // A different wallet may finish the stage but cannot capture zero-finder
    // fallback: the original uploader remains the receipt's finder.
    let submitter = solana_keypair::Keypair::new();
    h.svm.airdrop(&submitter.pubkey(), 1_000_000_000).unwrap();
    let mut sponsored = settle.clone();
    sponsored.accounts[0] = signer(submitter.pubkey());
    let tx = Transaction::new(
        &[&submitter],
        Message::new(&[sponsored], Some(&submitter.pubkey())),
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).unwrap();
    assert_eq!(h.balance(finder), 60_000_000);
    assert_eq!(h.balance(locked), 540_000_018);
    let receipt = h.svm.get_account(&settle.accounts[4].pubkey).unwrap();
    assert_eq!(&receipt.data[72..104], payer.as_ref());
    assert_eq!(&receipt.data[104..136], payer.as_ref());
    assert_eq!(
        u64::from_le_bytes(receipt.data[240..248].try_into().unwrap()),
        600_000_018
    );
    // Changing the unsigned finder changes the stage, not the receipt PDA.
    let changed = evidence(1, 1, submitter.pubkey());
    assert_eq!(
        Fork::parse(&wire).unwrap().hash(),
        Fork::parse(&changed).unwrap().hash()
    );
    let staged = stage(&mut h, &changed, true);
    let (other, _) = destinations(&mut h, submitter.pubkey());
    let retry = instruction(&h, &changed, staged, other, locked);
    assert!(!h.send(&[retry], false));
    assert_eq!(h.balance(other), 0);
    assert_eq!(h.balance(locked), 540_000_018);
}

#[test]
fn a_later_proof_can_slash_additional_double_signers_without_paying_old_bonds_again() {
    let mut h = funded(1);
    let replacement = register(&mut h, b"other", 98);
    deposit(&mut h, &replacement);
    let mut witnesses = vec![outside(&h), replacement];
    let old = evidence(1, 1, Address::default());
    let staged = stage(&mut h, &old, true);
    let payer = h.payer.pubkey();
    let (finder, locked) = destinations(&mut h, payer);
    let first = instruction(&h, &old, staged, finder, locked);
    assert!(h.send(&[first], false));
    assert_eq!(h.balance(finder), 60_000_000);
    // A service slash never confiscates a witness that only signed one side.
    assert_eq!(h.balance(witnesses[1].vault), 100_000_000);
    let wire = many_evidence(1, &witnesses);
    let staged = stage(&mut h, &wire, false);
    verify_witnesses(&mut h, staged, &wire, &witnesses);
    let mut settle = instruction(&h, &wire, staged, finder, locked);
    settle.accounts.extend([
        rw(witnesses[1].record),
        rw(witnesses[1].bond),
        rw(witnesses[1].vault),
    ]);
    assert!(h.send(&[settle], false));
    assert_eq!(h.balance(finder), 70_000_000);
    assert_eq!(h.balance(locked), 630_000_000);
    // Reordered annotations produce another proof hash, but no fresh assets.
    witnesses.reverse();
    let wire = many_evidence(1, &witnesses);
    let staged = stage(&mut h, &wire, false);
    verify_witnesses(&mut h, staged, &wire, &witnesses);
    let mut settle = instruction(&h, &wire, staged, finder, locked);
    settle.accounts.truncate(12);
    for w in &witnesses {
        settle
            .accounts
            .extend([rw(w.record), rw(w.bond), rw(w.vault)]);
    }
    assert!(!h.send(&[settle], false));
    assert_eq!(h.balance(finder), 70_000_000);
}

#[test]
fn fresh_fork_evidence_cannot_recover_a_bond_that_has_already_been_withdrawn() {
    let mut h = funded(1);
    h.clock(ISSUED - UNBOND);
    assert!(h.send(&[h.request()], true));
    h.clock(ISSUED);
    assert!(h.send(&[h.withdraw(h.source)], true));
    h.clock(ISSUED + 1);
    let wire = evidence(1, 1, Address::default());
    let staged = stage(&mut h, &wire, true);
    let payer = h.payer.pubkey();
    let (finder, locked) = destinations(&mut h, payer);
    let settle = instruction(&h, &wire, staged, finder, locked);
    assert!(!h.send(&[settle], false));
    assert_eq!(h.balance(h.source), 1_000_000_000);
    assert_eq!(h.balance(finder), 0);
    assert_eq!(h.svm.get_account(&h.log).unwrap().data[5], 0);
}

#[test]
fn shared_openssl_mesh_signed_proof_vectors_replay_through_real_staging_and_settlement() {
    let root: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/fork-v1/vectors.json")).unwrap();
    let mut checked = 0;
    for case in root["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let wire = hex::decode(case["wire_hex"].as_str().unwrap()).unwrap();
        let Ok(proof) = Fork::parse(&wire) else {
            continue;
        };
        if !matches!(proof.second, Target::Checkpoint(_))
            || matches!(
                name,
                "wrong-log" | "bad-checkpoint-signature" | "different-log-profiles-cannot-conflict"
            )
        {
            continue;
        }
        let version = proof.first[0];
        let mut h = funded(version);
        // The vectors use epoch timestamps 1–4 seconds. Fund at day 14 and
        // adjudicate immediately, inside the immutable 28-day proof window.
        h.clock(1001 + TIMELOCK_SECONDS);
        let pin_values = case
            .get("pins")
            .unwrap_or(&root["pins"])
            .as_array()
            .unwrap();
        if pin_values.len() > 4 {
            let directory_source = ata(&h.payer.pubkey(), &h.mint);
            mint_to(&mut h, directory_source, 2_000_000_000);
            let source = h.source;
            mint_to(&mut h, source, 2_000_000_000);
            let mut topup = h.directory_deposit();
            topup.data[1..].copy_from_slice(&2_000_000_000u64.to_le_bytes());
            assert!(h.send(&[topup], false));
        }
        let mut witnesses = Vec::new();
        for pin in pin_values {
            let id = pin["witness_id"].as_str().unwrap();
            let seed = match id {
                "both" => 12,
                "left" => 13,
                "right" => 14,
                _ => 40 + id.strip_prefix("witness-").unwrap().parse::<u8>().unwrap(),
            };
            let witness = register(&mut h, id.as_bytes(), seed);
            assert_eq!(
                hex::encode(witness.key.verifying_key().to_bytes()),
                pin["public_key"]
            );
            deposit(&mut h, &witness);
            witnesses.push(witness);
        }
        let staged = stage(&mut h, &wire, false);
        for index in 0..proof.attestation_count {
            let att = proof.attestation(index).unwrap();
            let Some(witness) = witnesses.iter().find(|w| w.id == att.id) else {
                continue;
            };
            let message = native_statement(att.id, att.checkpoint_hash);
            let valid_signature = witness
                .key
                .verifying_key()
                .verify_strict(
                    &message,
                    &ed25519_dalek::Signature::from_slice(att.signature).unwrap(),
                )
                .is_ok();
            let mut verify_ix = verify(&h, staged, index + 2);
            verify_ix.accounts[3] = ro(witness.record);
            assert_eq!(
                h.send(
                    &[
                        ed(
                            &witness.key.verifying_key().to_bytes(),
                            att.signature,
                            &message
                        ),
                        verify_ix
                    ],
                    false
                ),
                valid_signature,
                "{name}"
            );
        }
        let owner = if *proof.finder == [0; 32] {
            h.payer.pubkey()
        } else {
            Address::new_from_array(*proof.finder)
        };
        let (finder, locked) = destinations(&mut h, owner);
        let mut settle = instruction(&h, &wire, staged, finder, locked);
        settle.accounts.truncate(12);
        let expected = case["witnesses"].as_array().unwrap();
        for id in expected {
            let w = witnesses
                .iter()
                .find(|w| w.id == id.as_str().unwrap().as_bytes())
                .unwrap();
            settle
                .accounts
                .extend([rw(w.record), rw(w.bond), rw(w.vault)]);
        }
        let valid = case["valid"].as_bool().unwrap();
        let result = if expected.len() > 4 {
            send_v0(&mut h, settle).is_ok()
        } else {
            h.send(&[settle], false)
        };
        assert_eq!(result, valid, "{name}");
        let total = if valid {
            (if pin_values.len() > 4 {
                2_500_000_000
            } else {
                500_000_000
            }) + expected.len() as u64 * 100_000_000
        } else {
            0
        };
        assert_eq!(h.balance(finder), total / 10, "{name}");
        assert_eq!(h.balance(locked), total - total / 10, "{name}");
        assert_eq!(
            h.balance(h.vault),
            100_000_000,
            "unimplicated outside witness is untouched"
        );
        checked += 1;
    }
    assert!(
        checked >= 20,
        "the shared oracle cases must actually execute"
    );
}

#[test]
fn an_outsider_cannot_poison_a_stage_with_optional_unfunded_witness_annotations() {
    use solana_message::Message;
    use solana_transaction::Transaction;
    let mut h = funded(1);
    let unfunded = register(&mut h, b"unfunded", 96);
    let witnesses = [outside(&h), unfunded];
    let wire = many_evidence(1, &witnesses);
    let staged = stage(&mut h, &wire, false);
    let proof = Fork::parse(&wire).unwrap();
    for index in [1, 3] {
        let att = proof.attestation(index).unwrap();
        let mut legacy = verify(&h, staged, index + 2);
        legacy.accounts.truncate(4);
        legacy.accounts[3] = ro(witnesses[1].record);
        for include_foreign_authority in [false, true] {
            let mut ix = legacy.clone();
            if include_foreign_authority {
                ix.accounts.push(signer(h.operator.pubkey()));
            }
            let tx = Transaction::new(
                &[&h.operator],
                Message::new(
                    &[
                        ed(
                            &witnesses[1].key.verifying_key().to_bytes(),
                            att.signature,
                            &native_statement(att.id, att.checkpoint_hash),
                        ),
                        ix,
                    ],
                    Some(&h.operator.pubkey()),
                ),
                h.svm.latest_blockhash(),
            );
            assert!(
                h.svm.send_transaction(tx).is_err(),
                "an outsider must not select the uploader's optional accusations"
            );
            h.svm.expire_blockhash();
        }
    }
    for index in [0, 2] {
        let att = proof.attestation(index).unwrap();
        assert!(h.send(
            &[
                ed(
                    &witnesses[0].key.verifying_key().to_bytes(),
                    att.signature,
                    &native_statement(att.id, att.checkpoint_hash)
                ),
                verify(&h, staged, index + 2)
            ],
            false
        ));
    }
    let first = Checkpoint::parse(proof.first).unwrap();
    let tx = Transaction::new(
        &[&h.operator],
        Message::new(
            &[
                ed(&first.service_key, &first.signature, &first.statement()),
                verify(&h, staged, 0),
            ],
            Some(&h.operator.pubkey()),
        ),
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect("service verification remains permissionless");
    let payer = h.payer.pubkey();
    let (finder, locked) = destinations(&mut h, payer);
    assert!(h.send(&[instruction(&h, &wire, staged, finder, locked)], false));
    assert_eq!(h.balance(finder), 60_000_000);
    assert_eq!(h.svm.get_account(&witnesses[1].record).unwrap().data[5], 0);
}

struct Witness {
    id: Vec<u8>,
    key: SigningKey,
    record: Address,
    bond: Address,
    vault: Address,
}
fn outside(h: &Harness) -> Witness {
    Witness {
        id: b"outside".to_vec(),
        key: SigningKey::from_bytes(&[12; 32]),
        record: h.witness,
        bond: h.bond,
        vault: h.vault,
    }
}
fn register(h: &mut Harness, id: &[u8], seed: u8) -> Witness {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public = key.verifying_key().to_bytes();
    let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &public]);
    let record =
        Address::find_program_address(&[b"witness", &h.log_id, identity.as_ref()], &h.program).0;
    let statement = [
        b"morse-witness-register-v1".as_slice(),
        id,
        h.operator.pubkey().as_ref(),
        h.payer.pubkey().as_ref(),
    ]
    .concat();
    let signature = key.sign(&statement).to_bytes();
    let ix = h.ix(
        vec![
            signer(h.operator.pubkey()),
            signer(h.payer.pubkey()),
            ro(h.log),
            rw(record),
            ro(Address::default()),
            ro(Address::from_str_const(
                "Sysvar1nstructions1111111111111111111111111",
            )),
        ],
        [
            vec![4, 0, 0, id.len() as u8],
            id.to_vec(),
            public.to_vec(),
            h.payer.pubkey().as_ref().to_vec(),
            vec![0; 32],
            signature.to_vec(),
        ]
        .concat(),
    );
    assert!(h.send(&[ed(&public, &signature, &statement), ix], true));
    let bond =
        Address::find_program_address(&[b"bond", &h.log_id, identity.as_ref()], &h.program).0;
    Witness {
        id: id.to_vec(),
        key,
        record,
        bond,
        vault: ata(&bond, &h.mint),
    }
}
fn mint_to(h: &mut Harness, destination: Address, amount: u64) {
    assert!(h.send(
        &[Instruction {
            program_id: TOKEN,
            accounts: vec![rw(h.mint), rw(destination), signer(h.payer.pubkey())],
            data: [vec![7], amount.to_le_bytes().to_vec()].concat()
        }],
        false
    ));
}
fn deposit(h: &mut Harness, witness: &Witness) {
    let mut ix = h.deposit(100_000_000);
    ix.accounts[3] = rw(witness.record);
    ix.accounts[4] = rw(witness.bond);
    ix.accounts[5] = rw(witness.vault);
    assert!(h.send(&[ix], true));
}
fn native_statement(id: &[u8], checkpoint_hash: &[u8]) -> Vec<u8> {
    [
        b"mesh-msg/v1/transparency-witness".as_slice(),
        id,
        checkpoint_hash,
    ]
    .concat()
}
fn many_evidence(version: u8, witnesses: &[Witness]) -> Vec<u8> {
    let base = evidence(version, 1, Address::default());
    let proof = Fork::parse(&base).unwrap();
    let first = Checkpoint::parse(proof.first).unwrap();
    let second = match proof.second {
        Target::Checkpoint(cp) => Checkpoint::parse(cp).unwrap(),
        _ => unreachable!(),
    };
    let tagged = witnesses.len() > 8;
    let mut wire = base[..446].to_vec();
    wire[0] = if tagged { 3 } else { 1 };
    wire.push(witnesses.len() as u8 * 2);
    for cp in [first, second] {
        for witness in witnesses {
            wire.push(witness.id.len() as u8);
            wire.extend_from_slice(&witness.id);
            wire.extend_from_slice(&cp.hash());
            if tagged {
                wire.push(0);
            }
            wire.extend_from_slice(
                &witness
                    .key
                    .sign(&native_statement(&witness.id, &cp.hash()))
                    .to_bytes(),
            );
        }
    }
    wire
}
fn verify_witnesses(h: &mut Harness, address: Address, wire: &[u8], witnesses: &[Witness]) {
    let proof = Fork::parse(wire).unwrap();
    for index in 0..proof.attestation_count {
        let att = proof.attestation(index).unwrap();
        let witness = witnesses.iter().find(|w| w.id == att.id).unwrap();
        let mut ix = verify(h, address, index + 2);
        ix.accounts[3] = ro(witness.record);
        let (message, signature) = if att.algorithm == 4 {
            let cp = if Checkpoint::parse(proof.first).unwrap().hash() == *att.checkpoint_hash {
                proof.first
            } else {
                match proof.second {
                    Target::Checkpoint(cp) => cp,
                    _ => unreachable!(),
                }
            };
            (
                morse_judge::witness::c2sp_statement(
                    b"morseapp.io/log/main/v2",
                    cp,
                    u64::from_be_bytes(att.signature[..8].try_into().unwrap()),
                )
                .unwrap()
                .as_slice()
                .to_vec(),
                &att.signature[8..],
            )
        } else {
            (native_statement(att.id, att.checkpoint_hash), att.signature)
        };
        assert!(h.send(
            &[
                ed(&witness.key.verifying_key().to_bytes(), signature, &message),
                ix
            ],
            false
        ));
    }
}

fn maximum_contradiction(version: u8, witnesses: &[Witness]) -> Vec<u8> {
    let base = evidence(version, 1, Address::default());
    let proof = Fork::parse(&base).unwrap();
    let mut first = Checkpoint::parse(proof.first).unwrap();
    let mut second = match proof.second {
        Target::Checkpoint(cp) => Checkpoint::parse(cp).unwrap(),
        _ => unreachable!(),
    };
    let prefix = if version == 1 {
        b"mesh-msg/v1/transparency-node".as_slice()
    } else {
        &[1]
    };
    for (cp, leaf) in [(&mut first, [3; 32]), (&mut second, [4; 32])] {
        cp.tree_size = u32::MAX as u64;
        cp.tree_root = leaf;
        for _ in 0..32 {
            cp.tree_root = hashv(&[prefix, &cp.tree_root, &[5; 32]]).to_bytes();
        }
        cp.signature = SigningKey::from_bytes(&[11; 32])
            .sign(&cp.statement())
            .to_bytes();
    }
    let mut wire = [
        vec![3, b'F', b'R', b'K', 2],
        vec![0; 32],
        first.service_key.to_vec(),
        checkpoint(&first),
        vec![0],
        checkpoint(&second),
        vec![32],
    ]
    .concat();
    for cp in [&first, &second] {
        for witness in witnesses {
            wire.push(witness.id.len() as u8);
            wire.extend_from_slice(&witness.id);
            wire.extend_from_slice(&cp.hash());
            wire.push(if version == 2 { 4 } else { 0 });
            let message = if version == 2 {
                wire.extend_from_slice(&(ISSUED as u64 + 1).to_be_bytes());
                morse_judge::witness::c2sp_statement(
                    b"morseapp.io/log/main/v2",
                    &checkpoint(cp),
                    ISSUED as u64 + 1,
                )
                .unwrap()
                .as_slice()
                .to_vec()
            } else {
                native_statement(&witness.id, &cp.hash())
            };
            wire.extend_from_slice(&witness.key.sign(&message).to_bytes());
        }
    }
    wire.extend_from_slice(&0u64.to_be_bytes());
    for leaf in [[3; 32], [4; 32]] {
        wire.push(32);
        wire.extend_from_slice(&[5; 1024]);
        wire.extend_from_slice(&leaf);
    }
    assert_eq!(wire.len(), if version == 2 { 8009 } else { 7753 });
    wire
}
fn send_v0(h: &mut Harness, ix: Instruction) -> Result<(usize, u64), String> {
    use solana_address_lookup_table_interface::instruction::{
        create_lookup_table, extend_lookup_table,
    };
    use solana_clock::Clock;
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
    use solana_transaction::versioned::VersionedTransaction;
    let mut addresses = Vec::new();
    for meta in &ix.accounts {
        if !meta.is_signer && !addresses.contains(&meta.pubkey) {
            addresses.push(meta.pubkey);
        }
    }
    let slot = h.svm.get_sysvar::<Clock>().slot;
    let (create, table) = create_lookup_table(h.payer.pubkey(), h.payer.pubkey(), slot);
    assert!(h.send(&[create], false));
    for chunk in addresses.chunks(20) {
        assert!(h.send(
            &[extend_lookup_table(
                table,
                h.payer.pubkey(),
                Some(h.payer.pubkey()),
                chunk.to_vec()
            )],
            false
        ));
    }
    h.svm.warp_to_slot(slot + 1);
    let message = v0::Message::try_compile(
        &h.payer.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        &[AddressLookupTableAccount {
            key: table,
            addresses,
        }],
        h.svm.latest_blockhash(),
    )
    .unwrap();
    let loaded = message.account_keys.len()
        + message
            .address_table_lookups
            .iter()
            .map(|table| table.writable_indexes.len() + table.readonly_indexes.len())
            .sum::<usize>();
    assert!(loaded <= 64, "settlement must fit 64 runtime account locks");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&h.payer]).unwrap();
    let size = bincode::serialize(&tx).unwrap().len();
    assert!(size <= 1232, "serialized settlement is {size} bytes");
    h.svm
        .send_transaction(tx)
        .map(|meta| (size, meta.compute_units_consumed))
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn sixteen_double_signers_settle_in_one_packet_with_real_lookup_tables_and_token_cpis() {
    let mut fixtures = Vec::new();
    for version in [1, 2] {
        let mut h = funded(version);
        h.clock(ISSUED - UNBOND - 1);
        assert!(h.send(&[h.request()], true));
        h.clock(ISSUED + 1);
        assert!(h.send(&[h.withdraw(h.source)], true));
        let owner_ata = ata(&h.payer.pubkey(), &h.mint);
        mint_to(&mut h, owner_ata, 1_100_000_000);
        let mut topup = h.directory_deposit();
        topup.data[1..].copy_from_slice(&1_100_000_000u64.to_le_bytes());
        assert!(h.send(&[topup], false));
        let source = h.source;
        mint_to(&mut h, source, 1_500_000_000);
        let mut witnesses = Vec::new();
        for index in 0..16 {
            let witness = register(
                &mut h,
                format!("{:0<64}", format!("w{index:02}")).as_bytes(),
                30 + index,
            );
            deposit(&mut h, &witness);
            witnesses.push(witness);
        }
        let wire = maximum_contradiction(version, &witnesses);
        let staged = stage(&mut h, &wire, false);
        verify_witnesses(&mut h, staged, &wire, &witnesses);
        let payer = h.payer.pubkey();
        let (finder, locked) = destinations(&mut h, payer);
        let mut settle = instruction(&h, &wire, staged, finder, locked);
        settle.accounts.truncate(12);
        for witness in &witnesses {
            settle
                .accounts
                .extend([rw(witness.record), rw(witness.bond), rw(witness.vault)]);
        }
        let extra: Vec<_> = witnesses
            .iter()
            .flat_map(|w| [w.record, w.bond, w.vault])
            .collect();
        let snapshot = maximum_snapshot(&h, &extra);
        let before = h.svm.clone();
        let (size, units) =
            send_v0(&mut h, settle.clone()).expect("all sixteen bonds must settle atomically");
        eprintln!("profile {version}: full-16 settlement {size} bytes, {units} compute units");
        assert_eq!(h.balance(finder), 320_000_000);
        assert_eq!(h.balance(locked), 2_880_000_000);
        for witness in &witnesses {
            assert_eq!(h.balance(witness.vault), 0);
            assert_eq!(h.svm.get_account(&witness.record).unwrap().data[5], 3);
        }
        assert_eq!(
            &h.svm.get_account(&h.economy).unwrap().data[148..164],
            &[0; 16]
        );
        fixtures.push(maximum_fixture(
            &h, snapshot, &extra, &wire, &settle, version, false,
        ));
        // A separate bank branch exercises the largest anchored settlement:
        // 62 instruction accounts plus the judge and compute-budget programs.
        h.svm = before;
        fixtures.push(settle_maximum_anchor(
            &mut h, &wire, &witnesses, finder, locked,
        ));
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_MAXIMUM_FIXTURES_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
}

fn maximum_snapshot(h: &Harness, extra: &[Address]) -> serde_json::Value {
    let mut snapshot = h.snapshot("maximum settlement", serde_json::json!({}));
    for address in extra {
        let account = h.svm.get_account(address).unwrap();
        snapshot["accounts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "address":address.to_string(),"data_hex":hex::encode(account.data),
                "owner":account.owner.to_string(),"lamports":account.lamports.to_string()
            }));
    }
    let clock_address = Address::from_str_const("SysvarC1ock11111111111111111111111111111111");
    let clock = h.svm.get_account(&clock_address).unwrap();
    snapshot["clock"] = serde_json::json!({"address":clock_address.to_string(),
        "data_hex":hex::encode(clock.data),"owner":clock.owner.to_string(),
        "lamports":clock.lamports.to_string(),"executable":clock.executable});
    snapshot
}

fn maximum_fixture(
    h: &Harness,
    before: serde_json::Value,
    extra: &[Address],
    wire: &[u8],
    settle: &Instruction,
    version: u8,
    anchored: bool,
) -> serde_json::Value {
    let mut fixture = maximum_snapshot(h, extra);
    fixture["before_accounts"] = before["accounts"].clone();
    fixture["clock"] = before["clock"].clone();
    fixture["version"] = version.into();
    fixture["kind"] = 2.into();
    fixture["anchored"] = anchored.into();
    fixture["wire_hex"] = hex::encode(wire).into();
    fixture["receipt_hex"] =
        hex::encode(h.svm.get_account(&settle.accounts[4].pubkey).unwrap().data).into();
    fixture["receipt_address"] = settle.accounts[4].pubkey.to_string().into();
    fixture["finder"] = h.payer.pubkey().to_string().into();
    fixture["submitter"] = h.payer.pubkey().to_string().into();
    fixture["settlement_instruction_hex"] = hex::encode(&settle.data).into();
    fixture["settlement_accounts"] = settle.accounts.iter().map(|meta|serde_json::json!({
        "address":meta.pubkey.to_string(),"signer":meta.is_signer,"writable":meta.is_writable
    })).collect::<Vec<_>>().into();
    fixture
}

fn prepare_set(h: &mut Harness, generation: u16, witness: Address) -> Address {
    prepare_many_set(h, generation, &[witness])
}
fn prepare_many_set(h: &mut Harness, generation: u16, witnesses: &[Address]) -> Address {
    let set = Address::find_program_address(
        &[b"witness-set", &h.log_id, &generation.to_le_bytes()],
        &h.program,
    )
    .0;
    let mut accounts = vec![
        signer(h.payer.pubkey()),
        signer(h.payer.pubkey()),
        ro(h.config),
        ro(h.log),
        rw(set),
        ro(Address::default()),
    ];
    accounts.extend(witnesses.iter().copied().map(ro));
    assert!(h.send(
        &[h.ix(
            accounts,
            [vec![5], generation.to_le_bytes().to_vec()].concat()
        )],
        false
    ));
    set
}

fn settle_maximum_anchor(
    h: &mut Harness,
    wire: &[u8],
    witnesses: &[Witness],
    finder: Address,
    locked: Address,
) -> serde_json::Value {
    use morse_judge::state::{initialize_ring, RING_LEN};
    use solana_clock::Clock;
    let proof = Fork::parse(wire).unwrap();
    let second = match proof.second {
        Target::Checkpoint(cp) => Checkpoint::parse(cp).unwrap(),
        _ => unreachable!(),
    };
    let set = prepare_many_set(
        h,
        1,
        &witnesses.iter().map(|w| w.record).collect::<Vec<_>>(),
    );
    h.clock(h.svm.get_sysvar::<Clock>().unix_timestamp + TIMELOCK_SECONDS);
    activate(h, set);
    let ring = Address::find_program_address(&[b"ring", b"custody-test"], &h.program).0;
    let mut data = vec![0; RING_LEN];
    initialize_ring(&mut data, &h.log_id).unwrap();
    Harness::account(&mut h.svm, ring, h.program, data);
    post(h, ring, &second);
    let c2sp = second.version == 2;
    for (index, witness) in witnesses.iter().enumerate() {
        let att = proof.attestation(16 + index as u8).unwrap();
        let (message, signature, payload) = if c2sp {
            (
                morse_judge::witness::c2sp_statement(
                    b"morseapp.io/log/main/v2",
                    &checkpoint(&second),
                    u64::from_be_bytes(att.signature[..8].try_into().unwrap()),
                )
                .unwrap()
                .as_slice()
                .to_vec(),
                &att.signature[8..],
                [
                    vec![8, 0, 0, 0, 0, index as u8],
                    att.signature.to_vec(),
                    checkpoint(&second),
                ]
                .concat(),
            )
        } else {
            (
                native_statement(&witness.id, &second.hash()),
                att.signature,
                vec![9, 0, 0, 0, 0, index as u8],
            )
        };
        assert!(h.send(
            &[
                ed(&witness.key.verifying_key().to_bytes(), signature, &message),
                h.ix(
                    vec![
                        ro(h.log),
                        rw(ring),
                        ro(set),
                        ro(Address::from_str_const(
                            "Sysvar1nstructions1111111111111111111111111"
                        ))
                    ],
                    payload
                )
            ],
            false
        ));
    }
    let mut anchored = wire[..257].to_vec();
    anchored[0] = if c2sp { 2 } else { 1 };
    anchored.extend_from_slice(&[1, 0, 0, 0, 0, 16]);
    for index in 0..16 {
        let att = proof.attestation(index).unwrap();
        anchored.push(att.id.len() as u8);
        anchored.extend_from_slice(att.id);
        anchored.extend_from_slice(att.checkpoint_hash);
        if c2sp {
            anchored.push(4);
        }
        anchored.extend_from_slice(att.signature);
    }
    anchored.extend_from_slice(&wire[wire.len() - 2122..]);
    let staged = stage(h, &anchored, false);
    verify_witnesses(h, staged, &anchored, witnesses);
    let mut settle = anchored_instruction(
        h,
        &anchored,
        staged,
        finder,
        locked,
        (ring, set, second.hash(), false),
    );
    for witness in witnesses {
        settle
            .accounts
            .extend([rw(witness.record), rw(witness.bond), rw(witness.vault)]);
    }
    let mut extra: Vec<_> = witnesses
        .iter()
        .flat_map(|w| [w.record, w.bond, w.vault])
        .collect();
    extra.extend([ring, set]);
    let snapshot = maximum_snapshot(h, &extra);
    let (size, units) =
        send_v0(h, settle.clone()).expect("all sixteen historical cosigners settle atomically");
    eprintln!(
        "profile {}: full-16 anchored settlement {size} bytes, {units} compute units",
        second.version
    );
    assert_eq!(h.balance(finder), 320_000_000);
    assert_eq!(h.balance(locked), 2_880_000_000);
    for witness in witnesses {
        assert_eq!(h.balance(witness.vault), 0);
    }
    maximum_fixture(
        h,
        snapshot,
        &extra,
        &anchored,
        &settle,
        second.version,
        true,
    )
}
fn activate(h: &mut Harness, set: Address) {
    assert!(h.send(&[h.ix(vec![rw(h.log), ro(set)], vec![6])], false));
}
fn post(h: &mut Harness, ring: Address, cp: &Checkpoint) {
    assert!(h.send(
        &[
            ed(&cp.service_key, &cp.signature, &cp.statement()),
            h.ix(
                vec![
                    ro(h.log),
                    rw(ring),
                    signer(h.payer.pubkey()),
                    ro(Address::from_str_const(
                        "Sysvar1nstructions1111111111111111111111111"
                    ))
                ],
                [vec![3, 0, 0], checkpoint(cp)].concat()
            )
        ],
        false
    ));
}
fn anchor_evidence(version: u8, kind: u8) -> (Vec<u8>, Checkpoint) {
    let base = evidence(version, kind, Address::default());
    let proof = Fork::parse(&base).unwrap();
    let second = match proof.second {
        Target::Checkpoint(cp) => Checkpoint::parse(cp).unwrap(),
        _ => unreachable!(),
    };
    let a = proof.attestation(0).unwrap();
    let mut wire = base[..257].to_vec();
    wire.extend_from_slice(&[1, 0, 0, 0, 0, 1]); // ring index zero, one first-side signature
    wire.push(a.id.len() as u8);
    wire.extend_from_slice(a.id);
    wire.extend_from_slice(a.checkpoint_hash);
    wire.extend_from_slice(a.signature);
    if kind == 2 {
        wire.extend_from_slice(&base[base.len() - 74..]);
    }
    (wire, second)
}
fn anchored_instruction(
    h: &Harness,
    wire: &[u8],
    staged: Address,
    finder: Address,
    locked: Address,
    anchor: (Address, Address, [u8; 32], bool),
) -> Instruction {
    let (ring, set, expected, accuse_witness) = anchor;
    // Reuse the fixed settlement account contract; the FRK determines its own
    // receipt identity and the instruction explicitly pins the ring contents.
    let base = evidence(1, 1, Address::default());
    let mut ix = instruction(h, &base, staged, finder, locked);
    let proof = Fork::parse(wire).unwrap();
    ix.accounts[4] =
        rw(Address::find_program_address(&[b"proof", &h.log_id, &proof.hash()], &h.program).0);
    ix.accounts.splice(12..12, [ro(ring), ro(set)]);
    if !accuse_witness {
        ix.accounts.truncate(14);
    }
    ix.data = [vec![21 + proof.kind], expected.to_vec()].concat();
    ix
}

#[test]
fn anchored_verdicts_pin_historical_generation_key_and_contents_and_only_native_metadata_accuses_rollback(
) {
    use morse_judge::state::{initialize_ring, RING_LEN};
    use morse_judge::witness::c2sp_statement;
    let mut fixtures = Vec::new();
    for (version, c2sp) in [(1, false), (2, false), (2, true)] {
        for kind in [1, 2, 3] {
            let mut h = funded(version);
            h.clock(ISSUED - TIMELOCK_SECONDS);
            let witness = h.witness;
            let historical = prepare_set(&mut h, 1, witness);
            h.clock(ISSUED);
            activate(&mut h, historical);
            let ring = Address::find_program_address(&[b"ring", b"custody-test"], &h.program).0;
            let mut bytes = vec![0; RING_LEN];
            initialize_ring(&mut bytes, &h.log_id).unwrap();
            Harness::account(&mut h.svm, ring, h.program, bytes);
            let (wire, second) = anchor_evidence(version, kind);
            h.clock(ISSUED + 1);
            post(&mut h, ring, &second);
            let key = SigningKey::from_bytes(&[12; 32]);
            let message = if c2sp {
                c2sp_statement(
                    b"morseapp.io/log/main/v2",
                    &checkpoint(&second),
                    ISSUED as u64 + 1,
                )
                .unwrap()
                .as_slice()
                .to_vec()
            } else {
                native_statement(b"outside", &second.hash())
            };
            let signature = key.sign(&message).to_bytes();
            let payload = if c2sp {
                [
                    vec![8, 0, 0, 0, 0, 0],
                    (ISSUED as u64 + 1).to_be_bytes().to_vec(),
                    signature.to_vec(),
                    checkpoint(&second),
                ]
                .concat()
            } else {
                vec![9, 0, 0, 0, 0, 0]
            };
            assert!(h.send(
                &[
                    ed(&key.verifying_key().to_bytes(), &signature, &message),
                    h.ix(
                        vec![
                            ro(h.log),
                            rw(ring),
                            ro(historical),
                            ro(Address::from_str_const(
                                "Sysvar1nstructions1111111111111111111111111"
                            ))
                        ],
                        payload
                    )
                ],
                false
            ));
            // Same ID with a new key is a different immutable identity. The
            // current set must not reinterpret an old checkpoint's bitmap.
            let replacement = register(&mut h, b"outside", 99);
            let current = prepare_set(&mut h, 2, replacement.record);
            h.clock(ISSUED + 1 + TIMELOCK_SECONDS);
            activate(&mut h, current);
            let mut before = h.snapshot("before anchored settlement", serde_json::json!({}));
            for address in [ring, historical, current, replacement.record] {
                let account = h.svm.get_account(&address).unwrap();
                before["accounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "address":address.to_string(),"data_hex":hex::encode(account.data),
                        "owner":account.owner.to_string(),"lamports":account.lamports.to_string()
                    }));
            }
            let clock_address =
                Address::from_str_const("SysvarC1ock11111111111111111111111111111111");
            let clock = h.svm.get_account(&clock_address).unwrap();
            let staged = stage(&mut h, &wire, true);
            let owner = h.payer.pubkey();
            let (finder, locked) = destinations(&mut h, owner);
            let accuse = !c2sp || kind != 3;
            let settle = anchored_instruction(
                &h,
                &wire,
                staged,
                finder,
                locked,
                (ring, historical, second.hash(), accuse),
            );
            let mut wrong = settle.clone();
            wrong.accounts[13] = ro(current);
            assert!(
                !h.send(&[wrong], false),
                "current set must not replace historical set"
            );
            let mut wrong = settle.clone();
            wrong.data[1] ^= 1;
            assert!(
                !h.send(&[wrong], false),
                "ring entry hash must match what the reporter checked"
            );
            if !accuse {
                let mut false_accusation = settle.clone();
                false_accusation
                    .accounts
                    .extend([rw(h.witness), rw(h.bond), rw(h.vault)]);
                assert!(
                    !h.send(&[false_accusation], false),
                    "C2SP does not attest rollback metadata"
                );
            }
            assert!(
                h.send(std::slice::from_ref(&settle), false),
                "valid historical fork"
            );
            let amount = if accuse { 600_000_000 } else { 500_000_000 };
            assert_eq!(h.balance(finder), amount / 10);
            assert_eq!(h.balance(locked), amount - amount / 10);
            assert_eq!(h.balance(h.vault), if accuse { 0 } else { 100_000_000 });
            assert_eq!(h.svm.get_account(&replacement.record).unwrap().data[5], 0);
            let mut fixture = h.snapshot("anchored slashed", serde_json::json!({}));
            fixture["version"] = version.into();
            fixture["kind"] = kind.into();
            fixture["c2sp"] = c2sp.into();
            fixture["wire_hex"] = hex::encode(&wire).into();
            fixture["receipt_hex"] =
                hex::encode(h.svm.get_account(&settle.accounts[4].pubkey).unwrap().data).into();
            fixture["receipt_address"] = settle.accounts[4].pubkey.to_string().into();
            fixture["finder"] = owner.to_string().into();
            fixture["submitter"] = owner.to_string().into();
            fixture["before_accounts"] = before["accounts"].clone();
            fixture["clock"] = serde_json::json!({"address":clock_address.to_string(),
                "data_hex":hex::encode(clock.data),"owner":clock.owner.to_string(),
                "lamports":clock.lamports.to_string(),"executable":clock.executable});
            fixture["settlement_instruction_hex"] = hex::encode(&settle.data).into();
            fixture["settlement_accounts"] = settle.accounts.iter().map(|meta| serde_json::json!({
                "address":meta.pubkey.to_string(),"signer":meta.is_signer,"writable":meta.is_writable
            })).collect::<Vec<_>>().into();
            fixtures.push(fixture);
        }
    }
    if let Ok(path) = std::env::var("MORSE_RELAY_ANCHORED_FIXTURES_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }
}
