use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::env::var("MORSE_TOKEN_CUSTODY_FIXTURES_PATH").expect("set immutable fixture path"),
        )
        .unwrap(),
    )
    .unwrap()
}
fn instruction(v: &Value, payer: &Keypair) -> Instruction {
    let keys = v["accountKeys"].as_array().unwrap();
    let signers = v["signerKeys"].as_array().unwrap();
    let writable = v["writableKeys"].as_array().unwrap();
    Instruction {
        program_id: v["programId"].as_str().unwrap().parse().unwrap(),
        accounts: keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let is_signer = signers.contains(key)
                    && !(v["programId"] == "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
                        && index == 2);
                AccountMeta {
                    pubkey: if is_signer {
                        payer.pubkey()
                    } else {
                        key.as_str().unwrap().parse().unwrap()
                    },
                    is_signer,
                    is_writable: writable.contains(key),
                }
            })
            .collect(),
        data: STANDARD.decode(v["dataBase64"].as_str().unwrap()).unwrap(),
    }
}
fn wire(b: &mut Bridge, payer: &Keypair, ix: Instruction) -> Vec<u8> {
    let c = b.request(&json!({"method":"context"})).unwrap();
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    };
    let msg = v0::Message::try_compile(
        &payer.pubkey(),
        &[budget, ix],
        &[],
        c["blockhash"].as_str().unwrap().parse().unwrap(),
    )
    .unwrap();
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[payer]).unwrap();
    let bytes = bincode::serialize(&tx).unwrap();
    assert!(bytes.len() <= 1232);
    bytes
}
fn send(b: &mut Bridge, payer: &Keypair, ix: Instruction) -> Value {
    b.request(&json!({"method":"expire_blockhash"})).unwrap();
    let bytes = wire(b, payer, ix);
    b.request(&json!({"method":"execute","wire":STANDARD.encode(bytes)}))
        .unwrap()
}
fn read(b: &mut Bridge, address: &Value) -> Vec<u8> {
    let v = b
        .request(&json!({"method":"account","address":address}))
        .unwrap();
    STANDARD
        .decode(v["value"]["data"][0].as_str().unwrap())
        .unwrap()
}
fn amount(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn success(v: &Value) {
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["signature"].is_string());
}

#[test]
fn initialize_rejects_invalid_fixture_options_before_loading() {
    for (field, value) in [
        ("row_count", json!(65)),
        ("row_count", json!(-1)),
        ("row_count", json!(1.5)),
        ("row_count", json!("3")),
        ("row_count", Value::Null),
        ("all_excluded", json!("true")),
        ("all_excluded", json!(1)),
        ("all_excluded", Value::Null),
    ] {
        let mut request = json!({"payer":"11111111111111111111111111111111"});
        request[field] = value;
        let error = Bridge::initialize(&request).err().expect("invalid option");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn initialize_selects_valid_attendance_and_excludes_every_selected_member() {
    use judge_core::attendance::EpochHeader;
    use morse_rewards::state::Member;

    let payer = Keypair::new_from_array([205; 32]);
    let fixture = fixture();
    let snapshot = fixture["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "token-rewards-ready")
        .unwrap();
    let original = raw(&snapshot["accounts"]["attendance_epoch"]).unwrap();
    let source = EpochHeader::parse(&original).unwrap();
    for count in [0, 1, 2, 3, 64] {
        let (mut bank, init) = Bridge::initialize(&json!({
            "payer":payer.pubkey().to_string(),"row_count":count,"all_excluded":true
        }))
        .unwrap();
        let week = read(&mut bank, &init["addresses"]["attendance_epoch"]);
        let header = EpochHeader::parse(&week).unwrap();
        assert_eq!(header.witnesses as usize, count);
        assert_eq!(header.epoch, source.epoch);
        assert_eq!(header.log_id, source.log_id);
        assert_eq!(header.sealed, source.sealed);
        assert_eq!(header.posts, if count == 0 { 0 } else { source.posts });
        assert_eq!(
            header.max_post_slot,
            if count == 0 { 0 } else { source.max_post_slot }
        );
        assert_eq!(&week[80..80 + count * 40], &original[80..80 + count * 40]);
        assert!(week[80 + count * 40..].iter().all(|b| *b == 0));
        let witnesses = init["witnesses"].as_array().unwrap();
        assert_eq!(witnesses.len(), count);
        for (row, witness) in witnesses.iter().enumerate() {
            let address = key(witness, "address").unwrap();
            assert_eq!(address, bytes_key(&week, 80 + row * 40));
            assert_eq!(
                number(&witness["signed"]).unwrap(),
                u64_at(&week, 112 + row * 40)
            );
            assert_eq!(witness["row"], row);
            let member = read(&mut bank, &witness["member"]);
            let member = Member::parse(&member).unwrap();
            assert_eq!(member.witness.as_slice(), address.as_ref());
            assert_eq!(member.status, 2);
            assert_eq!(member.pending, 0);
            assert_eq!(member.ready, 0);
            assert!(member.effective <= source.epoch as i64 * 604800);
        }
        for role in [
            "epoch",
            "token_epoch",
            "next_epoch",
            "next_token_epoch",
            "next_attendance_epoch",
        ] {
            assert!(bank
                .request(&json!({"method":"account","address":init["addresses"][role]}))
                .unwrap()["value"]
                .is_null());
        }
    }
}

#[test]
fn selected_empty_and_excluded_fixtures_settle_through_signed_operations() {
    use morse_rewards::state::{Ledger, Pool};
    use morse_token::reward_state::TokenEpoch;

    let payer = Keypair::new_from_array([206; 32]);
    let vectors = &fixture()["write_vectors"];
    for (count, excluded) in [(0, false), (3, true)] {
        let (mut bank, init) = Bridge::initialize(&json!({
            "payer":payer.pubkey().to_string(),"row_count":count,"all_excluded":excluded
        }))
        .unwrap();
        let before = Pool::parse(&read(&mut bank, &init["addresses"]["pool"])).unwrap();
        for name in ["open", "begin"] {
            success(&send(
                &mut bank,
                &payer,
                instruction(&vectors[name], &payer),
            ));
        }
        if count != 0 {
            let mut append = instruction(&vectors["begin"], &payer);
            append.data = vec![16];
            let rows: Vec<_> = vectors["append"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|v| instruction(v, &payer).accounts[19..].to_vec())
                .collect();
            append.accounts.extend_from_slice(&rows[..count * 4]);
            success(&send(&mut bank, &payer, append));
        }
        success(&send(
            &mut bank,
            &payer,
            instruction(&vectors["finalize"], &payer),
        ));
        let ledger = Ledger::parse(&read(&mut bank, &init["addresses"]["epoch"])).unwrap();
        assert_eq!(ledger.status, 2);
        assert_eq!(ledger.count as usize, count);
        assert_eq!(ledger.expected as usize, count);
        assert_eq!(ledger.weight, 0);
        assert_eq!(ledger.floors, 0);
        let token = TokenEpoch::parse(&read(&mut bank, &init["addresses"]["token_epoch"])).unwrap();
        assert_eq!(token.status, 2);
        assert_eq!(token.amount, 0);
        assert_eq!(token.usd_committed, 0);
        let after = Pool::parse(&read(&mut bank, &init["addresses"]["pool"])).unwrap();
        assert_eq!(after.next_epoch, before.next_epoch + 1);
        assert_eq!(after.carry, before.carry + ledger.revenue);
        assert_eq!(after.subsidy, before.subsidy);
        assert_eq!(after.liabilities, before.liabilities);
        assert_eq!(after.active, 0);
    }
}

#[test]
fn signed_wire_lifecycle_and_atomic_refusals() {
    let payer = Keypair::new_from_array([203; 32]);
    let (mut bank, init) =
        Bridge::initialize(&json!({"payer":payer.pubkey().to_string()})).unwrap();
    assert_eq!(init["execution"], "local-sbf");
    assert!(init["witnesses"].as_array().unwrap().len() >= 3);
    let source = fixture();
    let snapshot = source["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "token-rewards-ready")
        .unwrap();
    assert_eq!(
        read(&mut bank, &init["addresses"]["attendance_epoch"]),
        raw(&snapshot["accounts"]["attendance_epoch"]).unwrap()
    );
    for k in [
        "program",
        "judge",
        "token",
        "log_name",
        "usdc_mint",
        "governance",
        "token_governance",
        "service_key",
        "log_version",
        "network_started",
        "token_slot",
        "judge_slot",
        "rewards_slot",
        "source_program",
        "source",
        "feed",
        "source_revision",
    ] {
        assert!(!init["pins"][k].is_null(), "missing pin {k}");
    }
    let vectors = &fixture()["write_vectors"];
    let open = instruction(&vectors["open"], &payer);
    let mut corrupt = wire(&mut bank, &payer, open.clone());
    corrupt[1] ^= 1;
    let failed = bank
        .request(&json!({"method":"execute","wire":STANDARD.encode(corrupt)}))
        .unwrap();
    assert_eq!(failed["ok"], false);
    assert_eq!(failed["debit_lamports"], "0");
    assert!(failed["error"]
        .as_str()
        .unwrap()
        .contains("SignatureFailure"));
    let rent_epoch = bank
        .request(&json!({"method":"rent","space":8416}))
        .unwrap();
    let rent_token = bank
        .request(&json!({"method":"rent","space":1280}))
        .unwrap();
    let fee = bank.request(&json!({"method":"fee"})).unwrap();
    let opened = send(&mut bank, &payer, open);
    success(&opened);
    assert_eq!(opened["fee_lamports"], fee["single_signer_fee_lamports"]);
    let parse = |v: &Value| v.as_str().unwrap().parse::<u64>().unwrap();
    assert_eq!(
        parse(&opened["debit_lamports"]),
        parse(&rent_epoch["lamports"])
            + parse(&rent_token["lamports"])
            + parse(&opened["fee_lamports"])
    );
    success(&send(
        &mut bank,
        &payer,
        instruction(&vectors["begin"], &payer),
    ));
    let before = read(&mut bank, &init["addresses"]["epoch"]);
    let incomplete = send(&mut bank, &payer, instruction(&vectors["finalize"], &payer));
    assert_eq!(incomplete["ok"], false);
    assert_eq!(read(&mut bank, &init["addresses"]["epoch"]), before);
    let begin = instruction(&vectors["begin"], &payer);
    let rows: Vec<_> = vectors["append"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| instruction(v, &payer).accounts[19..].to_vec())
        .collect();
    let mut append31 = begin.clone();
    append31.data = vec![16];
    append31.accounts.extend_from_slice(&rows[..12]);
    assert_eq!(append31.accounts.len(), 31);
    success(&send(&mut bank, &payer, append31));
    assert_eq!(read(&mut bank, &init["addresses"]["epoch"])[53], 3);
    for chunk in rows[12..].chunks(12) {
        let mut ix = begin.clone();
        ix.data = vec![16];
        ix.accounts.extend_from_slice(chunk);
        success(&send(&mut bank, &payer, ix));
    }
    success(&send(
        &mut bank,
        &payer,
        instruction(&vectors["finalize"], &payer),
    ));
    for (claims, setup, vault) in [
        ("claim", "claim_setup", "pool_morse_vault"),
        ("claim_usdc", "claim_usdc_setup", "pool_usdc_vault"),
    ] {
        success(&send(
            &mut bank,
            &payer,
            instruction(&vectors[setup], &payer),
        ));
        for claim in vectors[claims].as_array().unwrap() {
            let ix = instruction(claim, &payer);
            let vault_before = amount(&read(&mut bank, &init["addresses"][vault]), 64);
            success(&send(&mut bank, &payer, ix.clone()));
            let vault_after = amount(&read(&mut bank, &init["addresses"][vault]), 64);
            assert!(vault_after < vault_before);
            assert_eq!(send(&mut bank, &payer, ix)["ok"], false);
            assert_eq!(
                amount(&read(&mut bank, &init["addresses"][vault]), 64),
                vault_after
            );
        }
    }
    let full = read(&mut bank, &init["addresses"]["pool"]);
    let slice = bank.request(&json!({"method":"accounts","addresses":[init["addresses"]["pool"],Address::from([245;32]).to_string()],"offset":180,"length":8})).unwrap();
    assert_eq!(
        STANDARD
            .decode(slice["value"][0]["data"][0].as_str().unwrap())
            .unwrap(),
        full[180..188]
    );
    assert!(slice["value"][1].is_null());
}

#[test]
fn expired_stage_cancels_without_moving_funds() {
    let payer = Keypair::new_from_array([204; 32]);
    let (mut bank, init) =
        Bridge::initialize(&json!({"payer":payer.pubkey().to_string()})).unwrap();
    let vectors = &fixture()["write_vectors"];
    for name in ["open", "begin"] {
        success(&send(
            &mut bank,
            &payer,
            instruction(&vectors[name], &payer),
        ));
    }
    let pool = read(&mut bank, &init["addresses"]["pool"]);
    assert_eq!(
        send(&mut bank, &payer, instruction(&vectors["cancel"], &payer))["ok"],
        false
    );
    let old_wire = wire(&mut bank, &payer, instruction(&vectors["cancel"], &payer));
    bank.request(&json!({"method":"advance_clock","seconds":3600}))
        .unwrap();
    let expired = bank
        .request(&json!({"method":"execute","wire":STANDARD.encode(old_wire)}))
        .unwrap();
    assert_eq!(expired["ok"], false);
    assert!(expired["error"]
        .as_str()
        .unwrap()
        .contains("BlockhashNotFound"));
    success(&send(
        &mut bank,
        &payer,
        instruction(&vectors["cancel"], &payer),
    ));
    let after = read(&mut bank, &init["addresses"]["pool"]);
    assert_eq!(&pool[180..220], &after[180..220]);
    assert_eq!(amount(&after, 220), 0);
    assert_eq!(read(&mut bank, &init["addresses"]["epoch"])[52], 0);
}
