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
fn signed_wire_lifecycle_and_atomic_refusals() {
    let payer = Keypair::new_from_array([203; 32]);
    let (mut bank, init) = Bridge::initialize(&payer.pubkey().to_string()).unwrap();
    assert_eq!(init["execution"], "local-sbf");
    assert!(init["witnesses"].as_array().unwrap().len() >= 3);
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
    let (mut bank, init) = Bridge::initialize(&payer.pubkey().to_string()).unwrap();
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
