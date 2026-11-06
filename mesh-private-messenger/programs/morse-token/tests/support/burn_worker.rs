//! Optional same-bank handoff to the Mesh burn worker. No production RPC or funds.
//! LiteSVM checks real signatures/blockhash validity and executes the pinned SBFs;
//! slot/time/height labels below are explicitly controlled local fixture values.
use super::*;
use std::time::{Duration, Instant};

struct PrivateFixtureKey(PathBuf);
impl Drop for PrivateFixtureKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_json(directory: &Path, name: &str, value: &serde_json::Value) {
    let target = directory.join(name);
    assert!(
        !target.exists(),
        "worker handoff output must be fresh: {name}"
    );
    let temporary = directory.join(format!("{name}.tmp"));
    std::fs::write(&temporary, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    std::fs::rename(temporary, target).unwrap();
}
fn wait_packet(directory: &Path, name: &str) -> Transaction {
    let start = Instant::now();
    let path = directory.join(name);
    while !path.exists() {
        assert!(!directory.join("abort").exists(), "worker handoff aborted");
        assert!(
            start.elapsed() < Duration::from_secs(1200),
            "worker packet timed out: {name}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let encoded = std::fs::read_to_string(path).unwrap();
    assert!(
        encoded.len() <= 2000,
        "worker packet exceeds legacy transaction bound"
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .unwrap();
    assert!(bytes.len() <= 1232);
    let packet: Transaction = bincode::deserialize(&bytes).unwrap();
    assert_eq!(
        bincode::serialize(&packet).unwrap(),
        bytes,
        "trailing/noncanonical packet"
    );
    packet
}
fn validate_packet(h: &H, instruction: Instruction, tx: &Transaction) {
    tx.verify().expect("worker signature must verify");
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(tx.message.header.num_required_signatures, 1);
    assert_eq!(tx.message.account_keys[0], h.payer.pubkey());
    assert_eq!(tx.message.recent_blockhash, h.svm.latest_blockhash());
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    };
    let expected = [budget, instruction];
    assert_eq!(tx.message.instructions.len(), expected.len());
    for (compiled, instruction) in tx.message.instructions.iter().zip(expected) {
        assert_eq!(
            tx.message.account_keys[compiled.program_id_index as usize],
            instruction.program_id
        );
        assert_eq!(compiled.data, instruction.data);
        assert_eq!(compiled.accounts.len(), instruction.accounts.len());
        for (index, meta) in compiled.accounts.iter().zip(instruction.accounts) {
            let index = *index as usize;
            assert_eq!(tx.message.account_keys[index], meta.pubkey);
            assert_eq!(tx.message.is_signer(index), meta.is_signer);
            assert_eq!(
                tx.message.is_maybe_writable_with_reserved_addresses(
                    index,
                    None::<&std::collections::BTreeSet<Address>>,
                ),
                meta.is_writable
            );
        }
    }
}
fn state(
    h: &H,
    p: &Pool,
    epoch: u64,
    name: &str,
    height: u64,
    previous: &str,
) -> serde_json::Value {
    let market = credit_burn_ready_snapshot(h, p, epoch);
    let custody = carry_snapshot(h, p, epoch, name);
    let mut accounts = market["accounts"].as_array().unwrap()[..19].to_vec();
    // Re-read custody roles from this exact bank with the market reader's prefix.
    for row in custody["accounts"].as_array().unwrap() {
        let address: Address = row["address"].as_str().unwrap().parse().unwrap();
        accounts.push(match h.svm.get_account(&address) {
            None => serde_json::json!({"address":address.to_string(),"missing":true}),
            Some(a) => serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"space":a.data.len().to_string(),"lamports":a.lamports.to_string(),"executable":a.executable,"data_hex":hex::encode(&a.data[..a.data.len().min(5728)])}),
        });
    }
    assert_eq!(accounts.len(), 31);
    for (market, custody) in [
        (0, 19),
        (1, 20),
        (2, 21),
        (3, 22),
        (5, 23),
        (15, 24),
        (16, 25),
        (17, 29),
        (18, 30),
    ] {
        assert_eq!(
            accounts[market], accounts[custody],
            "duplicate roles must be the same bank record"
        );
    }
    let clock = h.svm.get_sysvar::<Clock>();
    assert_eq!(
        accounts[5]["data_hex"],
        hex::encode(bincode::serialize(&clock).unwrap())
    );
    let hash = h.svm.latest_blockhash().to_string();
    let execute = execute_chunk(h, p, epoch, 0, 5_000_000);
    serde_json::json!({"schema_version":1,"scope":"actual_isolated_sbf_worker_handoff",
        "name":name,"epoch":epoch.to_string(),"index":0,"route_hex":hex::encode(&execute.data[2..]),"spot":"2000000",
        "pins":{"program":h.program.to_string(),"governance":h.payer.pubkey().to_string(),"payer":h.payer.pubkey().to_string(),"program_slot":"0","usdc":p.usdc.to_string(),"treasury":p.creator.pubkey().to_string(),"factory":p.config.to_string()},
        "bank":{"slot":clock.slot.to_string(),"block_height":height.to_string(),"blockhash":hash,"previous_blockhash":previous,"parent_slot":clock.slot.saturating_sub(1).to_string(),"timestamp":clock.unix_timestamp.to_string(),"data_slice_length":5728,"accounts":accounts,
        "latest_blockhash":{"context_slot":clock.slot.to_string(),"blockhash":hash,"last_valid_block_height":(height+100).to_string()}},
        "role_names":["config","morse","profile","usdc","oracle","clock","jupiter","jupiter_data","raydium","raydium_data","pool","factory","vault0","vault1","observation","week","week_vault","program","program_data","config","morse","profile","usdc","clock","week","week_vault","carry","carry_vault","close_receipt","program","program_data"],
        "limits":["Clock, slot and block-height values are controlled local fixture observations; LiteSVM does not simulate ledger finality or RPC provider independence.","Actual signatures, old blockhash refusal, SBF/router/DEX/SPL execution and account bytes are checked in the same retained bank.","Oracle source publications are owned injected fixtures; no guardian verification, live feed, live funds or deployment."]})
}
pub(super) fn prove(h: &mut H, p: &Pool, epoch: u64) {
    let Some(directory) = std::env::var_os("MORSE_BURN_WORKER_HOOK_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    assert!(directory.is_dir());
    let saved = h.svm.clone();
    let week = week_address(h, epoch);
    let row = h.svm.get_account(&week).unwrap().data;
    assert_eq!(&row[..4], b"MTW\x02");
    let due = number(&row, 344) as i64;
    let end = number(&row, 336) as i64;
    let initial_previous = h.svm.latest_blockhash().to_string();
    fresh_spot(h, due);
    h.svm.warp_to_slot(10_000);
    let old_hash = h.svm.latest_blockhash().to_string();
    let initial = h.svm.clone();
    write_json(
        &directory,
        "initial.json",
        &state(h, p, epoch, "initial", 1000, &initial_previous),
    );
    if std::env::var_os("MORSE_BURN_WORKER_EXPORT_ONLY").is_some() {
        h.svm = saved;
        return;
    }
    let key_path = PathBuf::from(
        std::env::var_os("MORSE_BURN_WORKER_KEY_PATH").expect("private fixture key path required"),
    );
    assert!(
        !key_path.starts_with(&directory),
        "fixture key must stay outside proof directory"
    );
    assert!(!key_path.exists(), "fixture key path must be fresh");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .unwrap();
        file.write_all(hex::encode(h.payer.to_bytes()).as_bytes())
            .unwrap();
    }
    let private_key = PrivateFixtureKey(key_path);
    let old = wait_packet(&directory, "old.packet.base64");
    validate_packet(h, execute_chunk(h, p, epoch, 0, 5_000_000), &old);
    h.svm
        .simulate_transaction(old.clone())
        .expect("old packet must be executable before expiry");
    let pristine_week = h.svm.get_account(&week).unwrap();
    h.svm.expire_blockhash();
    h.svm.warp_to_slot(10_001);
    let failure = h
        .svm
        .send_transaction(old.clone())
        .expect_err("old packet must fail after expiry");
    assert_eq!(format!("{:?}", failure.err), "BlockhashNotFound");
    assert_eq!(h.svm.get_account(&week).unwrap(), pristine_week);
    write_json(
        &directory,
        "old-refusal.json",
        &serde_json::json!({"signature":old.signatures[0].to_string(),"error":format!("{:?}",failure.err),"logs":failure.meta.logs,"unchanged_week":true,"pre_expiry_simulation_passed":true}),
    );
    let expired_hash = h.svm.latest_blockhash().to_string();
    write_json(
        &directory,
        "expired.json",
        &state(h, p, epoch, "expired", 1101, &old_hash),
    );
    let replacement = wait_packet(&directory, "replacement.packet.base64");
    validate_packet(h, execute_chunk(h, p, epoch, 0, 5_000_000), &replacement);
    assert_ne!(
        old.message.recent_blockhash,
        replacement.message.recent_blockhash
    );
    let supply_before = number(&h.svm.get_account(&h.mint).unwrap().data, 36);
    let result = h
        .svm
        .send_transaction(replacement.clone())
        .expect("exact Mesh replacement must execute");
    let after = h.svm.get_account(&week).unwrap().data;
    assert_eq!(
        number(&after, 232) - number(&pristine_week.data, 232),
        10_000_000
    );
    let burned = supply_before - number(&h.svm.get_account(&h.mint).unwrap().data, 36);
    assert!(burned >= 4_950_000);
    h.svm.expire_blockhash();
    h.svm.warp_to_slot(10_002);
    write_json(
        &directory,
        "executed.json",
        &state(h, p, epoch, "executed", 1102, &expired_hash),
    );
    write_json(
        &directory,
        "replacement-result.json",
        &serde_json::json!({"signature":replacement.signatures[0].to_string(),"logs":result.logs,"compute_units":result.compute_units_consumed,"burned":burned.to_string(),"spent":"10000000","exact_packet_executed":true}),
    );
    let executed_hash = h.svm.latest_blockhash().to_string();
    fresh_spot(h, end + 1);
    h.svm.warp_to_slot(10_003);
    write_json(
        &directory,
        "executed-later.json",
        &state(h, p, epoch, "executed-later", 1103, &executed_hash),
    );
    // Fork the original same-bank state to prove missed disposition and existing close/carry.
    h.svm = initial;
    fresh_spot(h, end + 1);
    h.svm.warp_to_slot(10_100);
    write_json(
        &directory,
        "missed.json",
        &state(h, p, epoch, "missed", 1200, &old_hash),
    );
    let missed_hash = h.svm.latest_blockhash().to_string();
    h.warp((epoch as i64 + 1) * 604800);
    h.svm.expire_blockhash();
    h.svm.warp_to_slot(10_101);
    write_json(
        &directory,
        "close-ready.json",
        &state(h, p, epoch, "close-ready", 1201, &missed_hash),
    );
    let close_hash = h.svm.latest_blockhash().to_string();
    let closing = close(h, p, epoch);
    if std::env::var_os("MORSE_BURN_WORKER_CLOSE_HANDOFF").is_some() {
        let packet = wait_packet(&directory, "close.packet.base64");
        validate_packet(h, closing, &packet);
        let result = h
            .svm
            .send_transaction(packet.clone())
            .expect("exact Mesh close packet must execute");
        write_json(
            &directory,
            "close-result.json",
            &serde_json::json!({
                "origin":"exact_mesh_packet", "signature":packet.signatures[0].to_string(),
                "logs":result.logs,"compute_units":result.compute_units_consumed,
                "actual_packet_executed":true,"carried":"240000000"
            }),
        );
        h.svm.expire_blockhash();
    } else {
        send(h, &[closing], &[]);
        write_json(
            &directory,
            "close-result.json",
            &serde_json::json!({"origin":"rust_sdk_signed_existing_close","carried":"240000000"}),
        );
    }
    h.svm.warp_to_slot(10_102);
    write_json(
        &directory,
        "closed.json",
        &state(h, p, epoch, "closed", 1202, &close_hash),
    );
    assert_eq!(&h.svm.get_account(&week).unwrap().data[..4], b"MTC\x02");
    assert_eq!(
        number(&h.svm.get_account(&receipt(h, epoch)).unwrap().data, 132),
        240_000_000
    );
    drop(private_key);
    h.svm = saved;
    eprintln!("MORSE_BURN_WORKER_SBF expired_original_refused_exact_replacement_executed_missed_closed_same_bank");
}
