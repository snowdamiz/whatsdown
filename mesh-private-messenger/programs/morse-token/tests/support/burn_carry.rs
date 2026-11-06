//! Local SBF custody qualification: missed burn input stays exclusively in burn custody.
use super::*;
#[path = "burn_worker.rs"]
mod worker_tests;
#[path = "public_history_index.rs"]
mod public_history_index;
fn number(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}
fn carry(h: &H) -> Address {
    Address::find_program_address(&[b"burn-carry"], &h.program).0
}
fn week_address(h: &H, epoch: u64) -> Address {
    Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0
}
fn receipt(h: &H, epoch: u64) -> Address {
    Address::find_program_address(&[b"burn-carry-epoch", &epoch.to_le_bytes()], &h.program).0
}
pub(super) fn close(h: &H, p: &Pool, epoch: u64) -> Instruction {
    let week = week_address(h, epoch);
    Instruction {
        program_id: h.program,
        data: [vec![13], epoch.to_le_bytes().to_vec()].concat(),
        accounts: vec![
            AccountMeta::new(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            ro(Address::find_program_address(&[b"swap"], &h.program).0),
            rw(week),
            rw(ata(week, p.usdc)),
            rw(carry(h)),
            rw(ata(carry(h), p.usdc)),
            rw(receipt(h, epoch)),
            ro(p.usdc),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ],
    }
}
fn transfer(p: &Pool, destination: Address, amount: u64) -> Instruction {
    Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(p.source),
            ro(p.usdc),
            rw(destination),
            AccountMeta::new_readonly(p.creator.pubkey(), true),
        ],
        data: [vec![12], amount.to_le_bytes().to_vec(), vec![6]].concat(),
    }
}
#[test]
fn missed_input_is_closed_once_and_donations_never_become_accounted_carry() {
    let mut h = H::with_keys(
        Keypair::new_from_array([203; 32]),
        Address::new_from_array([204; 32]),
    );
    // Also qualify the classic SPL implementation, rather than only the bank's newer p-token ELF.
    // This exact 3.5.0 ELF is distributed inside the pinned litesvm 0.17.0 dependency.
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cargo"));
    let classic = std::fs::read_dir(cargo_home.join("registry/src"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| {
            entry
                .path()
                .join("litesvm-0.17.0/src/programs/elf/spl_token-3.5.0.so")
        })
        .find(|path| path.is_file())
        .expect("pinned LiteSVM classic SPL ELF");
    h.svm.add_program_from_file(TOKEN, classic).unwrap();
    if let Some(now) = std::env::var_os("MORSE_CREDIT_BURN_NATIVE_NOW") {
        let now: i64 = now.to_str().unwrap().parse().unwrap();
        h.warp(now.checked_sub(14 * 86400).unwrap());
    }
    assert!(h.send(h.init.clone()));
    let p = pool_with_usdc(&mut h, Keypair::new_from_array([205; 32]));
    let config = burn_configuration(&h, &p);
    send(&mut h, &[config], &[]);
    let ready = h.svm.get_sysvar::<Clock>().unix_timestamp + 14 * 86400;
    seed_oracle(&mut h, ready);
    let epoch = ready as u64 / 604800 + 1;
    if let Some(path) = std::env::var_os("MORSE_CREDIT_BURN_INITIAL_READY_PATH") {
        let value = credit_burn_ready_snapshot(&h, &p, epoch);
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        if let Some(request) = std::env::var_os("MORSE_CREDIT_BURN_FUND_REQUEST_PATH") {
            let baseline = h.svm.clone();
            execute_credit_burn_request(&mut h, &p, epoch, PathBuf::from(request));
            h.svm = baseline;
        }
    }
    let mut snapshots = Vec::new();
    let mut vectors = Vec::new();
    // Cash-only v2 may initialize carry, but cannot create accounted carry.
    let baseline = h.svm.clone();
    let cash_only = open_v2(&h, &p, epoch, 24_000_000, 0);
    vectors.push(
        serde_json::json!({"name":"fund-cash-only","instruction":instruction_report(&cash_only)}),
    );
    send(&mut h, &[cash_only], &[&p.creator]);
    let state = h.svm.get_account(&carry(&h)).unwrap().data;
    assert_eq!(number(&state, 100), 0);
    assert_eq!(number(&state, 148), 1);
    h.svm = baseline;
    let fund = open_week(&h, &p, epoch, 240_000_000);
    send(&mut h, &[fund], &[&p.creator]);
    let week = week_address(&h, epoch);
    let vault = ata(week, p.usdc);
    let due = number(&h.svm.get_account(&week).unwrap().data, 280) as i64;
    advance_oracle(&mut h, due);
    let execute = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    send(&mut h, &[execute], &[]);
    let carry_vault = ata(carry(&h), p.usdc);
    let carry_ata = create_ata(h.payer.pubkey(), carry(&h), p.usdc);
    send(
        &mut h,
        &[
            carry_ata,
            transfer(&p, vault, 17),
            transfer(&p, carry_vault, 19),
        ],
        &[&p.creator],
    );
    let closing = close(&h, &p, epoch);
    vectors.push(serde_json::json!({"name":"close-v1","instruction":instruction_report(&closing)}));
    failed(&mut h, closing.clone());
    assert_eq!(h.amount(vault), 230_000_017);
    h.warp((epoch as i64 + 1) * 604800);
    snapshots.push(carry_snapshot(&h, &p, epoch, "legacy-partial"));
    // Prefunded PDAs cannot claim a week. Late SPL overflow rolls rent and all accounting back.
    let carry_key = carry(&h);
    let receipt_key = receipt(&h, epoch);
    prefund(&mut h, carry_key);
    prefund(&mut h, receipt_key);
    let saved_vault = h.svm.get_account(&carry_vault).unwrap();
    // Reject substituted mint, profile, recipient, receipt and executable roles before any movement.
    let protected = [week, vault, carry_key, carry_vault, receipt_key, p.source];
    for (index, replacement) in [
        (3, h.config),
        (4, carry_key),
        (5, p.source),
        (6, receipt_key),
        (7, p.source),
        (8, carry_key),
        (9, h.mint),
        (10, ATA),
        (11, TOKEN),
        (12, TOKEN),
    ] {
        let mut wrong = closing.clone();
        wrong.accounts[index].pubkey = replacement;
        let before = accounts(&h, &protected);
        failed(&mut h, wrong);
        assert_eq!(accounts(&h, &protected), before);
    }
    let mut readonly = closing.clone();
    readonly.accounts[4].is_writable = false;
    failed(&mut h, readonly);
    let original_week = h.svm.get_account(&week).unwrap();
    let mut bad_week = original_week.clone();
    bad_week.data[256 + 72] = 1;
    h.svm.set_account(week, bad_week).unwrap();
    failed(&mut h, closing.clone());
    h.svm.set_account(week, original_week).unwrap();
    let mut fault = saved_vault.clone();
    fault.data[64..72].copy_from_slice(&u64::MAX.to_le_bytes());
    h.svm.set_account(carry_vault, fault).unwrap();
    let guarded = [week, vault, carry_key, carry_vault, receipt_key];
    let before = accounts(&h, &guarded);
    let logs = failed(&mut h, closing.clone());
    assert!(
        logs.iter()
            .any(|line| line.starts_with(&format!("Program {TOKEN} invoke"))),
        "{}",
        logs.join("\n")
    );
    assert!(
        logs.iter()
            .any(|line| line.starts_with(&format!("Program {TOKEN} failed"))),
        "recipient overflow must fail inside classic SPL: {}",
        logs.join("\n")
    );
    assert_eq!(accounts(&h, &guarded), before);
    h.svm.set_account(carry_vault, saved_vault).unwrap();
    // Oracle is now stale: recover custody without an executable market dependency.
    send(&mut h, std::slice::from_ref(&closing), &[]);
    assert_eq!(&h.svm.get_account(&week).unwrap().data[..4], b"MTC\x01");
    assert_eq!(h.amount(vault), 17);
    assert_eq!(h.amount(ata(carry(&h), p.usdc)), 230_000_019);
    assert_eq!(
        number(&h.svm.get_account(&carry(&h)).unwrap().data, 100),
        230_000_000
    );
    snapshots.push(carry_snapshot(&h, &p, epoch, "legacy-closed"));
    let closed = h.svm.get_account(&week).unwrap();
    let carried = h.svm.get_account(&carry(&h)).unwrap();
    let proof = h.svm.get_account(&receipt(&h, epoch)).unwrap();
    send(&mut h, std::slice::from_ref(&closing), &[]);
    assert_eq!(h.svm.get_account(&week).unwrap(), closed);
    assert_eq!(h.svm.get_account(&carry(&h)).unwrap(), carried);
    assert_eq!(h.svm.get_account(&receipt(&h, epoch)).unwrap(), proof);
    let mut wrong_proof = proof.clone();
    wrong_proof.data[212] ^= 1;
    h.svm.set_account(receipt_key, wrong_proof).unwrap();
    failed(&mut h, closing.clone());
    h.svm.set_account(receipt_key, proof).unwrap();
    // A clock rollback or new donation can never reopen a closed week.
    send(&mut h, &[transfer(&p, vault, 42)], &[&p.creator]);
    h.warp(due);
    let mint_before = h.svm.get_account(&h.mint).unwrap();
    let old_execute = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    failed(&mut h, old_execute);
    h.warp(due + 25200);
    let missed = execute_chunk(&h, &p, epoch, 1, 5_000_000);
    failed(&mut h, missed);
    let old_fund = open_week(&h, &p, epoch, 240_000_000);
    fail_signed(&mut h, old_fund, &[&p.creator]);
    send(&mut h, &[closing], &[]);
    assert_eq!(h.svm.get_account(&h.mint).unwrap(), mint_before);
    assert_eq!(h.amount(vault), 59);
    assert_eq!(h.svm.get_account(&carry_key).unwrap(), carried);

    // Two real funding CPIs: overflow only on the second must undo the first cash transfer.
    let next = epoch + 1;
    fresh_spot(&mut h, next as i64 * 604800);
    let next_week = week_address(&h, next);
    let next_vault = ata(next_week, p.usdc);
    let make_vault = create_ata(h.payer.pubkey(), next_week, p.usdc);
    send(
        &mut h,
        &[make_vault, transfer(&p, next_vault, 23)],
        &[&p.creator],
    );
    prefund(&mut h, next_week);
    let correct_vault = h.svm.get_account(&next_vault).unwrap();
    let mut fault = correct_vault.clone();
    fault.data[64..72].copy_from_slice(&(u64::MAX - 120_000_000).to_le_bytes());
    h.svm.set_account(next_vault, fault).unwrap();
    let mixed = open_v2(&h, &p, next, 120_000_000, 120_000_000);
    vectors
        .push(serde_json::json!({"name":"fund-mixed-v2","instruction":instruction_report(&mixed)}));
    let guarded = [next_week, next_vault, p.source, carry_key, carry_vault];
    let before = accounts(&h, &guarded);
    let mut insufficient = open_v2(&h, &p, next, 24, 230_000_001);
    fail_signed(&mut h, insufficient.clone(), &[&p.creator]);
    insufficient.accounts[18].pubkey = p.source;
    fail_signed(&mut h, insufficient, &[&p.creator]);
    assert_eq!(accounts(&h, &guarded), before);
    for (index, replacement) in [
        (7, carry_vault),
        (8, carry_vault),
        (8, next_vault),
        (18, p.source),
        (18, next_vault),
    ] {
        let mut aliased = mixed.clone();
        aliased.accounts[index].pubkey = replacement;
        fail_signed(&mut h, aliased, &[&p.creator]);
        assert_eq!(accounts(&h, &guarded), before);
    }
    let logs = fail_signed(&mut h, mixed.clone(), &[&p.creator]);
    assert!(
        logs.iter()
            .filter(|line| line.starts_with(&format!("Program {TOKEN} invoke")))
            .count()
            >= 2
    );
    assert!(
        logs.iter()
            .any(|line| line.starts_with(&format!("Program {TOKEN} failed"))),
        "second transfer must fail inside classic SPL"
    );
    assert_eq!(accounts(&h, &guarded), before);
    h.svm.set_account(next_vault, correct_vault).unwrap();
    if let Some(path) = std::env::var_os("MORSE_CREDIT_BURN_READY_FIXTURES_PATH") {
        let value = credit_burn_ready_snapshot(&h, &p, next);
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    send(&mut h, std::slice::from_ref(&mixed), &[&p.creator]);
    assert_eq!(h.amount(next_vault), 240_000_023);
    assert_eq!(
        number(&h.svm.get_account(&carry_key).unwrap().data, 100),
        110_000_000
    );
    snapshots.push(carry_snapshot(&h, &p, next, "mixed-funded"));
    worker_tests::prove(&mut h, &p, next);
    let state = h.svm.get_account(&next_week).unwrap().data;
    assert_eq!(&state[..4], b"MTW\x02");
    assert_eq!(state.len(), 2240);
    assert_eq!(number(&state, 256), 120_000_000);
    assert_eq!(number(&state, 264), 120_000_000);
    let before = accounts(&h, &guarded);
    // The old receipt remains idempotent even after its carry was assigned to a later week.
    let repeat_old = close(&h, &p, epoch);
    send(&mut h, &[repeat_old], &[]);
    assert_eq!(accounts(&h, &guarded), before);
    send(&mut h, std::slice::from_ref(&mixed), &[&p.creator]);
    assert_eq!(accounts(&h, &guarded), before);
    let mut conflict = mixed.clone();
    conflict.data[9..17].copy_from_slice(&119_999_999u64.to_le_bytes());
    fail_signed(&mut h, conflict, &[&p.creator]);
    // The legacy handler cannot reinterpret the new funded schedule.
    let legacy = open_week(&h, &p, next, 240_000_000);
    fail_signed(&mut h, legacy, &[&p.creator]);
    let due = number(&state, 344) as i64;
    fresh_spot(&mut h, due);
    let execute = execute_chunk(&h, &p, next, 0, 5_000_000);
    vectors
        .push(serde_json::json!({"name":"execute-v2","instruction":instruction_report(&execute)}));
    send(&mut h, &[execute], &[]);
    snapshots.push(carry_snapshot(&h, &p, next, "mixed-executed"));
    let executed = h.svm.get_account(&next_week).unwrap().data;
    assert_eq!(number(&executed, 232), 10_000_000);
    assert!(number(&executed, 240) >= 4_950_000);
    assert_eq!(&executed[256..320], &state[256..320]);

    // An all-missed legacy week and partially burned v2 week remain separate receipts.
    let third = next + 1;
    let legacy = open_week(&h, &p, third, 240_000_000);
    send(&mut h, &[legacy], &[&p.creator]);
    h.warp(third as i64 * 604800);
    // A real timelocked source rotation and simulated later own-code deployment cannot trap old custody.
    let branch = h.svm.clone();
    let rotated_source = Address::new_from_array([207; 32]);
    let rotation_time = h.svm.get_sysvar::<Clock>().unix_timestamp;
    let mut update = source_update(rotation_time, 2_000_000);
    update.data[41..73].fill(8);
    h.svm.set_account(rotated_source, update).unwrap();
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let propose = Instruction {
        program_id: h.program,
        accounts: vec![
            AccountMeta::new_readonly(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            rw(oracle),
            ro(PYTH),
            ro(rotated_source),
        ],
        data: [vec![6], rotated_source.as_ref().to_vec(), vec![8; 32]].concat(),
    };
    assert!(h.send(propose));
    h.warp(rotation_time + 14 * 86400);
    let mut update = source_update(rotation_time + 14 * 86400, 2_000_000);
    update.data[41..73].fill(8);
    h.svm.set_account(rotated_source, update).unwrap();
    assert!(h.send(Instruction {
        program_id: h.program,
        accounts: vec![
            ro(h.config),
            ro(h.mint),
            rw(oracle),
            ro(PYTH),
            ro(rotated_source)
        ],
        data: vec![7]
    }));
    let own_data = data_account(h.program);
    let mut own_image = h.svm.get_account(&own_data).unwrap();
    own_image.data[4..12].copy_from_slice(&1u64.to_le_bytes());
    h.svm.set_account(own_data, own_image).unwrap();
    let later_close = close(&h, &p, next);
    send(&mut h, &[later_close], &[]);
    assert_eq!(
        &h.svm.get_account(&next_week).unwrap().data[..4],
        b"MTC\x02"
    );
    h.svm = branch;
    // Market code can become unavailable while custody remains safely closable.
    let image_key = data_account(JUP);
    let mut image = h.svm.get_account(&image_key).unwrap();
    let original_image = image.clone();
    image.data[4..12].copy_from_slice(&1u64.to_le_bytes());
    h.svm.set_account(image_key, image).unwrap();
    let close_next = close(&h, &p, next);
    vectors
        .push(serde_json::json!({"name":"close-v2","instruction":instruction_report(&close_next)}));
    send(&mut h, &[close_next], &[]);
    assert_eq!(
        &h.svm.get_account(&next_week).unwrap().data[..4],
        b"MTC\x02"
    );
    snapshots.push(carry_snapshot(&h, &p, next, "mixed-closed"));
    assert_eq!(h.amount(next_vault), 23);
    assert_eq!(
        number(&h.svm.get_account(&carry_key).unwrap().data, 100),
        340_000_000
    );
    h.warp((third + 1) as i64 * 604800);
    let close_third = close(&h, &p, third);
    vectors.push(serde_json::json!({"name":"close-all-missed","instruction":instruction_report(&close_third)}));
    send(&mut h, std::slice::from_ref(&close_third), &[]);
    send(&mut h, &[close_third], &[]);
    assert_eq!(
        number(&h.svm.get_account(&carry_key).unwrap().data, 100),
        580_000_000
    );
    assert_eq!(h.amount(carry_vault), 580_000_019);
    assert_eq!(h.amount(ata(week_address(&h, third), p.usdc)), 0);
    snapshots.push(carry_snapshot(&h, &p, third, "all-missed-closed"));
    h.svm.set_account(image_key, original_image).unwrap();

    // Carry-only funding still needs the fixed treasury, even with no source token account.
    let fourth = third + 1;
    fresh_spot(&mut h, fourth as i64 * 604800);
    let carry_only = open_v2(&h, &p, fourth, 0, 240_000_000);
    vectors.push(
        serde_json::json!({"name":"fund-carry-only","instruction":instruction_report(&carry_only)}),
    );
    let mut unsigned = carry_only.clone();
    unsigned.accounts[0].is_signer = false;
    let before = h.svm.get_account(&carry_key).unwrap();
    failed(&mut h, unsigned);
    assert_eq!(h.svm.get_account(&carry_key).unwrap(), before);
    let own_ata = create_ata(h.payer.pubkey(), h.payer.pubkey(), p.usdc);
    let remaining = h.amount(p.source);
    let drain = transfer(&p, ata(h.payer.pubkey(), p.usdc), remaining);
    let close_source = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(p.source),
            rw(p.creator.pubkey()),
            AccountMeta::new_readonly(p.creator.pubkey(), true),
        ],
        data: vec![9],
    };
    send(&mut h, &[own_ata, drain, close_source], &[&p.creator]);
    assert!(h.svm.get_account(&p.source).is_none_or(|a| a.lamports == 0));
    send(&mut h, std::slice::from_ref(&carry_only), &[&p.creator]);
    assert_eq!(h.amount(ata(week_address(&h, fourth), p.usdc)), 240_000_000);
    assert_eq!(h.amount(carry_vault), 340_000_019);
    assert_eq!(
        number(&h.svm.get_account(&carry_key).unwrap().data, 100),
        340_000_000
    );
    send(&mut h, &[carry_only], &[&p.creator]);
    assert!(h.svm.get_account(&p.source).is_none_or(|a| a.lamports == 0));
    snapshots.push(carry_snapshot(&h, &p, fourth, "carry-only-funded"));
    if std::env::var_os("MORSE_PUBLIC_HISTORY_TOKEN_EXPORT").is_some() {
        public_history_index::export(
            &h.svm,
            &[h.program],
            carry_snapshot(&h, &p, fourth, "public-history-final-bank"),
            "MORSE_PUBLIC_HISTORY_TOKEN_EXPORT",
        );
    }
    if let Some(path) = std::env::var_os("MORSE_TOKEN_CARRY_FIXTURES_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"network":"local-sbf-only","snapshots":snapshots,"instructions":vectors})).unwrap()).unwrap();
    }
    eprintln!("MORSE_BURN_CARRY actual_partial_all_missed_v1_v2_cash_carry_donations_closed_replay_late_two_cpi_rollback");
}
fn open_v2(h: &H, p: &Pool, epoch: u64, cash: u64, carried: u64) -> Instruction {
    let mut ix = open_week(h, p, epoch, cash + carried);
    ix.data = [
        vec![14],
        epoch.to_le_bytes().to_vec(),
        cash.to_le_bytes().to_vec(),
        carried.to_le_bytes().to_vec(),
        ix.data[17..].to_vec(),
    ]
    .concat();
    ix.accounts
        .extend([rw(carry(h)), rw(ata(carry(h), p.usdc))]);
    ix
}
fn fail_signed(h: &mut H, ix: Instruction, extra: &[&Keypair]) -> Vec<String> {
    h.svm.expire_blockhash();
    let mut signers = vec![&h.payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&h.payer.pubkey()),
        &signers,
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect_err("adversarial carry packet unexpectedly succeeded")
        .meta
        .logs
}
fn fresh_spot(h: &mut H, time: i64) {
    h.warp(time);
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let d = h.svm.get_account(&oracle).unwrap().data;
    let source = Address::new_from_array(d[100..132].try_into().unwrap());
    h.svm
        .set_account(source, source_update(time, 2_000_000))
        .unwrap();
    let observe = oracle_instruction(h, 4, source);
    assert!(h.send(observe));
}
fn prefund(h: &mut H, key: Address) {
    h.svm
        .set_account(
            key,
            solana_account::Account {
                lamports: 1_000_000,
                ..Default::default()
            },
        )
        .unwrap();
}
fn accounts(h: &H, keys: &[Address]) -> Vec<Option<solana_account::Account>> {
    keys.iter().map(|key| h.svm.get_account(key)).collect()
}

fn carry_snapshot(h: &H, p: &Pool, epoch: u64, name: &str) -> serde_json::Value {
    let clock = Address::from_str_const("SysvarC1ock11111111111111111111111111111111");
    let week = week_address(h, epoch);
    let swap = Address::find_program_address(&[b"swap"], &h.program).0;
    let keys = [
        h.config,
        h.mint,
        swap,
        p.usdc,
        clock,
        week,
        ata(week, p.usdc),
        carry(h),
        ata(carry(h), p.usdc),
        receipt(h, epoch),
        h.program,
        data_account(h.program),
    ];
    let accounts:Vec<_>=keys.iter().map(|key|match h.svm.get_account(key) {
        None=>serde_json::json!({"address":key.to_string(),"missing":true}),
        Some(a)=>serde_json::json!({"address":key.to_string(),"owner":a.owner.to_string(),"space":a.data.len().to_string(),"lamports":a.lamports.to_string(),"executable":a.executable,"data_hex":hex::encode(&a.data[..a.data.len().min(2240)])}),
    }).collect();
    serde_json::json!({"name":name,"epoch":epoch.to_string(),"context_slot":h.svm.get_sysvar::<Clock>().slot.to_string(),"program":h.program.to_string(),"payer":h.payer.pubkey().to_string(),"governance":h.payer.pubkey().to_string(),"usdc":p.usdc.to_string(),"treasury":p.creator.pubkey().to_string(),"factory":p.config.to_string(),"program_slot":"0","accounts":accounts})
}

pub(super) fn prepared(h: &H, ix: &Instruction) -> Instruction {
    let expiry = ix.data.first() == Some(&15);
    let variable = if expiry {
        "MORSE_TOKEN_EXPIRY_INSTRUCTIONS_PATH"
    } else {
        "MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH"
    };
    let Some(path) = std::env::var_os(variable) else {
        return ix.clone();
    };
    let v2_execution = ix.data.first() == Some(&10)
        && ix
            .accounts
            .get(5)
            .and_then(|a| h.svm.get_account(&a.pubkey))
            .is_some_and(|a| a.data.get(..4) == Some(b"MTW\x02"));
    if ix.program_id != h.program || (!matches!(ix.data.first(), Some(13..=15)) && !v2_execution) {
        return ix.clone();
    }
    let root: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for value in root["instructions"].as_array().unwrap() {
        let candidate = Instruction {
            program_id: Address::from_str(value["program"].as_str().unwrap()).unwrap(),
            data: hex::decode(value["data_hex"].as_str().unwrap()).unwrap(),
            accounts: value["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| AccountMeta {
                    pubkey: Address::from_str(a["key"].as_str().unwrap()).unwrap(),
                    is_signer: a["signer"].as_bool().unwrap(),
                    is_writable: a["writable"].as_bool().unwrap(),
                })
                .collect(),
        };
        if &candidate == ix {
            eprintln!("MORSE_TOKEN_CARRY_MESH_REPLAY tag={}", ix.data[0]);
            return candidate;
        }
    }
    panic!(
        "actual carry packet has no exact Mesh instruction, tag={} keys={:?}",
        ix.data[0], ix.accounts
    );
}

// Complete canonical bank before the real cash+carry CPIs. Export only public
// account bytes; source/price owner fixtures retain their existing local scope.
fn credit_burn_ready_snapshot(h: &H, p: &Pool, epoch: u64) -> serde_json::Value {
    let swap = Address::find_program_address(&[b"swap"], &h.program).0;
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let week = week_address(h, epoch);
    let pool = h.svm.get_account(&p.pool).unwrap().data;
    let v0 = Address::new_from_array(pool[72..104].try_into().unwrap());
    let v1 = Address::new_from_array(pool[104..136].try_into().unwrap());
    let keys = [
        h.config,
        h.mint,
        swap,
        p.usdc,
        oracle,
        Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
        JUP,
        data_account(JUP),
        RAY,
        data_account(RAY),
        p.pool,
        p.config,
        v0,
        v1,
        p.observation,
        week,
        ata(week, p.usdc),
        h.program,
        data_account(h.program),
        carry(h),
        ata(carry(h), p.usdc),
        p.source,
    ];
    let accounts:Vec<_>=keys.iter().map(|key| match h.svm.get_account(key) {
        None=>serde_json::json!({"address":key.to_string(),"missing":true}),
        Some(a)=>serde_json::json!({"address":key.to_string(),"owner":a.owner.to_string(),"space":a.data.len().to_string(),"lamports":a.lamports.to_string(),"executable":a.executable,"data_hex":hex::encode(&a.data[..a.data.len().min(5728)])}),
    }).collect();
    serde_json::json!({"schema_version":1,"scope":"actual_isolated_sbf_pre_funding_bank",
        "context_slot":h.svm.get_sysvar::<Clock>().slot.to_string(),"epoch":epoch.to_string(),
        "program":h.program.to_string(),"payer":h.payer.pubkey().to_string(),"governance":h.payer.pubkey().to_string(),
        "treasury":p.creator.pubkey().to_string(),"usdc":p.usdc.to_string(),"factory":p.config.to_string(),"program_slot":"0","accounts":accounts})
}

// Test-only external treasury executor. The issuer returns this exact public
// instruction; only the deterministic local owner signs it inside LiteSVM.
fn execute_credit_burn_request(h: &mut H, p: &Pool, epoch: u64, request: PathBuf) {
    let root: serde_json::Value = serde_json::from_slice(&std::fs::read(request).unwrap()).unwrap();
    assert_eq!(root["cash"].as_str().unwrap(), "120000000");
    assert_eq!(root["carry"].as_str().unwrap(), "0");
    assert_eq!(root["epoch"].as_str().unwrap(), epoch.to_string());
    let mut ix = open_v2(h, p, epoch, 120_000_000, 0);
    ix.accounts[1] = AccountMeta::new(p.creator.pubkey(), true);
    let mut data = [
        vec![14],
        epoch.to_le_bytes().to_vec(),
        120_000_000u64.to_le_bytes().to_vec(),
        0u64.to_le_bytes().to_vec(),
    ]
    .concat();
    assert_eq!(root["weights"].as_array().unwrap().len(), 24);
    assert_eq!(root["entropy"].as_array().unwrap().len(), 24);
    for index in 0..24 {
        let w: u32 = root["weights"][index].as_str().unwrap().parse().unwrap();
        let e: u64 = root["entropy"][index].as_str().unwrap().parse().unwrap();
        data.extend(w.to_le_bytes());
        data.extend(e.to_le_bytes());
    }
    ix.data = data;
    assert_eq!(instruction_report(&ix), root["instruction"]);
    let before = h.amount(p.source);
    send(h, std::slice::from_ref(&ix), &[&p.creator]);
    assert_eq!(before - h.amount(p.source), 120_000_000);
    let after = h.amount(p.source);
    send(h, std::slice::from_ref(&ix), &[&p.creator]);
    assert_eq!(h.amount(p.source), after);
    let funded = carry_snapshot(h, p, epoch, "issuer-cash-funded");
    let week = week_address(h, epoch);
    let supply_before = number(&h.svm.get_account(&h.mint).unwrap().data, 36);
    for index in 0..24u8 {
        let row = h.svm.get_account(&week).unwrap().data;
        let at = 320 + index as usize * 80;
        let amount = number(&row, at);
        let due = number(&row, at + 24) as i64;
        advance_oracle(h, due);
        let mut execute = execute_chunk(h, p, epoch, index, amount.div_ceil(2) + 2);
        execute.data[10..18].copy_from_slice(&amount.to_le_bytes());
        send(h, std::slice::from_ref(&execute), &[]);
    }
    let burned = supply_before - number(&h.svm.get_account(&h.mint).unwrap().data, 36);
    assert!(burned >= 59_400_000);
    assert_eq!(h.amount(ata(week, p.usdc)), 0);
    let full = h.svm.get_account(&week).unwrap().data;
    assert_eq!(number(&full, 232), 120_000_000);
    assert_eq!(number(&full, 224), (1 << 24) - 1);
    h.warp((epoch as i64 + 1) * 604800);
    let closing = close(h, p, epoch);
    send(h, std::slice::from_ref(&closing), &[]);
    send(h, std::slice::from_ref(&closing), &[]);
    let closed = carry_snapshot(h, p, epoch, "issuer-cash-closed");
    assert_eq!(number(&h.svm.get_account(&carry(h)).unwrap().data, 100), 0);
    if let Some(path) = std::env::var_os("MORSE_CREDIT_BURN_EXECUTION_EXPORT_PATH") {
        let value = serde_json::json!({"schema_version":1,"scope":"actual_compiled_issuer_request_local_sbf_execution","funded":funded,"closed":closed,
            "source_before":before.to_string(),"source_after":after.to_string(),"cash_debited":"120000000","cash_spent":"120000000","burned_units":burned.to_string(),
            "actual_chunks":24,"actual_jupiter_raydium":true,"replay_no_second_cash_transfer":true,"closed_carry_units":"0","live_funds":false});
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    eprintln!("MORSE_CREDIT_BURN_CLI_SBF cash=120000000 chunks=24 burned={burned} exact_request_owner_signed_replay_no_double_cash");
}

fn expire_unfunded(h: &H, epoch: u64) -> Instruction {
    Instruction {
        program_id: h.program,
        data: [vec![15], epoch.to_le_bytes().to_vec()].concat(),
        accounts: vec![
            AccountMeta::new(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            ro(Address::find_program_address(&[b"swap"], &h.program).0),
            rw(week_address(h, epoch)),
            rw(receipt(h, epoch)),
            ro(Address::default()),
        ],
    }
}

fn expiry_snapshot(h: &H, p: &Pool, epoch: u64, name: &str) -> serde_json::Value {
    let mut snapshot = carry_snapshot(h, p, epoch, name);
    let selected: Vec<_> = [0, 1, 2, 3, 4, 5, 9, 10, 11]
        .into_iter()
        .map(|index| {
            let mut account = snapshot["accounts"][index].clone();
            if let Some(raw) = account["data_hex"].as_str() {
                account["data_hex"] = serde_json::json!(&raw[..raw.len().min(640)]);
            }
            account
        })
        .collect();
    snapshot["accounts"] = serde_json::json!(selected);
    snapshot
}

#[test]
fn expired_unfunded_week_is_permanent_and_cannot_capture_later_funding() {
    let mut h = H::with_keys(
        Keypair::new_from_array([210; 32]),
        Address::new_from_array([211; 32]),
    );
    assert!(h.send(h.init.clone()));
    let p = pool_with_usdc(&mut h, Keypair::new_from_array([212; 32]));
    let profile = burn_configuration(&h, &p);
    send(&mut h, &[profile], &[]);
    let ready = h.svm.get_sysvar::<Clock>().unix_timestamp + 14 * 86400;
    seed_oracle(&mut h, ready);
    let epoch = ready as u64 / 604800 + 1;
    let deadline = epoch * 604800 + 25200;
    let week = week_address(&h, epoch);
    let proof = receipt(&h, epoch);
    let expiration = expire_unfunded(&h, epoch);
    let protected = [h.config, h.mint, p.source, week, proof, carry(&h)];
    h.warp(deadline as i64 - 1);
    let before = accounts(&h, &protected);
    failed(&mut h, expiration.clone());
    assert_eq!(accounts(&h, &protected), before);
    h.warp(deadline as i64);
    prefund(&mut h, week);
    prefund(&mut h, proof);
    let source = h.svm.get_account(&p.source).unwrap();
    let before_expiry = expiry_snapshot(&h, &p, epoch, "before-expiry");
    if let Some(path) = std::env::var_os("MORSE_CREDIT_BURN_EXPIRE_REQUEST_PATH") {
        let request: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut expected = expiration.clone();
        expected.accounts[0] = AccountMeta::new(p.creator.pubkey(), true);
        assert_eq!(request["instruction"], instruction_report(&expected));
        let saved = h.svm.clone();
        send(&mut h, std::slice::from_ref(&expected), &[&p.creator]);
        let expired = expiry_snapshot(&h, &p, epoch, "external-owner-expired");
        send(&mut h, &[expected], &[&p.creator]);
        assert_eq!(
            expiry_snapshot(&h, &p, epoch, "external-owner-expired"),
            expired
        );
        if let Some(out) = std::env::var_os("MORSE_CREDIT_BURN_EXPIRE_EXECUTION_PATH") {
            std::fs::write(out, serde_json::to_vec_pretty(&expired).unwrap()).unwrap();
        }
        assert_eq!(h.svm.get_account(&p.source).unwrap(), source);
        h.svm = saved;
        eprintln!("MORSE_CREDIT_BURN_EXPIRE_CLI_SBF exact_external_rent_payer_instruction_replay_no_token_movement");
    }
    send(&mut h, std::slice::from_ref(&expiration), &[]);
    let tombstone = h.svm.get_account(&week).unwrap();
    let receipt_account = h.svm.get_account(&proof).unwrap();
    assert_eq!(tombstone.data.len(), 192);
    assert_eq!(&tombstone.data[..4], b"MBX\x01");
    assert_eq!(receipt_account.data.len(), 256);
    assert_eq!(&receipt_account.data[..4], b"MBU\x01");
    assert_eq!(number(&tombstone.data, 132), epoch);
    assert_eq!(number(&tombstone.data, 140), deadline);
    assert_eq!(number(&tombstone.data, 148), deadline);
    assert_eq!(h.svm.get_account(&p.source).unwrap(), source);
    assert!(h.svm.get_account(&carry(&h)).is_none());
    if let Some(path) = std::env::var_os("MORSE_TOKEN_EXPIRY_FIXTURES_PATH") {
        let mut snapshot = expiry_snapshot(&h, &p, epoch, "expired-unfunded");
        snapshot["before_expiry"] = before_expiry;
        snapshot["instruction"] = instruction_report(&expiration);
        std::fs::write(path, serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();
    }
    send(&mut h, std::slice::from_ref(&expiration), &[]);
    assert_eq!(h.svm.get_account(&week).unwrap(), tombstone);
    assert_eq!(h.svm.get_account(&proof).unwrap(), receipt_account);
    // Restore a fully valid funding clock/config/oracle context. Permanent
    // absence replacement, rather than wall-clock inference, blocks both tags.
    fresh_spot(&mut h, ready);
    let legacy = open_week(&h, &p, epoch, 240_000_000);
    fail_signed(&mut h, legacy, &[&p.creator]);
    let modern = open_v2(&h, &p, epoch, 240_000_000, 0);
    fail_signed(&mut h, modern, &[&p.creator]);
    assert_eq!(h.svm.get_account(&week).unwrap(), tombstone);
    assert_eq!(h.svm.get_account(&proof).unwrap(), receipt_account);
    assert_eq!(h.svm.get_account(&p.source).unwrap(), source);
    send(&mut h, &[expiration], &[]);
    assert_eq!(h.svm.get_account(&week).unwrap(), tombstone);
    assert_eq!(h.svm.get_account(&proof).unwrap(), receipt_account);
    // An old terminal proof must remain an inert receipt after genuine carry
    // is accumulated and reserved into a later week.
    let next = epoch + 1;
    fresh_spot(&mut h, (next * 604800) as i64);
    let cash = open_v2(&h, &p, next, 24_000_000, 0);
    send(&mut h, &[cash], &[&p.creator]);
    if let Some(path) = std::env::var_os("MORSE_TOKEN_EXPIRY_FIXTURES_PATH") {
        let mut root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        root["later_funded"] = carry_snapshot(&h, &p, next, "later-funded");
        std::fs::write(path, serde_json::to_vec_pretty(&root).unwrap()).unwrap();
    }
    h.warp(((next + 1) * 604800) as i64);
    let closing = close(&h, &p, next);
    send(&mut h, &[closing], &[]);
    fresh_spot(&mut h, ((next + 1) * 604800) as i64);
    let carried = open_v2(&h, &p, next + 1, 0, 24_000_000);
    send(&mut h, &[carried], &[&p.creator]);
    let protected = [
        week,
        proof,
        carry(&h),
        ata(carry(&h), p.usdc),
        week_address(&h, next + 1),
        ata(week_address(&h, next + 1), p.usdc),
        p.source,
    ];
    let before = accounts(&h, &protected);
    let expiration = expire_unfunded(&h, epoch);
    send(&mut h, std::slice::from_ref(&expiration), &[]);
    assert_eq!(accounts(&h, &protected), before);
    if let Some(path) = std::env::var_os("MORSE_CREDIT_BURN_NEXT_READY_PATH") {
        let time: i64 = std::env::var("MORSE_CREDIT_BURN_NATIVE_NOW")
            .unwrap()
            .parse()
            .unwrap();
        fresh_spot(&mut h, time);
        let current_next = time as u64 / 604800 + 1;
        let ready = credit_burn_ready_snapshot(&h, &p, current_next);
        std::fs::write(path, serde_json::to_vec_pretty(&ready).unwrap()).unwrap();
        if let Some(request) = std::env::var_os("MORSE_CREDIT_BURN_FUND_REQUEST_PATH") {
            let saved = h.svm.clone();
            execute_credit_burn_request(&mut h, &p, current_next, PathBuf::from(request));
            h.svm = saved;
        }
    }
    // Updated external code/source availability cannot revoke an already
    // permanent empty-week proof or require touching later carry custody.
    for executable in [JUP, RAY] {
        let key = data_account(executable);
        let mut image = h.svm.get_account(&key).unwrap();
        image.data[4..12].copy_from_slice(&1u64.to_le_bytes());
        h.svm.set_account(key, image).unwrap();
    }
    send(&mut h, &[expiration], &[]);
    assert_eq!(accounts(&h, &protected), before);
    eprintln!("MORSE_BURN_UNFUNDED_EXPIRY canonical_prefunding_boundary_permanent_both_funding_tags_clock_rollback_no_token_movement_later_carry_external_code_change");
}

#[test]
fn unfunded_expiry_rejects_initialized_roles_and_rolls_back_both_creations() {
    let mut h = H::with_keys(
        Keypair::new_from_array([213; 32]),
        Address::new_from_array([214; 32]),
    );
    assert!(h.send(h.init.clone()));
    let p = pool_with_usdc(&mut h, Keypair::new_from_array([215; 32]));
    let profile = burn_configuration(&h, &p);
    send(&mut h, &[profile], &[]);
    let ready = h.svm.get_sysvar::<Clock>().unix_timestamp + 14 * 86400;
    seed_oracle(&mut h, ready);
    let epoch = ready as u64 / 604800 + 1;
    let deadline = epoch * 604800 + 25200;
    h.warp(deadline as i64);
    let expiration = expire_unfunded(&h, epoch);
    let week = week_address(&h, epoch);
    let proof = receipt(&h, epoch);
    let protected = [h.config, h.mint, p.source, week, proof, carry(&h)];
    let baseline = h.svm.clone();
    for (index, key) in [
        (1, h.mint),
        (2, p.usdc),
        (3, h.config),
        (4, proof),
        (5, week),
        (6, TOKEN),
    ] {
        let mut wrong = expiration.clone();
        wrong.accounts[index].pubkey = key;
        let before = accounts(&h, &protected);
        failed(&mut h, wrong);
        assert_eq!(accounts(&h, &protected), before);
    }
    for index in [4, 5] {
        let mut wrong = expiration.clone();
        wrong.accounts[index].is_writable = false;
        failed(&mut h, wrong);
    }
    let mut unsigned = expiration.clone();
    unsigned.accounts[0] = rw(p.creator.pubkey());
    failed(&mut h, unsigned);
    for target in [week, proof] {
        for (owner, data, executable) in [
            (Address::default(), vec![0], false),
            (Address::new_from_array([216; 32]), vec![], false),
            (TOKEN, vec![0; 165], false),
            (h.program, vec![0; 192], false),
        ] {
            h.svm = baseline.clone();
            h.svm
                .set_account(
                    target,
                    solana_account::Account {
                        lamports: 10_000_000,
                        data,
                        owner,
                        executable,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            let before = accounts(&h, &protected);
            failed(&mut h, expiration.clone());
            assert_eq!(accounts(&h, &protected), before);
        }
    }
    for target in [week, proof] {
        h.svm = baseline.clone();
        let path = std::env::var_os("MORSE_TOKEN_SBF_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_token.so")
            });
        h.svm.add_program_from_file(target, path).unwrap();
        let before = accounts(&h, &protected);
        failed(&mut h, expiration.clone());
        assert_eq!(accounts(&h, &protected), before);
    }
    let rent_week = h.svm.minimum_balance_for_rent_exemption(192);
    let rent_receipt = h.svm.minimum_balance_for_rent_exemption(256);
    for (available, minimum_system_calls) in [(rent_week - 1, 1), (rent_week + rent_receipt - 1, 2)]
    {
        h.svm = baseline.clone();
        let mut payer = h.svm.get_account(&h.payer.pubkey()).unwrap();
        payer.lamports = available + 5000;
        h.svm.set_account(h.payer.pubkey(), payer).unwrap();
        let before = accounts(&h, &protected);
        let logs = failed(&mut h, expiration.clone());
        assert!(
            logs.iter()
                .filter(|line| line.starts_with("Program 11111111111111111111111111111111 invoke"))
                .count()
                >= minimum_system_calls,
            "must reach the intended rent CPI: {}",
            logs.join("\n")
        );
        assert_eq!(accounts(&h, &protected), before);
        assert_eq!(
            h.svm.get_account(&h.payer.pubkey()).unwrap().lamports,
            available
        );
    }
    // Neither legacy nor v2 funding can be reclassified as never funded,
    // before or after their exact unspent input moves to permanent carry.
    for modern in [false, true] {
        h.svm = baseline.clone();
        fresh_spot(&mut h, ready);
        let fund = if modern {
            open_v2(&h, &p, epoch, 24_000_000, 0)
        } else {
            open_week(&h, &p, epoch, 24_000_000)
        };
        send(&mut h, &[fund], &[&p.creator]);
        h.warp(deadline as i64);
        let before = accounts(&h, &protected);
        failed(&mut h, expiration.clone());
        assert_eq!(accounts(&h, &protected), before);
        h.warp((epoch as i64 + 1) * 604800);
        let closing = close(&h, &p, epoch);
        send(&mut h, &[closing], &[]);
        let before = accounts(&h, &protected);
        failed(&mut h, expiration.clone());
        assert_eq!(accounts(&h, &protected), before);
    }
    eprintln!("MORSE_BURN_UNFUNDED_EXPIRY_GUARDS wrong_roles_owners_initialized_state_both_rent_failures_atomic_all_funded_versions_rejected");
}
