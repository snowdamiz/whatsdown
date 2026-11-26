//! Smoke test against a real local validator (`scripts/smoke.sh` starts
//! `solana-test-validator` with both programs and runs this):
//! initialize, register `morse-main`, grow the ring, register and bond a
//! witness, bond the directory, anchor and cosign a checkpoint, stage and
//! prove a fork against the ring (paying a named finder whose token account
//! the submitter creates in the same transaction), then run the rewards drill
//! (settle the previous epoch with no payable witness).
//!
//! usage: smoke <rpc-url> <judge-id> <rewards-id> <deployer-keypair.json>

use morse_program_tests::{rpc::*, *};
use std::str::FromStr;

const MIN: u64 = 1_000_000; // 1 USDC
const DIR: u64 = 10_000_000; // 10 USDC

fn step(n: &str) {
    println!("smoke: {n}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 5, "usage: smoke <rpc-url> <judge-id> <rewards-id> <deployer-keypair.json>");
    let rpc = Rpc(args[1].clone());
    let key_bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(&args[4]).unwrap()).unwrap();
    let mut env = Env::bare(); // used only for its instruction builders
    env.judge = Address::from_str(&args[2]).unwrap();
    env.rewards = Address::from_str(&args[3]).unwrap();
    env.deployer = Keypair::try_from(&key_bytes[..]).unwrap();
    let payer = env.payer.insecure_clone();
    let gov = env.gov.insecure_clone();
    let deployer = env.deployer.insecure_clone();

    step("funding keys");
    rpc.airdrop(&payer.pubkey(), 100);
    for k in [&gov, &deployer, &env.anchor] {
        rpc.airdrop(&k.pubkey(), 5);
    }
    let usdc_mint = Keypair::new();
    create_mint(&rpc, &payer, &usdc_mint, &gov.pubkey());
    env.usdc = usdc_mint.pubkey();

    step("initialize judge and register morse-main");
    rpc.send(&[env.initialize_ix(&deployer.pubkey(), &gov.pubkey(), &[0; 32], MIN, MIN)], &payer, &[&deployer]);
    let service = key(0x51);
    rpc.send(&[env.register_log_ix(MAIN, &pubkey(&service), &env.anchor.pubkey(), &gov.pubkey(), 0)], &payer, &[&gov]);

    step("grow the anchor ring to 426,048 bytes");
    let mut calls = 0;
    loop {
        let len = rpc.data(&env.ring(MAIN)).len();
        if len == layout::RING_LEN {
            break;
        }
        let n = if len == 0 { 1 } else { (layout::RING_LEN - len).div_ceil(10_240).min(8) };
        rpc.send(&vec![env.grow_ring_ix(MAIN); n], &payer, &[]);
        calls += n;
    }
    step(&format!("ring ready after {calls} grow_ring instructions"));

    step("register and bond witness-a; bond the directory");
    let a = env.witness(MAIN, "witness-a", 0xA1);
    rpc.airdrop(&a.operator.pubkey(), 5);
    let ed = ed25519_sign(&a.key, &Env::register_msg(&a));
    rpc.send(&[ed, env.register_witness_ix(MAIN, &a, 0, 0)], &payer, &[&a.operator]);
    rpc.send(&[env.admit_witness_ix(MAIN, &a.account(&env.judge), &gov.pubkey(), 0xFF, 0, &env.judge)], &payer, &[&gov]);
    mint_to(&rpc, &payer, &env.usdc, &gov, &a.operator.pubkey(), MIN);
    rpc.send(&[env.bond_ix(MAIN, &a, &env.usdc, MIN)], &payer, &[&a.operator]);
    mint_to(&rpc, &payer, &env.usdc, &gov, &gov.pubkey(), DIR);
    rpc.send(&[env.bond_directory_ix(MAIN, &gov.pubkey(), &env.usdc, DIR)], &payer, &[&gov]);

    step("anchor a checkpoint and cosign it");
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let public = ktk(&service, 1, 1, [1; 32], now_ms);
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&public), &ktk_sig(&public))]);
    rpc.send(&[ed, env.post_anchor_ix(MAIN, &env.anchor.pubkey(), 0, &public)], &payer, &[&env.anchor]);
    let hash = checkpoint_hash(&public);
    let sig = witness_sig(&a.key, &a.id, &hash);
    let ed = ed25519_ix(&[(&pubkey(&a.key), &witness_msg(&a.id, &hash), &sig)]);
    rpc.send(&[ed, env.cosign_ix(MAIN, 0, 0, &a.account(&env.judge), 0)], &payer, &[]);
    let r = rpc.data(&env.ring(MAIN));
    assert_eq!(u32le(&r, layout::RH_COUNT), 1);
    assert_eq!(r[layout::ring_entry(0) + 96], 1, "cosign bit");

    step("stage and prove a same-size fork against ring entry 0");
    let shown = ktk(&service, 2, 1, [9; 32], now_ms + 1);
    let h2 = checkpoint_hash(&shown);
    let a_sig = witness_sig(&a.key, &a.id, &h2);
    let finder = Keypair::new().pubkey();
    let frk = Frk {
        kind: 1,
        finder: finder.to_bytes(),
        log_key: pubkey(&service),
        c1: shown,
        c2: C2::Ring(0),
        attestations: vec![(a.id.clone(), h2, a_sig)],
        contradiction: None,
    }
    .encode();
    let submitter = Keypair::new();
    rpc.airdrop(&submitter.pubkey(), 5);
    let stage = env.stage(&submitter.pubkey(), 1);
    rpc.send(&[env.stage_init_ix(MAIN, &submitter.pubkey(), 1, frk.len() as u16)], &payer, &[&submitter]);
    rpc.send(&[env.stage_write_ix(&submitter.pubkey(), &stage, 0, &frk)], &payer, &[&submitter]);
    let ed = ed25519_ix(&[(&pubkey(&service), &statement(&shown), &ktk_sig(&shown))]);
    rpc.send(&[ed, env.stage_verify_ix(MAIN, &stage, 0)], &payer, &[]);
    let ed = ed25519_ix(&[(&pubkey(&a.key), &witness_msg(&a.id, &h2), &a_sig)]);
    rpc.send(&[ed, env.stage_verify_ix(MAIN, &stage, 0)], &payer, &[]);
    let finder_ata = ata(&finder, &env.usdc);
    let accounts = env.prove_accounts(
        MAIN,
        &submitter.pubkey(),
        &proof_hash(&frk),
        Some(&stage),
        &finder_ata,
        &finder_ata,
        &[(a.account(&env.judge), a.vault(&env.judge))],
    );
    let prove = env.prove_staged_ix(1, accounts);
    let create = create_ata_idempotent(&submitter.pubkey(), &finder, &env.usdc);
    rpc.send(&[compute_budget(400_000), create, prove], &payer, &[&submitter]);
    assert_eq!(rpc.data(&env.log(MAIN))[layout::LOG_SERVICE_SLASHED], 1, "service slashed");
    assert_eq!(rpc.data(&a.account(&env.judge))[layout::W_STATUS], layout::SLASHED, "witness slashed");
    assert_eq!(rpc.balance(&finder_ata), (DIR + MIN) / 10, "finder paid 10%");
    assert_eq!(rpc.balance(&env.locked(MAIN)), (DIR + MIN) - (DIR + MIN) / 10, "90% locked");
    assert!(rpc.data(&stage).is_empty(), "stage closed");

    step("rewards drill: settle the previous epoch with no payable witness");
    let rewards = env.rewards;
    let mut data = vec![0u8];
    for part in [gov.pubkey().as_ref(), env.judge.as_ref(), env.log(MAIN).as_ref(), env.usdc.as_ref()] {
        data.extend_from_slice(part);
    }
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0i64.to_le_bytes());
    let init = Instruction {
        program_id: rewards,
        accounts: vec![
            AccountMeta::new(deployer.pubkey(), true),
            AccountMeta::new(pda(&[b"config"], &rewards), false),
            AccountMeta::new_readonly(env.programdata(&rewards), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data,
    };
    rpc.send(&[init], &payer, &[&deployer]);
    let pool_owner = pda(&[b"pool"], &rewards);
    let pool = mint_to(&rpc, &payer, &env.usdc, &gov, &pool_owner, 0);
    let src = mint_to(&rpc, &payer, &env.usdc, &gov, &gov.pubkey(), 3 * MIN);
    let fund = Instruction {
        program_id: rewards,
        accounts: vec![
            AccountMeta::new_readonly(gov.pubkey(), true),
            AccountMeta::new(src, false),
            AccountMeta::new(pool, false),
            AccountMeta::new_readonly(pda(&[b"config"], &rewards), false),
            AccountMeta::new_readonly(TOKEN, false),
        ],
        data: [&[2u8][..], &(3 * MIN).to_le_bytes()].concat(),
    };
    rpc.send(&[fund], &payer, &[&gov]);
    let unix = (now_ms / 1000) as i64;
    let epoch = ((unix - 900) / EPOCH - 1) as u64;
    let epoch_account = pda(&[b"epoch", &epoch.to_le_bytes()], &rewards);
    let settle = Instruction {
        program_id: rewards,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pda(&[b"config"], &rewards), false),
            AccountMeta::new_readonly(env.log(MAIN), false),
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(epoch_account, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(SYSTEM, false), // no price feed configured
            AccountMeta::new_readonly(a.account(&env.judge), false),
            AccountMeta::new_readonly(a.vault(&env.judge), false),
        ],
        data: [&[3u8][..], &epoch.to_le_bytes()].concat(),
    };
    rpc.send(&[settle], &payer, &[]);
    let ep = rpc.data(&epoch_account);
    assert_eq!(ep[3], 0, "nobody paid");
    assert_eq!(rpc.balance(&pool), 3 * MIN, "pool carried over");

    println!("smoke: OK (judge {}, rewards {})", env.judge, env.rewards);
}
