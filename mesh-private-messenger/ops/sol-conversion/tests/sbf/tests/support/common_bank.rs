//! Fresh common retained bank only. Keys never cross the Rust process boundary.
//! Existing token/Ray/SPL instructions initialize every accepted owned account.
use super::*;
const JUP: Address = Address::from_str_const("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
const PYTH: Address = Address::from_str_const("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ");
const BTC_AMOUNT: u64 = 74_599_302;
const CASH: u64 = 299_003_525;
pub struct Context {
    program: Address,
    cfg: Address,
    morse: Address,
    profile: Address,
    pool: Address,
    amm: Address,
    vault0: Address,
    vault1: Address,
    observation: Address,
    oracle: Address,
    source: Address,
    provider: Keypair,
    initialized_at: i64,
}
fn common_send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    extra: &[&Keypair],
    instructions: &[Instruction],
) {
    let mut ixs = vec![budget()];
    ixs.extend_from_slice(instructions);
    svm.expire_blockhash();
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    let wire = wincode::serialize(&tx).unwrap();
    let result = svm.send_transaction(tx.clone()).unwrap_or_else(|e| {
        panic!(
            "common fixture tag={:?}: {:?}\n{}",
            instructions[0].data.first(),
            e.err,
            e.meta.logs.join("\n")
        )
    });
    if let Some(dir) = std::env::var_os("MORSE_SOL_CONVERSION_EXPORT") {
        use std::io::Write;
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("common-transactions.jsonl"))
            .unwrap();
        writeln!(f,"{}",json!({"wire":B64.encode(wire),"signature":tx.signatures[0].to_string(),"tags":instructions.iter().map(|v|v.data.first()).collect::<Vec<_>>(),"slot":svm.get_sysvar::<Clock>().slot,"time":svm.get_sysvar::<Clock>().unix_timestamp,"fee":result.fee,"units":result.compute_units_consumed,"logs":result.logs})).unwrap();
    }
}
fn pda(program: Address, seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, &program).0
}
fn ix(program: Address, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: program,
        accounts,
        data,
    }
}
fn mint_to(mint: Address, to: Address, authority: Address, units: u64) -> Instruction {
    ix(
        TOKEN,
        vec![rw(mint), rw(to), AccountMeta::new_readonly(authority, true)],
        [vec![14], units.to_le_bytes().to_vec(), vec![6]].concat(),
    )
}
fn set_time(svm: &mut LiteSVM, now: i64) {
    let mut c = svm.get_sysvar::<Clock>();
    c.unix_timestamp = now;
    c.slot += 1;
    svm.set_sysvar(&c);
}
fn oracle_source(now: i64, slot: u64) -> Account {
    let mut d = vec![0; 134];
    d[..8].copy_from_slice(&[34, 241, 35, 99, 157, 126, 244, 205]);
    d[8..40].fill(99);
    d[40] = 1;
    d[41..73].fill(7);
    d[73..81].copy_from_slice(&2_000_000i64.to_le_bytes());
    d[89..93].copy_from_slice(&(-6i32).to_le_bytes());
    d[93..101].copy_from_slice(&now.to_le_bytes());
    d[101..109].copy_from_slice(&(now - 1).to_le_bytes());
    d[125..133].copy_from_slice(&slot.to_le_bytes());
    Account {
        lamports: 10_000_000,
        data: d,
        owner: PYTH,
        executable: false,
        rent_epoch: 0,
    }
}
fn refresh_oracle(svm: &mut LiteSVM, ctx: &Context, payer: &Keypair, now: i64) {
    set_time(svm, now);
    let slot = svm.get_sysvar::<Clock>().slot;
    svm.set_account(ctx.source, oracle_source(now, slot))
        .unwrap();
    common_send(
        svm,
        payer,
        &[],
        &[ix(
            ctx.program,
            vec![
                ro(ctx.cfg),
                ro(ctx.morse),
                rw(ctx.oracle),
                ro(PYTH),
                ro(ctx.source),
            ],
            vec![4],
        )],
    );
}
pub fn setup(
    svm: &mut LiteSVM,
    payer: &Keypair,
    owner: &Keypair,
    usdc: Address,
    amm: Address,
    fee: Address,
    now: i64,
    dex: &Path,
) -> Context {
    // Deliberate fresh genesis backdating makes the existing immutable 14-day
    // profile delay mature without changing production windows or sleeping.
    let initialized_at = now - 14 * 86400 - 60;
    set_time(svm, initialized_at);
    let program = Address::new_from_array(
        solana_sha256_hasher::hash(b"owned-common-bank-token-program-v1").to_bytes(),
    );
    let token_elf = PathBuf::from(
        std::env::var_os("MORSE_COMMON_BANK_TOKEN_ELF").expect("explicit existing token ELF"),
    );
    svm.add_program_from_file(program, &token_elf).unwrap();
    let pd = metadata(program);
    let mut data = svm.get_account(&pd).unwrap();
    data.data[4..12].fill(0);
    data.data[12] = 1;
    data.data[13..45].copy_from_slice(payer.pubkey().as_ref());
    svm.set_account(pd, data).unwrap();
    let jupiter = std::fs::read(dex.join("jupiter.so")).unwrap();
    svm.add_program(JUP, &jupiter).unwrap();
    for p in [JUP, RAY] {
        let key = metadata(p);
        let mut d = svm.get_account(&key).unwrap();
        d.data[4..12].fill(0);
        svm.set_account(key, d).unwrap();
    }
    let cfg = pda(program, &[b"token"]);
    let morse = pda(program, &[b"mint"]);
    let alloc: Vec<_> = (0..7)
        .map(|i| pda(program, &[b"allocation", &[i]]))
        .collect();
    let mut keys = vec![
        AccountMeta::new_readonly(payer.pubkey(), true),
        AccountMeta::new(payer.pubkey(), true),
        rw(cfg),
        rw(morse),
        ro(program),
        ro(pd),
        ro(TOKEN),
        ro(ATA),
        ro(Address::default()),
    ];
    for a in &alloc {
        keys.extend([rw(*a), rw(ata(*a, morse))]);
    }
    let mut init = vec![0];
    init.extend(payer.pubkey().as_ref());
    for _ in 0..7 {
        init.extend(owner.pubkey().as_ref());
    }
    common_send(svm, payer, &[], &[ix(program, keys, init)]);
    common_send(
        svm,
        payer,
        &[],
        &[ix(
            program,
            vec![
                AccountMeta::new(payer.pubkey(), true),
                ro(cfg),
                rw(alloc[5]),
                rw(ata(alloc[5], morse)),
                rw(ata(owner.pubkey(), morse)),
                ro(owner.pubkey()),
                ro(morse),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            vec![1, 5],
        )],
    );
    let provider = Keypair::new();
    svm.airdrop(&provider.pubkey(), 10_000_000).unwrap();
    let usd_liquidity = 20_000_000_000_000u64;
    let morse_liquidity = 10_000_000_000_000u64;
    common_send(
        svm,
        payer,
        &[owner],
        &[
            create_ata(payer.pubkey(), provider.pubkey(), usdc),
            mint_to(
                usdc,
                ata(provider.pubkey(), usdc),
                owner.pubkey(),
                BTC_AMOUNT,
            ),
            mint_to(
                usdc,
                ata(owner.pubkey(), usdc),
                owner.pubkey(),
                usd_liquidity + 300,
            ),
        ],
    );
    let (m0, m1, a0, a1) = if usdc < morse {
        (usdc, morse, usd_liquidity, morse_liquidity)
    } else {
        (morse, usdc, morse_liquidity, usd_liquidity)
    };
    let pool = pda(RAY, &[b"pool", amm.as_ref(), m0.as_ref(), m1.as_ref()]);
    let auth = pda(RAY, &[b"vault_and_lp_mint_auth_seed"]);
    let lp = pda(RAY, &[b"pool_lp_mint", pool.as_ref()]);
    let vault0 = pda(RAY, &[b"pool_vault", pool.as_ref(), m0.as_ref()]);
    let vault1 = pda(RAY, &[b"pool_vault", pool.as_ref(), m1.as_ref()]);
    let observation = pda(RAY, &[b"observation", pool.as_ref()]);
    common_send(
        svm,
        payer,
        &[owner],
        &[ix(
            RAY,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                ro(amm),
                ro(auth),
                rw(pool),
                ro(m0),
                ro(m1),
                rw(lp),
                rw(ata(owner.pubkey(), m0)),
                rw(ata(owner.pubkey(), m1)),
                rw(ata(owner.pubkey(), lp)),
                rw(vault0),
                rw(vault1),
                rw(fee),
                rw(observation),
                ro(TOKEN),
                ro(TOKEN),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
                ro(Address::from_str_const(
                    "SysvarRent111111111111111111111111111111111",
                )),
            ],
            [
                solana_sha256_hasher::hash(b"global:initialize").to_bytes()[..8].to_vec(),
                a0.to_le_bytes().to_vec(),
                a1.to_le_bytes().to_vec(),
                0u64.to_le_bytes().to_vec(),
            ]
            .concat(),
        )],
    );
    let profile = pda(program, &[b"swap"]);
    common_send(
        svm,
        payer,
        &[],
        &[ix(
            program,
            vec![
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(payer.pubkey(), true),
                ro(cfg),
                ro(morse),
                rw(profile),
                ro(usdc),
                ro(owner.pubkey()),
                ro(pool),
                ro(amm),
                ro(vault0),
                ro(vault1),
                ro(observation),
                ro(JUP),
                ro(metadata(JUP)),
                ro(RAY),
                ro(metadata(RAY)),
                ro(Address::default()),
            ],
            vec![8],
        )],
    );
    let oracle = pda(program, &[b"oracle"]);
    let source = Address::new_unique();
    svm.set_account(PYTH, svm.get_account(&TOKEN).unwrap())
        .unwrap();
    set_time(svm, now);
    svm.set_account(source, oracle_source(now, svm.get_sysvar::<Clock>().slot))
        .unwrap();
    common_send(
        svm,
        payer,
        &[],
        &[ix(
            program,
            vec![
                AccountMeta::new_readonly(payer.pubkey(), true),
                AccountMeta::new(payer.pubkey(), true),
                ro(cfg),
                ro(morse),
                rw(oracle),
                ro(PYTH),
                ro(source),
                ro(Address::default()),
            ],
            [vec![3], source.as_ref().to_vec(), vec![7; 32]].concat(),
        )],
    );
    let ctx = Context {
        program,
        cfg,
        morse,
        profile,
        pool,
        amm,
        vault0,
        vault1,
        observation,
        oracle,
        source,
        provider,
        initialized_at,
    };
    ctx
}
fn bank(
    svm: &LiteSVM,
    ctx: &Context,
    payer: &Keypair,
    owner: &Keypair,
    usdc: Address,
    epoch: u64,
    name: &str,
) -> Value {
    let week = pda(ctx.program, &[b"burn-week", &epoch.to_le_bytes()]);
    let carry = pda(ctx.program, &[b"burn-carry"]);
    let receipt = pda(ctx.program, &[b"burn-carry-epoch", &epoch.to_le_bytes()]);
    let keys = [
        ctx.cfg,
        ctx.morse,
        ctx.profile,
        usdc,
        ctx.oracle,
        Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
        JUP,
        metadata(JUP),
        RAY,
        metadata(RAY),
        ctx.pool,
        ctx.amm,
        ctx.vault0,
        ctx.vault1,
        ctx.observation,
        week,
        ata(week, usdc),
        ctx.program,
        metadata(ctx.program),
        carry,
        ata(carry, usdc),
        ata(owner.pubkey(), usdc),
        receipt,
        payer.pubkey(),
        owner.pubkey(),
    ];
    let c = svm.get_sysvar::<Clock>();
    json!({"schema":1,"name":name,"slot":c.slot.to_string(),"now":c.unix_timestamp.to_string(),"epoch":epoch.to_string(),"program":ctx.program.to_string(),"program_slot":"0","governance":payer.pubkey().to_string(),"treasury":owner.pubkey().to_string(),"usdc":usdc.to_string(),"factory":ctx.amm.to_string(),"blockhash":svm.latest_blockhash().to_string(),"accounts":keys.iter().map(|k|json!({"address":k.to_string(),"account":account_json(svm,*k)})).collect::<Vec<_>>()})
}
fn fund(
    ctx: &Context,
    payer: Address,
    owner: Address,
    usdc: Address,
    epoch: u64,
    weights: &[u32],
    entropy: &[u64],
) -> Instruction {
    assert_eq!(weights.len(), 24);
    assert_eq!(entropy.len(), 24);
    let week = pda(ctx.program, &[b"burn-week", &epoch.to_le_bytes()]);
    let carry = pda(ctx.program, &[b"burn-carry"]);
    let mut d = [
        vec![14],
        epoch.to_le_bytes().to_vec(),
        CASH.to_le_bytes().to_vec(),
        0u64.to_le_bytes().to_vec(),
    ]
    .concat();
    for i in 0..24 {
        d.extend(weights[i].to_le_bytes());
        d.extend(entropy[i].to_le_bytes());
    }
    ix(
        ctx.program,
        vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(payer, true),
            ro(ctx.cfg),
            ro(ctx.morse),
            ro(ctx.profile),
            ro(usdc),
            rw(week),
            rw(ata(week, usdc)),
            rw(ata(owner, usdc)),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
            ro(JUP),
            ro(metadata(JUP)),
            ro(RAY),
            ro(metadata(RAY)),
            ro(ctx.oracle),
            rw(carry),
            rw(ata(carry, usdc)),
        ],
        d,
    )
}
fn budget() -> Instruction {
    ix(
        Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        vec![],
        [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    )
}
fn message_handoff(
    svm: &mut LiteSVM,
    dir: &Path,
    stem: &str,
    expected: Instruction,
    payer: &Keypair,
    owner: Option<&Keypair>,
) -> (Transaction, Vec<u8>) {
    let message = Message::new_with_blockhash(
        &[budget(), expected],
        Some(&payer.pubkey()),
        &svm.latest_blockhash(),
    );
    let request = dir.join(format!("{stem}.message.base64"));
    let supplied = if std::env::var_os("MORSE_COMMON_BANK_SELF_TEST").is_some() {
        message.clone()
    } else {
        let raw = B64.decode(wait(&request)).unwrap();
        let m: Message = wincode::deserialize(&raw).unwrap();
        assert_eq!(m.serialize(), raw);
        equivalent_message(&m, &message);
        m
    };
    let mut signers = vec![payer];
    if let Some(o) = owner {
        signers.push(o);
    }
    let tx = Transaction::new(&signers, supplied, svm.latest_blockhash());
    let wire = wincode::serialize(&tx).unwrap();
    assert!(wire.len() <= 1232);
    std::fs::write(
        dir.join(format!("{stem}.signed.packet.base64")),
        B64.encode(&wire),
    )
    .unwrap();
    if std::env::var_os("MORSE_COMMON_BANK_SELF_TEST").is_none() {
        assert_eq!(
            B64.decode(wait(&dir.join(format!("{stem}.send.packet.base64"))))
                .unwrap(),
            wire
        );
    }
    (tx, wire)
}
pub fn run(
    svm: &mut LiteSVM,
    dir: &Path,
    payer: &Keypair,
    owner: &Keypair,
    usdc: Address,
    ctx: &Context,
) {
    let proceed = if std::env::var_os("MORSE_COMMON_BANK_SELF_TEST").is_some() {
        json!({"now":svm.get_sysvar::<Clock>().unix_timestamp,"amount":BTC_AMOUNT.to_string()})
    } else {
        serde_json::from_slice(&wait(&dir.join("btc-transfer-proceed.json"))).unwrap()
    };
    let now = proceed["now"].as_i64().unwrap();
    assert_eq!(proceed["amount"], BTC_AMOUNT.to_string());
    assert!(now >= svm.get_sysvar::<Clock>().unix_timestamp);
    let host_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(now <= host_now + 30);
    refresh_oracle(svm, ctx, payer, now);
    svm.expire_blockhash();
    let source = ata(ctx.provider.pubkey(), usdc);
    let destination = ata(owner.pubkey(), usdc);
    let transfer = ix(
        TOKEN,
        vec![
            rw(source),
            ro(usdc),
            rw(destination),
            AccountMeta::new_readonly(ctx.provider.pubkey(), true),
        ],
        [vec![12], BTC_AMOUNT.to_le_bytes().to_vec(), vec![6]].concat(),
    );
    let tx = Transaction::new_signed_with_payer(
        &[transfer],
        Some(&payer.pubkey()),
        &[payer, &ctx.provider],
        svm.latest_blockhash(),
    );
    let before = amount(svm, destination);
    let pre: Vec<_> = tx
        .message
        .account_keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect();
    let tokens = token_rows(svm, &tx.message.account_keys, usdc);
    let result = svm.send_transaction(tx.clone()).unwrap();
    assert_eq!(amount(svm, destination) - before, BTC_AMOUNT);
    assert_eq!(amount(svm, source), 0);
    assert!(result.inner_instructions.iter().all(|v| v.is_empty()));
    let wire = wincode::serialize(&tx).unwrap();
    let c = svm.get_sysvar::<Clock>();
    let transaction = json!({"slot":c.slot,"blockTime":c.unix_timestamp,"version":"legacy","transaction":[B64.encode(&wire),"base64"],"meta":{"err":null,"fee":result.fee,"preBalances":pre,"postBalances":tx.message.account_keys.iter().map(|k|svm.get_balance(k).unwrap_or(0)).collect::<Vec<_>>(),"preTokenBalances":tokens,"postTokenBalances":token_rows(svm,&tx.message.account_keys,usdc),"loadedAddresses":{"writable":[],"readonly":[]},"innerInstructions":[],"logMessages":result.logs,"computeUnitsConsumed":result.compute_units_consumed}});
    write(
        &dir.join("btc-transfer.json"),
        &json!({"signature":tx.signatures[0].to_string(),"amount":BTC_AMOUNT.to_string(),"transaction":transaction,"accounts":tx.message.account_keys.iter().map(|k|json!({"address":k.to_string(),"account":account_json(svm,*k)})).collect::<Vec<_>>() }),
    );
    let epoch = (now as u64 / 604800) + 1;
    let ready = bank(svm, ctx, payer, owner, usdc, epoch, "common-ready");
    write(&dir.join("funding-ready.json"), &ready);
    let before_funding = svm.clone();
    let before = amount(svm, destination);
    assert_eq!(before, CASH + 1000);
    // Mesh's persisted random schedule is the only accepted schedule. The local
    // signer checks canonical instruction roles and all bytes before signing.
    let plan = if std::env::var_os("MORSE_COMMON_BANK_SELF_TEST").is_some() {
        json!({"cash":CASH.to_string(),"carry":"0","weights":vec!["1";24],"entropy":(0..24).map(|v|(v*999999u64).to_string()).collect::<Vec<_>>()})
    } else {
        serde_json::from_slice(&wait(&dir.join("aggregate-funding.plan.json"))).unwrap()
    };
    assert_eq!(plan["cash"], CASH.to_string());
    assert_eq!(plan["carry"], "0");
    let weights: Vec<u32> = plan["weights"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    let entropy: Vec<u64> = plan["entropy"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().parse().unwrap())
        .collect();
    let instruction = fund(
        ctx,
        owner.pubkey(),
        owner.pubkey(),
        usdc,
        epoch,
        &weights,
        &entropy,
    );
    let (tx, wire) = message_handoff(
        svm,
        dir,
        "aggregate-funding",
        instruction.clone(),
        payer,
        Some(owner),
    );
    let meta = svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.logs.join("\n")));
    assert_eq!(before - amount(svm, destination), CASH);
    let week = pda(ctx.program, &[b"burn-week", &epoch.to_le_bytes()]);
    assert_eq!(amount(svm, ata(week, usdc)), CASH);
    assert_eq!(&svm.get_account(&week).unwrap().data[..4], b"MTW\x02");
    let after = amount(svm, destination);
    for _ in 0..2 {
        common_send(svm, payer, &[owner], std::slice::from_ref(&instruction));
        assert_eq!(amount(svm, destination), after);
        assert_eq!(amount(svm, ata(week, usdc)), CASH);
    }
    let mut funded = bank(svm, ctx, payer, owner, usdc, epoch, "common-funded");
    funded["packet"] = json!(B64.encode(&wire));
    funded["cash_debited"] = json!(CASH.to_string());
    funded["units"] = json!(meta.compute_units_consumed);
    funded["exact_intent_replays"] = json!(2);
    write(&dir.join("funded.json"), &funded);
    // Alternate branch starts from the exact genuine pre-funding bank, never
    // from a fabricated empty week nor a continuation of the funded branch.
    *svm = before_funding;
    let deadline = (epoch * 604800 + 25200) as i64;
    refresh_oracle(svm, ctx, payer, deadline);
    write(
        &dir.join("expiry-ready.json"),
        &bank(
            svm,
            ctx,
            payer,
            owner,
            usdc,
            epoch,
            "alternate-expiry-ready",
        ),
    );
    let receipt = pda(ctx.program, &[b"burn-carry-epoch", &epoch.to_le_bytes()]);
    let expire = ix(
        ctx.program,
        vec![
            AccountMeta::new(owner.pubkey(), true),
            ro(ctx.cfg),
            ro(ctx.morse),
            ro(ctx.profile),
            rw(week),
            rw(receipt),
            ro(Address::default()),
        ],
        [vec![15], epoch.to_le_bytes().to_vec()].concat(),
    );
    let (tx, wire) = message_handoff(
        svm,
        dir,
        "aggregate-expiry",
        expire.clone(),
        payer,
        Some(owner),
    );
    let result = svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.logs.join("\n")));
    let balance = amount(svm, destination);
    assert_eq!(balance, before);
    common_send(svm, payer, &[owner], &[expire]);
    assert_eq!(amount(svm, destination), balance);
    assert_eq!(&svm.get_account(&week).unwrap().data[..4], b"MBX\x01");
    assert_eq!(&svm.get_account(&receipt).unwrap().data[..4], b"MBU\x01");
    let mut expired = bank(svm, ctx, payer, owner, usdc, epoch, "alternate-expired");
    expired["packet"] = json!(B64.encode(&wire));
    expired["units"] = json!(result.compute_units_consumed);
    expired["source_unchanged"] = json!(true);
    expired["profile_initialized_at"] = json!(ctx.initialized_at);
    write(&dir.join("expired.json"), &expired);
    eprintln!("COMMON_BANK actual_SOL_output actual_provider_transfer exact_tag14 freshhash_replays actual_tag15_alternate_branch");
}

pub fn annotate_initial(svm: &LiteSVM, dir: &Path, ctx: &Context, owner: &Keypair) {
    let path = dir.join("initial-unscoped.json");
    let mut initial: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    initial["observation_time"] = json!(svm.get_sysvar::<Clock>().unix_timestamp);
    let usdc = Address::from_str(initial["usdc"].as_str().unwrap()).unwrap();
    initial["custody"] = json!(ata(owner.pubkey(), usdc).to_string());
    initial["common_genesis"] = json!({"program":ctx.program.to_string(),"cfg":ctx.cfg.to_string(),"morse":ctx.morse.to_string(),"profile":ctx.profile.to_string(),"profile_initialized_at":ctx.initialized_at,"provider":ctx.provider.pubkey().to_string(),"provider_genesis_units":BTC_AMOUNT.to_string(),"ordinary_usdc_genesis_units":"300","preexisting_source_surplus":"1000","actual_program_initialization":true,"controlled_backdated_profile_genesis":true,"no_historical_account_reidentification":true});
    write(&dir.join("initial.json"), &initial);
}
