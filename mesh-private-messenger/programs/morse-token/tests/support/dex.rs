//! Actual pinned Jupiter + Raydium SBF, isolated bank; no live transactions.
use super::*;
use base64::Engine;
use std::{path::Path, str::FromStr};
const JUP: Address = Address::from_str_const("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
const RAY: Address = Address::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
const EVENT: Address = Address::from_str_const("D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf");
fn snapshot(h: &mut H, name: &str) -> Address {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ops/token/fixtures/dex")
        .join(format!("{name}.json"));
    let raw = std::fs::read(path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let row = &value["value"];
    let key = Address::from_str(value["address"].as_str().unwrap()).unwrap();
    let account = solana_account::Account {
        lamports: row["lamports"].as_u64().unwrap(),
        data: base64::engine::general_purpose::STANDARD
            .decode(row["data"][0].as_str().unwrap())
            .unwrap(),
        owner: Address::from_str(row["owner"].as_str().unwrap()).unwrap(),
        executable: row["executable"].as_bool().unwrap(),
        rent_epoch: row["rentEpoch"].as_u64().unwrap(),
    };
    h.svm.set_account(key, account).unwrap();
    key
}
fn load_programs(h: &mut H) {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../../../ops/token/dex-source.json")).unwrap();
    let directory = std::env::var_os("MORSE_TOKEN_DEX_BIN_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../.morse/witness-proof/token-dex")
        },
        PathBuf::from,
    );
    for row in manifest["snapshots"].as_array().unwrap() {
        let path = directory.join(format!("{}.so", row["name"].as_str().unwrap()));
        let data = std::fs::read(&path)
            .expect("fetch and verify pinned read-only DEX ELF snapshots first");
        assert_eq!(
            hex::encode(solana_sha256_hasher::hash(&data).to_bytes()),
            row["elf_sha256"].as_str().unwrap()
        );
        h.svm
            .add_program_from_file(
                Address::from_str(row["program"].as_str().unwrap()).unwrap(),
                path,
            )
            .unwrap();
        let key = Address::from_str(row["program"].as_str().unwrap()).unwrap();
        let pd = data_account(key);
        let mut metadata = h.svm.get_account(&pd).unwrap();
        metadata.data[4..12].copy_from_slice(&0u64.to_le_bytes());
        h.svm.set_account(pd, metadata).unwrap();
    }
}
fn send(h: &mut H, ixs: &[Instruction], extra: &[&Keypair]) -> String {
    send_packet(h, ixs, extra).0
}
fn send_packet(h: &mut H, ixs: &[Instruction], extra: &[&Keypair]) -> (String, String) {
    h.svm.expire_blockhash();
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    };
    let prepared: Vec<_> = ixs.iter().map(|ix| carry_tests::prepared(h, ix)).collect();
    let instructions = [&[budget], prepared.as_slice()].concat();
    let mut signers = vec![&h.payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&h.payer.pubkey()),
        &signers,
        h.svm.latest_blockhash(),
    );
    let signature = tx.signatures[0].to_string();
    let wire = base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap());
    if let Err(e) = h.svm.send_transaction(tx) {
        panic!("{:?}\n{}", e.err, e.meta.logs.join("\n"));
    }
    (signature, wire)
}
fn create_ata(payer: Address, owner: Address, mint: Address) -> Instruction {
    Instruction {
        program_id: ATA,
        accounts: vec![
            AccountMeta::new(payer, true),
            rw(ata(owner, mint)),
            ro(owner),
            ro(mint),
            ro(Address::default()),
            ro(TOKEN),
        ],
        data: vec![1],
    }
}
struct Pool {
    creator: Keypair,
    usdc: Address,
    source: Address,
    destination: Address,
    pool: Address,
    authority: Address,
    config: Address,
    input_vault: Address,
    output_vault: Address,
    observation: Address,
}
fn pool(h: &mut H) -> Pool {
    pool_with_usdc(h, Keypair::new())
}
fn pool_with_usdc(h: &mut H, usd_key: Keypair) -> Pool {
    load_programs(h);
    let config = snapshot(h, "amm-config");
    let fee = snapshot(h, "create-pool-fee");
    snapshot(h, "native-mint");
    let creator = Keypair::new_from_array([25; 32]);
    assert_eq!(creator.pubkey(), h.beneficiaries[5]);
    h.svm.airdrop(&creator.pubkey(), 10_000_000_000).unwrap();
    assert!(h.send(h.claim(5)));
    let usdc = usd_key.pubkey();
    let amount_token = 10_000_000_000_000u64;
    let amount_usdc = 20_000_000_000_000u64;
    let source = ata(creator.pubkey(), usdc);
    let destination = ata(creator.pubkey(), h.mint);
    let rent = h.svm.minimum_balance_for_rent_exemption(82);
    let mut create_data = 0u32.to_le_bytes().to_vec();
    create_data.extend(rent.to_le_bytes());
    create_data.extend(82u64.to_le_bytes());
    create_data.extend(TOKEN.as_ref());
    let create = Instruction {
        program_id: Address::default(),
        accounts: vec![
            AccountMeta::new(h.payer.pubkey(), true),
            AccountMeta::new(usdc, true),
        ],
        data: create_data,
    };
    let initialize = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(usdc)],
        data: [vec![20, 6], creator.pubkey().as_ref().to_vec(), vec![0]].concat(),
    };
    let mint = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(usdc),
            rw(source),
            AccountMeta::new_readonly(creator.pubkey(), true),
        ],
        data: [
            vec![14],
            (amount_usdc + 1_000_000_000).to_le_bytes().to_vec(),
            vec![6],
        ]
        .concat(),
    };
    send(
        h,
        &[
            create,
            initialize,
            create_ata(h.payer.pubkey(), creator.pubkey(), usdc),
            mint,
        ],
        &[&usd_key, &creator],
    );
    let (mint0, mint1, amount0, amount1) = if usdc < h.mint {
        (usdc, h.mint, amount_usdc, amount_token)
    } else {
        (h.mint, usdc, amount_token, amount_usdc)
    };
    let pool = Address::find_program_address(
        &[b"pool", config.as_ref(), mint0.as_ref(), mint1.as_ref()],
        &RAY,
    )
    .0;
    let authority = Address::find_program_address(&[b"vault_and_lp_mint_auth_seed"], &RAY).0;
    let lp = Address::find_program_address(&[b"pool_lp_mint", pool.as_ref()], &RAY).0;
    let vault0 =
        Address::find_program_address(&[b"pool_vault", pool.as_ref(), mint0.as_ref()], &RAY).0;
    let vault1 =
        Address::find_program_address(&[b"pool_vault", pool.as_ref(), mint1.as_ref()], &RAY).0;
    let observation = Address::find_program_address(&[b"observation", pool.as_ref()], &RAY).0;
    let discriminator = solana_sha256_hasher::hash(b"global:initialize").to_bytes();
    let ix = Instruction {
        program_id: RAY,
        accounts: vec![
            AccountMeta::new(creator.pubkey(), true),
            ro(config),
            ro(authority),
            rw(pool),
            ro(mint0),
            ro(mint1),
            rw(lp),
            rw(ata(creator.pubkey(), mint0)),
            rw(ata(creator.pubkey(), mint1)),
            rw(ata(creator.pubkey(), lp)),
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
        data: [
            discriminator[..8].to_vec(),
            amount0.to_le_bytes().to_vec(),
            amount1.to_le_bytes().to_vec(),
            0u64.to_le_bytes().to_vec(),
        ]
        .concat(),
    };
    send(h, &[ix], &[&creator]);
    let (input_vault, output_vault) = if mint0 == usdc {
        (vault0, vault1)
    } else {
        (vault1, vault0)
    };
    Pool {
        creator,
        usdc,
        source,
        destination,
        pool,
        authority,
        config,
        input_vault,
        output_vault,
        observation,
    }
}
#[test]
fn pinned_jupiter_v2_and_raydium_cp_execute_real_single_hop_with_classic_spl() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let p = pool(&mut h);
    let now = h.svm.get_sysvar::<Clock>().unix_timestamp;
    h.warp(now + 2);
    let data = [
        vec![187, 100, 250, 204, 49, 196, 175, 20],
        100_000_000u64.to_le_bytes().to_vec(),
        50_000_000u64.to_le_bytes().to_vec(),
        100u16.to_le_bytes().to_vec(),
        vec![0; 4],
        1u32.to_le_bytes().to_vec(),
        vec![46],
        10000u16.to_le_bytes().to_vec(),
        vec![0, 1],
    ]
    .concat();
    let minimum = morse_token::swap::route(&data, 100_000_000, 2_000_000)
        .unwrap()
        .minimum_output;
    let ix = Instruction {
        program_id: JUP,
        accounts: vec![
            AccountMeta::new_readonly(p.creator.pubkey(), true),
            rw(p.source),
            rw(p.destination),
            ro(p.usdc),
            ro(h.mint),
            ro(TOKEN),
            ro(TOKEN),
            ro(JUP),
            ro(EVENT),
            ro(JUP),
            ro(RAY),
            ro(p.creator.pubkey()),
            ro(p.authority),
            ro(p.config),
            rw(p.pool),
            rw(p.source),
            rw(p.destination),
            rw(p.input_vault),
            rw(p.output_vault),
            ro(TOKEN),
            ro(TOKEN),
            ro(p.usdc),
            ro(h.mint),
            rw(p.observation),
        ],
        data,
    };
    let before = h.amount(p.source);
    let output = h.amount(p.destination);
    send(&mut h, &[ix], &[&p.creator]);
    assert_eq!(before - h.amount(p.source), 100_000_000);
    assert!(h.amount(p.destination) - output >= minimum);
    assert_eq!(
        h.svm.get_account(&h.mint).unwrap().data[36..44],
        SUPPLY.to_le_bytes()
    );
}
fn data_account(program: Address) -> Address {
    Address::find_program_address(&[program.as_ref()], &LOADER).0
}
fn burn_configuration(h: &H, p: &Pool) -> Instruction {
    let cfg = Address::find_program_address(&[b"swap"], &h.program).0;
    let pool = h.svm.get_account(&p.pool).unwrap().data;
    let vault0 = Address::new_from_array(pool[72..104].try_into().unwrap());
    let vault1 = Address::new_from_array(pool[104..136].try_into().unwrap());
    Instruction {
        program_id: h.program,
        accounts: vec![
            AccountMeta::new_readonly(h.payer.pubkey(), true),
            AccountMeta::new(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            rw(cfg),
            ro(p.usdc),
            ro(p.creator.pubkey()),
            ro(p.pool),
            ro(p.config),
            ro(vault0),
            ro(vault1),
            ro(p.observation),
            ro(JUP),
            ro(data_account(JUP)),
            ro(RAY),
            ro(data_account(RAY)),
            ro(Address::default()),
        ],
        data: vec![8],
    }
}
fn open_week(h: &H, p: &Pool, epoch: u64, budget: u64) -> Instruction {
    let cfg = Address::find_program_address(&[b"swap"], &h.program).0;
    let week = Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
    let mut data = vec![9];
    data.extend(epoch.to_le_bytes());
    data.extend(budget.to_le_bytes());
    for i in 0..24 {
        data.extend(1u32.to_le_bytes());
        data.extend((i as u64 * 999_999).to_le_bytes());
    }
    Instruction {
        program_id: h.program,
        accounts: vec![
            AccountMeta::new_readonly(p.creator.pubkey(), true),
            AccountMeta::new(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            ro(cfg),
            ro(p.usdc),
            rw(week),
            rw(ata(week, p.usdc)),
            rw(p.source),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
            ro(JUP),
            ro(data_account(JUP)),
            ro(RAY),
            ro(data_account(RAY)),
            ro(Address::find_program_address(&[b"oracle"], &h.program).0),
        ],
        data,
    }
}
#[test]
fn weekly_funding_waits_for_qualified_profile_and_receipt_replays_without_double_transfer() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let p = pool(&mut h);
    let ix = burn_configuration(&h, &p);
    send(&mut h, std::slice::from_ref(&ix), &[]);
    send(&mut h, &[ix], &[]);
    let now = h.svm.get_sysvar::<Clock>().unix_timestamp;
    let ready = now + 14 * 86400;
    let epoch = ready as u64 / 604800 + 1;
    let budget = 240_000_000;
    let before = h.amount(p.source);
    let early = open_week(&h, &p, now as u64 / 604800 + 1, budget);
    let mut signers = vec![&h.payer, &p.creator];
    h.svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[early],
        Some(&h.payer.pubkey()),
        &signers,
        h.svm.latest_blockhash(),
    );
    assert!(h.svm.send_transaction(tx).is_err());
    assert_eq!(h.amount(p.source), before);
    signers.clear();
    seed_oracle(&mut h, ready);
    let fund = open_week(&h, &p, epoch, budget);
    send(&mut h, std::slice::from_ref(&fund), &[&p.creator]);
    assert_eq!(before - h.amount(p.source), budget);
    let week = Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
    assert_eq!(h.amount(ata(week, p.usdc)), budget);
    let state = h.svm.get_account(&week).unwrap();
    assert_eq!(state.data.len(), morse_token::burn::WEEK_LEN);
    send(&mut h, std::slice::from_ref(&fund), &[&p.creator]);
    assert_eq!(h.amount(p.source), before - budget);
    h.warp((epoch as i64 + 2) * 604800);
    send(&mut h, &[fund], &[&p.creator]);
    assert_eq!(h.amount(p.source), before - budget);
    assert_eq!(h.svm.get_account(&week).unwrap(), state);
}

fn seed_oracle(h: &mut H, until: i64) {
    let start = (until / 3600 - 168) * 3600;
    h.warp(start);
    let mut clock = h.svm.get_sysvar::<Clock>();
    clock.slot = 100;
    h.svm.set_sysvar(&clock);
    h.svm
        .set_account(PYTH, h.svm.get_account(&TOKEN).unwrap())
        .unwrap();
    let source = Address::new_unique();
    h.svm
        .set_account(source, source_update(start, 2_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(h, 3, source)));
    let observe = oracle_instruction(h, 4, source);
    let mut time = start + 60;
    while time <= until {
        h.warp(time);
        h.svm
            .set_account(source, source_update(time, 2_000_000))
            .unwrap();
        assert!(h.send(observe.clone()));
        time += 60;
    }
    h.warp(until);
}
fn execute_chunk(h: &H, p: &Pool, epoch: u64, index: u8, quoted: u64) -> Instruction {
    let swap = Address::find_program_address(&[b"swap"], &h.program).0;
    let week = Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
    let chunk =
        Address::find_program_address(&[b"burn-chunk", week.as_ref(), &[index]], &h.program).0;
    let mut data = vec![10, index];
    data.extend([187, 100, 250, 204, 49, 196, 175, 20]);
    data.extend(10_000_000u64.to_le_bytes());
    data.extend(quoted.to_le_bytes());
    data.extend(100u16.to_le_bytes());
    data.extend([0; 4]);
    data.extend(1u32.to_le_bytes());
    data.push(46);
    data.extend(10000u16.to_le_bytes());
    data.extend([0, 1]);
    Instruction {
        program_id: h.program,
        accounts: vec![
            AccountMeta::new(h.payer.pubkey(), true),
            ro(h.config),
            rw(h.mint),
            ro(swap),
            ro(p.usdc),
            rw(week),
            rw(ata(week, p.usdc)),
            ro(chunk),
            rw(ata(chunk, p.usdc)),
            rw(ata(chunk, h.mint)),
            ro(Address::find_program_address(&[b"oracle"], &h.program).0),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
            ro(JUP),
            ro(data_account(JUP)),
            ro(RAY),
            ro(data_account(RAY)),
            rw(p.pool),
            ro(p.config),
            rw(p.input_vault),
            rw(p.output_vault),
            rw(p.observation),
            ro(p.authority),
            ro(EVENT),
        ],
        data,
    }
}
fn advance_oracle(h: &mut H, until: i64) {
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let d = h.svm.get_account(&oracle).unwrap().data;
    let source = Address::new_from_array(d[100..132].try_into().unwrap());
    let mut time = i64::from_le_bytes(d[164..172].try_into().unwrap()) + 60;
    let observe = oracle_instruction(h, 4, source);
    while time <= until {
        h.warp(time);
        h.svm
            .set_account(source, source_update(time, 2_000_000))
            .unwrap();
        assert!(h.send(observe.clone()));
        time += 60;
    }
    h.warp(until);
}
#[test]
fn four_local_weeks_execute_all_96_chunks_with_actual_router_dex_and_program_owned_burns() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let p = pool(&mut h);
    let configure = burn_configuration(&h, &p);
    send(&mut h, &[configure], &[]);
    let ready = h.svm.get_sysvar::<Clock>().unix_timestamp + 14 * 86400;
    seed_oracle(&mut h, ready);
    let first = ready as u64 / 604800 + 1;
    let mut burned = 0u64;
    let mut weeks = Vec::new();
    let mut transactions = Vec::new();
    let mut instructions = Vec::new();
    for epoch in first..first + 4 {
        let open = open_week(&h, &p, epoch, 240_000_000);
        send(&mut h, &[open], &[&p.creator]);
        let week =
            Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
        let initial_data = h.svm.get_account(&week).unwrap().data;
        for index in 0..24u8 {
            let data = h.svm.get_account(&week).unwrap().data;
            let at = morse_token::burn::WEEK_HEADER + index as usize * morse_token::burn::CHUNK_LEN;
            let due = u64::from_le_bytes(data[at + 24..at + 32].try_into().unwrap()) as i64;
            advance_oracle(&mut h, due);
            let execute = execute_chunk(&h, &p, epoch, index, 5_000_000);
            let before = u64::from_le_bytes(
                h.svm.get_account(&h.mint).unwrap().data[36..44]
                    .try_into()
                    .unwrap(),
            );
            let (signature, wire) = send_packet(&mut h, std::slice::from_ref(&execute), &[]);
            instructions.push(instruction_report(&execute));
            let after = u64::from_le_bytes(
                h.svm.get_account(&h.mint).unwrap().data[36..44]
                    .try_into()
                    .unwrap(),
            );
            assert!(before - after >= 4_950_000);
            burned += before - after;
            transactions.push(serde_json::json!({"epoch":epoch.to_string(),"index":index,"signature":signature,"wire_base64":wire,"input":10_000_000u64.to_string(),"burned":(before-after).to_string(),"due":due.to_string()}));
            send(&mut h, &[execute], &[]);
            assert_eq!(
                u64::from_le_bytes(
                    h.svm.get_account(&h.mint).unwrap().data[36..44]
                        .try_into()
                        .unwrap()
                ),
                after
            );
            let chunk = Address::find_program_address(
                &[b"burn-chunk", week.as_ref(), &[index]],
                &h.program,
            )
            .0;
            assert_eq!(h.amount(ata(chunk, p.usdc)), 0);
            assert_eq!(h.amount(ata(chunk, h.mint)), 0);
        }
        let d = h.svm.get_account(&week).unwrap().data;
        assert_eq!(
            u64::from_le_bytes(d[224..232].try_into().unwrap()),
            (1 << 24) - 1
        );
        assert_eq!(
            u64::from_le_bytes(d[232..240].try_into().unwrap()),
            240_000_000
        );
        assert_eq!(h.amount(ata(week, p.usdc)), 0);
        weeks.push(serde_json::json!({"epoch":epoch.to_string(),"address":week.to_string(),"vault":ata(week,p.usdc).to_string(),"data_hex":hex::encode(d),"initial_data_hex":hex::encode(initial_data)}));
    }
    if let Some(path) = std::env::var_os("MORSE_TOKEN_BURN_FIXTURES_PATH") {
        let swap = Address::find_program_address(&[b"swap"], &h.program).0;
        let value = serde_json::json!({"schema_version":1,"network":"local-sbf-qualification","program":h.program.to_string(),"payer":h.payer.pubkey().to_string(),"treasury":p.creator.pubkey().to_string(),"morse_mint":h.mint.to_string(),"usdc_mint":p.usdc.to_string(),"profile_address":swap.to_string(),"profile_hex":hex::encode(h.svm.get_account(&swap).unwrap().data),"pool_address":p.pool.to_string(),"pool_hex":hex::encode(h.svm.get_account(&p.pool).unwrap().data),"factory_hex":hex::encode(h.svm.get_account(&p.config).unwrap().data),"accounts":public_accounts(&h,&p,swap,first),"context_slot":h.svm.get_sysvar::<Clock>().slot.to_string(),"config_hex":hex::encode(h.svm.get_account(&h.config).unwrap().data),"now":h.svm.get_sysvar::<Clock>().unix_timestamp.to_string(),"oracle_hex":hex::encode(h.svm.get_account(&Address::find_program_address(&[b"oracle"],&h.program).0).unwrap().data),"weeks":weeks,"transactions":transactions,"total_burned":burned.to_string(),"supply_after":(SUPPLY-burned).to_string(),"instructions":{"configure":instruction_report(&burn_configuration(&h,&p)),"fund":instruction_report(&open_week(&h,&p,first,240_000_000)),"execute":instructions},"boundary":"Actual isolated bank execution and offline valid signatures; no live chain burn or deployment."});
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    assert_eq!(
        u64::from_le_bytes(
            h.svm.get_account(&h.mint).unwrap().data[36..44]
                .try_into()
                .unwrap()
        ),
        SUPPLY - burned
    );
    assert_eq!(h.amount(p.source), 40_000_000);
    // Exported legacy fixtures remain active; independently close all four fully spent weeks.
    h.warp((first + 4) as i64 * 604800);
    for epoch in first..first + 4 {
        let closing = carry_tests::close(&h, &p, epoch);
        send(&mut h, std::slice::from_ref(&closing), &[]);
        send(&mut h, &[closing], &[]);
        let receipt =
            Address::find_program_address(&[b"burn-carry-epoch", &epoch.to_le_bytes()], &h.program)
                .0;
        let data = h.svm.get_account(&receipt).unwrap().data;
        assert_eq!(u64::from_le_bytes(data[132..140].try_into().unwrap()), 0);
    }
    let carry = Address::find_program_address(&[b"burn-carry"], &h.program).0;
    assert_eq!(h.amount(ata(carry, p.usdc)), 0);
    let data = h.svm.get_account(&carry).unwrap().data;
    assert_eq!(u64::from_le_bytes(data[100..108].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(data[140..148].try_into().unwrap()), 4);
    eprintln!("MORSE_BURN_ZERO_REMAINING permanent_four_zero_receipts_no_redistribution");
}
fn failed(h: &mut H, ix: Instruction) -> Vec<String> {
    h.svm.expire_blockhash();
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[budget, ix],
        Some(&h.payer.pubkey()),
        &[&h.payer],
        h.svm.latest_blockhash(),
    );
    h.svm
        .send_transaction(tx)
        .expect_err("adversarial packet unexpectedly succeeded")
        .meta
        .logs
}
#[test]
fn burn_guards_and_real_cpi_failure_preserve_escrow_while_spot_remains_distinct_from_twap() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let p = pool(&mut h);
    let configure = burn_configuration(&h, &p);
    send(&mut h, &[configure], &[]);
    let ready = h.svm.get_sysvar::<Clock>().unix_timestamp + 14 * 86400;
    seed_oracle(&mut h, ready);
    let epoch = ready as u64 / 604800 + 1;
    let fund = open_week(&h, &p, epoch, 240_000_000);
    send(&mut h, std::slice::from_ref(&fund), &[&p.creator]);
    let week = Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
    let original = h.svm.get_account(&week).unwrap();
    let early = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    let logs = failed(&mut h, early);
    assert!(logs.iter().any(|s| s.contains("invalid program argument")));
    assert_eq!(h.svm.get_account(&week).unwrap(), original);
    let due = u64::from_le_bytes(
        original.data[morse_token::burn::WEEK_HEADER + 24..morse_token::burn::WEEK_HEADER + 32]
            .try_into()
            .unwrap(),
    ) as i64;
    h.warp(due);
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let source = Address::new_from_array(
        h.svm.get_account(&oracle).unwrap().data[100..132]
            .try_into()
            .unwrap(),
    );
    h.svm
        .set_account(source, source_update(due, 2_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 4, source)));
    assert!(
        !h.send(oracle_instruction(&h, 5, source)),
        "a fresh spot after a gap must not fabricate seven-day coverage"
    );
    let chunk = Address::find_program_address(&[b"burn-chunk", week.as_ref(), &[0]], &h.program).0;
    let input = ata(chunk, p.usdc);
    let output = ata(chunk, h.mint);
    let transfer = |from, mint, to, amount| Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(from),
            ro(mint),
            rw(to),
            AccountMeta::new_readonly(p.creator.pubkey(), true),
        ],
        data: [vec![12], (amount as u64).to_le_bytes().to_vec(), vec![6]].concat(),
    };
    let donations = [
        create_ata(h.payer.pubkey(), chunk, p.usdc),
        create_ata(h.payer.pubkey(), chunk, h.mint),
        transfer(p.source, p.usdc, input, 17),
        transfer(p.destination, h.mint, output, 19),
    ];
    send(&mut h, &donations, &[&p.creator]);
    let before = h.svm.get_account(&week).unwrap();
    let supply = h.svm.get_account(&h.mint).unwrap().data;
    let mut wrong = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    wrong.accounts[8] = rw(p.source);
    failed(&mut h, wrong);
    assert_eq!(h.svm.get_account(&week).unwrap(), before);
    let pd = data_account(JUP);
    let data = h.svm.get_account(&pd).unwrap();
    let mut changed = data.clone();
    changed.data[4..12].copy_from_slice(&1u64.to_le_bytes());
    h.svm.set_account(pd, changed).unwrap();
    let ix = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    let logs = failed(&mut h, ix);
    assert!(!logs
        .iter()
        .any(|s| s.contains(&format!("Program {JUP} invoke"))));
    assert_eq!(h.svm.get_account(&week).unwrap(), before);
    h.svm.set_account(pd, data).unwrap();
    let ix = execute_chunk(&h, &p, epoch, 0, 50_000_000);
    let logs = failed(&mut h, ix);
    assert!(logs
        .iter()
        .any(|s| s.contains(&format!("Program {JUP} invoke"))));
    assert!(logs
        .iter()
        .any(|s| s.contains(&format!("Program {RAY} invoke"))));
    assert_eq!(h.svm.get_account(&week).unwrap(), before);
    assert_eq!(h.svm.get_account(&h.mint).unwrap().data, supply);
    assert_eq!(h.amount(input), 17);
    assert_eq!(h.amount(output), 19);
    let execute = execute_chunk(&h, &p, epoch, 0, 5_000_000);
    send(&mut h, std::slice::from_ref(&execute), &[]);
    assert_eq!(h.amount(input), 17);
    assert_eq!(h.amount(output), 19);
    assert_eq!(h.amount(ata(week, p.usdc)), 230_000_000);
    let paid = h.svm.get_account(&week).unwrap();
    let after = h.svm.get_account(&h.mint).unwrap().data;
    let conflict = execute_chunk(&h, &p, epoch, 0, 6_000_000);
    failed(&mut h, conflict);
    assert_eq!(h.svm.get_account(&week).unwrap(), paid);
    assert_eq!(h.svm.get_account(&h.mint).unwrap().data, after);
    let second_end = u64::from_le_bytes(
        paid.data[morse_token::burn::WEEK_HEADER + morse_token::burn::CHUNK_LEN + 16
            ..morse_token::burn::WEEK_HEADER + morse_token::burn::CHUNK_LEN + 24]
            .try_into()
            .unwrap(),
    ) as i64;
    h.warp(second_end);
    let late = execute_chunk(&h, &p, epoch, 1, 5_000_000);
    failed(&mut h, late);
    assert_eq!(h.svm.get_account(&week).unwrap(), paid);
    send(&mut h, &[execute], &[]);
    let source_before = h.amount(p.source);
    send(&mut h, &[fund], &[&p.creator]);
    assert_eq!(h.amount(p.source), source_before);
    assert_eq!(h.amount(ata(week, p.usdc)), 230_000_000);
}

fn instruction_report(ix: &Instruction) -> serde_json::Value {
    serde_json::json!({"schemaVersion":1,"programId":ix.program_id.to_string(),"accountCount":ix.accounts.len(),"accountKeys":ix.accounts.iter().map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"signerKeys":ix.accounts.iter().filter(|a|a.is_signer).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"writableKeys":ix.accounts.iter().filter(|a|a.is_writable).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"dataBase64":base64::engine::general_purpose::STANDARD.encode(&ix.data),"dataBytes":ix.data.len()})
}

fn public_accounts(h: &H, p: &Pool, swap: Address, first: u64) -> serde_json::Value {
    let pdj = data_account(JUP);
    let pdr = data_account(RAY);
    let pool = h.svm.get_account(&p.pool).unwrap().data;
    let v0 = Address::new_from_array(pool[72..104].try_into().unwrap());
    let v1 = Address::new_from_array(pool[104..136].try_into().unwrap());
    let mut result = serde_json::Map::new();
    for (name, key) in [
        ("config", h.config),
        ("morse", h.mint),
        ("profile", swap),
        ("program", h.program),
        ("program_data", data_account(h.program)),
        ("usdc", p.usdc),
        (
            "oracle",
            Address::find_program_address(&[b"oracle"], &h.program).0,
        ),
        (
            "clock",
            Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
        ),
        ("jupiter", JUP),
        ("jupiter_data", pdj),
        ("raydium", RAY),
        ("raydium_data", pdr),
        ("pool", p.pool),
        ("factory", p.config),
        ("vault0", v0),
        ("vault1", v1),
        ("observation", p.observation),
    ] {
        let a = h.svm.get_account(&key).unwrap();
        let data = &a.data[..a.data.len().min(5728)];
        result.insert(name.into(),serde_json::json!({"address":key.to_string(),"owner":a.owner.to_string(),"executable":a.executable,"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"data_hex":hex::encode(data)}));
    }
    for index in 0..4 {
        let epoch = first + index;
        let week =
            Address::find_program_address(&[b"burn-week", &epoch.to_le_bytes()], &h.program).0;
        for (name, key) in [
            (format!("week{index}"), week),
            (format!("week_vault{index}"), ata(week, p.usdc)),
        ] {
            let a = h.svm.get_account(&key).unwrap();
            result.insert(name,serde_json::json!({"address":key.to_string(),"owner":a.owner.to_string(),"executable":a.executable,"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"data_hex":hex::encode(a.data)}));
        }
    }
    serde_json::Value::Object(result)
}

#[path = "burn_carry.rs"]
mod carry_tests;
