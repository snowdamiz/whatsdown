//! Owned SOL/WSOL->USDC bank using the previously pinned actual Raydium/SPL ELFs.
//! No public provider, custody key, transaction or token-program modification.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

#[path = "support/common_bank.rs"]
mod common_bank;
#[path = "support/failed_retry.rs"]
mod failed_retry;
#[path = "support/rewards_funding.rs"]
mod rewards_funding;

const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const RAY: Address = Address::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
const NATIVE: Address = Address::from_str_const("So11111111111111111111111111111111111111112");
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
fn rw(a: Address) -> AccountMeta {
    AccountMeta::new(a, false)
}
fn ro(a: Address) -> AccountMeta {
    AccountMeta::new_readonly(a, false)
}
fn ata(owner: Address, mint: Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(solana_sha256_hasher::hash(bytes).to_bytes())
}
fn metadata(program: Address) -> Address {
    Address::find_program_address(&[program.as_ref()], &LOADER).0
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
fn transfer(from: Address, to: Address, amount: u64) -> Instruction {
    Instruction {
        program_id: Address::default(),
        accounts: vec![AccountMeta::new(from, true), rw(to)],
        data: [2u32.to_le_bytes().to_vec(), amount.to_le_bytes().to_vec()].concat(),
    }
}
fn send(svm: &mut LiteSVM, payer: &Keypair, extra: &[&Keypair], instructions: &[Instruction]) {
    svm.expire_blockhash();
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    if let Err(e) = svm.send_transaction(tx) {
        panic!("{:?}\n{}", e.err, e.meta.logs.join("\n"));
    }
}
fn snapshot(svm: &mut LiteSVM, product: &Path, name: &str) -> Address {
    let value: Value = serde_json::from_slice(
        &std::fs::read(
            product
                .join("ops/token/fixtures/dex")
                .join(format!("{name}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let a = &value["value"];
    let key = Address::from_str(value["address"].as_str().unwrap()).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: a["lamports"].as_u64().unwrap(),
            data: B64.decode(a["data"][0].as_str().unwrap()).unwrap(),
            owner: Address::from_str(a["owner"].as_str().unwrap()).unwrap(),
            executable: a["executable"].as_bool().unwrap(),
            rent_epoch: a["rentEpoch"].as_u64().unwrap(),
        },
    )
    .unwrap();
    key
}
fn amount(svm: &LiteSVM, key: Address) -> u64 {
    let a = svm.get_account(&key).unwrap();
    u64::from_le_bytes(a.data[64..72].try_into().unwrap())
}
fn account_json(svm: &LiteSVM, key: Address) -> Value {
    match svm.get_account(&key) {
        None => Value::Null,
        Some(a) => {
            json!({"owner":a.owner.to_string(),"lamports":a.lamports,"executable":a.executable,"rentEpoch":a.rent_epoch,"data":[B64.encode(a.data),"base64"]})
        }
    }
}
fn token_rows(svm: &LiteSVM, keys: &[Address], usdc: Address) -> Vec<Value> {
    keys.iter().enumerate().filter_map(|(index,key)| {
        let a=svm.get_account(key)?;
        if a.owner!=TOKEN || a.data.len()!=165 { return None; }
        let mint=Address::new_from_array(a.data[..32].try_into().unwrap());
        let owner=Address::new_from_array(a.data[32..64].try_into().unwrap());
        assert!(mint==usdc || mint==NATIVE);
        Some(json!({"accountIndex":index,"mint":mint.to_string(),"owner":owner.to_string(),"programId":TOKEN.to_string(),"uiTokenAmount":{"amount":u64::from_le_bytes(a.data[64..72].try_into().unwrap()).to_string(),"decimals":if mint==NATIVE {9}else{6},"uiAmount":Value::Null,"uiAmountString":"0"}}))
    }).collect()
}
fn write(path: &Path, value: &Value) {
    use std::io::Write;
    let temporary = path.with_extension("json.partial");
    let mut file = std::fs::File::create(&temporary).unwrap();
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    std::fs::rename(temporary, path).unwrap();
}
fn wait(path: &Path) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if path.with_file_name("abort").exists() {
            panic!("owned driver aborted");
        }
        if path.is_file() {
            return std::fs::read(path).unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(1200),
            "owned file handoff timed out"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Key ordering is not unique in a Solana legacy message. Compare complete
// privileges and every decompiled instruction before signing the exact request.
fn equivalent_message(request: &Message, expected: &Message) {
    assert_eq!(request.recent_blockhash, expected.recent_blockhash);
    assert_eq!(
        request.header.num_required_signatures,
        expected.header.num_required_signatures
    );
    let privileges = |m: &Message, index: usize| {
        let h = &m.header;
        let signed = index < usize::from(h.num_required_signatures);
        let writable = if signed {
            index < usize::from(h.num_required_signatures - h.num_readonly_signed_accounts)
        } else {
            index < m.account_keys.len() - usize::from(h.num_readonly_unsigned_accounts)
        };
        (signed, writable)
    };
    assert_eq!(request.account_keys.len(), expected.account_keys.len());
    for (index, key) in request.account_keys.iter().enumerate() {
        assert_eq!(request.account_keys.iter().filter(|v| *v == key).count(), 1);
        let other = expected
            .account_keys
            .iter()
            .position(|v| v == key)
            .expect("unexpected account");
        assert_eq!(privileges(request, index), privileges(expected, other));
    }
    assert_eq!(
        request.account_keys[0], expected.account_keys[0],
        "fee payer"
    );

    assert_eq!(request.instructions.len(), expected.instructions.len());
    for (a, b) in request.instructions.iter().zip(&expected.instructions) {
        assert_eq!(
            request.account_keys[usize::from(a.program_id_index)],
            expected.account_keys[usize::from(b.program_id_index)]
        );
        assert_eq!(a.data, b.data);
        let keys = |m: &Message, indices: &[u8]| {
            indices
                .iter()
                .map(|i| m.account_keys[usize::from(*i)])
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(request, &a.accounts), keys(expected, &b.accounts));
    }
}

#[test]
fn common_bank_real_outputs_and_exact_burn_funding() {
    let product = PathBuf::from(
        std::env::var_os("MORSE_SOL_CONVERSION_PRODUCT").expect("explicit owned product source"),
    );
    let dex = PathBuf::from(
        std::env::var_os("MORSE_TOKEN_DEX_BIN_DIR").expect("explicit pinned DEX directory"),
    );
    let output = std::env::var_os("MORSE_SOL_CONVERSION_EXPORT").map(PathBuf::from);
    let mut svm = LiteSVM::new();
    let pins: Value =
        serde_json::from_slice(&std::fs::read(product.join("ops/token/dex-source.json")).unwrap())
            .unwrap();
    let ray = pins["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "raydium")
        .unwrap();
    let elf = std::fs::read(dex.join("raydium.so")).unwrap();
    assert_eq!(hash(&elf), ray["elf_sha256"]);
    svm.add_program(RAY, &elf).unwrap();
    let classic = PathBuf::from(
        std::env::var_os("MORSE_SOL_CONVERSION_TOKEN_ELF")
            .expect("explicit pinned classic SPL ELF"),
    );
    svm.add_program_from_file(TOKEN, &classic).unwrap();
    let payer = Keypair::new();
    let owner = Keypair::new();
    let mint = Keypair::new();
    let usdc = mint.pubkey();
    svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
    svm.airdrop(&owner.pubkey(), 100_000_000_000_000).unwrap();
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = 1000;
    clock.unix_timestamp = std::env::var("MORSE_COMMON_BANK_NOW")
        .expect("explicit fresh observation time")
        .parse()
        .unwrap();
    svm.set_sysvar(&clock);
    let amm = snapshot(&mut svm, &product, "amm-config");
    let fee = snapshot(&mut svm, &product, "create-pool-fee");
    snapshot(&mut svm, &product, "native-mint");
    let native_ata = ata(owner.pubkey(), NATIVE);
    let usdc_ata = ata(owner.pubkey(), usdc);
    let liquidity_sol = 10_000_000_000_000u64;
    let liquidity_usdc = 1_500_000_000_000u64;
    let mint_rent = svm.minimum_balance_for_rent_exemption(82);
    let create_mint = Instruction {
        program_id: Address::default(),
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(usdc, true),
        ],
        data: [
            0u32.to_le_bytes().to_vec(),
            mint_rent.to_le_bytes().to_vec(),
            82u64.to_le_bytes().to_vec(),
            TOKEN.as_ref().to_vec(),
        ]
        .concat(),
    };
    let initialize_mint = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(usdc)],
        data: [vec![20, 6], owner.pubkey().as_ref().to_vec(), vec![0]].concat(),
    };
    let mint_usdc = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(usdc),
            rw(usdc_ata),
            AccountMeta::new_readonly(owner.pubkey(), true),
        ],
        data: [
            vec![14],
            (liquidity_usdc + 1000).to_le_bytes().to_vec(),
            vec![6],
        ]
        .concat(),
    };
    send(
        &mut svm,
        &payer,
        &[&owner, &mint],
        &[
            create_mint,
            initialize_mint,
            create_ata(payer.pubkey(), owner.pubkey(), usdc),
            create_ata(payer.pubkey(), owner.pubkey(), NATIVE),
            mint_usdc,
            transfer(owner.pubkey(), native_ata, liquidity_sol),
            Instruction {
                program_id: TOKEN,
                accounts: vec![rw(native_ata)],
                data: vec![17],
            },
        ],
    );
    let (m0, m1, a0, a1) = if NATIVE < usdc {
        (NATIVE, usdc, liquidity_sol, liquidity_usdc)
    } else {
        (usdc, NATIVE, liquidity_usdc, liquidity_sol)
    };
    let pool =
        Address::find_program_address(&[b"pool", amm.as_ref(), m0.as_ref(), m1.as_ref()], &RAY).0;
    let authority = Address::find_program_address(&[b"vault_and_lp_mint_auth_seed"], &RAY).0;
    let lp = Address::find_program_address(&[b"pool_lp_mint", pool.as_ref()], &RAY).0;
    let vault0 =
        Address::find_program_address(&[b"pool_vault", pool.as_ref(), m0.as_ref()], &RAY).0;
    let vault1 =
        Address::find_program_address(&[b"pool_vault", pool.as_ref(), m1.as_ref()], &RAY).0;
    let observation = Address::find_program_address(&[b"observation", pool.as_ref()], &RAY).0;
    let init = Instruction {
        program_id: RAY,
        accounts: vec![
            AccountMeta::new(owner.pubkey(), true),
            ro(amm),
            ro(authority),
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
        data: [
            solana_sha256_hasher::hash(b"global:initialize").to_bytes()[..8].to_vec(),
            a0.to_le_bytes().to_vec(),
            a1.to_le_bytes().to_vec(),
            0u64.to_le_bytes().to_vec(),
        ]
        .concat(),
    };
    send(&mut svm, &payer, &[&owner], &[init]);
    let common_context = common_bank::setup(
        &mut svm,
        &payer,
        &owner,
        usdc,
        amm,
        fee,
        clock.unix_timestamp,
        &dex,
    );
    clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp += 2;
    svm.set_sysvar(&clock);
    let minimum_failure = std::env::var_os("MORSE_SOL_CONVERSION_MINIMUM_FAILURE").is_some();
    let quote_micros = if minimum_failure {
        200_000_000u64
    } else {
        150_000_000u64
    };
    let oracle = Address::new_from_array(
        solana_sha256_hasher::hash(b"owned-sol-conversion-oracle").to_bytes(),
    );
    let mut price = vec![0u8; 134];
    price[..8].copy_from_slice(&hex::decode("22f123639d7ef4cd").unwrap());
    price[40] = 1;
    price[41..73].copy_from_slice(
        &hex::decode("ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d").unwrap(),
    );
    price[73..81].copy_from_slice(&((quote_micros as i64) * 100).to_le_bytes());
    price[81..89].copy_from_slice(&1_000_000u64.to_le_bytes());
    price[89..93].copy_from_slice(&(-8i32).to_le_bytes());
    price[93..101].copy_from_slice(&clock.unix_timestamp.to_le_bytes());
    price[101..109].copy_from_slice(&(clock.unix_timestamp - 1).to_le_bytes());
    price[125..133].copy_from_slice(&clock.slot.to_le_bytes());
    svm.set_account(
        oracle,
        Account {
            lamports: 2_000_000,
            data: price,
            owner: Address::from_str_const("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp"),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let (input_vault, output_vault) = if m0 == NATIVE {
        (vault0, vault1)
    } else {
        (vault1, vault0)
    };
    let bucket = std::env::var("MORSE_SOL_CONVERSION_BUCKET")
        .unwrap_or_else(|_| "0".into())
        .parse::<u8>()
        .unwrap();
    assert!(bucket <= 1);
    let funding_context = if std::env::var_os("MORSE_SOL_CONVERSION_FUNDING_HANDOFF").is_some() {
        Some(rewards_funding::setup(
            &mut svm,
            &payer,
            usdc,
            clock.unix_timestamp,
        ))
    } else {
        None
    };
    let rent = svm.minimum_balance_for_rent_exemption(165);
    let principal = if bucket == 0 {
        1_000_000_000u64
    } else {
        1_500_000_000u64
    };
    let minimum = ((u128::from(principal) * u128::from(quote_micros) * 9900)
        .div_ceil(10_000_000_000_000)) as u64;
    let providers = ["http://127.0.0.1:24494", "http://127.0.0.1:24495"];
    let mut provider_bytes = b"morse-credit-treasury-providers-v1".to_vec();
    for url in providers {
        provider_bytes.extend((url.len() as u16).to_le_bytes());
        provider_bytes.extend(url.as_bytes());
    }
    let provider_hash = solana_sha256_hasher::hash(&provider_bytes).to_bytes();
    let cluster = solana_sha256_hasher::hashv(&[
        b"owned-common-bank-genesis-v1",
        owner.pubkey().as_ref(),
        payer.pubkey().as_ref(),
        usdc.as_ref(),
    ])
    .to_bytes();
    let nonce_authority = solana_sha256_hasher::hash(b"owned-unused-nonce-authority").to_bytes();
    let nonce_address = solana_sha256_hasher::hash(b"owned-unused-nonce-address").to_bytes();
    let rewards_program = solana_sha256_hasher::hash(b"owned-output-bridge-program").to_bytes();
    let rewards_pool =
        Address::find_program_address(&[b"pool"], &Address::new_from_array(rewards_program))
            .0
            .to_bytes();
    let mut chain_bytes = b"morse-credit-treasury-config-v1".to_vec();
    for key in [
        provider_hash,
        cluster,
        usdc.to_bytes(),
        owner.pubkey().to_bytes(),
        payer.pubkey().to_bytes(),
        nonce_authority,
        nonce_address,
        rewards_program,
        rewards_pool,
    ] {
        chain_bytes.extend(key);
    }
    let scope = solana_sha256_hasher::hash(&chain_bytes).to_bytes();
    let members = solana_sha256_hasher::hash(b"owned-sol-conversion-members").to_bytes();
    let policy=solana_sha256_hasher::hash(b"morse-credit-revenue-split-v2:gross=2/10,3/10,5/10;carry=per-share-numerator;reserve=sum-carry/10").to_bytes();
    let ray_code =
        solana_sha256_hasher::hash(&svm.get_account(&metadata(RAY)).unwrap().data).to_bytes();
    let token_code =
        solana_sha256_hasher::hash(&svm.get_account(&metadata(TOKEN)).unwrap().data).to_bytes();
    let amm_hash = solana_sha256_hasher::hash(&svm.get_account(&amm).unwrap().data).to_bytes();
    let mut profile_bytes = b"morse-sol-conversion-profile-v1".to_vec();
    profile_bytes.extend(scope);
    for key in [
        owner.pubkey(),
        payer.pubkey(),
        usdc,
        pool,
        amm,
        authority,
        input_vault,
        output_vault,
        observation,
        oracle,
    ] {
        profile_bytes.extend(key.as_ref());
    }
    profile_bytes.extend(ray_code);
    profile_bytes.extend(token_code);
    profile_bytes.extend(amm_hash);
    profile_bytes.extend(rent.to_le_bytes());
    profile_bytes.extend(100000u64.to_le_bytes());
    let profile_hash = solana_sha256_hasher::hash(&profile_bytes).to_bytes();
    let id = solana_sha256_hasher::hashv(&[
        b"morse-credit-sol-conversion-v1",
        &profile_hash,
        &1u64.to_le_bytes(),
        &[2],
        &policy,
        &members,
        &[bucket],
        &principal.to_le_bytes(),
    ])
    .to_bytes();
    let seed = hex::encode(id)[..32].to_owned();
    let escrow = Address::new_from_array(
        solana_sha256_hasher::hashv(&[owner.pubkey().as_ref(), seed.as_bytes(), TOKEN.as_ref()])
            .to_bytes(),
    );
    let create = Instruction {
        program_id: Address::default(),
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            rw(escrow),
            AccountMeta::new_readonly(owner.pubkey(), true),
        ],
        data: [
            3u32.to_le_bytes().to_vec(),
            owner.pubkey().as_ref().to_vec(),
            32u64.to_le_bytes().to_vec(),
            seed.as_bytes().to_vec(),
            rent.to_le_bytes().to_vec(),
            165u64.to_le_bytes().to_vec(),
            TOKEN.as_ref().to_vec(),
        ]
        .concat(),
    };
    let initialize = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(escrow), ro(NATIVE)],
        data: [vec![18], owner.pubkey().as_ref().to_vec()].concat(),
    };
    let swap = Instruction {
        program_id: RAY,
        accounts: vec![
            AccountMeta::new_readonly(owner.pubkey(), true),
            ro(authority),
            ro(amm),
            rw(pool),
            rw(escrow),
            rw(usdc_ata),
            rw(input_vault),
            rw(output_vault),
            ro(TOKEN),
            ro(TOKEN),
            ro(NATIVE),
            ro(usdc),
            rw(observation),
        ],
        data: [
            solana_sha256_hasher::hash(b"global:swap_base_input").to_bytes()[..8].to_vec(),
            principal.to_le_bytes().to_vec(),
            minimum.to_le_bytes().to_vec(),
        ]
        .concat(),
    };
    let close = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(escrow),
            rw(payer.pubkey()),
            AccountMeta::new_readonly(owner.pubkey(), true),
        ],
        data: vec![9],
    };
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 600000u32.to_le_bytes().to_vec()].concat(),
    };
    let instructions = vec![
        budget,
        create,
        initialize,
        transfer(owner.pubkey(), escrow, principal),
        Instruction {
            program_id: TOKEN,
            accounts: vec![rw(escrow)],
            data: vec![17],
        },
        swap,
        close,
    ];
    svm.expire_blockhash();
    let mut message = Message::new_with_blockhash(
        &instructions,
        Some(&payer.pubkey()),
        &svm.latest_blockhash(),
    );
    let mut tx = Transaction::new(&[&payer, &owner], message.clone(), svm.latest_blockhash());
    let mut wire = wincode::serialize(&tx).unwrap();
    assert!(wire.len() <= 1232, "packet {}", wire.len());
    let mut keys = message.account_keys.clone();
    keys.extend([
        metadata(RAY),
        metadata(TOKEN),
        amm,
        pool,
        observation,
        native_ata,
        usdc_ata,
        oracle,
        Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
    ]);
    keys.sort();
    keys.dedup();
    if let Some(dir) = &output {
        std::fs::create_dir_all(dir).unwrap();
        let accounts: Vec<_> = keys
            .iter()
            .map(|k| json!({"address":k.to_string(),"account":account_json(&svm,*k)}))
            .collect();
        write(
            &dir.join("initial-unscoped.json"),
            &json!({"slot":clock.slot.to_string(),"now":clock.unix_timestamp.to_string(),"id":hex::encode(id),"treasury_config":hex::encode(scope),"providers":providers,"cluster":hex::encode(cluster),"providers_hash":hex::encode(provider_hash),"nonce_authority":hex::encode(nonce_authority),"nonce_address":hex::encode(nonce_address),"rewards_program":hex::encode(rewards_program),"rewards_pool":hex::encode(rewards_pool),"membership_hash":hex::encode(members),"policy_hash":hex::encode(policy),"profile_hash":hex::encode(profile_hash),"batch_id":"1","bucket":bucket,"principal":principal.to_string(),"minimum":minimum.to_string(),"rent":rent.to_string(),"blockhash":svm.latest_blockhash().to_string(),"owner":owner.pubkey().to_string(),"payer":payer.pubkey().to_string(),"usdc":usdc.to_string(),"amm_config":amm.to_string(),"pool":pool.to_string(),"authority":authority.to_string(),"input_vault":input_vault.to_string(),"output_vault":output_vault.to_string(),"observation":observation.to_string(),"oracle":oracle.to_string(),"amm_hash":hex::encode(amm_hash),"raydium_code":hex::encode(ray_code),"token_code":hex::encode(token_code),"accounts":accounts,"message":B64.encode(message.serialize()),"wire":B64.encode(&wire),"boundary":"Actual owned DEX/SPL bank; injected full-verification-bit Pyth account is not guardian-proof evidence. Clock/slot controlled, not production finality or liquidity."}),
        );
        common_bank::annotate_initial(&svm, dir, &common_context, &owner);
        if std::env::var_os("MORSE_SOL_CONVERSION_HANDOFF").is_some() {
            let requested = B64.decode(wait(&dir.join("message.base64"))).unwrap();
            let supplied: Message = wincode::deserialize(&requested).expect("legacy message");
            assert_eq!(
                supplied.serialize(),
                requested,
                "trailing/noncanonical message"
            );
            equivalent_message(&supplied, &message);
            message = supplied;
            tx = Transaction::new(&[&payer, &owner], message.clone(), svm.latest_blockhash());
            wire = wincode::serialize(&tx).unwrap();
            assert!(wire.len() <= 1232);
            std::fs::write(dir.join("signed.packet.base64"), B64.encode(&wire)).unwrap();
            assert_eq!(
                B64.decode(wait(&dir.join("send.packet.base64"))).unwrap(),
                wire,
                "submitted packet changed"
            );
        }
    }
    let pre_owner = svm.get_balance(&owner.pubkey()).unwrap();
    let pre_payer = svm.get_balance(&payer.pubkey()).unwrap();
    let pre_usdc = amount(&svm, usdc_ata);
    let pre_balances: Vec<_> = message
        .account_keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect();
    let pre_tokens = token_rows(&svm, &message.account_keys, usdc);
    let (result, execution_error) = match svm.send_transaction(tx.clone()) {
        Ok(meta) => {
            assert!(!minimum_failure);
            (meta, Value::Null)
        }
        Err(error) => {
            assert!(
                minimum_failure,
                "{:?}\n{}",
                error.err,
                error.meta.logs.join("\n")
            );
            (error.meta, serde_json::to_value(error.err).unwrap())
        }
    };
    let spent = if minimum_failure { 0 } else { principal };
    let received = amount(&svm, usdc_ata) - pre_usdc;
    if minimum_failure {
        assert_eq!(received, 0)
    } else {
        assert!(received >= minimum)
    };
    assert_eq!(pre_owner - svm.get_balance(&owner.pubkey()).unwrap(), spent);
    assert_eq!(
        pre_payer - svm.get_balance(&payer.pubkey()).unwrap(),
        result.fee
    );
    assert_eq!(svm.get_balance(&escrow).unwrap_or(0), 0);
    let paid_balance = svm.get_balance(&payer.pubkey());
    assert!(svm.send_transaction(tx.clone()).is_err());
    assert!(svm.send_transaction(tx.clone()).is_err());
    assert_eq!(svm.get_balance(&payer.pubkey()), paid_balance);
    assert_eq!(amount(&svm, usdc_ata) - pre_usdc, received);
    if let Some(dir) = &output {
        let post_balances: Vec<_> = message
            .account_keys
            .iter()
            .map(|k| svm.get_balance(k).unwrap_or(0))
            .collect();
        write(
            &dir.join("execution.json"),
            &json!({"signature":tx.signatures[0].to_string(),"execution_error":execution_error,"message":B64.encode(message.serialize()),"wire":B64.encode(&wire),"slot":clock.slot,"block_time":clock.unix_timestamp,"fee":result.fee,"received_usdc":received.to_string(),"spent_lamports":spent.to_string(),"pre_usdc":pre_usdc.to_string(),"pre_balances":pre_balances,"post_balances":post_balances,"pre_tokens":pre_tokens,"post_tokens":token_rows(&svm,&message.account_keys,usdc),"units":result.compute_units_consumed,"logs":result.logs,"duplicate_refusals":2,"accounts":keys.iter().map(|k|json!({"address":k.to_string(),"account":account_json(&svm,*k)})).collect::<Vec<_>>(),"source_key_index":message.account_keys.iter().position(|k|*k==usdc_ata).unwrap()}),
        );
    }
    if std::env::var_os("MORSE_COMMON_BANK_HANDOFF").is_some() {
        common_bank::run(
            &mut svm,
            output.as_ref().unwrap(),
            &payer,
            &owner,
            usdc,
            &common_context,
        );
    }
    if minimum_failure {
        assert!(funding_context.is_none());
        failed_retry::run(
            &mut svm,
            output.as_ref().expect("failure export"),
            &payer,
            &owner,
            usdc,
            oracle,
            &keys,
            &instructions,
            principal,
        );
    }
    if let Some(ctx) = &funding_context {
        rewards_funding::execute(
            &mut svm,
            output.as_ref().expect("funding export"),
            ctx,
            &payer,
            &owner,
            usdc,
            id,
            profile_hash,
            &tx,
            &wire,
            received,
            principal,
            result.fee,
        );
    }
}
