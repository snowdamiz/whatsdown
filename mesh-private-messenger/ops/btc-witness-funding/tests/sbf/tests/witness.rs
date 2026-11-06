//! Owned classic SPL TransferChecked. No provider/mainnet finality or real USDC.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{path::PathBuf, str::FromStr};
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
fn rw(a: Address) -> AccountMeta {
    AccountMeta::new(a, false)
}
fn ro(a: Address) -> AccountMeta {
    AccountMeta::new_readonly(a, false)
}
fn ata(owner: Address, mint: Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
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
fn account(svm: &LiteSVM, key: Address) -> Value {
    let a = svm.get_account(&key).unwrap();
    json!({"owner":a.owner.to_string(),"lamports":a.lamports,"executable":a.executable,"rentEpoch":a.rent_epoch,"data":[B64.encode(a.data),"base64"]})
}
fn rows(svm: &LiteSVM, keys: &[Address], mint: Address) -> Vec<Value> {
    keys.iter().enumerate().filter_map(|(i,k)|{let a=svm.get_account(k)?;if a.owner!=TOKEN||a.data.len()!=165{return None;}let owner=Address::new_from_array(a.data[32..64].try_into().unwrap());Some(json!({"accountIndex":i,"mint":mint.to_string(),"owner":owner.to_string(),"programId":TOKEN.to_string(),"uiTokenAmount":{"amount":u64::from_le_bytes(a.data[64..72].try_into().unwrap()).to_string(),"decimals":6,"uiAmount":Value::Null,"uiAmountString":"0"}}))}).collect()
}
#[test]
fn actual_owned_btc_witness_funding() {
    let out = PathBuf::from(std::env::var("BTC_SBF_OUTPUT").expect("owned output directory"));
    std::fs::create_dir_all(&out).unwrap();
    let elf = PathBuf::from(std::env::var("BTC_SBF_TOKEN_ELF").expect("pinned token ELF"));
    let bytes = std::fs::read(&elf).unwrap();
    assert_eq!(
        hex::encode(solana_sha256_hasher::hash(&bytes).to_bytes()),
        "7b44674b9704fa7640fbebfac68389f338b500b8c2bc29175c27ed66838b5a3c"
    );
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(TOKEN, &elf).unwrap();
    let payer = Keypair::new();
    let mint_key = Keypair::new();
    let owner_key = Keypair::new();
    assert!(
        std::env::var_os("BTC_SBF_SCOPE").is_none(),
        "fresh bank only; historical owner key unavailable"
    );
    let scope = std::env::var("BTC_SBF_SCOPE").ok().map(|p| {
        let bytes = std::fs::read(&p).unwrap();
        let expected = std::env::var("BTC_SBF_SCOPE_SHA256").unwrap();
        assert_eq!(
            hex::encode(solana_sha256_hasher::hash(&bytes).to_bytes()),
            expected
        );
        serde_json::from_slice::<Value>(&bytes).unwrap()
    });
    let mint = scope
        .as_ref()
        .map(|s| Address::from_str(s["usdc"].as_str().unwrap()).unwrap())
        .unwrap_or(mint_key.pubkey());
    let owner = scope
        .as_ref()
        .map(|s| Address::from_str(s["owner"].as_str().unwrap()).unwrap())
        .unwrap_or(owner_key.pubkey());
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    svm.airdrop(&owner, 10_000_000).unwrap();
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = 1000;
    clock.unix_timestamp = std::env::var("BTC_SBF_NOW").unwrap().parse().unwrap();
    svm.set_sysvar(&clock);
    let source = ata(payer.pubkey(), mint);
    let destination = ata(owner, mint);
    if let Some(pins) = &scope {
        let row = pins["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["address"] == mint.to_string())
            .expect("exact exported mint prestate");
        let a = &row["account"];
        assert_eq!(a["owner"], TOKEN.to_string());
        let data = B64.decode(a["data"][0].as_str().unwrap()).unwrap();
        assert_eq!(data.len(), 82);
        assert_eq!(data[44], 6);
        assert_eq!(data[45], 1);
        svm.set_account(
            mint,
            Account {
                lamports: a["lamports"].as_u64().unwrap(),
                data,
                owner: TOKEN,
                executable: false,
                rent_epoch: a["rentEpoch"].as_u64().unwrap(),
            },
        )
        .unwrap();
        let init = Transaction::new_signed_with_payer(
            &[
                create_ata(payer.pubkey(), payer.pubkey(), mint),
                create_ata(payer.pubkey(), owner, mint),
            ],
            Some(&payer.pubkey()),
            &[&payer],
            svm.latest_blockhash(),
        );
        svm.send_transaction(init).unwrap();
        // Explicit owned genesis liquidity, before any exported account snapshot.
        // The following real signed transfer, not this fixture seed, creates arrival.
        let mut seeded = svm.get_account(&source).unwrap();
        seeded.data[64..72].copy_from_slice(&100_000_000u64.to_le_bytes());
        svm.set_account(source, seeded).unwrap();
    } else {
        let init = [
            Instruction {
                program_id: Address::default(),
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(mint, true),
                ],
                data: [
                    0u32.to_le_bytes().to_vec(),
                    svm.minimum_balance_for_rent_exemption(82)
                        .to_le_bytes()
                        .to_vec(),
                    82u64.to_le_bytes().to_vec(),
                    TOKEN.as_ref().to_vec(),
                ]
                .concat(),
            },
            Instruction {
                program_id: TOKEN,
                accounts: vec![rw(mint)],
                data: [vec![20, 6], payer.pubkey().as_ref().to_vec(), vec![0]].concat(),
            },
            create_ata(payer.pubkey(), payer.pubkey(), mint),
            create_ata(payer.pubkey(), owner, mint),
            Instruction {
                program_id: TOKEN,
                accounts: vec![
                    rw(mint),
                    rw(source),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                data: [vec![14], 100_000_000u64.to_le_bytes().to_vec(), vec![6]].concat(),
            },
        ];
        let setup = Transaction::new_signed_with_payer(
            &init,
            Some(&payer.pubkey()),
            &[&payer, &mint_key],
            svm.latest_blockhash(),
        );
        svm.send_transaction(setup).unwrap();
    }
    let ctx = rewards_funding::setup(&mut svm, &payer, mint, clock.unix_timestamp);
    let providers: Vec<String> =
        serde_json::from_str(&std::env::var("BTC_FUNDING_PROVIDERS").unwrap()).unwrap();
    assert_eq!(providers.len(), 2);
    let mut provider_bytes = b"morse-credit-treasury-providers-v1".to_vec();
    for url in &providers {
        assert!(url.starts_with("http://127.0.0.1:"));
        provider_bytes.extend_from_slice(&(url.len() as u16).to_le_bytes());
        provider_bytes.extend_from_slice(url.as_bytes());
    }
    let providers_hash = solana_sha256_hasher::hash(&provider_bytes).to_bytes();
    let cluster = solana_sha256_hasher::hash(b"owned-btc-witness-bank-cluster-v1").to_bytes();
    let nonce_authority =
        solana_sha256_hasher::hash(b"owned-btc-witness-unused-nonce-authority").to_bytes();
    let nonce_address = solana_sha256_hasher::hash(b"owned-btc-witness-unused-nonce").to_bytes();
    let mut chain = b"morse-credit-treasury-config-v1".to_vec();
    for value in [
        &providers_hash,
        &cluster,
        mint.as_ref(),
        owner.as_ref(),
        payer.pubkey().as_ref(),
        &nonce_authority,
        &nonce_address,
        ctx.program.as_ref(),
        ctx.pool.as_ref(),
    ] {
        chain.extend_from_slice(value);
    }
    let treasury_config = solana_sha256_hasher::hash(&chain).to_bytes();
    let initial = json!({"owner":owner.to_string(),"payer":payer.pubkey().to_string(),"usdc":mint.to_string(),"custody":destination.to_string(),"cluster":hex::encode(cluster),"providers":providers,"providers_hash":hex::encode(providers_hash),"nonce_authority":hex::encode(nonce_authority),"nonce_address":hex::encode(nonce_address),"rewards_program":hex::encode(ctx.program.as_ref()),"rewards_pool":hex::encode(ctx.pool.as_ref()),"treasury_config":hex::encode(treasury_config),"observation_time":clock.unix_timestamp,"judge":hex::encode(ctx.judge.as_ref()),"log_name":"sol-conversion","boundary":"Fresh owned key-retaining SPL/rewards bank; judge headers are fixture state; no production finality or provider independence."});
    write(&out.join("initial.json"), &initial);
    let transfer = wait(&out.join("btc-transfer-proceed.json"));
    assert_eq!(transfer["amount"], "49699202");
    clock.unix_timestamp = transfer["now"].as_i64().unwrap();
    svm.set_sysvar(&clock);
    svm.expire_blockhash();
    let amount = std::env::var("BTC_SBF_TRANSFER_MICROS")
        .unwrap_or_else(|_| "49699202".to_owned())
        .parse::<u64>()
        .unwrap();
    assert!(amount > 0 && amount <= 100_000_000);
    let ix = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(source),
            ro(mint),
            rw(destination),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data: [vec![12], amount.to_le_bytes().to_vec(), vec![6]].concat(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let keys = tx.message.account_keys.clone();
    let before = keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect::<Vec<_>>();
    let pre = rows(&svm, &keys, mint);
    let wire = wincode::serialize(&tx).unwrap();
    let signature = tx.signatures[0].to_string();
    let result = svm.send_transaction(tx).unwrap();
    let current = keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect::<Vec<_>>();
    let post = rows(&svm, &keys, mint);
    let response = json!({"slot":clock.slot,"blockTime":clock.unix_timestamp,"version":"legacy","transaction":[B64.encode(&wire),"base64"],"meta":{"err":Value::Null,"fee":before[0]-current[0],"preBalances":before,"postBalances":current,"preTokenBalances":pre,"postTokenBalances":post,"loadedAddresses":{"writable":[],"readonly":[]},"innerInstructions":[]}});
    let proof = json!({"boundary":"Separate owned classic SPL3.5.0 TransferChecked bank; exact pinned mint prestate and explicit provider genesis liquidity; controlled clock/RPC finality fixtures, no mainnet continuity or live USDC/provider evidence.","scope_sha256":std::env::var("BTC_SBF_SCOPE_SHA256").ok(),"treasury_config":scope.as_ref().map(|s|s["treasury_config"].clone()),"source_prestate_amount":"100000000","owner":owner.to_string(),"mint":mint.to_string(),"custody":destination.to_string(),"amount":amount.to_string(),"signature":signature,"wire_sha256":hex::encode(solana_sha256_hasher::hash(&wire).to_bytes()),"token_elf_sha256":hex::encode(solana_sha256_hasher::hash(&bytes).to_bytes()),"logs":result.logs,"transaction":response,"accounts":[{"address":destination.to_string(),"account":account(&svm,destination)},{"address":mint.to_string(),"account":account(&svm,mint)}],"custody_account":account(&svm,destination),"mint_account":account(&svm,mint)});
    std::fs::write(
        out.join("btc-transfer.json"),
        serde_json::to_vec_pretty(&proof).unwrap(),
    )
    .unwrap();
    assert_eq!(
        u64::from_le_bytes(
            svm.get_account(&destination).unwrap().data[64..72]
                .try_into()
                .unwrap()
        ),
        amount
    );
    let mut attempts = Vec::new();
    for serial in 0..256 {
        let command = wait(&out.join(format!("command-{serial}.json")));
        let kind = command["kind"].as_str().unwrap();
        let result = match kind {
            "inspect" => {
                let keys = command["keys"].as_array().unwrap();
                assert!(keys.len() <= 3);
                json!({"slot":svm.get_sysvar::<Clock>().slot,"accounts":keys.iter().map(|key|{let a=Address::from_str(key.as_str().unwrap()).unwrap();json!({"address":a.to_string(),"account":if svm.get_account(&a).is_some(){account(&svm,a)}else{Value::Null}})}).collect::<Vec<_>>()})
            }
            "warp" => {
                let epoch = command["epoch"].as_u64().unwrap();
                let mut c = svm.get_sysvar::<Clock>();
                assert!(epoch > (c.unix_timestamp as u64 / 604800));
                c.unix_timestamp = (epoch * 604800 + 100) as i64;
                c.slot += 1;
                svm.set_sysvar(&c);
                svm.expire_blockhash();
                json!({"epoch":epoch,"slot":c.slot})
            }
            "open" => {
                let epoch = svm.get_sysvar::<Clock>().unix_timestamp as u64 / 604800;
                let ledger =
                    Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &ctx.program)
                        .0;
                send(
                    &mut svm,
                    &payer,
                    &[],
                    &[Instruction {
                        program_id: ctx.program,
                        accounts: vec![
                            AccountMeta::new(payer.pubkey(), true),
                            ro(ctx.pool),
                            rw(ledger),
                            ro(Address::default()),
                        ],
                        data: [vec![1], epoch.to_le_bytes().to_vec()].concat(),
                    }],
                );
                json!({"epoch":epoch})
            }
            "fund" => {
                let raw = &command["instruction"];
                let data = B64.decode(raw["dataBase64"].as_str().unwrap()).unwrap();
                assert_eq!(data.len(), 42);
                assert_eq!(data[0], 12);
                assert_eq!(data[1], 0);
                assert_eq!(
                    u64::from_le_bytes(data[2..10].try_into().unwrap()),
                    49699202
                );
                let epoch = command["epoch"].as_u64().unwrap();
                let id = &data[10..42];
                let receipt =
                    Address::find_program_address(&[b"funding", owner.as_ref(), id], &ctx.program)
                        .0;
                let ledger =
                    Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &ctx.program)
                        .0;
                let expected = Instruction {
                    program_id: ctx.program,
                    accounts: vec![
                        AccountMeta::new_readonly(owner, true),
                        AccountMeta::new(payer.pubkey(), true),
                        rw(ctx.pool),
                        rw(ledger),
                        rw(ctx.vault),
                        rw(destination),
                        ro(mint),
                        ro(TOKEN),
                        rw(receipt),
                        ro(Address::default()),
                    ],
                    data,
                };
                assert_eq!(raw["programId"], ctx.program.to_string());
                let keys = raw["accountKeys"].as_array().unwrap();
                assert_eq!(keys.len(), expected.accounts.len());
                let signer_keys: Vec<String> = expected
                    .accounts
                    .iter()
                    .filter(|m| m.is_signer)
                    .map(|m| m.pubkey.to_string())
                    .collect();
                let writable_keys: Vec<String> = expected
                    .accounts
                    .iter()
                    .filter(|m| m.is_writable)
                    .map(|m| m.pubkey.to_string())
                    .collect();
                assert_eq!(raw["signerKeys"], json!(signer_keys));
                assert_eq!(raw["writableKeys"], json!(writable_keys));
                for (a, b) in keys.iter().zip(&expected.accounts) {
                    assert_eq!(a.as_str().unwrap(), b.pubkey.to_string());
                }
                let before = account(&svm, destination);
                let vault_before = account(&svm, ctx.vault);
                svm.expire_blockhash();
                let tx = Transaction::new_signed_with_payer(
                    &[expected],
                    Some(&payer.pubkey()),
                    &[&payer, &owner_key],
                    svm.latest_blockhash(),
                );
                let wire = wincode::serialize(&tx).unwrap();
                assert!(wire.len() <= 1232);
                let outcome = svm.send_transaction(tx);
                let ok = outcome.is_ok();
                assert_eq!(ok, command["expect_ok"].as_bool().unwrap());
                if !ok {
                    assert_eq!(before, account(&svm, destination));
                    assert_eq!(vault_before, account(&svm, ctx.vault));
                    assert!(svm.get_account(&receipt).is_none());
                }
                let r = json!({"ok":ok,"epoch":epoch,"wire_bytes":wire.len(),"wire_sha256":hex::encode(solana_sha256_hasher::hash(&wire).to_bytes()),"source_before":before,"source_after":account(&svm,destination),"vault_before":vault_before,"vault_after":account(&svm,ctx.vault),"receipt":if svm.get_account(&receipt).is_some(){account(&svm,receipt)}else{Value::Null},"outcome":format!("{outcome:?}")});
                attempts.push(r.clone());
                r
            }
            "stop" => {
                write(&out.join("attempts.json"), &json!(attempts));
                write(
                    &out.join(format!("reply-{serial}.json")),
                    &json!({"stopped":true}),
                );
                break;
            }
            _ => panic!("unrecognized owned command"),
        };
        write(&out.join(format!("reply-{serial}.json")), &result);
    }
}

#[path = "support/rewards_funding.rs"]
mod rewards_funding;
fn metadata(program: Address) -> Address {
    Address::find_program_address(
        &[program.as_ref()],
        &Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111"),
    )
    .0
}
fn send(svm: &mut LiteSVM, payer: &Keypair, extra: &[&Keypair], ixs: &[Instruction]) {
    svm.expire_blockhash();
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).unwrap();
}
fn write(path: &std::path::Path, value: &Value) {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    std::fs::rename(temp, path).unwrap();
}
fn wait(path: &std::path::Path) -> Value {
    let start = std::time::Instant::now();
    while !path.is_file() {
        assert!(
            start.elapsed().as_secs() < 1200,
            "owned bounded handoff timeout: {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
