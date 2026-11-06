//! Local execution only. Fixture snapshots initialize one disposable bank;
//! every relay transition uses fully signed Kit transactions with SBF execution.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_address_lookup_table_interface::state::AddressLookupTable;
use solana_clock::Clock;
use solana_slot_hashes::SlotHashes;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
};

fn address(value: &Value) -> Address {
    Address::from_str(value.as_str().expect("address")).expect("canonical address")
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex bytes")
}
fn output(value: Value) {
    println!("{value}");
    io::stdout().flush().expect("flush");
}
fn context(svm: &LiteSVM, payer: Address) -> Value {
    json!({"blockhash":svm.latest_blockhash().to_string(),"lastValidBlockHeight":"1000000",
        "slot":svm.get_sysvar::<Clock>().slot.to_string(),"payerBalance":svm.get_balance(&payer).unwrap().to_string()})
}

fn main() {
    let mut lines = io::stdin().lock().lines();
    let initialize: Value =
        serde_json::from_str(&lines.next().expect("initialize").expect("input")).expect("json");
    assert_eq!(initialize["method"], "initialize");
    let fixture = &initialize["fixture"];
    let payer = address(&initialize["payer"]);
    let mut svm = LiteSVM::new();
    let loader = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    let mut programs = Vec::new();
    for (role, field, variable) in [
        ("judge", "program", "MORSE_JUDGE_SBF_PATH"),
        ("token", "token_program", "MORSE_TOKEN_SBF_PATH"),
        ("rewards", "rewards_program", "MORSE_REWARDS_SBF_PATH"),
    ] {
        let program = address(&fixture[field]);
        let path = std::env::var_os(variable).map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../target/deploy/morse_{role}.so"))
            },
            PathBuf::from,
        );
        let elf = std::fs::read(&path).expect("SBF ELF");
        svm.add_program(program, &elf).expect("load SBF");
        let data_address = Address::find_program_address(&[program.as_ref()], &loader).0;
        let mut metadata = svm.get_account(&data_address).expect("fresh programdata");
        let old = bytes(&fixture["accounts"][format!("{role}_data")]["data_hex"]);
        // Preserve only the explicitly retained deployment identity. Keep the
        // executable body from the ELF loaded above, never truncated fixture code.
        metadata.data[..45].copy_from_slice(&old[..45]);
        svm.set_account(data_address, metadata).unwrap();
        programs.push(json!({"role":role,"path":path,"sha256":hex::encode(solana_sha256_hasher::hash(&elf).to_bytes())}));
    }
    svm.airdrop(&payer, 20_000_000_000).unwrap();
    for (role, value) in fixture["accounts"].as_object().expect("fixture accounts") {
        if value["missing"] == true
            || [
                "judge",
                "judge_data",
                "token",
                "token_data",
                "rewards",
                "rewards_data",
            ]
            .contains(&role.as_str())
        {
            continue;
        }
        let mut data = bytes(&value["data_hex"]);
        if let Some(space) = value["space"].as_str() {
            data.resize(space.parse().expect("fixture space"), 0);
        }
        svm.set_account(
            address(&value["address"]),
            Account {
                lamports: value["lamports"].as_str().unwrap().parse().unwrap(),
                data,
                owner: address(&value["owner"]),
                executable: value["executable"].as_bool().unwrap_or(false),
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = fixture["context_slot"].as_str().unwrap().parse().unwrap();
    clock.unix_timestamp = fixture["now"].as_str().unwrap().parse().unwrap();
    svm.set_sysvar(&clock);
    // LiteSVM starts with its own recent-slot history. A retained fixture clock
    // must not coexist with future entries from that unrelated initial clock.
    let mut hashes = SlotHashes::default();
    hashes.add(clock.slot, svm.latest_blockhash().to_bytes().into());
    svm.set_sysvar(&hashes);
    let mut initialized = context(&svm, payer);
    initialized["programs"] = json!(programs);
    initialized["signature_verification"] = json!(true);
    output(initialized);
    for line in lines {
        let request: Value = serde_json::from_str(&line.expect("input")).expect("json");
        match request["method"].as_str().expect("method") {
            "read_context" => output(context(&svm, payer)),
            "context" => {
                svm.expire_blockhash();
                output(context(&svm, payer));
            }
            "send" => {
                let raw = STANDARD
                    .decode(request["wire"].as_str().expect("transaction"))
                    .unwrap();
                assert!(raw.len() <= 1232, "packet limit");
                let transaction: VersionedTransaction =
                    bincode::deserialize(&raw).expect("versioned transaction");
                let mut writable = Vec::new();
                let mut readonly = Vec::new();
                for lookup in transaction.message.address_table_lookups().unwrap_or(&[]) {
                    let account = svm.get_account(&lookup.account_key).expect("lookup table");
                    let table =
                        AddressLookupTable::deserialize(&account.data).expect("lookup state");
                    writable.extend(
                        lookup
                            .writable_indexes
                            .iter()
                            .map(|index| table.addresses[usize::from(*index)]),
                    );
                    readonly.extend(
                        lookup
                            .readonly_indexes
                            .iter()
                            .map(|index| table.addresses[usize::from(*index)]),
                    );
                }
                let keys: Vec<_> = transaction
                    .message
                    .static_account_keys()
                    .iter()
                    .chain(writable.iter())
                    .chain(readonly.iter())
                    .copied()
                    .collect();
                let pre: Vec<_> = keys
                    .iter()
                    .map(|key| svm.get_balance(key).unwrap_or(0).to_string())
                    .collect();
                match svm.send_transaction(transaction) {
                    Ok(meta) => output(
                        json!({"ok":true,"units":meta.compute_units_consumed,"fee":meta.fee,
                        "signature":meta.signature.to_string(),"logs":meta.logs,"pre_balances":pre,
                        "post_balances":keys.iter().map(|key| svm.get_balance(key).unwrap_or(0).to_string()).collect::<Vec<_>>(),
                        "loaded_addresses":{"writable":writable.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "readonly":readonly.iter().map(ToString::to_string).collect::<Vec<_>>()}}),
                    ),
                    Err(error) => output(
                        json!({"ok":false,"error":format!("{:?}",error.err),"logs":error.meta.logs,
                        "fee":error.meta.fee,"pre_balances":pre,
                        "post_balances":keys.iter().map(|key| svm.get_balance(key).unwrap_or(0).to_string()).collect::<Vec<_>>(),
                        "loaded_addresses":{"writable":writable.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "readonly":readonly.iter().map(ToString::to_string).collect::<Vec<_>>()}}),
                    ),
                }
            }
            "rent" => output(json!({"lamports":svm.minimum_balance_for_rent_exemption(
                usize::try_from(request["space"].as_u64().expect("space")).expect("space bound")).to_string()})),
            "account" => {
                let key = address(&request["address"]);
                output(match svm.get_account(&key) {
                    None => Value::Null,
                    Some(value) => {
                        json!({"owner":value.owner.to_string(),"data_hex":hex::encode(value.data),
                        "lamports":value.lamports.to_string(),"executable":value.executable,
                        "rent_epoch":value.rent_epoch.to_string()})
                    }
                });
            }
            "advance" => {
                let slot = svm.get_sysvar::<Clock>().slot;
                svm.warp_to_slot(slot + 1);
                output(context(&svm, payer));
            }
            "advance_lookup_history" => {
                let slot = svm.get_sysvar::<Clock>().slot;
                let mut hashes = svm.get_sysvar::<SlotHashes>();
                hashes.add(slot, svm.latest_blockhash().to_bytes().into());
                svm.set_sysvar(&hashes);
                svm.warp_to_slot(slot + 1);
                output(context(&svm, payer));
            }
            "retire_lookup_history" => {
                let mut clock = svm.get_sysvar::<Clock>();
                clock.slot += 513;
                svm.set_sysvar(&clock);
                svm.set_sysvar(&SlotHashes::default());
                output(context(&svm, payer));
            }
            "remove_accounts" => {
                for value in request["addresses"].as_array().expect("addresses") {
                    svm.set_account(address(value), Account::default()).unwrap();
                }
                output(context(&svm, payer));
            }
            "stop" => break,
            _ => panic!("unknown local bridge method"),
        }
    }
}
