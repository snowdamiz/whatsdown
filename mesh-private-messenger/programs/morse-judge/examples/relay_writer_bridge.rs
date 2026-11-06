//! Local execution only: accepts fully signed Kit transactions against fresh
//! funded SBF fixture accounts. No protocol decisions, private keys or network.
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
    json!({"blockhash":svm.latest_blockhash().to_string(),"lastValidBlockHeight":"1000",
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
    let path = std::env::var_os("MORSE_JUDGE_SBF_PATH").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_judge.so"),
        PathBuf::from,
    );
    svm.add_program_from_file(address(&fixture["program"]), path)
        .expect("judge SBF");
    svm.airdrop(&payer, 20_000_000_000).unwrap();
    for value in fixture["before_accounts"]
        .as_array()
        .expect("fixture accounts")
    {
        svm.set_account(
            address(&value["address"]),
            Account {
                lamports: value["lamports"].as_str().unwrap().parse().unwrap(),
                data: bytes(&value["data_hex"]),
                owner: address(&value["owner"]),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    svm.set_sysvar(&bincode::deserialize::<Clock>(&bytes(&fixture["clock"]["data_hex"])).unwrap());
    output(context(&svm, payer));
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
                        "signature":meta.signature.to_string(),"pre_balances":pre,
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
                        "lamports":value.lamports.to_string(),"executable":value.executable})
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
            "stop" => break,
            _ => panic!("unknown local bridge method"),
        }
    }
}
