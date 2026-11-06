//! Test-only Solana payment oracle: executes an externally SDK-signed packet
//! in LiteSVM with bundled real SPL/ATA SBF programs. No RPC or real funds.
use base64::{engine::general_purpose::STANDARD, Engine};
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    io::{self, Read},
    str::FromStr,
};
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
fn key(v: &Value, name: &str) -> Address {
    Address::from_str(v[name].as_str().unwrap()).unwrap()
}
fn tokens(svm: &LiteSVM, keys: &[Address], mint: Address, decimals: u8) -> Vec<Value> {
    keys.iter().enumerate().filter_map(|(index,key)|{
 let account=svm.get_account(key)?;if account.owner!=TOKEN||account.data.len()!=165{return None}let owner=Address::new_from_array(account.data[32..64].try_into().unwrap());
 Some(json!({"accountIndex":index,"mint":mint.to_string(),"owner":owner.to_string(),"programId":TOKEN.to_string(),"uiTokenAmount":{"amount":u64::from_le_bytes(account.data[64..72].try_into().unwrap()).to_string(),"decimals":decimals,"uiAmount":null,"uiAmountString":"0"}}))
}).collect()
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let value: Value = serde_json::from_str(&input).unwrap();
    let mut fixture = value["fixture"].clone();
    let wire = hex::decode(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let tx: VersionedTransaction = bincode::deserialize(&wire).unwrap();
    let keys = tx.message.static_account_keys().to_vec();
    let mint = key(&fixture, "mint");
    let payer = key(&fixture, "payer");
    let source_owner = fixture["source_owner"]
        .as_str()
        .map(|value| Address::from_str(value).unwrap())
        .unwrap_or(payer);
    let source_amount = value["token_source_amount"]
        .as_str()
        .map(|value| value.parse::<u64>().unwrap())
        .unwrap_or(100_000_000);
    let decimals = u8::try_from(value["token_decimals"].as_u64().unwrap_or(6)).unwrap();
    assert!(decimals <= 18);
    let source = key(&fixture, "source");
    let destination = key(&fixture, "destination");
    let mut svm = LiteSVM::new().with_blockhash_check(false);
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = 100000;
    clock.unix_timestamp = value["block_time"].as_i64().unwrap_or(1001);
    svm.set_sysvar(&clock);
    if let Some(lamports) = value["payer_lamports"].as_str() {
        svm.set_account(
            payer,
            Account {
                lamports: lamports.parse::<u64>().unwrap(),
                data: vec![],
                owner: Address::default(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    } else {
        svm.airdrop(&payer, 1_000_000_000).unwrap();
    }
    if fixture["asset"].as_u64().unwrap_or(0) == 0 {
        let mut data = vec![0; 82];
        data[36..44].copy_from_slice(&source_amount.to_le_bytes());
        data[44] = decimals;
        data[45] = 1;
        svm.set_account(
            mint,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(82),
                data,
                owner: TOKEN,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let mut data = vec![0; 165];
        data[..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(source_owner.as_ref());
        data[64..72].copy_from_slice(&source_amount.to_le_bytes());
        data[108] = 1;
        svm.set_account(
            source,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(165),
                data,
                owner: TOKEN,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    if let Some(lamports) = value["prefund"].as_u64() {
        if lamports > 0 {
            svm.set_account(
                destination,
                Account {
                    lamports,
                    data: vec![],
                    owner: Address::default(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        }
    }
    if value["existing_ata"].as_bool().unwrap_or(false) {
        let deposit = key(&fixture, "deposit");
        let mut data = vec![0; 165];
        data[..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(deposit.as_ref());
        data[108] = 1;
        svm.set_account(
            destination,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(165),
                data,
                owner: TOKEN,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    let pre = keys
        .iter()
        .map(|key| svm.get_account(key).map_or(0, |a| a.lamports))
        .collect::<Vec<_>>();
    let pre_tokens = tokens(&svm, &keys, mint, decimals);
    let repeat_tx = tx.clone();
    let result = svm.send_transaction(tx).unwrap_or_else(|e| {
        panic!(
            "local signed payment failed: {:?}\n{:?}",
            e.err, e.meta.logs
        )
    });
    let replay_count = value["replay_count"].as_u64().unwrap_or(0);
    assert!(replay_count <= 16);
    for _ in 0..replay_count {
        let failure = svm
            .send_transaction(repeat_tx.clone())
            .expect_err("identical packet must not pay twice");
        assert_eq!(format!("{:?}", failure.err), "AlreadyProcessed");
    }
    let post = keys
        .iter()
        .map(|key| svm.get_account(key).map_or(0, |a| a.lamports))
        .collect::<Vec<_>>();
    let post_tokens = tokens(&svm, &keys, mint, decimals);
    let inner=result.inner_instructions.iter().enumerate().filter(|(_,rows)|!rows.is_empty()).map(|(index,rows)|json!({"index":index,"instructions":rows.iter().map(|row|json!({"programIdIndex":row.instruction.program_id_index,"accounts":row.instruction.accounts,"data_hex":hex::encode(&row.instruction.data),"stackHeight":row.stack_height})).collect::<Vec<_>>()})).collect::<Vec<_>>();
    let response = json!({"jsonrpc":"2.0","id":41,"result":{"slot":100000,"blockTime":clock.unix_timestamp,"version":fixture["version"],"transaction":[STANDARD.encode(wire),"base64"],"meta":{"err":null,"fee":result.fee,"loadedAddresses":{"writable":[],"readonly":[]},"innerInstructions":inner,"preBalances":pre,"postBalances":post,"preTokenBalances":pre_tokens,"postTokenBalances":post_tokens}}});
    fixture["response"] = json!(response.to_string());
    fixture["slot_text"] = json!("100000");
    fixture["sbf_logs"] = json!(result.logs);
    fixture["replay_rejections"] = json!(replay_count);
    println!("{}", fixture);
}
