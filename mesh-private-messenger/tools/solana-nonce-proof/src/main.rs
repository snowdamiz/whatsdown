//! Test-only bank: no RPC, production wallet or caller-provided private keys.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use solana_account::{Account, ReadableAccount};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::{Message, SanitizedMessage};
use solana_nonce::{state::State, versions::Versions};
use solana_runtime::{bank::Bank as AgaveBank, bank_forks::BankForks, genesis_utils::create_genesis_config};
use solana_signer::Signer;
use solana_system_interface::instruction;
use solana_transaction::Transaction;
use std::{
    io::{self, BufRead, Write},
    sync::{Arc,RwLock},
};

struct Bank {
    svm: Arc<AgaveBank>,
    _forks: Arc<RwLock<BankForks>>,
    payer: Keypair,
    authority: Keypair,
    nonce: Keypair,
    source: Keypair,
    destination: Address,
    cluster: Address,
    buyer: Keypair,
}
impl Bank {
    fn new() -> Self {
        let payer = Keypair::new_from_array([1; 32]);
        let authority = Keypair::new_from_array([2; 32]);
        let nonce = Keypair::new_from_array([3; 32]);
        let source = Keypair::new_from_array([4; 32]);
        let buyer = Keypair::new_from_array([5; 32]);
        let mut genesis = create_genesis_config(1_000_000_000_000_000_000).genesis_config;
        genesis.fee_rate_governor.lamports_per_signature = 5_000;
        genesis.fee_rate_governor.target_lamports_per_signature = 5_000;
        for (address, lamports) in [
            (payer.pubkey(), 1_000_000_000),
            (source.pubkey(), 30_000_000_000_000_000),
            (buyer.pubkey(), 30_000_000_000_000_000),
        ] {
            genesis.accounts.insert(
                address,
                Account {
                    lamports,
                    data: Vec::new(),
                    owner: Address::default(),
                    executable: false,
                    rent_epoch: 0,
                },
            );
        }
        let cluster = Address::new_from_array(genesis.hash().to_bytes());
        let (genesis_bank, forks) = AgaveBank::new_with_bank_forks_for_tests(&genesis);
        // Enter a real non-genesis slot before any fee-bearing transaction.
        // Both banks belong to the actual fork graph used by the program cache.
        let svm = AgaveBank::new_from_parent_with_bank_forks(
            &forks,
            genesis_bank.clone(),
            genesis_bank.leader().clone(),
            1,
        );
        let init = instruction::create_nonce_account(
            &payer.pubkey(),
            &nonce.pubkey(),
            &authority.pubkey(),
            svm.get_minimum_balance_for_rent_exemption(State::size()),
        );
        let transaction = Transaction::new_signed_with_payer(
            &init,
            Some(&payer.pubkey()),
            &[&payer, &nonce],
            svm.last_blockhash(),
        );
        svm.process_transaction(&transaction).unwrap();
        Self {
            svm,
            _forks: forks,
            cluster,
            buyer,
            payer,
            authority,
            nonce,
            source,
            destination: Address::new_from_array([9; 32]),
        }
    }
    fn state(&self) -> Value {
        let account = self.svm.get_account(&self.nonce.pubkey()).unwrap();
        let versions: Versions = wincode::deserialize(account.data()).unwrap();
        let data = match versions.state() {
            State::Initialized(data) => data,
            _ => panic!("initialized nonce"),
        };
        json!({
            "payer": self.payer.pubkey().to_string(),
            "cluster": self.cluster.to_string(),
            "recent_blockhash": self.svm.last_blockhash().to_string(),
            "timestamp": self.svm.clock().unix_timestamp.to_string(),
            "buyer": self.buyer.pubkey().to_string(),
            "buyer_balance": self.svm.get_balance(&self.buyer.pubkey()).to_string(),
            "authority": self.authority.pubkey().to_string(),
            "source": self.source.pubkey().to_string(),
            "destination": self.destination.to_string(),
            "address": self.nonce.pubkey().to_string(),
            "nonce": data.blockhash().to_string(),
            "lamports_per_signature": data.get_lamports_per_signature().to_string(),
            "account": {"owner": account.owner().to_string(), "data_base64": STANDARD.encode(account.data()),
                "lamports": account.lamports().to_string(), "executable": account.executable()},
            "source_balance": self.svm.get_balance(&self.source.pubkey()).to_string(),
            "destination_balance": self.svm.get_balance(&self.destination).to_string(),
        })
    }
    fn handle(&mut self, request: &Value) -> Value {
        match request["method"].as_str().unwrap() {
            "state" => self.state(),
            "expire" => {
                self.svm.register_unique_recent_blockhash_for_test();
                self.state()
            }
            "oracle_message" => {
                let amount: u64 = request["amount"].as_str().unwrap().parse().unwrap();
                let account = self.svm.get_account(&self.nonce.pubkey()).unwrap();
                let versions: Versions = wincode::deserialize(account.data()).unwrap();
                let nonce = match versions.state() {
                    State::Initialized(data) => data.blockhash(),
                    _ => panic!("initialized nonce"),
                };
                let advance = instruction::advance_nonce_account(
                    &self.nonce.pubkey(),
                    &self.authority.pubkey(),
                );
                let transfer =
                    instruction::transfer(&self.source.pubkey(), &self.destination, amount);
                let message = Message::new_with_blockhash(
                    &[advance.clone(), transfer],
                    Some(&self.payer.pubkey()),
                    &nonce,
                );
                json!({"message_hex": hex::encode(message.serialize()), "advance": {
                    "program": advance.program_id.to_string(), "data_hex": hex::encode(advance.data),
                    "accounts": advance.accounts.iter().map(|meta| json!({"address": meta.pubkey.to_string(),
                        "signer": meta.is_signer, "writable": meta.is_writable})).collect::<Vec<_>>()}})
            }
            "send" => {
                let bytes = hex::decode(request["wire_hex"].as_str().unwrap()).unwrap();
                assert!(bytes.len() <= 1232);
                let transaction: Transaction = wincode::deserialize(&bytes).unwrap();
                transaction
                    .verify()
                    .expect("fixture verifies all Ed25519 signatures");
                let before = self.state();
                let actual_payer = transaction.message.account_keys[0];
                let fee_before = self.svm.get_balance(&actual_payer);
                let sanitized = SanitizedMessage::try_from_legacy_message(transaction.message.clone(), &Default::default()).unwrap();
                let expected_fee = self.svm.get_fee_for_message(&sanitized).unwrap_or(0);
                let pre_balances: Vec<_> = transaction
                    .message
                    .account_keys
                    .iter()
                    .map(|key| self.svm.get_balance(key))
                    .collect();
                let result = self.svm.process_transaction(&transaction);
                let fee = if fee_before == self.svm.get_balance(&actual_payer) { 0 } else { expected_fee };
                let post_balances: Vec<_> = transaction
                    .message
                    .account_keys
                    .iter()
                    .map(|key| self.svm.get_balance(key))
                    .collect();
                let response = json!({"jsonrpc": "2.0", "id": 41, "result": {
                    "slot": self.svm.slot(), "blockTime": self.svm.clock().unix_timestamp,
                    "version": "legacy", "transaction": [STANDARD.encode(&bytes), "base64"],
                    "meta": {"err": result.as_ref().err(), "fee": fee,
                        "loadedAddresses": {"writable": [], "readonly": []},
                        "innerInstructions": [], "preTokenBalances": [], "postTokenBalances": [],
                        "preBalances": pre_balances, "postBalances": post_balances}}})
                .to_string();
                match result {
                    Ok(()) => json!({"ok": true, "fee": fee.to_string(), "before": before,
                        "after": self.state(), "rpc_response": response}),
                    Err(error) => json!({"ok": false, "fee": fee.to_string(),
                        "error": format!("{:?}", error), "before": before,
                        "after": self.state(), "rpc_response": response}),
                }
            }
            _ => panic!("unknown test method"),
        }
    }
}
fn main() {
    let mut bank = Bank::new();
    for line in io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line.unwrap()).unwrap();
        println!("{}", bank.handle(&request));
        io::stdout().flush().unwrap();
    }
}
