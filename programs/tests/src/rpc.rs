//! Minimal blocking JSON-RPC client for the smoke test and `morse-admin`.

use crate::*;
use base64::Engine;
use serde_json::{json, Value};
use std::{str::FromStr, thread::sleep, time::Duration};

pub struct Rpc(pub String);

impl Rpc {
    pub fn call(&self, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = ureq::post(&self.0).send_json(&body).unwrap_or_else(|e| panic!("{method}: {e}")).body_mut().read_json().unwrap();
        if let Some(e) = v.get("error") {
            panic!("{method} failed: {}", serde_json::to_string_pretty(e).unwrap());
        }
        v["result"].clone()
    }
    pub fn confirm(&self, sig: &str) {
        for _ in 0..120 {
            let s = &self.call("getSignatureStatuses", json!([[sig]]))["value"][0];
            if !s.is_null() {
                assert!(s["err"].is_null(), "transaction {sig} failed: {}", s["err"]);
                if s["confirmationStatus"] == "confirmed" || s["confirmationStatus"] == "finalized" {
                    return;
                }
            }
            sleep(Duration::from_millis(250));
        }
        panic!("transaction {sig} not confirmed");
    }
    pub fn send(&self, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) {
        let hash = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))["value"]["blockhash"].as_str().unwrap().to_string();
        let mut all = vec![payer];
        all.extend(signers.iter().copied().filter(|k| k.pubkey() != payer.pubkey()));
        let tx =
            solana_transaction::Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &all, solana_hash::Hash::from_str(&hash).unwrap());
        let wire = bincode::serialize(&tx).unwrap();
        assert!(wire.len() <= 1232, "transaction too large: {} bytes", wire.len());
        let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
        let sig = self.call("sendTransaction", json!([b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]));
        self.confirm(sig.as_str().unwrap());
    }
    pub fn data(&self, addr: &Address) -> Vec<u8> {
        let v = self.call("getAccountInfo", json!([addr.to_string(), {"encoding": "base64", "commitment": "confirmed"}]));
        match v["value"]["data"][0].as_str() {
            Some(d) => base64::engine::general_purpose::STANDARD.decode(d).unwrap(),
            None => vec![],
        }
    }
    pub fn airdrop(&self, to: &Address, sol: u64) {
        let sig = self.call("requestAirdrop", json!([to.to_string(), sol * 1_000_000_000, {"commitment": "confirmed"}]));
        self.confirm(sig.as_str().unwrap());
    }
    pub fn rent(&self, len: usize) -> u64 {
        self.call("getMinimumBalanceForRentExemption", json!([len])).as_u64().unwrap()
    }
    pub fn balance(&self, token_account: &Address) -> u64 {
        let d = self.data(token_account);
        if d.len() == 165 {
            u64le(&d, 64)
        } else {
            0
        }
    }
}

pub fn create_mint(rpc: &Rpc, payer: &Keypair, mint: &Keypair, authority: &Address) {
    let mut create = vec![0u8, 0, 0, 0];
    create.extend_from_slice(&rpc.rent(82).to_le_bytes());
    create.extend_from_slice(&82u64.to_le_bytes());
    create.extend_from_slice(TOKEN.as_ref());
    let create = Instruction {
        program_id: SYSTEM,
        accounts: vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(mint.pubkey(), true)],
        data: create,
    };
    let init = Instruction {
        program_id: TOKEN,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: [&[20u8, 6][..], authority.as_ref(), &[0]].concat(),
    };
    rpc.send(&[create, init], payer, &[mint]);
}

/// Creates `owner`'s associated token account (idempotent) and mints to it.
pub fn mint_to(rpc: &Rpc, payer: &Keypair, mint: &Address, authority: &Keypair, owner: &Address, amount: u64) -> Address {
    let dest = ata(owner, mint);
    let mut ixs = vec![create_ata_idempotent(&payer.pubkey(), owner, mint)];
    if amount > 0 {
        ixs.push(Instruction {
            program_id: TOKEN,
            accounts: vec![AccountMeta::new(*mint, false), AccountMeta::new(dest, false), AccountMeta::new_readonly(authority.pubkey(), true)],
            data: [&[7u8][..], &amount.to_le_bytes()].concat(),
        });
    }
    let signers: &[&Keypair] = if amount > 0 { &[authority] } else { &[] };
    rpc.send(&ixs, payer, signers);
    dest
}
