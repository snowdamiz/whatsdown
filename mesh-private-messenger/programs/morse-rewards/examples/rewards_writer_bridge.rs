//! Disposable local chain boundary. Accepts externally signed Kit transactions;
//! never connects to a network or reads an operator's secret key.
use base64::{engine::general_purpose::STANDARD, Engine};
use judge_core::attendance::{
    activate_clock, initialize_clock, initialize_epoch, CLOCK_LEN, EPOCH_LEN,
};
use litesvm::LiteSVM;
use morse_rewards::state::*;
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_sha256_hasher::{hash, hashv};
use solana_transaction::versioned::VersionedTransaction;
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
};
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
fn key(v: &Value, k: &str) -> Address {
    Address::from_str(v[k].as_str().expect("address")).expect("canonical address")
}
fn number(v: &Value) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| v.as_str().expect("integer").parse().expect("integer"))
}
fn token_ata(a: Address, m: Address) -> Address {
    Address::find_program_address(&[a.as_ref(), TOKEN.as_ref(), m.as_ref()], &ATA).0
}
fn account(s: &mut LiteSVM, a: Address, o: Address, d: Vec<u8>) {
    s.set_account(
        a,
        Account {
            lamports: s.minimum_balance_for_rent_exemption(d.len()),
            owner: o,
            data: d,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("fixture account");
}
fn token_account(s: &mut LiteSVM, a: Address, o: Address, m: Address, balance: u64) {
    let mut d = vec![0; 165];
    d[..32].copy_from_slice(m.as_ref());
    d[32..64].copy_from_slice(o.as_ref());
    put64(&mut d, 64, balance);
    d[108] = 1;
    account(s, a, TOKEN, d);
}
fn output(v: Value) {
    println!("{v}");
    io::stdout().flush().expect("flush");
}
struct Witness {
    address: Address,
    bond: Address,
    member: Address,
    payout: Address,
    vault: Address,
    signed: u64,
}
struct Bridge {
    svm: LiteSVM,
    judge: Address,
    pool: Address,
    vault: Address,
    source: Address,
    economy: Address,
    clock: Address,
    id: [u8; 32],
    started: i64,
    initial_epoch: u64,
    witnesses: Vec<Witness>,
}
impl Bridge {
    fn week(&self, e: u64) -> Address {
        Address::find_program_address(
            &[b"attendance-epoch", &self.id, &e.to_le_bytes()],
            &self.judge,
        )
        .0
    }
    fn epoch(&self) -> u64 {
        (self.svm.get_sysvar::<Clock>().unix_timestamp / EPOCH_SECONDS) as u64
    }
    fn receipt(&mut self, e: u64) {
        let a = self.week(e);
        let mut d = vec![0; EPOCH_LEN];
        initialize_epoch(&mut d, &self.id, e).unwrap();
        put64(&mut d, 44, 100);
        put64(&mut d, 52, 99_999);
        d[60..62].copy_from_slice(&3u16.to_le_bytes());
        d[62] = u8::from(e < self.epoch());
        let mut rows: Vec<_> = self.witnesses.iter().collect();
        rows.sort_by_key(|w| w.address);
        for (n, w) in rows.iter().enumerate() {
            let o = 80 + n * 40;
            d[o..o + 32].copy_from_slice(w.address.as_ref());
            put64(&mut d, o + 32, w.signed)
        }
        account(&mut self.svm, a, self.judge, d);
        let mut clock = self.svm.get_account(&self.clock).unwrap();
        let latest = u64_at(&clock.data, 60).max(e);
        put64(&mut clock.data, 60, latest);
        self.svm.set_account(self.clock, clock).unwrap();
    }
    fn account_value(&self, a: Address, offset: usize, length: Option<usize>) -> Value {
        self.svm.get_account(&a).map_or(Value::Null,|v|{let end=offset.saturating_add(length.unwrap_or(v.data.len())).min(v.data.len());let data=if offset>=v.data.len(){&[]}else{&v.data[offset..end]};json!({"owner":v.owner.to_string(),"executable":v.executable,"lamports":v.lamports.to_string(),"space":v.data.len().to_string(),"data":[STANDARD.encode(data),"base64"]})})
    }
    fn state(&self) -> Value {
        let p = Pool::parse(&self.svm.get_account(&self.pool).unwrap().data).unwrap();
        json!({"next_epoch":p.next_epoch.to_string(),"subsidy":p.subsidy.to_string(),"carry":p.carry.to_string(),"liabilities":p.liabilities.to_string(),"accounted":p.accounted.to_string(),"vault_balance":u64_at(&self.svm.get_account(&self.vault).unwrap().data,64).to_string(),"source_balance":u64_at(&self.svm.get_account(&self.source).unwrap().data,64).to_string()})
    }
}
fn main() {
    let mut input = io::stdin().lock().lines();
    let req: Value =
        serde_json::from_str(&input.next().expect("initialize").expect("line")).expect("JSON");
    assert_eq!(req["method"], "initialize");
    let payer = key(&req, "payer");
    let funder = if req["funder"].is_string() {
        key(&req, "funder")
    } else {
        payer
    };
    let governance = if req["governance"].is_string() {
        key(&req, "governance")
    } else {
        payer
    };
    let program = Address::from([0x66; 32]);
    let judge = Address::from([0x33; 32]);
    let mint = Address::from([0x77; 32]);
    let id = hash(b"morse-main").to_bytes();
    let log = Address::find_program_address(&[b"log", b"morse-main"], &judge).0;
    let clock_address = Address::find_program_address(&[b"attendance", &id], &judge).0;
    let economy = Address::find_program_address(&[b"economics", &id], &judge).0;
    let pool = Address::find_program_address(&[b"pool"], &program).0;
    let vault = token_ata(pool, mint);
    let source = token_ata(funder, mint);
    let started = 1_700_000_000;
    let first = (started / EPOCH_SECONDS) as u64 + 1;
    let initial_epoch = first + 2;
    let mut svm = LiteSVM::new();
    for (a, env, file) in [
        (program, "MORSE_REWARDS_SBF_PATH", "morse_rewards.so"),
        (judge, "MORSE_JUDGE_SBF_PATH", "morse_judge.so"),
    ] {
        let binary = std::env::var_os(env).map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../target/deploy")
                    .join(file)
            },
            PathBuf::from,
        );
        svm.add_program_from_file(a, binary)
            .expect("build SBF first");
    }
    let mut wallets = vec![payer, funder, governance];
    wallets.sort();
    wallets.dedup();
    for a in wallets {
        svm.airdrop(&a, 10_000_000_000).expect("fixture lamports");
    }
    let mut chain_clock = svm.get_sysvar::<Clock>();
    chain_clock.slot = 100_000;
    chain_clock.unix_timestamp = initial_epoch as i64 * EPOCH_SECONDS;
    svm.set_sysvar(&chain_clock);
    let mut d = vec![0; 82];
    d[..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..36].copy_from_slice(funder.as_ref());
    put64(&mut d, 36, 9_800_000_000);
    d[44] = 6;
    d[45] = 1;
    account(&mut svm, mint, TOKEN, d);
    token_account(&mut svm, source, funder, mint, 9_000_000_000);
    token_account(&mut svm, vault, pool, mint, 0);
    let ring = Address::find_program_address(&[b"ring", b"morse-main"], &judge).0;
    let directory_bond = Address::find_program_address(&[b"bond", &id, b"directory"], &judge).0;
    let directory_vault = token_ata(directory_bond, mint);
    token_account(&mut svm, directory_vault, directory_bond, mint, 500_000_000);
    let mut d = vec![0; 352];
    d[..4].copy_from_slice(b"MLG\x01");
    d[4] = 1;
    d[6] = 10;
    d[7] = 1;
    d[8..18].copy_from_slice(b"morse-main");
    d[40..72].copy_from_slice(&id);
    d[72..104].copy_from_slice(&[0x11; 32]);
    d[104..136].copy_from_slice(governance.as_ref());
    d[136..168].copy_from_slice(ring.as_ref());
    d[168..200].copy_from_slice(directory_vault.as_ref());
    account(&mut svm, log, judge, d);
    let mut d = vec![0; CLOCK_LEN];
    initialize_clock(&mut d, &id).unwrap();
    activate_clock(&mut d, started, 90_000).unwrap();
    account(&mut svm, clock_address, judge, d);
    let mut d = vec![0; 192];
    d[..4].copy_from_slice(b"MEC\x01");
    d[4..36].copy_from_slice(&id);
    d[36..68].copy_from_slice(mint.as_ref());
    d[68..100].copy_from_slice(funder.as_ref());
    put64(&mut d, 100, 100_000_000);
    put64(&mut d, 108, 500_000_000);
    put64(&mut d, 148, 300_000_000);
    put64(&mut d, 156, 500_000_000);
    d[164] = 1;
    account(&mut svm, economy, judge, d);
    let mut witnesses = vec![];
    for n in 0..3 {
        let wid = [b"outside-a".as_slice(), b"outside-b", b"morse-a"][n];
        let signing = [(0x51 + n) as u8; 32];
        let identity = hashv(&[
            b"morse-witness-record-v1",
            &[wid.len() as u8],
            wid,
            &signing,
        ]);
        let address =
            Address::find_program_address(&[b"witness", &id, identity.as_ref()], &judge).0;
        let bond = Address::find_program_address(&[b"bond", &id, identity.as_ref()], &judge).0;
        let member = Address::find_program_address(&[b"member", address.as_ref()], &program).0;
        let bond_vault = token_ata(bond, mint);
        let payout = req["payouts"].get(n).and_then(Value::as_str).map_or_else(
            || Address::from([(0x71 + n) as u8; 32]),
            |s| Address::from_str(s).expect("payout"),
        );
        token_account(&mut svm, token_ata(payout, mint), payout, mint, 0);
        token_account(&mut svm, bond_vault, bond, mint, 100_000_000);
        let mut d = vec![0; 320];
        d[..4].copy_from_slice(b"MWI\x01");
        d[4] = wid.len() as u8;
        d[5] = 1;
        d[8..8 + wid.len()].copy_from_slice(wid);
        d[72..104].copy_from_slice(&signing);
        d[104..136].copy_from_slice(funder.as_ref());
        d[136..168].copy_from_slice(payout.as_ref());
        d[200..232].copy_from_slice(&id);
        d[232..264].copy_from_slice(bond_vault.as_ref());
        account(&mut svm, address, judge, d);
        let mut d = vec![0; 208];
        d[..4].copy_from_slice(b"MBD\x01");
        d[4] = 1;
        d[5] = 1;
        d[8..40].copy_from_slice(&id);
        d[40..72].copy_from_slice(address.as_ref());
        d[72..104].copy_from_slice(funder.as_ref());
        d[104..136].copy_from_slice(mint.as_ref());
        d[136..168].copy_from_slice(bond_vault.as_ref());
        put64(&mut d, 168, 100_000_000);
        d[176..184].copy_from_slice(&started.to_le_bytes());
        account(&mut svm, bond, judge, d);
        let mut d = vec![0; MEMBER_LEN];
        d[..4].copy_from_slice(b"MRM\x01");
        d[4..36].copy_from_slice(address.as_ref());
        d[36] = if n == 2 { 2 } else { 1 };
        d[48..56].copy_from_slice(&(started + TIMELOCK_SECONDS).to_le_bytes());
        account(&mut svm, member, program, d);
        witnesses.push(Witness {
            address,
            bond,
            member,
            payout,
            vault: bond_vault,
            signed: [95, 90, 100][n],
        });
    }
    let mut d = vec![0; POOL_LEN];
    d[..4].copy_from_slice(b"MRP\x01");
    d[4..36].copy_from_slice(governance.as_ref());
    d[36..68].copy_from_slice(judge.as_ref());
    d[68..100].copy_from_slice(log.as_ref());
    d[100..132].copy_from_slice(&id);
    d[132..164].copy_from_slice(mint.as_ref());
    d[164..172].copy_from_slice(&started.to_le_bytes());
    put64(&mut d, 172, first);
    put64(&mut d, 180, initial_epoch);
    d[268..300].copy_from_slice(witnesses[2].address.as_ref());
    account(&mut svm, pool, program, d);
    let mut b = Bridge {
        svm,
        judge,
        pool,
        vault,
        source,
        economy,
        clock: clock_address,
        id,
        started,
        initial_epoch,
        witnesses,
    };
    b.receipt(initial_epoch);
    let mut sorted: Vec<_> = b.witnesses.iter().map(|w| w.address).collect();
    sorted.sort();
    let ws:Vec<_>=b.witnesses.iter().enumerate().map(|(n,w)|json!({"id":(["outside-a","outside-b","morse-a"][n]),"key":hex::encode([(0x51+n)as u8;32]),"address":w.address.to_string(),"bond":w.bond.to_string(),"member":w.member.to_string(),"payout":w.payout.to_string(),"payout_ata":token_ata(w.payout,mint).to_string(),"vault":w.vault.to_string(),"signed":w.signed.to_string(),"row":sorted.iter().position(|a|*a==w.address).unwrap()})).collect();
    output(
        json!({"log_name":"morse-main","program":program.to_string(),"judge":judge.to_string(),"mint":mint.to_string(),"pool":pool.to_string(),"vault":vault.to_string(),"source":source.to_string(),"log":log.to_string(),"clock":clock_address.to_string(),"economics":economy.to_string(),"log_id":hex::encode(id),"epoch":initial_epoch.to_string(),"week":b.week(initial_epoch).to_string(),"started":started.to_string(),"now":b.svm.get_sysvar::<Clock>().unix_timestamp.to_string(),"payer":payer.to_string(),"funder":funder.to_string(),"governance":governance.to_string(),"witnesses":ws}),
    );
    for line in input {
        let v: Value = serde_json::from_str(&line.expect("line")).expect("JSON");
        let slot = b.svm.get_sysvar::<Clock>().slot;
        match v["method"].as_str().expect("method") {
            "expire_blockhash" => {
                b.svm.expire_blockhash();
                output(json!({"blockhash":b.svm.latest_blockhash().to_string()}));
            }
            "context" => output(
                json!({"blockhash":b.svm.latest_blockhash().to_string(),"block_height":slot.to_string(),"last_valid_block_height":(slot+150).to_string(),"slot":slot.to_string(),"unix_timestamp":b.svm.get_sysvar::<Clock>().unix_timestamp.to_string()}),
            ),
            "account" => {
                let off = v.get("offset").map_or(0, |n| number(n) as usize);
                let len = v.get("length").map(|n| number(n) as usize);
                output(
                    json!({"context":{"slot":slot.to_string()},"value":b.account_value(key(&v,"address"),off,len)}),
                );
            }
            "accounts" => {
                let off = v.get("offset").map_or(0, |n| number(n) as usize);
                let len = v.get("length").map(|n| number(n) as usize);
                let values: Vec<_> = v["addresses"]
                    .as_array()
                    .expect("addresses")
                    .iter()
                    .map(|a| {
                        b.account_value(
                            Address::from_str(a.as_str().expect("address")).expect("address"),
                            off,
                            len,
                        )
                    })
                    .collect();
                output(json!({"context":{"slot":slot.to_string()},"value":values}));
            }
            "warp" => {
                let mut c = b.svm.get_sysvar::<Clock>();
                c.unix_timestamp = number(&v["unix_timestamp"]) as i64;
                c.slot = v.get("slot").map_or(c.slot + 2000, number);
                assert!(c.unix_timestamp >= b.started);
                b.svm.set_sysvar(&c);
                b.svm.expire_blockhash();
                let current = b.epoch();
                assert!(current - b.initial_epoch <= 1000);
                for e in b.initial_epoch..=current {
                    b.receipt(e)
                }
                output(
                    json!({"slot":c.slot.to_string(),"unix_timestamp":c.unix_timestamp.to_string(),"epoch":current.to_string()}),
                );
            }
            "revision" => {
                let mut a = b.svm.get_account(&b.economy).unwrap();
                let n = u64_at(&a.data, 168) + 1;
                put64(&mut a.data, 168, n);
                b.svm.set_account(b.economy, a).unwrap();
                output(json!({"revision":n.to_string()}));
            }
            "missing_week" => {
                let epoch = number(&v["epoch"]);
                let address = b.week(epoch);
                b.svm.set_account(address, Account::default()).unwrap();
                output(json!({"address":address.to_string()}));
            }
            "missing_payout" => {
                let row = number(&v["row"]) as usize;
                let w = b
                    .witnesses
                    .iter()
                    .find(|w| sorted.iter().position(|a| *a == w.address) == Some(row))
                    .expect("row");
                let address = token_ata(w.payout, mint);
                b.svm.set_account(address, Account::default()).unwrap();
                output(json!({"address":address.to_string()}));
            }
            "state" => output(b.state()),
            "send" => {
                let bytes = STANDARD
                    .decode(v["transaction"].as_str().expect("transaction"))
                    .expect("base64");
                assert!(bytes.len() <= 1232);
                let tx: VersionedTransaction =
                    bincode::deserialize(&bytes).expect("signed Kit transaction");
                let result = b.svm.send_transaction(tx);
                let (ok, error, fee, logs) = match result {
                    Ok(m) => (true, None, m.fee, m.logs),
                    Err(e) => (false, Some(format!("{:?}", e.err)), e.meta.fee, e.meta.logs),
                };
                output(
                    json!({"ok":ok,"error":error,"fee_lamports":fee,"logs":logs,"state":b.state()}),
                );
            }
            _ => panic!("unknown bridge method"),
        }
    }
}
