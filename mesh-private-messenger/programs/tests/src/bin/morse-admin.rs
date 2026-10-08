//! `morse-admin`: the deployment runbook's tool (protocol/morse-judge-v1.md
//! §12). Deployer and operator actions are signed with local keypair files
//! and sent; governance actions are printed as a Squads vault transaction
//! (instructions as JSON, plus a base58 legacy message whose fee payer and
//! signer is the vault), never signed here.
//!
//! Run from `programs/` after `cargo-build-sbf` (the instruction builders are
//! the test harness's): `cargo run -q -p morse-program-tests --bin morse-admin -- <command> ...`

use base64::Engine;
use morse_program_tests::{rpc::Rpc, *};
use serde_json::json;
use std::{collections::HashMap, str::FromStr};

const USAGE: &str = "usage: morse-admin <command> [--flag value ...]
common: --url URL (default http://127.0.0.1:8899) --judge PROGRAM_ID [--rewards PROGRAM_ID]
  init-judge        --deployer KEYFILE --authority VAULT --usdc MINT [--token MINT] --min-bond-usdc N --min-bond-token N
  grow-ring         --payer KEYFILE --log NAME
  apply             --payer KEYFILE
  register-message  --log NAME --id ID --operator PUBKEY --payout PUBKEY
  register-witness  --operator KEYFILE --log NAME --id ID --witness-key HEX --signature HEX --payout PUBKEY [--operator-hash HEX] [--excluded]
  bond              --operator KEYFILE --log NAME --id ID --mint MINT --amount N
  unbond            --operator KEYFILE --log NAME --id ID
  withdraw          --operator KEYFILE --log NAME --id ID --mint MINT
  init-rewards      --deployer KEYFILE --authority VAULT --log NAME --usdc MINT --floor N --floor-until UNIX
  show              --log NAME
  gov register-log         NAME --authority VAULT --service-key HEX --anchor PUBKEY --usdc MINT [--canary]
  gov close-log            NAME --authority VAULT --destination PUBKEY [--stages STAGE:SUBMITTER,...]   (slashed canary logs, 28 days after the slash)
  gov admit-witness        NAME --authority VAULT --id ID [--replace INDEX --replaced-id ID] [--excluded]
  gov bond-directory       NAME --authority VAULT --mint MINT --amount N
  gov set-anchor-authority NAME --authority VAULT --anchor PUBKEY
  gov unbond-directory     NAME --authority VAULT
  gov withdraw-directory   NAME --authority VAULT --mint MINT
  gov propose KIND --authority VAULT --value V   (cancel|authority|token-mint|rewards|min-bond-usdc|min-bond-token)
  gov rewards-param KIND --authority VAULT --value V   (authority|token-mint|oracle|price-feed|floor|floor-until|target)";

struct Args {
    pos: Vec<String>,
    flags: HashMap<String, String>,
}

impl Args {
    fn parse() -> Args {
        let (mut pos, mut flags) = (vec![], HashMap::new());
        let mut it = std::env::args().skip(1).peekable();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                let value = if it.peek().is_some_and(|v| !v.starts_with("--")) { it.next().unwrap() } else { "true".into() };
                flags.insert(name.to_string(), value);
            } else {
                pos.push(a);
            }
        }
        Args { pos, flags }
    }
    fn get(&self, k: &str) -> &str {
        self.flags.get(k).unwrap_or_else(|| panic!("missing --{k}\n{USAGE}"))
    }
    fn addr(&self, k: &str) -> Address {
        Address::from_str(self.get(k)).unwrap_or_else(|_| panic!("--{k}: not a base58 address"))
    }
    fn num(&self, k: &str) -> u64 {
        self.get(k).parse().unwrap_or_else(|_| panic!("--{k}: not a number"))
    }
    fn hex32(&self, k: &str) -> [u8; 32] {
        hex::decode(self.get(k)).ok().and_then(|b| b.try_into().ok()).unwrap_or_else(|| panic!("--{k}: 64 hex digits"))
    }
    fn keypair(&self, k: &str) -> Keypair {
        let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(self.get(k)).expect("keypair file")).unwrap();
        Keypair::try_from(&bytes[..]).unwrap()
    }
    fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
}

/// A witness handle for the harness builders (only log, id and operator
/// matter for addresses and bond instructions).
fn witness(log: &str, id: &str, operator: Keypair) -> Witness {
    Witness { id: id.into(), key: key(0), operator, payout: Keypair::new(), log: log_id(log) }
}

fn print_governance(vault: &Address, ixs: &[Instruction]) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let list: Vec<_> = ixs
        .iter()
        .map(|i| {
            json!({
                "programId": i.program_id.to_string(),
                "accounts": i.accounts.iter().map(|m| json!({"pubkey": m.pubkey.to_string(), "isSigner": m.is_signer, "isWritable": m.is_writable})).collect::<Vec<_>>(),
                "data": b64.encode(&i.data),
            })
        })
        .collect();
    let message = solana_message::Message::new(ixs, Some(vault));
    let out = json!({"vault": vault.to_string(), "instructions": list, "message_base58": bs58::encode(bincode::serialize(&message).unwrap()).into_string()});
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn main() {
    let a = Args::parse();
    if a.pos.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let rpc = Rpc(a.flags.get("url").cloned().unwrap_or_else(|| "http://127.0.0.1:8899".into()));
    let mut env = Env::bare(); // instruction builders only
    env.judge = a.addr("judge");
    if a.has("rewards") {
        env.rewards = a.addr("rewards");
    }
    if a.has("usdc") {
        env.usdc = a.addr("usdc");
    }
    let judge = env.judge;
    match a.pos[0].as_str() {
        "init-judge" => {
            let deployer = a.keypair("deployer");
            let token = if a.has("token") { a.addr("token").to_bytes() } else { [0; 32] };
            env.rewards = if a.has("rewards") { a.addr("rewards") } else { Address::new_from_array([0; 32]) };
            let i = env.initialize_ix(&deployer.pubkey(), &a.addr("authority"), &token, a.num("min-bond-usdc"), a.num("min-bond-token"));
            rpc.send(&[i], &deployer, &[]);
            println!("judge initialized: config {}", env.config());
        }
        "grow-ring" => {
            env.payer = a.keypair("payer");
            let log = a.get("log");
            loop {
                let len = rpc.data(&env.ring(log)).len();
                if len == layout::RING_LEN {
                    break;
                }
                let n = if len == 0 { 1 } else { (layout::RING_LEN - len).div_ceil(10_240).min(8) };
                rpc.send(&vec![env.grow_ring_ix(log); n], &env.payer, &[]);
                println!("ring {}: {} / {} bytes", env.ring(log), rpc.data(&env.ring(log)).len(), layout::RING_LEN);
            }
        }
        "apply" => {
            let payer = a.keypair("payer");
            rpc.send(&[env.apply_ix()], &payer, &[]);
            println!("pending parameter change applied");
        }
        "register-message" => {
            let msg = [&b"morse-witness-register-v1"[..], a.get("id").as_bytes(), a.addr("operator").as_ref(), a.addr("payout").as_ref()].concat();
            println!("{}", hex::encode(msg));
        }
        "register-witness" => {
            let operator = a.keypair("operator");
            let (log, id) = (a.get("log"), a.get("id"));
            let key = a.hex32("witness-key");
            let sig: [u8; 64] = hex::decode(a.get("signature")).ok().and_then(|b| b.try_into().ok()).expect("--signature: 128 hex digits");
            let payout = a.addr("payout");
            let msg = [&b"morse-witness-register-v1"[..], id.as_bytes(), operator.pubkey().as_ref(), payout.as_ref()].concat();
            let mut data = vec![ix::REGISTER_WITNESS];
            data.extend_from_slice(&key);
            data.extend_from_slice(payout.as_ref());
            data.extend_from_slice(&if a.has("operator-hash") { a.hex32("operator-hash") } else { [0; 32] });
            data.extend_from_slice(&[a.has("excluded") as u8, 0, id.len() as u8]);
            data.extend_from_slice(id.as_bytes());
            let w = witness(log, id, operator.insecure_clone());
            let register = Instruction {
                program_id: judge,
                accounts: vec![
                    AccountMeta::new(operator.pubkey(), true),
                    AccountMeta::new_readonly(env.log(log), false),
                    AccountMeta::new(w.account(&judge), false),
                    AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
                    AccountMeta::new_readonly(SYSTEM, false),
                ],
                data,
            };
            rpc.send(&[ed25519_ix(&[(&key, &msg, &sig)]), register], &operator, &[]);
            println!("witness {id} registered: account {}, bond vault {}", w.account(&judge), w.vault(&judge));
        }
        "bond" | "unbond" | "withdraw" => {
            let operator = a.keypair("operator");
            let (log, id) = (a.get("log"), a.get("id"));
            let w = witness(log, id, operator.insecure_clone());
            let i = match a.pos[0].as_str() {
                "bond" => env.bond_ix(log, &w, &a.addr("mint"), a.num("amount")),
                "unbond" => env.unbond_ix(log, &operator.pubkey(), 1, &w.account(&judge)),
                _ => env.withdraw_ix(log, &operator.pubkey(), 1, &w.account(&judge), &w.vault(&judge), &ata(&operator.pubkey(), &a.addr("mint"))),
            };
            rpc.send(&[i], &operator, &[]);
            println!("{} done for {id}", a.pos[0]);
        }
        "init-rewards" => {
            let deployer = a.keypair("deployer");
            let r = env.rewards;
            let mut data = vec![0u8];
            for part in [a.addr("authority").as_ref(), judge.as_ref(), env.log(a.get("log")).as_ref(), a.addr("usdc").as_ref()] {
                data.extend_from_slice(part);
            }
            data.extend_from_slice(&a.num("floor").to_le_bytes());
            data.extend_from_slice(&(a.num("floor-until") as i64).to_le_bytes());
            let i = Instruction {
                program_id: r,
                accounts: vec![
                    AccountMeta::new(deployer.pubkey(), true),
                    AccountMeta::new(pda(&[b"config"], &r), false),
                    AccountMeta::new_readonly(env.programdata(&r), false),
                    AccountMeta::new_readonly(SYSTEM, false),
                ],
                data,
            };
            let pool = ata(&pda(&[b"pool"], &r), &a.addr("usdc"));
            rpc.send(&[i, create_ata_idempotent(&deployer.pubkey(), &pda(&[b"pool"], &r), &a.addr("usdc"))], &deployer, &[]);
            println!("rewards initialized: config {}, pool vault {pool}, burn authority {}", pda(&[b"config"], &r), pda(&[b"burn"], &r));
        }
        "show" => show(&rpc, &env, a.get("log")),
        "gov" => governance(&a, &env),
        other => panic!("unknown command {other}\n{USAGE}"),
    }
}

fn governance(a: &Args, env: &Env) {
    let vault = a.addr("authority");
    let what = a.pos.get(1).map(String::as_str).unwrap_or_default();
    let name = a.pos.get(2).map(String::as_str).unwrap_or_default();
    let judge = env.judge;
    let ixs = match what {
        "register-log" => {
            let mut i = env.register_log_ix(name, &a.hex32("service-key"), &a.addr("anchor"), &vault, a.has("canary") as u8);
            i.accounts[1] = AccountMeta::new(vault, true); // the vault pays the log and locked-vault rent
            vec![i]
        }
        "admit-witness" => {
            let w = witness(name, a.get("id"), Keypair::new());
            let (replace, replaced) = if a.has("replace") {
                (a.num("replace") as u8, witness(name, a.get("replaced-id"), Keypair::new()).account(&judge))
            } else {
                (0xFF, judge)
            };
            vec![env.admit_witness_ix(name, &w.account(&judge), &vault, replace, a.has("excluded") as u8, &replaced)]
        }
        "bond-directory" => vec![env.bond_directory_ix(name, &vault, &a.addr("mint"), a.num("amount"))],
        "set-anchor-authority" => vec![env.set_anchor_authority_ix(name, &vault, &a.addr("anchor"))],
        "close-log" => {
            let stages: Vec<(Address, Address)> = a
                .flags
                .get("stages")
                .map(|s| {
                    s.split(',')
                        .map(|p| {
                            let (st, sub) = p.split_once(':').expect("--stages STAGE:SUBMITTER,...");
                            (Address::from_str(st).unwrap(), Address::from_str(sub).unwrap())
                        })
                        .collect()
                })
                .unwrap_or_default();
            vec![env.close_log_ix(name, &vault, &a.addr("destination"), &stages)]
        }
        "unbond-directory" => vec![env.unbond_ix(name, &vault, 0, &env.log(name))],
        "withdraw-directory" => vec![env.withdraw_ix(name, &vault, 0, &env.log(name), &env.dir_vault(name), &ata(&vault, &a.addr("mint")))],
        "propose" => {
            let kinds = ["cancel", "authority", "token-mint", "rewards", "min-bond-usdc", "min-bond-token"];
            let kind = kinds.iter().position(|k| *k == name).unwrap_or_else(|| panic!("propose kind: {kinds:?}")) as u8;
            vec![env.propose_ix(&vault, kind, value32(a, kind >= 4))]
        }
        "rewards-param" => {
            let kinds = ["", "authority", "token-mint", "oracle", "price-feed", "floor", "floor-until", "target"];
            let kind = kinds.iter().position(|k| *k == name).filter(|k| *k > 0).unwrap_or_else(|| panic!("rewards-param kind: {kinds:?}")) as u8;
            let r = env.rewards;
            vec![Instruction {
                program_id: r,
                accounts: vec![AccountMeta::new_readonly(vault, true), AccountMeta::new(pda(&[b"config"], &r), false)],
                data: [&[1u8, kind][..], &value32(a, kind >= 5)].concat(),
            }]
        }
        _ => panic!("unknown governance action {what}\n{USAGE}"),
    };
    print_governance(&vault, &ixs);
}

/// `--value` as an address, or as a little-endian integer in the first 8 bytes.
fn value32(a: &Args, integer: bool) -> [u8; 32] {
    let mut v = [0u8; 32];
    if integer {
        v[..8].copy_from_slice(&a.get("value").parse::<i64>().expect("--value: integer").to_le_bytes());
    } else if a.has("value") {
        v = a.addr("value").to_bytes();
    }
    v
}

fn show(rpc: &Rpc, env: &Env, name: &str) {
    let cfg = rpc.data(&env.config());
    if cfg.len() == 192 {
        let addr = |o: usize| Address::try_from(&cfg[o..o + 32]).unwrap();
        println!("config {}: authority {}, usdc {}, token {}, rewards {}", env.config(), addr(8), addr(40), addr(72), addr(104));
        println!("  min bond usdc {}, token {}; pending kind {} after {}", u64le(&cfg, 136), u64le(&cfg, 144), cfg[3], u64le(&cfg, 152) as i64);
    }
    let l = rpc.data(&env.log(name));
    if l.len() != layout::LOG_LEN {
        println!("log {} not registered", env.log(name));
        return;
    }
    let addr = |d: &[u8], o: usize| Address::try_from(&d[o..o + 32]).unwrap();
    println!("log {} ({name}): service key {}, anchor authority {}", env.log(name), hex::encode(&l[48..80]), addr(&l, 80));
    println!(
        "  service_slashed {}, directory status {}, directory bond {}, locked {}",
        l[3],
        l[5],
        rpc.balance(&env.dir_vault(name)),
        rpc.balance(&env.locked(name))
    );
    let r = rpc.data(&env.ring(name));
    if r.len() == layout::RING_LEN {
        println!(
            "  ring {}: head {}, count {}, last sequence {}, size {}, slot {}",
            env.ring(name),
            u32le(&r, 32),
            u32le(&r, 36),
            u64le(&r, 40),
            u64le(&r, 48),
            u64le(&r, 56)
        );
    } else {
        println!("  ring {}: {} of {} bytes (run grow-ring)", env.ring(name), r.len(), layout::RING_LEN);
    }
    for i in 0..l[4] as usize {
        let e = layout::LOG_LIST + i * layout::ENTRY_LEN;
        let id = String::from_utf8_lossy(&l[e + 1..e + 1 + l[e] as usize]).to_string();
        let account = addr(&l, e + 104);
        let w = rpc.data(&account);
        if w.len() != 336 {
            println!("  [{i}] {id}: witness account {account} missing");
            continue;
        }
        println!(
            "  [{i}] {id}: key {}, status {}, excluded {}, bond {}",
            hex::encode(&l[e + 72..e + 104]),
            w.get(3).copied().unwrap_or(255),
            w.get(4).copied().unwrap_or(255),
            rpc.balance(&addr(&w, 232))
        );
    }
}
