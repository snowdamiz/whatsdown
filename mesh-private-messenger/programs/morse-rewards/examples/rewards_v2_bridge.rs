//! Disposable local SBF bank. No RPC, operator key loading, or native program fallback.
//! Run with MORSE_TOKEN_CUSTODY_FIXTURES_PATH and fresh target/deploy/*.so files.
use base64::{engine::general_purpose::STANDARD, Engine};
use litesvm::LiteSVM;
use morse_rewards::state::{put64, u64_at, MEMBER_LEN};
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_sha256_hasher::hash;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("expected string: {key}"))
}
fn address(s: &str) -> Result<Address, String> {
    s.parse().map_err(|e| format!("address: {e}"))
}
fn key(v: &Value, k: &str) -> Result<Address, String> {
    address(text(v, k)?)
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| "expected nonnegative integer".into())
}
fn ata(owner: Address, mint: Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}
fn raw(v: &Value) -> Result<Vec<u8>, String> {
    hex::decode(text(v, "data_hex")?).map_err(|e| e.to_string())
}
fn bytes_key(d: &[u8], at: usize) -> Address {
    Address::new_from_array(d[at..at + 32].try_into().unwrap())
}
fn account(
    svm: &mut LiteSVM,
    address: Address,
    owner: Address,
    data: Vec<u8>,
) -> Result<(), String> {
    svm.set_account(
        address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            owner,
            data,
            executable: false,
            rent_epoch: 0,
        },
    )
    .map_err(|e| e.to_string())
}
struct Bridge {
    svm: LiteSVM,
    height: u64,
    // A local counter advances only when the current hash is explicitly expired.
    statuses: serde_json::Map<String, Value>,
}
impl Bridge {
    fn initialize(payer: &str) -> Result<(Self, Value), String> {
        let payer = address(payer)?;
        let path = std::env::var("MORSE_TOKEN_CUSTODY_FIXTURES_PATH").map_err(|_| {
            "set MORSE_TOKEN_CUSTODY_FIXTURES_PATH to the immutable custody fixture"
        })?;
        let fixture_bytes = std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
        let fixture: Value = serde_json::from_slice(&fixture_bytes).map_err(|e| e.to_string())?;
        let snapshot = fixture["snapshots"]
            .as_array()
            .ok_or("fixture snapshots")?
            .iter()
            .find(|s| s["name"] == "token-rewards-ready")
            .ok_or("missing token-rewards-ready snapshot")?;
        let accounts = snapshot["accounts"].as_object().ok_or("fixture accounts")?;
        let rewards = key(snapshot, "rewards_program")?;
        let judge = key(snapshot, "program")?;
        let token = key(snapshot, "token_program")?;
        let epoch = number(&snapshot["epoch"])?;
        let mut svm = LiteSVM::new();
        let mut binaries = Vec::new();
        for (name, program, env) in [
            ("judge", judge, "MORSE_JUDGE_SBF_PATH"),
            ("token", token, "MORSE_TOKEN_SBF_PATH"),
            ("rewards", rewards, "MORSE_REWARDS_SBF_PATH"),
        ] {
            let binary = std::env::var_os(env).map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../target/deploy/morse_{name}.so"))
            });
            let bytes = std::fs::read(&binary)
                .map_err(|e| format!("{}: {e}; build SBF first", binary.display()))?;
            svm.add_program(program, &bytes)
                .map_err(|e| format!("load {}: {e}", binary.display()))?;
            let pd = Address::find_program_address(&[program.as_ref()], &LOADER).0;
            let mut metadata = svm.get_account(&pd).ok_or("programdata")?;
            // Reuse deployment pins only; executable code is the newly loaded ELF.
            let old = raw(&accounts[&format!("{name}_data")])?;
            metadata.data[..45].copy_from_slice(&old[..45]);
            svm.set_account(pd, metadata).map_err(|e| e.to_string())?;
            binaries.push(json!({"program":program.to_string(),"path":binary,"sha256":hex::encode(hash(&bytes).to_bytes())}));
        }
        for (role, value) in accounts {
            if value["missing"] == true
                || [
                    "judge",
                    "judge_data",
                    "token",
                    "token_data",
                    "rewards",
                    "rewards_data",
                    "clock",
                    "epoch",
                    "token_epoch",
                ]
                .contains(&role.as_str())
            {
                continue;
            }
            let mut data = raw(value)?;
            let space = usize::try_from(number(&value["space"])?).map_err(|e| e.to_string())?;
            if data.len() != space {
                if role != "attendance_clock"
                    || space != judge_core::attendance::CLOCK_LEN
                    || data.len() != 8416
                {
                    return Err(format!("unsupported truncated fixture account: {role}"));
                }
                data.resize(space, 0);
            }
            if role == "pool" {
                put64(&mut data, 220, 0);
            }
            svm.set_account(
                key(value, "address")?,
                Account {
                    lamports: number(&value["lamports"])?,
                    owner: key(value, "owner")?,
                    data,
                    executable: value["executable"].as_bool().ok_or("executable flag")?,
                    rent_epoch: 0,
                },
            )
            .map_err(|e| e.to_string())?;
        }
        let c: Clock =
            bincode::deserialize(&raw(&accounts["clock"])?).map_err(|e| e.to_string())?;
        svm.set_sysvar(&c);
        svm.airdrop(&payer, 20_000_000_000)
            .map_err(|e| format!("airdrop: {e:?}"))?;
        for role in ["witness0", "witness1"] {
            let witness = key(&accounts[role], "address")?;
            let member = Address::find_program_address(&[b"member", witness.as_ref()], &rewards).0;
            let mut data = vec![0; MEMBER_LEN];
            data[..4].copy_from_slice(b"MRM\x01");
            data[4..36].copy_from_slice(witness.as_ref());
            data[36] = 1;
            put64(&mut data, 48, (epoch - 1) * 604800);
            account(&mut svm, member, rewards, data)?;
        }
        let pool = raw(&accounts["pool"])?;
        let log = raw(&accounts["log"])?;
        let cfg = raw(&accounts["token_config"])?;
        let oracle = raw(&accounts["oracle"])?;
        let usdc = key(&accounts["usdc"], "address")?;
        let morse = key(&accounts["morse"], "address")?;
        let mut witnesses = Vec::new();
        let week = raw(&accounts["attendance_epoch"])?;
        let count = u16::from_le_bytes(week[60..62].try_into().unwrap()) as usize;
        if count < 3 {
            return Err("fixture requires at least three attendance rows".into());
        }
        for row in 0..count {
            let witness = bytes_key(&week, 80 + row * 40);
            let data = svm
                .get_account(&witness)
                .ok_or("attendance witness missing")?
                .data;
            let identity = solana_sha256_hasher::hashv(&[
                b"morse-witness-record-v1",
                &[data[4]],
                &data[8..8 + data[4] as usize],
                &data[72..104],
            ]);
            let bond =
                Address::find_program_address(&[b"bond", &log[40..72], identity.as_ref()], &judge)
                    .0;
            let pending =
                Address::find_program_address(&[b"bond-pending", bond.as_ref()], &judge).0;
            let member = Address::find_program_address(&[b"member", witness.as_ref()], &rewards).0;
            let payout = bytes_key(&data, 136);
            witnesses.push(json!({"row":row,"id":String::from_utf8_lossy(&data[8..8+data[4] as usize]),"key_hex":hex::encode(&data[72..104]),"address":witness.to_string(),"witness":witness.to_string(),"bond":bond.to_string(),"pending":pending.to_string(),"member":member.to_string(),"payout":payout.to_string(),"payout_usdc_ata":ata(payout,usdc).to_string(),"payout_morse_ata":ata(payout,morse).to_string(),"signed":u64_at(&week,112+row*40).to_string()}));
        }
        let pins = json!({"program":rewards.to_string(),"judge":judge.to_string(),"token":token.to_string(),"log_name":snapshot["log_name"],"usdc_mint":usdc.to_string(),"governance":bytes_key(&pool,4).to_string(),"token_governance":bytes_key(&cfg,4).to_string(),"service_key":hex::encode(&log[72..104]),"log_version":log[4],"network_started":u64_at(&pool,164).to_string(),"token_slot":u64_at(&raw(&accounts["token_data"] )?,4).to_string(),"judge_slot":u64_at(&raw(&accounts["judge_data"] )?,4).to_string(),"rewards_slot":u64_at(&raw(&accounts["rewards_data"] )?,4).to_string(),"source_program":bytes_key(&oracle,68).to_string(),"source":bytes_key(&oracle,100).to_string(),"feed":hex::encode(&oracle[132..164]),"source_revision":u64_at(&oracle,292).to_string()});
        let addresses: serde_json::Map<String, Value> = accounts
            .iter()
            .map(|(k, v)| (k.clone(), v["address"].clone()))
            .collect();
        let bank = Self {
            svm,
            height: c.slot,
            statuses: serde_json::Map::new(),
        };
        let mut init = pins.clone();
        init.as_object_mut().unwrap().extend(json!({"pins":pins,"payer":payer.to_string(),"epoch":epoch.to_string(),"addresses":addresses,"witnesses":witnesses,"context":bank.context(),"execution":"local-sbf","signature_verification":true,"provenance":{"fixture_path":path,"fixture_sha256":hex::encode(hash(&fixture_bytes).to_bytes()),"snapshot":"token-rewards-ready","fixture_reused":true,"programs":binaries,"adaptations":["target epoch and token epoch omitted; pool active cleared for actual open/begin/append","two omitted eligible member records supplied with effective time before target epoch","truncated attendance clock tail zero-filled; exported 8416-byte prefix retained","deployment metadata pins retained with fresh SBF ELF code","external payer funded with disposable lamports"],"limits":"Injected local fixture state and LiteSVM, not live RPC, oracle publication or native program execution"}}).as_object().unwrap().clone());
        Ok((bank, init))
    }
    fn context(&self) -> Value {
        let c = self.svm.get_sysvar::<Clock>();
        json!({"slot":c.slot.to_string(),"unix_timestamp":c.unix_timestamp.to_string(),"blockhash":self.svm.latest_blockhash().to_string(),"block_height":self.height.to_string(),"last_valid_block_height":self.height.to_string(),"height_semantics":"local counter; current hash remains valid until explicit expiry or clock advance"})
    }
    fn account_value(&self, address: Address, offset: usize, length: Option<usize>) -> Value {
        self.svm.get_account(&address).map_or(Value::Null,|a| {
            let start=offset.min(a.data.len()); let end=offset.saturating_add(length.unwrap_or(a.data.len())).min(a.data.len());
            json!({"owner":a.owner.to_string(),"executable":a.executable,"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"data":[STANDARD.encode(&a.data[start..end]),"base64"]})
        })
    }
    fn expire(&mut self) -> Result<(), String> {
        self.height = self.height.checked_add(1).ok_or("height overflow")?;
        self.svm.expire_blockhash();
        Ok(())
    }
    fn request(&mut self, request: &Value) -> Result<Value, String> {
        match text(request, "method")? {
            "context" | "latest_blockhash" => Ok(self.context()),
            "rent" => {
                let space =
                    usize::try_from(number(&request["space"])?).map_err(|e| e.to_string())?;
                if space > 10_485_760 {
                    return Err("space exceeds maximum account size".into());
                }
                Ok(
                    json!({"lamports":self.svm.minimum_balance_for_rent_exemption(space).to_string(),"context":self.context()}),
                )
            }
            "fee" => {
                let fee = self
                    .svm
                    .get_fee_structure()
                    .lamports_per_signature
                    .to_string();
                Ok(
                    json!({"lamports_per_signature":fee,"single_signer_fee_lamports":fee,"scope":"base signature fee; execute reports actual fees including any priority fee","context":self.context()}),
                )
            }
            "account" | "accounts" => {
                let offset = request.get("offset").map(number).transpose()?.unwrap_or(0);
                let length = request.get("length").map(number).transpose()?;
                let offset = usize::try_from(offset).map_err(|e| e.to_string())?;
                let length = length
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|e| e.to_string())?;
                let value = if request["method"] == "account" {
                    self.account_value(key(request, "address")?, offset, length)
                } else {
                    let keys = request["addresses"].as_array().ok_or("addresses array")?;
                    let mut values = Vec::new();
                    for k in keys {
                        values.push(self.account_value(
                            address(k.as_str().ok_or("address string")?)?,
                            offset,
                            length,
                        ));
                    }
                    json!(values)
                };
                Ok(json!({"context":self.context(),"value":value}))
            }
            "expire_blockhash" => {
                self.expire()?;
                Ok(self.context())
            }
            "advance_clock" | "warp" => {
                let mut c = self.svm.get_sysvar::<Clock>();
                let now = if request.get("unix_timestamp").is_some() {
                    number(&request["unix_timestamp"])?
                } else {
                    (c.unix_timestamp as u64)
                        .checked_add(number(&request["seconds"])?)
                        .ok_or("clock overflow")?
                };
                let now = i64::try_from(now).map_err(|e| e.to_string())?;
                let slot = request
                    .get("slot")
                    .map(number)
                    .transpose()?
                    .unwrap_or(c.slot.checked_add(1).ok_or("slot overflow")?);
                if now < c.unix_timestamp || slot < c.slot {
                    return Err("clock must advance monotonically".into());
                }
                c.unix_timestamp = now;
                c.slot = slot;
                self.svm.set_sysvar(&c);
                self.expire()?;
                Ok(self.context())
            }
            "status" => Ok(
                json!({"context":self.context(),"value":self.statuses.get(text(request,"signature")?)}),
            ),
            "execute" | "send" => {
                let encoded = request
                    .get("wire")
                    .or_else(|| request.get("transaction"))
                    .and_then(Value::as_str)
                    .ok_or("wire base64 string")?;
                let bytes = STANDARD.decode(encoded).map_err(|e| e.to_string())?;
                if bytes.len() > 1232 {
                    return Err("wire exceeds 1232 bytes".into());
                }
                let tx: VersionedTransaction =
                    bincode::deserialize(&bytes).map_err(|e| format!("transaction wire: {e}"))?;
                if bincode::serialize(&tx).map_err(|e| e.to_string())? != bytes {
                    return Err("noncanonical transaction wire".into());
                }
                let payer = *tx
                    .message
                    .static_account_keys()
                    .first()
                    .ok_or("transaction payer")?;
                let signature = tx
                    .signatures
                    .first()
                    .ok_or("transaction signature")?
                    .to_string();
                let before = self.svm.get_balance(&payer).unwrap_or(0);
                let (ok, error, meta) = match self.svm.send_transaction(tx) {
                    Ok(m) => (true, None, m),
                    Err(e) => (false, Some(format!("{:?}", e.err)), e.meta),
                };
                let after = self.svm.get_balance(&payer).unwrap_or(0);
                let status = json!({"ok":ok,"error":error,"slot":self.svm.get_sysvar::<Clock>().slot.to_string(),"confirmation_status":"local-bank"});
                // A replay refusal does not erase the first execution's status.
                self.statuses
                    .entry(signature.clone())
                    .or_insert(status.clone());
                Ok(
                    json!({"signature":signature,"status":status,"ok":ok,"error":error,"fee_lamports":meta.fee.to_string(),"debit_lamports":before.saturating_sub(after).to_string(),"credit_lamports":after.saturating_sub(before).to_string(),"payer_balance_before":before.to_string(),"payer_balance_after":after.to_string(),"compute_units_consumed":meta.compute_units_consumed,"logs":meta.logs,"context":self.context()}),
                )
            }
            _ => Err("unknown bridge method".into()),
        }
    }
}
fn main() {
    let mut bank = None;
    for line in io::stdin().lock().lines() {
        let response = (|| -> Result<Value, String> {
            let line = line.map_err(|e| e.to_string())?;
            let request: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            if request["method"] == "initialize" {
                if bank.is_some() {
                    return Err("already initialized; start a new process for a fresh bank".into());
                }
                let (b, result) = Bridge::initialize(text(&request, "payer")?)?;
                bank = Some(b);
                Ok(result)
            } else {
                bank.as_mut().ok_or("initialize first")?.request(&request)
            }
        })();
        println!(
            "{}",
            response.unwrap_or_else(|e| json!({"ok":false,"error":e}))
        );
        if io::stdout().flush().is_err() {
            break;
        }
    }
}
#[cfg(test)]
#[path = "support/rewards_v2_bridge_tests.rs"]
mod tests;
