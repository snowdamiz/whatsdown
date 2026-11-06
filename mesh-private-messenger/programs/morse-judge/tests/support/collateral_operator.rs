//! Opt-in local-only SDK/SBF observation and exact-context Mesh packet replay.
//! Never contains signer material and never changes the ordinary harness path.
use super::Harness;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

static WITNESSES: OnceLock<Mutex<BTreeMap<Address, BTreeSet<Address>>>> = OnceLock::new();

fn remember(h: &Harness, instructions: &[Instruction]) {
    let mut table = WITNESSES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap();
    assert!(table.len() < 64 || table.contains_key(&h.program));
    let known = table.entry(h.program).or_default();
    // A test process creates several independent banks with the same program ID.
    // Retain only actual records from this bank before adding the next request.
    known.retain(|key| {
        h.svm.get_account(key).is_some_and(|a| {
            a.owner == h.program && a.data.len() == 320 && &a.data[..4] == b"MWI\x01"
        })
    });
    known.insert(h.witness);
    for ix in instructions.iter().filter(|ix| ix.program_id == h.program) {
        if ix.data.first() == Some(&4) && ix.accounts.len() == 6 {
            known.insert(ix.accounts[3].pubkey);
        }
        for meta in &ix.accounts {
            if h.svm.get_account(&meta.pubkey).is_some_and(|a| {
                a.owner == h.program && a.data.len() == 320 && &a.data[..4] == b"MWI\x01"
            }) {
                known.insert(meta.pubkey);
            }
        }
    }
    assert!(
        known.len() <= 64,
        "bounded local fixture witness observations"
    );
}

const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const CLOCK: Address = Address::from_str_const("SysvarC1ock11111111111111111111111111111111");
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const BUDGET: Address = Address::from_str_const("ComputeBudget111111111111111111111111111111");

fn report(ix: &Instruction) -> serde_json::Value {
    use base64::Engine;
    serde_json::json!({"schemaVersion":1,"programId":ix.program_id.to_string(),"accountCount":ix.accounts.len(),"accountKeys":ix.accounts.iter().map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"signerKeys":ix.accounts.iter().filter(|a|a.is_signer).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"writableKeys":ix.accounts.iter().filter(|a|a.is_writable).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"dataBase64":base64::engine::general_purpose::STANDARD.encode(&ix.data),"dataBytes":ix.data.len()})
}
fn raw(ix: &Instruction) -> serde_json::Value {
    serde_json::json!({"program":ix.program_id.to_string(),"data_hex":hex::encode(&ix.data),"accounts":ix.accounts.iter().map(|a|serde_json::json!({"key":a.pubkey.to_string(),"signer":a.is_signer,"writable":a.is_writable})).collect::<Vec<_>>()})
}
fn decode(value: &serde_json::Value) -> Instruction {
    Instruction {
        program_id: value["program"].as_str().unwrap().parse().unwrap(),
        data: hex::decode(value["data_hex"].as_str().unwrap()).unwrap(),
        accounts: value["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| AccountMeta {
                pubkey: a["key"].as_str().unwrap().parse().unwrap(),
                is_signer: a["signer"].as_bool().unwrap(),
                is_writable: a["writable"].as_bool().unwrap(),
            })
            .collect(),
    }
}
fn pda(program: &Address, seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, program).0
}
fn vault(owner: &Address, mint: &Address) -> Address {
    pda(&ATA, &[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()])
}

fn accounts(h: &Harness, instructions: &[Instruction]) -> serde_json::Value {
    let mut keys = BTreeSet::new();
    // Optional public query roles emitted by Mesh before a replay. Observe them
    // from this bank even when the instruction itself does not mention them.
    // This never manufactures an absence or changes an instruction/account.
    if let Some(path) = std::env::var_os("MORSE_COLLATERAL_OPERATOR_EXTRA_KEYS_PATH") {
        let encoded = std::fs::read(path).unwrap();
        assert!(encoded.len() <= 2 * 1024 * 1024);
        let requests: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let requests = requests["requests"].as_array().unwrap();
        assert!(requests.len() <= 256);
        let packet: Vec<_> = instructions
            .iter()
            .filter(|ix| ix.program_id != BUDGET)
            .map(raw)
            .collect();
        for request in requests {
            if request["expected"] == serde_json::Value::Array(packet.clone()) {
                let requested = request["keys"].as_array().unwrap();
                assert!(requested.len() <= 100);
                for key in requested {
                    keys.insert(key.as_str().unwrap().parse::<Address>().unwrap());
                }
            }
        }
    }
    if let Some(table) = WITNESSES.get() {
        if let Some(known) = table.lock().unwrap().get(&h.program) {
            keys.extend(known.iter().copied());
        }
    }
    if let Some(log) = h.svm.get_account(&h.log).filter(|v| v.data.len() == 352) {
        keys.insert(Address::new_from_array(
            log.data[136..168].try_into().unwrap(),
        ));
        let generation = &log.data[208..210];
        if generation != [0, 0] {
            keys.insert(pda(&h.program, &[b"witness-set", &h.log_id, generation]));
        }
    }
    keys.extend([
        CLOCK,
        h.program,
        pda(&LOADER, &[h.program.as_ref()]),
        h.config,
        h.log,
        h.economy,
        h.mint,
        h.payer.pubkey(),
        h.operator.pubkey(),
    ]);
    let binding = pda(&h.program, &[b"token-binding", &h.log_id]);
    keys.insert(binding);
    let mut programs = None;
    if let Some(value) = h
        .svm
        .get_account(&binding)
        .filter(|a| a.owner == h.program && a.data.len() == 320 && &a.data[..4] == b"MJB\x02")
    {
        programs = Some((
            Address::new_from_array(value.data[68..100].try_into().unwrap()),
            Address::new_from_array(value.data[196..228].try_into().unwrap()),
        ));
    }
    for ix in instructions {
        keys.insert(ix.program_id);
        keys.extend(ix.accounts.iter().map(|a| a.pubkey));
        if ix.program_id == h.program
            && ix.data.first().is_some_and(|t| matches!(t, 31 | 32))
            && ix.accounts.len() == 15
        {
            programs = Some((ix.accounts[6].pubkey, ix.accounts[11].pubkey));
        }
    }
    if let Some((token, rewards)) = programs {
        let mint = pda(&token, &[b"mint"]);
        keys.extend([
            token,
            rewards,
            pda(&LOADER, &[token.as_ref()]),
            pda(&LOADER, &[rewards.as_ref()]),
            pda(&token, &[b"token"]),
            mint,
            pda(&token, &[b"oracle"]),
            pda(&rewards, &[b"pool"]),
        ]);
        let mut owners = BTreeSet::from([h.payer.pubkey(), h.operator.pubkey()]);
        owners.extend(
            instructions
                .iter()
                .flat_map(|ix| ix.accounts.iter())
                .filter(|meta| meta.is_signer)
                .map(|meta| meta.pubkey),
        );
        let locked = pda(&h.program, &[b"locked", &h.log_id]);
        owners.insert(locked);
        for ix in instructions {
            for meta in &ix.accounts {
                if let Some(a) = h
                    .svm
                    .get_account(&meta.pubkey)
                    .filter(|a| a.owner == h.program)
                {
                    if a.data.len() >= 1189
                        && &a.data[..4] == b"MST\x01"
                        && a.data[4] == 1
                        && &a.data[1153..1156] == b"FRK"
                    {
                        let finder =
                            Address::new_from_array(a.data[1157..1189].try_into().unwrap());
                        owners.insert(if finder == Address::default() {
                            Address::new_from_array(a.data[16..48].try_into().unwrap())
                        } else {
                            finder
                        });
                    }
                    if a.data.len() >= 400 && &a.data[..4] == b"MPR\x02" {
                        owners.insert(Address::new_from_array(a.data[72..104].try_into().unwrap()));
                    }
                }
            }
        }
        for owner in owners {
            keys.extend([vault(&owner, &h.mint), vault(&owner, &mint)]);
        }
        let directory = pda(&h.program, &[b"bond", &h.log_id, b"directory"]);
        keys.extend([
            directory,
            pda(&h.program, &[b"bond-pending", directory.as_ref()]),
            vault(&directory, &h.mint),
            vault(&directory, &mint),
        ]);
        let initial: Vec<_> = keys.iter().copied().collect();
        for address in initial {
            if let Some(a) = h.svm.get_account(&address).filter(|a| a.owner == h.program) {
                if a.data.len() == 320 && &a.data[..4] == b"MWI\x01" {
                    let id_len = a.data[4] as usize;
                    if id_len <= 64 {
                        let identity = solana_sha256_hasher::hashv(&[
                            b"morse-witness-record-v1",
                            &[id_len as u8],
                            &a.data[8..8 + id_len],
                            &a.data[72..104],
                        ]);
                        let bond = pda(&h.program, &[b"bond", &h.log_id, identity.as_ref()]);
                        keys.extend([
                            bond,
                            pda(&h.program, &[b"bond-pending", bond.as_ref()]),
                            vault(&bond, &h.mint),
                            vault(&bond, &mint),
                        ]);
                    }
                }
                if a.data.len() == 208 && &a.data[..3] == b"MBD" {
                    keys.extend([
                        pda(&h.program, &[b"bond-pending", address.as_ref()]),
                        vault(&address, &h.mint),
                        vault(&address, &mint),
                    ]);
                }
            }
        }
    }
    let values:serde_json::Map<_,_>=keys.into_iter().map(|address| {
        let value=match h.svm.get_account(&address) {
            None=>serde_json::json!({"address":address.to_string(),"missing":true}),
            Some(a)=>serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"lamports":a.lamports.to_string(),"rent_epoch":a.rent_epoch.to_string(),"space":a.data.len().to_string(),"executable":a.executable,"data_hex":hex::encode(&a.data[..a.data.len().min(9216)]),"full_data_sha256":solana_sha256_hasher::hash(&a.data).to_string()})
        }; (address.to_string(),value)
    }).collect();
    serde_json::Value::Object(values)
}

pub struct Observation {
    path: Option<PathBuf>,
    before: serde_json::Value,
    digest: String,
    sdk: Vec<Instruction>,
    pub instructions: Vec<Instruction>,
    replayed: bool,
}

pub fn begin(h: &Harness, instructions: &[Instruction]) -> Option<Observation> {
    let path = std::env::var_os("MORSE_COLLATERAL_OPERATOR_FIXTURES_PATH").map(PathBuf::from);
    let replay = std::env::var_os("MORSE_COLLATERAL_OPERATOR_REPLAY_PATH").map(PathBuf::from);
    if path.is_none() && replay.is_none() {
        return None;
    }
    remember(h, instructions);
    if !instructions.iter().any(|ix| {
        ix.program_id == h.program
            && ix
                .data
                .first()
                .is_some_and(|tag| matches!(tag,10..=14|31..=45))
    }) {
        return None;
    }
    let before = accounts(h, instructions);
    let digest = solana_sha256_hasher::hash(&serde_json::to_vec(&before).unwrap()).to_string();
    let expected: Vec<_> = instructions
        .iter()
        .filter(|ix| ix.program_id != BUDGET)
        .cloned()
        .collect();
    let mut replacement = instructions.to_vec();
    let mut replayed = false;
    if let Some(file) = replay {
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        for candidate in root["packets"].as_array().unwrap() {
            if candidate["context_digest"] == digest
                && candidate["expected"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(decode)
                    .collect::<Vec<_>>()
                    == expected
            {
                let actual: Vec<_> = candidate["instructions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(decode)
                    .collect();
                // The independent SDK bytes and every account flag must match.
                // A mismatched Mesh result is a test failure, never a fallback.
                assert_eq!(
                    actual, expected,
                    "Mesh collateral packet differs from SDK vector"
                );
                replacement = instructions
                    .iter()
                    .filter(|ix| ix.program_id == BUDGET)
                    .cloned()
                    .chain(actual)
                    .collect();
                replayed = true;
                break;
            }
        }
    }
    Some(Observation {
        path,
        before,
        digest,
        sdk: instructions.to_vec(),
        instructions: replacement,
        replayed,
    })
}

pub fn finish(h: &Harness, observation: Observation, success: bool) {
    let Some(path) = observation.path else {
        return;
    };
    let mut root = if path.exists() {
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap()
    } else {
        serde_json::json!({"schema_version":1,"scope":"actual-local-SBF-collateral-operator","judge":h.program.to_string(),"log_name":"custody-test","log_id":hex::encode(h.log_id),"payer":h.payer.pubkey().to_string(),"operator":h.operator.pubkey().to_string(),"attempts":[]})
    };
    let attempts = root["attempts"].as_array_mut().unwrap();
    assert!(attempts.len() < 256, "bounded operator fixture capture");
    attempts.push(serde_json::json!({"ordinal":attempts.len(),"fee_payer":h.payer.pubkey().to_string(),"operator":h.operator.pubkey().to_string(),"context_digest":observation.digest,"sdk_reports":observation.sdk.iter().filter(|ix|ix.program_id!=BUDGET).map(report).collect::<Vec<_>>(),"sdk":observation.sdk.iter().filter(|ix|ix.program_id!=BUDGET).map(raw).collect::<Vec<_>>(),"success":success,"mesh_replayed":observation.replayed,"before":observation.before,"after":accounts(h,&observation.sdk)}));
    let temporary = path.with_extension("json.partial");
    std::fs::write(&temporary, serde_json::to_vec(&root).unwrap()).unwrap();
    std::fs::rename(temporary, path).unwrap();
}
