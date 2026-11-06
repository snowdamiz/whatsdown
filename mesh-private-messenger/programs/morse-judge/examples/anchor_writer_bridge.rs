//! Local proof harness: accepts fully signed Kit transactions and executes the
//! actual judge SBF. Never connects to a chain or loads a wallet secret.
use base64::{engine::general_purpose::STANDARD, Engine};
use litesvm::LiteSVM;
use morse_judge::state::{initialize_ring, RingHeader, LOG_LEN, RING_LEN};
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

fn key(value: &Value, field: &str) -> Address {
    Address::from_str(value[field].as_str().expect("address")).expect("canonical address")
}

fn binary(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().expect("hex bytes")).expect("canonical hex")
}

fn account(svm: &mut LiteSVM, address: Address, owner: Address, data: Vec<u8>) {
    svm.set_account(
        address,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(data.len()),
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .expect("fixture account");
}

fn output(value: Value) {
    println!("{value}");
    io::stdout().flush().expect("flush bridge response");
}

fn main() {
    let mut input = io::stdin().lock().lines();
    let request: Value =
        serde_json::from_str(&input.next().expect("initialize").expect("input")).expect("request");
    assert_eq!(request["method"], "initialize");
    let version = request["version"].as_u64().expect("version") as u8;
    assert!(matches!(version, 1 | 2));
    let service = binary(&request, "service");
    let witness = binary(&request, "witness");
    assert_eq!(service.len(), 32);
    assert_eq!(witness.len(), 32);
    let payer = key(&request, "payer");
    let authority = key(&request, "authority");
    let program = Address::new_from_array([3; 32]);
    let name = b"morse-main";
    let log_id = hash(name).to_bytes();
    let (log, _) = Address::find_program_address(&[b"log", name], &program);
    let (ring, _) = Address::find_program_address(&[b"ring", name], &program);
    let (generation, _) =
        Address::find_program_address(&[b"witness-set", &log_id, &7u16.to_le_bytes()], &program);
    let mut svm = LiteSVM::new();
    let binary = std::env::var_os("MORSE_JUDGE_SBF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_judge.so")
        });
    svm.add_program_from_file(program, binary)
        .expect("build judge SBF first");
    svm.airdrop(&payer, 1_000_000_000)
        .expect("local test lamports");
    svm.airdrop(&authority, 1_000_000)
        .expect("local test authority");
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot = 100;
    clock.unix_timestamp = 1_791_504_000;
    svm.set_sysvar(&clock);
    let mut data = vec![0; LOG_LEN];
    data[..4].copy_from_slice(b"MLG\x01");
    data[4] = version;
    data[6] = name.len() as u8;
    let attendance_enabled = request["attendance"].as_bool().unwrap_or(false);
    data[7] = u8::from(attendance_enabled);
    data[8..8 + name.len()].copy_from_slice(name);
    data[40..72].copy_from_slice(&log_id);
    data[72..104].copy_from_slice(&service);
    data[104..136].copy_from_slice(authority.as_ref());
    data[136..168].copy_from_slice(ring.as_ref());
    data[208..210].copy_from_slice(&7u16.to_le_bytes());
    if version == 2 {
        let origin = b"morseapp.io/log/main/v2";
        data[210..212].copy_from_slice(&(origin.len() as u16).to_le_bytes());
        data[212..212 + origin.len()].copy_from_slice(origin);
    }
    account(&mut svm, log, program, data);
    let mut ring_data = vec![0; RING_LEN];
    initialize_ring(&mut ring_data, &log_id).unwrap();
    account(&mut svm, ring, program, ring_data);
    if attendance_enabled {
        let address = Address::find_program_address(&[b"attendance", &log_id], &program).0;
        let mut data = vec![0; morse_judge::attendance::CLOCK_LEN];
        morse_judge::attendance::initialize_clock(&mut data, &log_id).unwrap();
        morse_judge::attendance::activate_clock(&mut data, clock.unix_timestamp - 10, 99).unwrap();
        account(&mut svm, address, program, data);
    }
    let mut set = vec![0; 2752];
    set[..4].copy_from_slice(b"MWS\x01");
    set[4..36].copy_from_slice(&log_id);
    set[36..38].copy_from_slice(&7u16.to_le_bytes());
    set[38] = 1;
    let id = b"witness-a";
    let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &witness]).to_bytes();
    let (record, _) = Address::find_program_address(&[b"witness", &log_id, &identity], &program);
    set[64..96].copy_from_slice(record.as_ref());
    set[96] = id.len() as u8;
    set[104..104 + id.len()].copy_from_slice(id);
    set[168..200].copy_from_slice(&witness);
    set[200..232].copy_from_slice(payer.as_ref());
    account(&mut svm, generation, program, set);
    output(
        json!({"program":program.to_string(), "log":log.to_string(), "ring":ring.to_string(), "generation":generation.to_string()}),
    );
    for line in input {
        let value: Value = serde_json::from_str(&line.expect("input")).expect("request");
        if value["method"] == "context" {
            svm.expire_blockhash();
            output(json!({"blockhash":svm.latest_blockhash().to_string()}));
            continue;
        }
        if value["method"] == "account" {
            let address = key(&value, "address");
            let offset = value["offset"].as_u64().expect("slice offset") as usize;
            let length = value["length"].as_u64().expect("slice length") as usize;
            assert!(length <= 128 * 104);
            let account = svm.get_account(&address).map(|account| {
                let end = offset.checked_add(length).expect("bounded slice");
                assert!(end <= account.data.len());
                json!({"owner":account.owner.to_string(), "executable":account.executable,
                    "lamports":account.lamports.to_string(), "space":account.data.len().to_string(),
                    "data":[STANDARD.encode(&account.data[offset..end]), "base64"]})
            });
            output(
                json!({"context":{"slot":svm.get_sysvar::<Clock>().slot.to_string()}, "value":account}),
            );
            continue;
        }
        assert_eq!(value["method"], "send");
        let bytes = STANDARD
            .decode(value["transaction"].as_str().expect("wire"))
            .expect("base64");
        assert!(bytes.len() <= 1232);
        let transaction: VersionedTransaction =
            bincode::deserialize(&bytes).expect("Kit transaction");
        let result = svm.send_transaction(transaction);
        let fee = match &result {
            Ok(metadata) => metadata.fee,
            Err(failure) => failure.meta.fee,
        };
        let current = svm.get_account(&ring).unwrap();
        let header = RingHeader::parse(&current.data[..64]).unwrap();
        let entry = &current.data[64 + header.head as usize * 104..][..104];
        output(
            json!({"ok":result.is_ok(), "error":result.err().map(|error| format!("{error:?}")),
            "fee_lamports":fee, "count":header.count, "slot":header.slot.to_string(), "checkpoint_hash":hex::encode(&entry[48..80]),
            "cosign_bitmap":u16::from_le_bytes(entry[96..98].try_into().unwrap()),
            "native_bitmap":u16::from_le_bytes(entry[100..102].try_into().unwrap())}),
        );
    }
}
