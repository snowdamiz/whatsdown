use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use morse_judge::{
    checkpoint::Checkpoint,
    process_instruction,
    state::{RingHeader, RING_LEN, TIMELOCK_SECONDS},
};
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{path::PathBuf, str::FromStr};

#[path = "common/attendance_cases.rs"]
mod attendance_cases;
#[path = "common/witness_cases.rs"]
mod witness_cases;

fn readonly(key: Address) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
fn signer(key: Address) -> AccountMeta {
    AccountMeta::new_readonly(key, true)
}
fn writable(key: Address) -> AccountMeta {
    AccountMeta::new(key, false)
}

fn send(svm: &mut LiteSVM, signers: &[&Keypair], instructions: &[Instruction]) -> bool {
    svm.expire_blockhash();
    let tx = Transaction::new(
        signers,
        Message::new(instructions, Some(&signers[0].pubkey())),
        svm.latest_blockhash(),
    );
    let result = svm.send_transaction(tx);
    if let Err(error) = &result {
        eprintln!("refusal: {:?}", error.err);
    }
    result.is_ok()
}

fn post(
    program: Address,
    log: Address,
    ring: Address,
    authority: Address,
    sequence: u64,
    size: u64,
    root: u8,
) -> Vec<Instruction> {
    let signing = SigningKey::from_bytes(&[11; 32]);
    let mut checkpoint = Checkpoint {
        version: 2,
        sequence,
        tree_size: size,
        tree_root: [root; 32],
        previous_hash: [0; 32],
        timestamp: 1000,
        service_key: signing.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    checkpoint.signature = signing.sign(&checkpoint.statement()).to_bytes();
    let mut ed = vec![1, 0];
    for n in [48u16, u16::MAX, 16, u16::MAX, 112, 146, u16::MAX] {
        ed.extend_from_slice(&n.to_le_bytes());
    }
    ed.extend_from_slice(&checkpoint.service_key);
    ed.extend_from_slice(&checkpoint.signature);
    ed.extend_from_slice(&checkpoint.statement());
    let mut data = vec![3, 0, 0, 2, b'K', b'T', b'K'];
    data.extend_from_slice(&sequence.to_be_bytes());
    data.extend_from_slice(&size.to_be_bytes());
    data.extend_from_slice(&checkpoint.tree_root);
    data.extend_from_slice(&checkpoint.previous_hash);
    data.extend_from_slice(&checkpoint.timestamp.to_be_bytes());
    data.extend_from_slice(&checkpoint.service_key);
    data.extend_from_slice(&checkpoint.signature);
    vec![
        Instruction {
            program_id: Address::from_str("Ed25519SigVerify111111111111111111111111111").unwrap(),
            accounts: vec![],
            data: ed,
        },
        Instruction {
            program_id: program,
            accounts: vec![
                readonly(log),
                writable(ring),
                signer(authority),
                readonly(Address::from_str("Sysvar1nstructions1111111111111111111111111").unwrap()),
            ],
            data,
        },
    ]
}

#[test]
fn unknown_instruction_is_refused() {
    assert!(process_instruction(&Address::new_unique(), &mut [], &[255]).is_err());
}

#[test]
fn real_accounts_enforce_bootstrap_authority_timelock_allocation_and_signed_posts() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_judge.so");
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    let outsider = Keypair::new();
    let anchor = Keypair::new();
    for key in [&payer, &outsider, &anchor] {
        svm.airdrop(&key.pubkey(), 20_000_000_000).unwrap();
    }
    let program = Address::new_unique();
    svm.add_program_from_file(program, binary)
        .expect("build the judge SBF program");
    let loader = Address::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
    let (programdata, _) = Address::find_program_address(&[program.as_ref()], &loader);
    let mut deployed = svm.get_account(&programdata).unwrap();
    deployed.data[12] = 1;
    deployed.data[13..45].copy_from_slice(payer.pubkey().as_ref());
    svm.set_account(programdata, deployed).unwrap();
    let (config, _) = Address::find_program_address(&[b"config"], &program);
    // Pre-funding public PDAs must not let an outsider block initialization.
    svm.airdrop(&config, svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    let mut init_data = vec![0];
    init_data.extend_from_slice(payer.pubkey().as_ref());
    let init = Instruction {
        program_id: program,
        accounts: vec![
            signer(payer.pubkey()),
            AccountMeta::new(payer.pubkey(), true),
            writable(config),
            readonly(program),
            readonly(programdata),
            readonly(Address::default()),
        ],
        data: init_data,
    };
    let mut hijack = init.clone();
    hijack.accounts[0] = signer(outsider.pubkey());
    assert!(!send(&mut svm, &[&payer, &outsider], &[hijack]));
    let mut fake = init.clone();
    fake.accounts[4] = readonly(outsider.pubkey());
    assert!(!send(&mut svm, &[&payer], &[fake]));
    assert!(send(&mut svm, &[&payer], std::slice::from_ref(&init)));
    assert!(!send(&mut svm, &[&payer], &[init]));
    let (log, _) = Address::find_program_address(&[b"log", b"morse-main"], &program);
    let (ring, _) = Address::find_program_address(&[b"ring", b"morse-main"], &program);
    svm.airdrop(&log, svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    svm.airdrop(&ring, svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    let origin = b"morseapp.io/log/main/v2";
    let mut data = vec![1, 10];
    data.extend_from_slice(b"morse-main");
    data.push(2);
    data.extend_from_slice(&SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes());
    data.extend_from_slice(anchor.pubkey().as_ref());
    data.push(origin.len() as u8);
    data.extend_from_slice(origin);
    let register = Instruction {
        program_id: program,
        accounts: vec![
            signer(payer.pubkey()),
            AccountMeta::new(payer.pubkey(), true),
            readonly(config),
            writable(log),
            writable(ring),
            readonly(Address::default()),
        ],
        data,
    };
    let mut unauthorized = register.clone();
    unauthorized.accounts[0] = signer(outsider.pubkey());
    assert!(!send(&mut svm, &[&payer, &outsider], &[unauthorized]));
    assert!(send(&mut svm, &[&payer], std::slice::from_ref(&register)));
    assert!(!send(&mut svm, &[&payer], &[register]));
    assert_eq!(svm.get_account(&ring).unwrap().data.len(), 64);
    let grow = Instruction {
        program_id: program,
        accounts: vec![readonly(log), writable(ring)],
        data: vec![2],
    };
    let funded = svm.get_account(&ring).unwrap();
    let mut underfunded = funded.clone();
    underfunded.lamports = svm.minimum_balance_for_rent_exemption(64);
    svm.set_account(ring, underfunded).unwrap();
    assert!(!send(&mut svm, &[&outsider], std::slice::from_ref(&grow)));
    svm.set_account(ring, funded).unwrap();
    let first = post(program, log, ring, anchor.pubkey(), 1, 8, 2);
    assert!(!send(&mut svm, &[&payer, &anchor], &first));
    let mut length = 64;
    while length < RING_LEN {
        assert!(send(&mut svm, &[&outsider], std::slice::from_ref(&grow)));
        let next = svm.get_account(&ring).unwrap().data.len();
        assert_eq!(next, (length + 10240).min(RING_LEN));
        length = next;
    }
    assert!(!send(&mut svm, &[&payer, &anchor], &first));
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp += TIMELOCK_SECONDS;
    clock.slot = 100;
    svm.set_sysvar(&clock);
    let before = svm.get_account(&ring).unwrap();
    let mut wrong_authority = first.clone();
    wrong_authority[1].accounts[2] = signer(outsider.pubkey());
    assert!(!send(&mut svm, &[&payer, &outsider], &wrong_authority));
    let mut unsigned = first.clone();
    unsigned[1].accounts[2].is_signer = false;
    assert!(!send(&mut svm, &[&payer], &unsigned));
    assert!(!send(&mut svm, &[&payer, &anchor], &first[1..]));
    let mut wrong_key = first.clone();
    wrong_key[1].data[3 + 92] ^= 1;
    assert!(!send(&mut svm, &[&payer, &anchor], &wrong_key));
    let different_service = SigningKey::from_bytes(&[12; 32]);
    let mut foreign = Checkpoint::parse(&first[1].data[3..]).unwrap();
    foreign.service_key = different_service.verifying_key().to_bytes();
    foreign.signature = different_service.sign(&foreign.statement()).to_bytes();
    let mut foreign_post = first.clone();
    foreign_post[0].data[16..48].copy_from_slice(&foreign.service_key);
    foreign_post[0].data[48..112].copy_from_slice(&foreign.signature);
    foreign_post[0].data[112..].copy_from_slice(&foreign.statement());
    foreign_post[1].data[3 + 92..3 + 124].copy_from_slice(&foreign.service_key);
    foreign_post[1].data[3 + 124..].copy_from_slice(&foreign.signature);
    assert!(send(&mut svm, &[&payer], &foreign_post[..1]));
    assert!(!send(&mut svm, &[&payer, &anchor], &foreign_post));
    let mut readonly_ring = first.clone();
    readonly_ring[1].accounts[1].is_writable = false;
    assert!(!send(&mut svm, &[&payer, &anchor], &readonly_ring));
    for key in [log, ring] {
        let original = svm.get_account(&key).unwrap();
        let mut substituted = original.clone();
        substituted.owner = Address::default();
        svm.set_account(key, substituted).unwrap();
        assert!(!send(&mut svm, &[&payer, &anchor], &first));
        svm.set_account(key, original.clone()).unwrap();
        // Even a byte-identical program-owned account at another address is
        // not this log/ring PDA.
        let copy_address = Address::new_unique();
        svm.set_account(copy_address, original).unwrap();
        let mut aliased = first.clone();
        let position = if key == log { 0 } else { 1 };
        aliased[1].accounts[position].pubkey = copy_address;
        assert!(!send(&mut svm, &[&payer, &anchor], &aliased));
    }
    let mut slash_marked = svm.get_account(&log).unwrap();
    let original_log = slash_marked.clone();
    slash_marked.data[5] = 1;
    svm.set_account(log, slash_marked).unwrap();
    assert!(!send(&mut svm, &[&payer, &anchor], &first));
    svm.set_account(log, original_log).unwrap();
    assert_eq!(svm.get_account(&ring).unwrap(), before);
    assert!(send(&mut svm, &[&payer, &anchor], &first));
    let stored = svm.get_account(&ring).unwrap();
    assert_eq!(RingHeader::parse(&stored.data[..64]).unwrap().count, 1);
    clock.slot = 101;
    svm.set_sysvar(&clock);
    assert!(send(&mut svm, &[&payer, &anchor], &first));
    assert_eq!(svm.get_account(&ring).unwrap(), stored);
    assert!(send(
        &mut svm,
        &[&payer, &anchor],
        &post(program, log, ring, anchor.pubkey(), 2, 7, 3)
    ));
    assert_eq!(svm.get_account(&ring).unwrap().data[64 + 104 + 99], 1);
    witness_cases::exercise(
        &mut svm, &payer, &outsider, &anchor, program, config, log, ring,
    );
}
