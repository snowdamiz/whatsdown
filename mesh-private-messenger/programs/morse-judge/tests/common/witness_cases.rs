use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use solana_sha256_hasher::{hash, hashv};

pub(super) fn ed(signing: &SigningKey, message: &[u8]) -> Instruction {
    let mut data = vec![1, 0];
    for n in [
        48u16,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&n.to_le_bytes());
    }
    data.extend_from_slice(&signing.verifying_key().to_bytes());
    data.extend_from_slice(&signing.sign(message).to_bytes());
    data.extend_from_slice(message);
    Instruction {
        program_id: Address::from_str("Ed25519SigVerify111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}

fn sysvar() -> AccountMeta {
    readonly(Address::from_str("Sysvar1nstructions1111111111111111111111111").unwrap())
}

fn registration(
    program: Address,
    log: Address,
    operator: &Keypair,
    id: &[u8],
    key: &SigningKey,
) -> (Address, Vec<Instruction>) {
    let public = key.verifying_key().to_bytes();
    let record = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &public]).to_bytes();
    let log_id = hash(b"morse-main").to_bytes();
    let (address, _) = Address::find_program_address(&[b"witness", &log_id, &record], &program);
    let mut statement = b"morse-witness-register-v1".to_vec();
    statement.extend_from_slice(id);
    statement.extend_from_slice(operator.pubkey().as_ref());
    statement.extend_from_slice(operator.pubkey().as_ref());
    let proof = ed(key, &statement);
    let mut data = vec![4, 0, 0, id.len() as u8];
    data.extend_from_slice(id);
    data.extend_from_slice(&public);
    data.extend_from_slice(operator.pubkey().as_ref());
    data.extend_from_slice(&[37; 32]);
    data.extend_from_slice(&proof.data[48..112]);
    (
        address,
        vec![
            proof,
            Instruction {
                program_id: program,
                accounts: vec![
                    signer(operator.pubkey()),
                    AccountMeta::new(operator.pubkey(), true),
                    readonly(log),
                    writable(address),
                    readonly(Address::default()),
                    sysvar(),
                ],
                data,
            },
        ],
    )
}

fn prepare(
    program: Address,
    config: Address,
    log: Address,
    payer: &Keypair,
    generation: u16,
    witnesses: &[Address],
) -> (Address, Instruction) {
    let log_id = hash(b"morse-main").to_bytes();
    let (set, _) = Address::find_program_address(
        &[b"witness-set", &log_id, &generation.to_le_bytes()],
        &program,
    );
    let mut accounts = vec![
        signer(payer.pubkey()),
        AccountMeta::new(payer.pubkey(), true),
        readonly(config),
        readonly(log),
        writable(set),
        readonly(Address::default()),
    ];
    accounts.extend(witnesses.iter().copied().map(readonly));
    let mut data = vec![5];
    data.extend_from_slice(&generation.to_le_bytes());
    (
        set,
        Instruction {
            program_id: program,
            accounts,
            data,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn native(
    program: Address,
    log: Address,
    ring: Address,
    set: Address,
    index: u16,
    bit: u8,
    id: &[u8],
    key: &SigningKey,
    checkpoint_hash: &[u8],
) -> Vec<Instruction> {
    let mut statement = b"mesh-msg/v1/transparency-witness".to_vec();
    statement.extend_from_slice(id);
    statement.extend_from_slice(checkpoint_hash);
    let proof = ed(key, &statement);
    let mut data = vec![7];
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&[0, 0, bit]);
    data.extend_from_slice(&proof.data[48..112]);
    vec![
        proof,
        Instruction {
            program_id: program,
            accounts: vec![readonly(log), writable(ring), readonly(set), sysvar()],
            data,
        },
    ]
}

#[allow(clippy::too_many_arguments)]
pub fn exercise(
    svm: &mut LiteSVM,
    payer: &Keypair,
    outsider: &Keypair,
    anchor: &Keypair,
    program: Address,
    config: Address,
    log: Address,
    ring: Address,
) {
    let old_key = SigningKey::from_bytes(&[31; 32]);
    let new_key = SigningKey::from_bytes(&[32; 32]);
    let (old, register) = registration(program, log, outsider, b"witness-a", &old_key);
    let mut stolen = register.clone();
    stolen[1].accounts[0] = signer(payer.pubkey());
    assert!(!send(svm, &[payer, outsider], &stolen));
    assert!(!send(svm, &[outsider], &register[1..]));
    let mut unsigned_operator = register.clone();
    unsigned_operator[1].accounts[0].is_signer = false;
    unsigned_operator[1].accounts[1] = AccountMeta::new(payer.pubkey(), true);
    assert!(!send(svm, &[payer], &unsigned_operator));
    let wallet_bytes = outsider.to_bytes();
    let wallet_signing_key = SigningKey::from_bytes(wallet_bytes[..32].try_into().unwrap());
    let (_, shared_key) = registration(program, log, outsider, b"wallet-key", &wallet_signing_key);
    assert!(
        !send(svm, &[outsider], &shared_key),
        "wallet and witness keys must be separate"
    );
    assert!(
        send(svm, &[outsider], &register),
        "operator and witness proof register a witness"
    );
    assert!(!send(svm, &[outsider], &register));
    assert_eq!(
        &svm.get_account(&old).unwrap().data[72..104],
        &old_key.verifying_key().to_bytes()
    );
    let (new, new_registration) = registration(program, log, outsider, b"witness-a", &new_key);
    assert!(send(svm, &[outsider], &new_registration));
    assert_ne!(old, new);
    let long_id = [b'z'; 64];
    let (_, long_registration) = registration(
        program,
        log,
        outsider,
        &long_id,
        &SigningKey::from_bytes(&[77; 32]),
    );
    assert!(
        send(svm, &[outsider], &long_registration),
        "64-byte IDs use bounded hashed PDA seeds"
    );
    let (set1, stage1) = prepare(program, config, log, payer, 1, &[old]);
    let mut unauthorized = stage1.clone();
    unauthorized.accounts[0] = signer(outsider.pubkey());
    assert!(!send(svm, &[payer, outsider], &[unauthorized]));
    let (_, duplicate) = prepare(program, config, log, payer, 1, &[old, old]);
    assert!(!send(svm, &[payer], &[duplicate]));
    let (_, duplicate_id) = prepare(program, config, log, payer, 1, &[old, new]);
    assert!(!send(svm, &[payer], &[duplicate_id]));
    assert!(send(svm, &[payer], std::slice::from_ref(&stage1)));
    assert!(!send(svm, &[payer], &[stage1]));
    let activate = |set| Instruction {
        program_id: program,
        accounts: vec![writable(log), readonly(set)],
        data: vec![6],
    };
    let mut clock = svm.get_sysvar::<Clock>();
    clock.unix_timestamp += TIMELOCK_SECONDS - 1;
    svm.set_sysvar(&clock);
    assert!(!send(svm, &[outsider], &[activate(set1)]));
    clock.unix_timestamp += 1;
    svm.set_sysvar(&clock);
    assert!(send(svm, &[outsider], &[activate(set1)]));
    assert_eq!(&svm.get_account(&log).unwrap().data[208..210], &[1, 0]);
    let cp1 = post(program, log, ring, anchor.pubkey(), 3, 9, 4);
    assert!(send(svm, &[payer, anchor], &cp1));
    let checkpoint = Checkpoint::parse(&cp1[1].data[3..]).unwrap();
    let signed = native(
        program,
        log,
        ring,
        set1,
        2,
        0,
        b"witness-a",
        &old_key,
        &checkpoint.hash(),
    );
    let wrong = native(
        program,
        log,
        ring,
        set1,
        2,
        0,
        b"witness-a",
        &new_key,
        &checkpoint.hash(),
    );
    assert!(send(svm, &[payer], &wrong[..1]));
    assert!(!send(svm, &[payer], &wrong));
    assert!(!send(svm, &[payer], &signed[1..]));
    let mut readonly_ring = signed.clone();
    readonly_ring[1].accounts[1].is_writable = false;
    assert!(!send(svm, &[payer], &readonly_ring));
    let mut outside_set = signed.clone();
    outside_set[1].data[5] = 1;
    assert!(!send(svm, &[payer], &outside_set));
    let set_record = svm.get_account(&set1).unwrap();
    let mut wrong_owner = set_record.clone();
    wrong_owner.owner = Address::default();
    svm.set_account(set1, wrong_owner).unwrap();
    assert!(!send(svm, &[payer], &signed));
    svm.set_account(set1, set_record.clone()).unwrap();
    let copied_address = Address::new_unique();
    svm.set_account(copied_address, set_record).unwrap();
    let mut copied = signed.clone();
    copied[1].accounts[2] = readonly(copied_address);
    assert!(!send(svm, &[payer], &copied));
    let mut nonexistent = signed.clone();
    nonexistent[1].data[1..3].copy_from_slice(&4095u16.to_le_bytes());
    assert!(!send(svm, &[payer], &nonexistent));
    let mut future_clock = clock.clone();
    future_clock.slot -= 1;
    svm.set_sysvar(&future_clock);
    assert!(!send(svm, &[payer], &signed));
    svm.set_sysvar(&clock);
    let ring_before = svm.get_account(&ring).unwrap();
    let mut overwritten = ring_before.clone();
    overwritten.data[64 + 2 * 104 + 48] ^= 1;
    svm.set_account(ring, overwritten).unwrap();
    assert!(
        !send(svm, &[payer], &signed),
        "a signature cannot follow an overwritten ring index"
    );
    svm.set_account(ring, ring_before).unwrap();
    assert!(send(svm, &[payer], &signed));
    let offset = 64 + 2 * 104;
    let recorded = svm.get_account(&ring).unwrap();
    assert_eq!(&recorded.data[offset + 96..offset + 98], &[1, 0]);
    assert_eq!(&recorded.data[offset + 100..offset + 104], &[1, 0, 1, 0]);
    assert!(send(svm, &[payer], &signed));
    assert_eq!(recorded, svm.get_account(&ring).unwrap());
    let (set2, stage2) = prepare(program, config, log, payer, 2, &[new]);
    assert!(send(svm, &[payer], &[stage2]));
    clock.unix_timestamp += TIMELOCK_SECONDS;
    svm.set_sysvar(&clock);
    assert!(send(svm, &[outsider], &[activate(set2)]));
    assert!(!send(svm, &[outsider], &[activate(set1)]));
    let mut substituted = signed.clone();
    substituted[1].accounts[2] = readonly(set2);
    assert!(!send(svm, &[payer], &substituted));
    assert!(
        send(svm, &[payer], &signed),
        "rotation preserves old generation attribution"
    );
    let cp2 = post(program, log, ring, anchor.pubkey(), 4, 10, 5);
    assert!(send(svm, &[payer, anchor], &cp2));
    let checkpoint2 = Checkpoint::parse(&cp2[1].data[3..]).unwrap();
    let seconds = clock.unix_timestamp as u64;
    let message = format!(
        "cosignature/v1\ntime {seconds}\nmorseapp.io/log/main/v2\n10\n{}\nmorse-checkpoint {}\n",
        STANDARD.encode(checkpoint2.tree_root),
        STANDARD.encode(&cp2[1].data[3..])
    );
    let proof = ed(&new_key, message.as_bytes());
    let mut c2sp_data = vec![8, 3, 0, 0, 0, 0];
    c2sp_data.extend_from_slice(&seconds.to_be_bytes());
    c2sp_data.extend_from_slice(&proof.data[48..112]);
    c2sp_data.extend_from_slice(&cp2[1].data[3..]);
    let c2sp = vec![
        proof,
        Instruction {
            program_id: program,
            accounts: vec![readonly(log), writable(ring), readonly(set2), sysvar()],
            data: c2sp_data,
        },
    ];
    let mut foreign = c2sp.clone();
    let other_message = message.replace("main/v2", "canary/v2");
    foreign[0] = ed(&new_key, other_message.as_bytes());
    let foreign_sig = foreign[0].data[48..112].to_vec();
    foreign[1].data[14..78].copy_from_slice(&foreign_sig);
    assert!(send(svm, &[payer], &foreign[..1]));
    assert!(
        !send(svm, &[payer], &foreign),
        "a valid canary signature cannot cosign main"
    );
    let mut changed_checkpoint = c2sp.clone();
    changed_checkpoint[1].data[78 + 52] ^= 1;
    assert!(!send(svm, &[payer], &changed_checkpoint));
    assert!(send(svm, &[outsider], &c2sp));
    let c2sp_recorded = svm.get_account(&ring).unwrap();
    let c2sp_offset = 64 + 3 * 104;
    assert_eq!(
        &c2sp_recorded.data[c2sp_offset + 96..c2sp_offset + 98],
        &[1, 0]
    );
    assert_eq!(
        &c2sp_recorded.data[c2sp_offset + 100..c2sp_offset + 104],
        &[0, 0, 2, 0]
    );
    assert!(send(svm, &[payer], &c2sp));
    assert_eq!(c2sp_recorded, svm.get_account(&ring).unwrap());
    let new_signed = native(
        program,
        log,
        ring,
        set2,
        3,
        0,
        b"witness-a",
        &new_key,
        &checkpoint2.hash(),
    );
    let old_signed = native(
        program,
        log,
        ring,
        set1,
        3,
        0,
        b"witness-a",
        &old_key,
        &checkpoint2.hash(),
    );
    assert!(!send(svm, &[payer], &old_signed));
    clock.slot += 1500;
    svm.set_sysvar(&clock);
    assert!(
        send(svm, &[outsider], &new_signed),
        "anyone pays at the inclusive slot boundary"
    );
    clock.slot += 1;
    svm.set_sysvar(&clock);
    assert!(!send(svm, &[outsider], &new_signed));
    assert!(!send(svm, &[outsider], &c2sp));
    assert_eq!(
        &svm.get_account(&set1).unwrap().data[64 + 104..64 + 136],
        &old_key.verifying_key().to_bytes()
    );
    // Maximum-size sets are real transactions, with all 16 registered records.
    let mut members = vec![];
    for index in 0..16u8 {
        let key = SigningKey::from_bytes(&[50 + index; 32]);
        let id = format!("witness-{index:02}");
        let (address, register) = registration(program, log, outsider, id.as_bytes(), &key);
        assert!(send(svm, &[outsider], &register));
        members.push(address);
    }
    let (_, reordered) = prepare(program, config, log, payer, 3, &[members[1], members[0]]);
    assert!(!send(svm, &[payer], &[reordered]));
    let (alias, alias_registration) = registration(program, log, outsider, b"witness-z", &new_key);
    assert!(send(svm, &[outsider], &alias_registration));
    let (_, repeated_key) = prepare(program, config, log, payer, 3, &[new, alias]);
    assert!(!send(svm, &[payer], &[repeated_key]));
    let (set3, full) = prepare(program, config, log, payer, 3, &members);
    assert!(send(svm, &[payer], &[full]));
    assert_eq!(svm.get_account(&set3).unwrap().data[38], 16);
    clock.unix_timestamp += TIMELOCK_SECONDS;
    svm.set_sysvar(&clock);
    assert!(send(svm, &[outsider], &[activate(set3)]));
    let last_bit_checkpoint = post(program, log, ring, anchor.pubkey(), 5, 11, 6);
    assert!(send(svm, &[payer, anchor], &last_bit_checkpoint));
    let cp = Checkpoint::parse(&last_bit_checkpoint[1].data[3..]).unwrap();
    let last_bit = native(
        program,
        log,
        ring,
        set3,
        4,
        15,
        b"witness-15",
        &SigningKey::from_bytes(&[65; 32]),
        &cp.hash(),
    );
    assert!(send(svm, &[outsider], &last_bit));
    assert_eq!(
        &svm.get_account(&ring).unwrap().data[64 + 4 * 104 + 96..64 + 4 * 104 + 98],
        &[0, 128]
    );
    let original = svm.get_account(&log).unwrap();
    let mut exhausted = original.clone();
    exhausted.data[208..210].copy_from_slice(&u16::MAX.to_le_bytes());
    svm.set_account(log, exhausted).unwrap();
    let (_, wrapped) = prepare(program, config, log, payer, 0, &[new]);
    assert!(!send(svm, &[payer], &[wrapped]));
    svm.set_account(log, original).unwrap();
    attendance_cases::exercise(
        svm,
        payer,
        outsider,
        anchor,
        program,
        config,
        log,
        ring,
        set3,
        members[15],
    );
}
