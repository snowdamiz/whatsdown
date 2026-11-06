use super::*;
use morse_judge::attendance::{ClockHeader, EpochHeader, CLOCK_LEN, EPOCH_SECONDS};
use solana_sha256_hasher::hash;

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
    set: Address,
    witness: Address,
) {
    let id = hash(b"morse-main").to_bytes();
    let clock_account = Address::find_program_address(&[b"attendance", &id], &program).0;
    let ix = |accounts, data| Instruction {
        program_id: program,
        accounts,
        data,
    };
    let init = ix(
        vec![
            signer(payer.pubkey()),
            AccountMeta::new(payer.pubkey(), true),
            readonly(config),
            readonly(log),
            writable(clock_account),
            readonly(Address::default()),
        ],
        vec![25],
    );
    // A donation cannot occupy the canonical PDA or redirect its rent.
    svm.airdrop(&clock_account, svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    let mut unauthorized = init.clone();
    unauthorized.accounts[0] = signer(outsider.pubkey());
    assert!(!send(svm, &[payer, outsider], &[unauthorized]));
    assert!(send(svm, &[payer], &[init]));
    let enable = ix(
        vec![
            signer(payer.pubkey()),
            readonly(config),
            writable(log),
            writable(clock_account),
        ],
        vec![27],
    );
    assert!(!send(svm, &[payer], std::slice::from_ref(&enable)));
    let grow = ix(vec![readonly(log), writable(clock_account)], vec![26]);
    while svm.get_account(&clock_account).unwrap().data.len() < CLOCK_LEN {
        assert!(send(svm, &[outsider], std::slice::from_ref(&grow)));
    }
    let mut now = svm.get_sysvar::<Clock>();
    let epoch = (now.unix_timestamp / EPOCH_SECONDS) as u64;
    now.unix_timestamp = (epoch + 1) as i64 * EPOCH_SECONDS - 20;
    now.slot += 1;
    svm.set_sysvar(&now);
    let mut unauthorized = enable.clone();
    unauthorized.accounts[0] = signer(outsider.pubkey());
    assert!(!send(svm, &[outsider], &[unauthorized]));
    assert!(send(svm, &[payer], std::slice::from_ref(&enable)));
    assert!(!send(svm, &[payer], &[enable]));
    assert_eq!(svm.get_account(&log).unwrap().data[7], 1);
    assert_eq!(
        ClockHeader::parse(&svm.get_account(&clock_account).unwrap().data)
            .unwrap()
            .first_full_epoch,
        epoch + 1
    );
    let week_address = |epoch: u64| {
        Address::find_program_address(&[b"attendance-epoch", &id, &epoch.to_le_bytes()], &program).0
    };
    let week = week_address(epoch);
    let next = week_address(epoch + 1);
    let open = |epoch: u64| {
        ix(
            vec![
                AccountMeta::new(outsider.pubkey(), true),
                readonly(log),
                readonly(clock_account),
                writable(week_address(epoch)),
                readonly(Address::default()),
            ],
            [vec![28], epoch.to_le_bytes().to_vec()].concat(),
        )
    };
    assert!(!send(svm, &[outsider], &[open(epoch - 1)]));
    assert!(!send(svm, &[outsider], &[open(epoch + 1)]));
    assert!(send(svm, &[outsider], &[open(epoch)]));
    let counts = |svm: &LiteSVM, address| {
        EpochHeader::parse(&svm.get_account(&address).unwrap().data).unwrap()
    };
    let post_with = |sequence, week| {
        let mut instructions = post(program, log, ring, anchor.pubkey(), sequence, 12, 9);
        instructions[1]
            .accounts
            .extend([writable(clock_account), writable(week)]);
        instructions
    };
    let first = post_with(6, week);
    let before = svm.get_account(&ring).unwrap();
    assert!(!send(
        svm,
        &[payer, anchor],
        &post(program, log, ring, anchor.pubkey(), 6, 12, 9)
    ));
    assert_eq!(svm.get_account(&ring).unwrap(), before);
    for position in [4, 5] {
        let mut readonly = first.clone();
        readonly[1].accounts[position].is_writable = false;
        assert!(!send(svm, &[payer, anchor], &readonly));
        let actual = first[1].accounts[position].pubkey;
        let fake = Address::new_unique();
        svm.set_account(fake, svm.get_account(&actual).unwrap())
            .unwrap();
        let mut substituted = first.clone();
        substituted[1].accounts[position].pubkey = fake;
        assert!(!send(svm, &[payer, anchor], &substituted));
        assert_eq!(svm.get_account(&ring).unwrap(), before);
    }
    assert!(send(svm, &[payer, anchor], &first));
    assert!(send(svm, &[payer, anchor], &first));
    assert_eq!(counts(svm, week).posts, 1);
    assert!(send(svm, &[outsider], &[open(epoch)]));
    assert_eq!(counts(svm, week).posts, 1);
    let checkpoint = Checkpoint::parse(&first[1].data[3..]).unwrap();
    let index = RingHeader::parse(&svm.get_account(&ring).unwrap().data[..64])
        .unwrap()
        .head;
    let key = SigningKey::from_bytes(&[65; 32]);
    let statement =
        morse_judge::witness::c2sp_statement(b"morseapp.io/log/main/v2", &first[1].data[3..], 1)
            .unwrap();
    let proof = witness_cases::ed(&key, statement.as_slice());
    let mut data = vec![8];
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(&[0, 0, 15]);
    data.extend_from_slice(&1u64.to_be_bytes());
    data.extend_from_slice(&proof.data[48..112]);
    data.extend_from_slice(&first[1].data[3..]);
    let c2sp = vec![
        proof,
        ix(
            vec![
                readonly(log),
                writable(ring),
                readonly(set),
                readonly(Address::from_str_const(
                    "Sysvar1nstructions1111111111111111111111111",
                )),
                readonly(clock_account),
                writable(week),
            ],
            data,
        ),
    ];
    let mut compact = c2sp.clone();
    compact[1].data = [
        vec![30],
        c2sp[1].data[1..14].to_vec(),
        c2sp[1].data[78..].to_vec(),
    ]
    .concat();
    assert!(!send(svm, &[outsider], &compact[1..]));
    let mut wrong_checkpoint = compact.clone();
    wrong_checkpoint[1].data[14 + 52] ^= 1;
    assert!(!send(svm, &[outsider], &wrong_checkpoint));
    let mut unrelated = compact.clone();
    unrelated[0] = witness_cases::ed(&key, b"valid signature, wrong C2SP statement");
    assert!(!send(svm, &[outsider], &unrelated));
    assert_eq!(counts(svm, week).witnesses, 0);
    assert!(send(svm, &[outsider], &compact));
    assert!(send(svm, &[outsider], &c2sp));
    let mut native = witness_cases::native(
        program,
        log,
        ring,
        set,
        index,
        15,
        b"witness-15",
        &key,
        &checkpoint.hash(),
    );
    native[1]
        .accounts
        .extend([readonly(clock_account), writable(week)]);
    assert!(send(svm, &[outsider], &native));
    assert!(send(svm, &[outsider], &native));
    let receipt = svm.get_account(&week).unwrap().data;
    assert_eq!(&receipt[80..112], witness.as_ref());
    assert_eq!(&receipt[112..120], &1u64.to_le_bytes());
    assert_eq!(counts(svm, week).witnesses, 1);
    assert!(send(svm, &[payer, anchor], &post_with(7, week)));
    let late_cp = Checkpoint::parse(&post_with(7, week)[1].data[3..]).unwrap();
    let mut late = witness_cases::native(
        program,
        log,
        ring,
        set,
        index + 1,
        15,
        b"witness-15",
        &key,
        &late_cp.hash(),
    );
    late[1]
        .accounts
        .extend([readonly(clock_account), writable(week)]);
    now.unix_timestamp += 20;
    now.slot += 50;
    svm.set_sysvar(&now);
    assert!(send(svm, &[outsider], &[open(epoch + 1)]));
    assert!(!send(svm, &[payer, anchor], &post_with(8, week)));
    assert!(send(svm, &[payer, anchor], &post_with(8, next)));
    let mut wrong_week = late.clone();
    wrong_week[1].accounts[5] = writable(next);
    assert!(!send(svm, &[outsider], &wrong_week));
    assert!(send(svm, &[outsider], &late));
    assert_eq!(
        &svm.get_account(&week).unwrap().data[112..120],
        &2u64.to_le_bytes()
    );
    assert_eq!(counts(svm, week).posts, 2);
    assert_eq!(counts(svm, next).posts, 1);
    let seal = ix(vec![readonly(log), writable(week)], vec![29]);
    assert!(!send(svm, &[outsider], std::slice::from_ref(&seal)));
    now.slot += 1501;
    svm.set_sysvar(&now);
    assert!(send(svm, &[outsider], std::slice::from_ref(&seal)));
    assert!(send(svm, &[outsider], &[seal]));
    assert!(counts(svm, week).sealed);
    assert!(!send(svm, &[outsider], &late));
}
