//! Independent signed two-checkpoint evidence, admitted through the real stage entrypoints.
use crate::custody_support::*;
use ed25519_dalek::{Signer as _, SigningKey};
use morse_judge::{
    checkpoint::Checkpoint,
    fork::{Fork, Target},
};
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::Instruction;
use solana_sha256_hasher::hash;
use solana_signer::Signer;
fn wire(cp: &Checkpoint) -> Vec<u8> {
    [
        vec![cp.version, b'K', b'T', b'K'],
        cp.sequence.to_be_bytes().to_vec(),
        cp.tree_size.to_be_bytes().to_vec(),
        cp.tree_root.to_vec(),
        cp.previous_hash.to_vec(),
        cp.timestamp.to_be_bytes().to_vec(),
        cp.service_key.to_vec(),
        cp.signature.to_vec(),
    ]
    .concat()
}
fn ed(key: &[u8], signature: &[u8], message: &[u8]) -> Instruction {
    let mut data = vec![1, 0];
    for v in [
        48,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend(v.to_le_bytes());
    }
    data.extend(key);
    data.extend(signature);
    data.extend(message);
    Instruction {
        program_id: Address::from_str_const("Ed25519SigVerify111111111111111111111111111"),
        accounts: vec![],
        data,
    }
}
pub fn prepare_kind(
    h: &mut Harness,
    witnesses: &[(&[u8], u8, Address)],
    kind: u8,
) -> (Vec<u8>, Address) {
    assert!(matches!(kind, 2 | 3));
    let service = SigningKey::from_bytes(&[11; 32]);
    let time = h.svm.get_sysvar::<Clock>().unix_timestamp as u64 * 1000;
    let mut first = Checkpoint {
        version: 1,
        sequence: 1,
        tree_size: 1,
        tree_root: [3; 32],
        previous_hash: [0; 32],
        timestamp: time - 1000,
        service_key: service.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    first.signature = service.sign(&first.statement()).to_bytes();
    let mut second = first.clone();
    second.tree_root = [4; 32];
    second.timestamp = time;
    second.signature = service.sign(&second.statement()).to_bytes();
    let tagged = witnesses.len() > 8;
    let mut bytes = [
        vec![if tagged { 3 } else { 1 }, b'F', b'R', b'K', kind],
        h.payer.pubkey().as_ref().to_vec(),
        first.service_key.to_vec(),
        wire(&first),
        vec![0],
        wire(&second),
        vec![2 * witnesses.len() as u8],
    ]
    .concat();
    for cp in [&first, &second] {
        for (id, seed, _) in witnesses {
            let statement = [
                b"mesh-msg/v1/transparency-witness".as_slice(),
                id,
                &cp.hash(),
            ]
            .concat();
            bytes.push(id.len() as u8);
            bytes.extend(*id);
            bytes.extend(cp.hash());
            if tagged {
                bytes.push(0);
            }
            bytes.extend(
                SigningKey::from_bytes(&[*seed; 32])
                    .sign(&statement)
                    .to_bytes(),
            );
        }
    }
    if kind == 2 {
        bytes.extend(0u64.to_be_bytes());
        bytes.push(0); // first singleton audit path
        bytes.extend([3u8; 32]);
        bytes.push(0); // second singleton audit path
        bytes.extend([4u8; 32]);
    }
    let stage = Address::find_program_address(
        &[b"stage", h.payer.pubkey().as_ref(), hash(&bytes).as_ref()],
        &h.program,
    )
    .0;
    assert!(h.send(
        &[h.ix(
            vec![
                signer(h.payer.pubkey()),
                ro(h.log),
                rw(stage),
                ro(Address::default())
            ],
            [
                vec![10],
                (bytes.len() as u16).to_le_bytes().to_vec(),
                hash(&bytes).as_ref().to_vec()
            ]
            .concat()
        )],
        false
    ));
    for (i, chunk) in bytes.chunks(900).enumerate() {
        assert!(h.send(
            &[h.ix(
                vec![signer(h.payer.pubkey()), rw(stage)],
                [
                    vec![11],
                    (i as u16 * 900).to_le_bytes().to_vec(),
                    chunk.to_vec()
                ]
                .concat()
            )],
            false
        ));
    }
    assert!(h.send(
        &[h.ix(
            vec![signer(h.payer.pubkey()), ro(h.log), rw(stage)],
            vec![12]
        )],
        false
    ));
    let fork = Fork::parse(&bytes).unwrap();
    let second = match fork.second {
        Target::Checkpoint(cp) => cp,
        _ => unreachable!(),
    };
    for (i, cp) in [fork.first, second].iter().enumerate() {
        let cp = Checkpoint::parse(cp).unwrap();
        assert!(h.send(
            &[
                ed(&cp.service_key, &cp.signature, &cp.statement()),
                h.ix(
                    vec![
                        ro(h.log),
                        rw(stage),
                        ro(Address::from_str_const(
                            "Sysvar1nstructions1111111111111111111111111"
                        ))
                    ],
                    vec![13, i as u8, 0, 0]
                )
            ],
            false
        ));
    }
    for i in 0..fork.attestation_count {
        let att = fork.attestation(i).unwrap();
        let (_, seed, record) = witnesses.iter().find(|(id, _, _)| *id == att.id).unwrap();
        let message = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            att.id,
            att.checkpoint_hash,
        ]
        .concat();
        assert!(h.send(
            &[
                ed(
                    &SigningKey::from_bytes(&[*seed; 32])
                        .verifying_key()
                        .to_bytes(),
                    att.signature,
                    &message
                ),
                h.ix(
                    vec![
                        ro(h.log),
                        rw(stage),
                        ro(Address::from_str_const(
                            "Sysvar1nstructions1111111111111111111111111"
                        )),
                        ro(*record),
                        signer(h.payer.pubkey())
                    ],
                    vec![13, i + 2, 0, 0]
                )
            ],
            false
        ));
    }
    (bytes, stage)
}

/// Actual generation admission and post/cosign transitions from an explicitly
/// empty canonical genesis ring. No accepted checkpoint/bitmap is injected.
pub fn prepare_anchor(
    h: &mut Harness,
    witnesses: &[(&[u8], u8, Address)],
    kind: u8,
) -> (Vec<u8>, Address, Address, Address, [u8; 32]) {
    assert!(matches!(kind, 1..=3));
    let generation = 1u16;
    let set = Address::find_program_address(
        &[b"witness-set", &h.log_id, &generation.to_le_bytes()],
        &h.program,
    )
    .0;
    let mut accounts = vec![
        signer(h.payer.pubkey()),
        signer(h.payer.pubkey()),
        ro(h.config),
        ro(h.log),
        rw(set),
        ro(Address::default()),
    ];
    accounts.extend(witnesses.iter().map(|(_, _, address)| ro(*address)));
    assert!(h.send(
        &[h.ix(
            accounts,
            [vec![5], generation.to_le_bytes().to_vec()].concat()
        )],
        false
    ));
    h.clock(h.svm.get_sysvar::<Clock>().unix_timestamp + morse_judge::state::TIMELOCK_SECONDS);
    assert!(h.send(&[h.ix(vec![rw(h.log), ro(set)], vec![6])], false));
    let ring = Address::find_program_address(&[b"ring", b"custody-test"], &h.program).0;
    let mut empty = vec![0; morse_judge::state::RING_LEN];
    morse_judge::state::initialize_ring(&mut empty, &h.log_id).unwrap();
    Harness::account(&mut h.svm, ring, h.program, empty);
    let service = SigningKey::from_bytes(&[11; 32]);
    let now = h.svm.get_sysvar::<Clock>().unix_timestamp as u64 * 1000;
    let mut first = Checkpoint {
        version: 1,
        sequence: 1,
        tree_size: 1,
        tree_root: [3; 32],
        previous_hash: [0; 32],
        timestamp: now - 1000,
        service_key: service.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    first.signature = service.sign(&first.statement()).to_bytes();
    let mut second = first.clone();
    second.tree_root = [4; 32];
    second.timestamp = now;
    second.signature = service.sign(&second.statement()).to_bytes();
    let instructions = Address::from_str_const("Sysvar1nstructions1111111111111111111111111");
    let attendance = h.svm.get_account(&h.log).unwrap().data[7] == 1;
    let clock = Address::find_program_address(&[b"attendance", &h.log_id], &h.program).0;
    let epoch =
        morse_judge::attendance::epoch_at(h.svm.get_sysvar::<Clock>().unix_timestamp).unwrap();
    let week = Address::find_program_address(
        &[b"attendance-epoch", &h.log_id, &epoch.to_le_bytes()],
        &h.program,
    )
    .0;
    if attendance {
        assert!(h.send(
            &[h.ix(
                vec![
                    signer(h.payer.pubkey()),
                    ro(h.log),
                    ro(clock),
                    rw(week),
                    ro(Address::default())
                ],
                [vec![28], epoch.to_le_bytes().to_vec()].concat()
            )],
            false
        ));
    }
    let mut post_accounts = vec![
        ro(h.log),
        rw(ring),
        signer(h.payer.pubkey()),
        ro(instructions),
    ];
    if attendance {
        post_accounts.extend([rw(clock), rw(week)]);
    }
    assert!(h.send(
        &[
            ed(&second.service_key, &second.signature, &second.statement()),
            h.ix(post_accounts, [vec![3, 0, 0], wire(&second)].concat())
        ],
        false
    ));
    for (index, (id, seed, _)) in witnesses.iter().enumerate() {
        let message = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            id,
            &second.hash(),
        ]
        .concat();
        let key = SigningKey::from_bytes(&[*seed; 32]);
        let signature = key.sign(&message).to_bytes();
        let mut accounts = vec![ro(h.log), rw(ring), ro(set), ro(instructions)];
        if attendance {
            accounts.extend([ro(clock), rw(week)]);
        }
        assert!(h.send(
            &[
                ed(&key.verifying_key().to_bytes(), &signature, &message),
                h.ix(accounts, vec![9, 0, 0, 0, 0, index as u8])
            ],
            false
        ));
    }
    let mut bytes = [
        vec![1, b'F', b'R', b'K', kind],
        h.payer.pubkey().as_ref().to_vec(),
        first.service_key.to_vec(),
        wire(&first),
        vec![1, 0, 0, 0, 0, witnesses.len() as u8],
    ]
    .concat();
    for (id, seed, _) in witnesses {
        let message = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            id,
            &first.hash(),
        ]
        .concat();
        bytes.push(id.len() as u8);
        bytes.extend(*id);
        bytes.extend(first.hash());
        bytes.extend(
            SigningKey::from_bytes(&[*seed; 32])
                .sign(&message)
                .to_bytes(),
        );
    }
    if kind == 2 {
        bytes.extend(0u64.to_be_bytes());
        bytes.push(0);
        bytes.extend([3u8; 32]);
        bytes.push(0);
        bytes.extend([4u8; 32]);
    }
    let stage = Address::find_program_address(
        &[b"stage", h.payer.pubkey().as_ref(), hash(&bytes).as_ref()],
        &h.program,
    )
    .0;
    assert!(h.send(
        &[h.ix(
            vec![
                signer(h.payer.pubkey()),
                ro(h.log),
                rw(stage),
                ro(Address::default())
            ],
            [
                vec![10],
                (bytes.len() as u16).to_le_bytes().to_vec(),
                hash(&bytes).as_ref().to_vec()
            ]
            .concat()
        )],
        false
    ));
    for (index, chunk) in bytes.chunks(900).enumerate() {
        assert!(h.send(
            &[h.ix(
                vec![signer(h.payer.pubkey()), rw(stage)],
                [
                    vec![11],
                    (index as u16 * 900).to_le_bytes().to_vec(),
                    chunk.to_vec()
                ]
                .concat()
            )],
            false
        ));
    }
    assert!(h.send(
        &[h.ix(
            vec![signer(h.payer.pubkey()), ro(h.log), rw(stage)],
            vec![12]
        )],
        false
    ));
    assert!(h.send(
        &[
            ed(&first.service_key, &first.signature, &first.statement()),
            h.ix(
                vec![ro(h.log), rw(stage), ro(instructions)],
                vec![13, 0, 0, 0]
            )
        ],
        false
    ));
    let proof = Fork::parse(&bytes).unwrap();
    for index in 0..proof.attestation_count {
        let att = proof.attestation(index).unwrap();
        let (_, seed, record) = witnesses.iter().find(|(id, _, _)| *id == att.id).unwrap();
        let message = [
            b"mesh-msg/v1/transparency-witness".as_slice(),
            att.id,
            att.checkpoint_hash,
        ]
        .concat();
        assert!(h.send(
            &[
                ed(
                    &SigningKey::from_bytes(&[*seed; 32])
                        .verifying_key()
                        .to_bytes(),
                    att.signature,
                    &message
                ),
                h.ix(
                    vec![
                        ro(h.log),
                        rw(stage),
                        ro(instructions),
                        ro(*record),
                        signer(h.payer.pubkey())
                    ],
                    vec![13, index + 2, 0, 0]
                )
            ],
            false
        ));
    }
    (bytes, stage, ring, set, second.hash())
}
