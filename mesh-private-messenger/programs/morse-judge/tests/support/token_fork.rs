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
pub fn prepare(h: &mut Harness, witnesses: &[(&[u8], u8, Address)]) -> (Vec<u8>, Address) {
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
        vec![if tagged { 3 } else { 1 }, b'F', b'R', b'K', 1],
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
pub fn register(h: &mut Harness, id: &[u8], seed: u8) -> (Address, Address, Address, Address) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public = key.verifying_key().to_bytes();
    let statement = [
        b"morse-witness-register-v1".as_slice(),
        id,
        h.operator.pubkey().as_ref(),
        h.payer.pubkey().as_ref(),
    ]
    .concat();
    let signature = key.sign(&statement).to_bytes();
    let identity =
        solana_sha256_hasher::hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &public]);
    let witness =
        Address::find_program_address(&[b"witness", &h.log_id, identity.as_ref()], &h.program).0;
    let bond =
        Address::find_program_address(&[b"bond", &h.log_id, identity.as_ref()], &h.program).0;
    let pending = Address::find_program_address(&[b"bond-pending", bond.as_ref()], &h.program).0;
    let vault = ata(&bond, &h.mint);
    assert!(h.send(
        &[
            ed(&public, &signature, &statement),
            h.ix(
                vec![
                    signer(h.operator.pubkey()),
                    signer(h.payer.pubkey()),
                    ro(h.log),
                    rw(witness),
                    ro(Address::default()),
                    ro(Address::from_str_const(
                        "Sysvar1nstructions1111111111111111111111111"
                    ))
                ],
                [
                    vec![4, 0, 0, id.len() as u8],
                    id.to_vec(),
                    public.to_vec(),
                    h.payer.pubkey().as_ref().to_vec(),
                    vec![0; 32],
                    signature.to_vec()
                ]
                .concat()
            )
        ],
        true
    ));
    (witness, bond, pending, vault)
}
pub fn send_v0(h: &mut Harness, ix: Instruction) -> Result<(usize, usize, u64), String> {
    use solana_address_lookup_table_interface::instruction::{
        create_lookup_table, extend_lookup_table,
    };
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
    use solana_transaction::versioned::VersionedTransaction;
    let mut addresses = Vec::new();
    for meta in &ix.accounts {
        if !meta.is_signer && !addresses.contains(&meta.pubkey) {
            addresses.push(meta.pubkey);
        }
    }
    let slot = h.svm.get_sysvar::<Clock>().slot;
    // This bank deliberately uses a manually bounded slot for oracle fixtures;
    // supply the corresponding recent bank hash to the real ALT program.
    let mut hashes = h.svm.get_sysvar::<solana_slot_hashes::SlotHashes>();
    hashes.add(slot, h.svm.latest_blockhash());
    h.svm.set_sysvar(&hashes);
    let (create, table) = create_lookup_table(h.payer.pubkey(), h.payer.pubkey(), slot);
    assert!(h.send(&[create], false));
    for chunk in addresses.chunks(20) {
        assert!(h.send(
            &[extend_lookup_table(
                table,
                h.payer.pubkey(),
                Some(h.payer.pubkey()),
                chunk.to_vec()
            )],
            false
        ));
    }
    h.svm.warp_to_slot(slot + 1);
    h.svm.expire_blockhash();
    let observation =
        crate::custody_support::collateral_operator::begin(h, std::slice::from_ref(&ix));
    let ix = observation.as_ref().map_or(ix, |value| {
        assert_eq!(value.instructions.len(), 1);
        value.instructions[0].clone()
    });
    let message = v0::Message::try_compile(
        &h.payer.pubkey(),
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        &[AddressLookupTableAccount {
            key: table,
            addresses,
        }],
        h.svm.latest_blockhash(),
    )
    .unwrap();
    let locks = message.account_keys.len()
        + message
            .address_table_lookups
            .iter()
            .map(|t| t.writable_indexes.len() + t.readonly_indexes.len())
            .sum::<usize>();
    assert!(locks <= 64, "actual compiled account locks: {locks}");
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&h.payer]).unwrap();
    let bytes = bincode::serialize(&tx).unwrap().len();
    assert!(bytes <= 1232);
    let result = h
        .svm
        .send_transaction(tx)
        .map(|m| (locks, bytes, m.compute_units_consumed))
        .map_err(|e| format!("{e:?}"));
    if let Some(value) = observation {
        crate::custody_support::collateral_operator::finish(h, value, result.is_ok());
    }
    result
}
