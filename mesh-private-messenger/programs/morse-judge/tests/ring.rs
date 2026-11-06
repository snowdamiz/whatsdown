use morse_judge::{
    checkpoint::Checkpoint,
    state::{append_anchor, initialize_ring, RingHeader, RING_LEN},
};

fn checkpoint(sequence: u64, size: u64, root: u8) -> Checkpoint {
    Checkpoint {
        version: 2,
        sequence,
        tree_size: size,
        tree_root: [root; 32],
        previous_hash: [0; 32],
        timestamp: 1000,
        service_key: [5; 32],
        signature: [6; 64],
    }
}

#[test]
fn ring_wraps_preserves_u64_and_resets_old_cosignatures() {
    let mut ring = vec![0; RING_LEN];
    initialize_ring(&mut ring, &[17; 32]).unwrap();
    assert_eq!(RingHeader::parse(&ring[..64]).unwrap().count, 0);
    for sequence in 1..=4097 {
        append_anchor(&mut ring, &checkpoint(sequence, sequence, 34), 500, 7).unwrap();
        // A future cosign handler updates these fields; overwrite must clear them.
        let head = RingHeader::parse(&ring[..64]).unwrap().head as usize;
        ring[64 + head * 104 + 96..64 + head * 104 + 98].fill(255);
        ring[64 + head * 104 + 100..64 + head * 104 + 102].fill(255);
    }
    let header = RingHeader::parse(&ring[..64]).unwrap();
    assert_eq!(
        (
            header.head,
            header.count,
            header.sequence,
            header.size,
            header.slot
        ),
        (0, 4096, 4097, 4097, 500)
    );
    let offset = append_anchor(&mut ring, &checkpoint(u64::MAX, u64::MAX, 34), 501, 8)
        .unwrap()
        .unwrap();
    assert_eq!(offset, 1);
    let entry = &ring[168..272];
    assert_eq!(&entry[..16], &[255; 16]);
    assert_eq!(&entry[96..104], &[0, 0, 2, 0, 0, 0, 8, 0]);
    // Independent account fixture used by the Mesh decoder.
    assert_eq!(&ring[..4], b"MRG\x01");
    assert_eq!(&ring[4..36], &[17; 32]);
}

#[test]
fn retries_do_not_refresh_slots_and_regressions_are_retained() {
    let mut ring = vec![0; RING_LEN];
    initialize_ring(&mut ring, &[17; 32]).unwrap();
    let first = checkpoint(10, 20, 1);
    assert_eq!(append_anchor(&mut ring, &first, 100, 0).unwrap(), Some(0));
    let before = ring.clone();
    assert_eq!(append_anchor(&mut ring, &first, 200, 0).unwrap(), None);
    assert_eq!(ring, before);
    for next in [
        checkpoint(11, 19, 1),
        checkpoint(9, 21, 2),
        checkpoint(9, 21, 3),
    ] {
        let index = append_anchor(&mut ring, &next, 201, 0).unwrap().unwrap();
        assert_eq!(ring[64 + index as usize * 104 + 99], 1);
    }
    let before = ring.clone();
    assert!(append_anchor(&mut ring, &checkpoint(12, 22, 1), 200, 0).is_err());
    assert_eq!(ring, before);
}

#[test]
fn incomplete_and_noncanonical_rings_are_refused_before_writing() {
    for size in [0, 63, 64, RING_LEN - 1, RING_LEN + 1] {
        let mut ring = vec![0; size];
        if size >= 64 {
            initialize_ring(&mut ring, &[17; 32]).unwrap();
        }
        let before = ring.clone();
        assert!(append_anchor(&mut ring, &checkpoint(1, 1, 1), 100, 0).is_err());
        assert_eq!(ring, before);
    }
    let mut ring = vec![0; RING_LEN];
    initialize_ring(&mut ring, &[17; 32]).unwrap();
    ring[36..38].copy_from_slice(&4096u16.to_le_bytes());
    assert!(append_anchor(&mut ring, &checkpoint(1, 1, 1), 100, 0).is_err());
}
