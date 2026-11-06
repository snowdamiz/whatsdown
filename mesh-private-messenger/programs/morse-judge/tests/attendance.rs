use morse_judge::{
    attendance::{
        activate_clock, initialize_clock, initialize_epoch, record_post, record_signature,
        seal_epoch, ClockHeader, EpochHeader, CLOCK_LEN, EPOCH_LEN, EPOCH_SECONDS,
    },
    witness::COSIGN_WINDOW,
};

fn records(epoch: u64) -> (Vec<u8>, Vec<u8>) {
    let mut clock = vec![0; CLOCK_LEN];
    initialize_clock(&mut clock, &[9; 32]).unwrap();
    activate_clock(&mut clock, epoch as i64 * EPOCH_SECONDS + 10, 100).unwrap();
    let mut week = vec![0; EPOCH_LEN];
    initialize_epoch(&mut week, &[9; 32], epoch).unwrap();
    (clock, week)
}

#[test]
fn attendance_survives_ring_wrap_and_uses_posting_week() {
    let (mut clock, mut week) = records(10);
    for n in 0..4100u64 {
        record_post(&mut clock, &mut week, (n % 4096) as u16, 101 + n, 10).unwrap();
        record_signature(&clock, &mut week, (n % 4096) as u16, 101 + n, &[7; 32]).unwrap();
    }
    assert_eq!(EpochHeader::parse(&week).unwrap().posts, 4100);
    assert_eq!(u64::from_le_bytes(week[112..120].try_into().unwrap()), 4100);
    // A slot from the overwritten entry cannot be credited to its replacement.
    assert!(record_signature(&clock, &mut week, 0, 101, &[8; 32]).is_err());
    let mut next = vec![0; EPOCH_LEN];
    initialize_epoch(&mut next, &[9; 32], 11).unwrap();
    record_post(&mut clock, &mut next, 4, 4201, 11).unwrap();
    // A late cosign belongs to its posting week, regardless of current week.
    assert!(record_signature(&clock, &mut next, 3, 4200, &[8; 32]).is_err());
    record_signature(&clock, &mut week, 3, 4200, &[8; 32]).unwrap();
    assert_eq!(EpochHeader::parse(&week).unwrap().witnesses, 2);
    assert_eq!(EpochHeader::parse(&next).unwrap().posts, 1);
}

#[test]
fn seal_waits_for_both_week_end_and_final_cosign_window() {
    let (mut clock, mut week) = records(10);
    record_post(&mut clock, &mut week, 0, 1000, 10).unwrap();
    assert!(seal_epoch(&mut week, 11 * EPOCH_SECONDS - 1, 1001 + COSIGN_WINDOW).is_err());
    assert!(seal_epoch(&mut week, 11 * EPOCH_SECONDS, 1000 + COSIGN_WINDOW).is_err());
    seal_epoch(&mut week, 11 * EPOCH_SECONDS, 1001 + COSIGN_WINDOW).unwrap();
    let saved = week.clone();
    assert!(record_signature(&clock, &mut week, 0, 1000, &[7; 32]).is_err());
    assert!(record_post(&mut clock, &mut week, 1, 3000, 10).is_err());
    assert_eq!(week, saved);
    // Permissionless retries do not alter a sealed receipt.
    seal_epoch(&mut week, 11 * EPOCH_SECONDS, 1001 + COSIGN_WINDOW).unwrap();
    assert_eq!(week, saved);
}

#[test]
fn activation_and_counters_fail_closed() {
    let (mut clock, mut week) = records(10);
    assert_eq!(ClockHeader::parse(&clock).unwrap().first_full_epoch, 11);
    assert!(activate_clock(&mut clock, 11 * EPOCH_SECONDS, 200).is_err());
    assert!(record_post(&mut clock, &mut week, 4096, 101, 10).is_err());
    assert!(record_post(&mut clock, &mut week, 0, 99, 10).is_err());
    let mut other = vec![0; EPOCH_LEN];
    initialize_epoch(&mut other, &[8; 32], 10).unwrap();
    assert!(record_post(&mut clock, &mut other, 0, 101, 10).is_err());
    record_post(&mut clock, &mut week, 0, 101, 10).unwrap();
    record_signature(&clock, &mut week, 0, 101, &[7; 32]).unwrap();
    // The processor additionally deduplicates by the ring bitmap; no row may
    // exceed the denominator even if a caller violates that contract.
    assert!(record_signature(&clock, &mut week, 0, 101, &[7; 32]).is_err());
    let mut damaged = week.clone();
    damaged[63] = 1;
    assert!(EpochHeader::parse(&damaged).is_err());
    damaged = week.clone();
    damaged[120] = 1;
    assert!(EpochHeader::parse(&damaged).is_err());
    week[44..52].copy_from_slice(&u64::MAX.to_le_bytes());
    let saved = week.clone();
    assert!(record_post(&mut clock, &mut week, 1, 102, 10).is_err());
    assert_eq!(week, saved);
}

#[test]
fn untracked_pre_activation_entries_are_never_backfilled() {
    let (clock, mut week) = records(10);
    assert!(!record_signature(&clock, &mut week, 0, 99, &[7; 32]).unwrap());
    assert!(!record_signature(&clock, &mut week, 0, 100, &[7; 32]).unwrap());
    assert!(record_signature(&clock, &mut week, 0, 101, &[7; 32]).is_err());
    assert_eq!(EpochHeader::parse(&week).unwrap().posts, 0);
}
