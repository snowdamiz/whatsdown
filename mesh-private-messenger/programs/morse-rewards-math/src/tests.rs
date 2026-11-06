use super::*;

const MONTHLY: u64 = 300_000_000;
const WEEK: i64 = 604_800;

#[test]
fn exact_attendance_thresholds_use_full_u64_counts() {
    for (signed, posts, expected) in [
        (0, 0, 0),
        (0, 100, 0),
        (80, 100, 0),
        (81, 100, 20),
        (90, 100, 200),
        (94, 100, 280),
        (95, 100, 300),
        (100, 100, 300),
        (4, 5, 0),
        (5, 6, 4),
        (u64::MAX, u64::MAX, 3 * u64::MAX as u128),
        (u64::MAX - 1, u64::MAX, 3 * u64::MAX as u128),
    ] {
        assert_eq!(attendance_weight(signed, posts), Ok(expected));
    }
    assert_eq!(
        attendance_weight(101, 100),
        Err(MathError::InvalidAttendance)
    );
    assert_eq!(attendance_weight(1, 0), Err(MathError::InvalidAttendance));
}

#[test]
fn multiply_divide_matches_unbounded_integer_reference_vectors() {
    for (index, line) in include_str!("../tests/fixtures/multiply_divide.csv")
        .lines()
        .enumerate()
        .skip(1)
    {
        let mut columns = line.split(',');
        let a = columns.next().unwrap().parse().unwrap();
        let b = columns.next().unwrap().parse().unwrap();
        let divisor = columns.next().unwrap().parse().unwrap();
        let expected = match columns.next().unwrap() {
            "division_by_zero" => Err(MathError::DivisionByZero),
            "overflow" => Err(MathError::Overflow),
            value => Ok(value.parse().unwrap()),
        };
        assert_eq!(multiply_divide(a, b, divisor), expected, "vector {index}");
        assert_eq!(
            multiply_divide(b, a, divisor),
            expected,
            "swapped vector {index}"
        );
    }
}

#[test]
fn calendar_months_match_shared_mesh_policy_vectors() {
    // Values also asserted by the authoritative Mesh reward policy tests.
    assert_eq!(first_year_floor(0, 0, WEEK), Ok(67_741_935));
    assert_eq!(first_year_floor(0, WEEK, 2 * WEEK), Ok(67_741_935));
    for line in include_str!("../tests/fixtures/calendar_floor.csv")
        .lines()
        .skip(1)
    {
        let mut columns = line.split(',');
        let label = columns.next().unwrap();
        let origin = columns.next().unwrap().parse().unwrap();
        let start = columns.next().unwrap().parse().unwrap();
        let finish = columns.next().unwrap().parse().unwrap();
        let expected = columns.next().unwrap().parse().unwrap();
        assert_eq!(
            first_year_floor(origin, start, finish),
            Ok(expected),
            "{label}"
        );
    }
}

#[test]
fn weekly_calendar_entitlements_telescope_exactly_without_anniversary_drift() {
    for (origin, final_anniversary) in [
        (1_706_704_496, 1_738_326_896), // Jan 31 2024 12:34:56 UTC
        (1_709_168_496, 1_740_704_496), // Feb 29 2024 01:01:36 UTC
        (4_107_546_096, 4_139_082_096), // Mar 1 2100 01:01:36 UTC
    ] {
        let mut start = origin;
        let mut sum = 0;
        while start < final_anniversary {
            let finish = core::cmp::min(start + WEEK, final_anniversary);
            sum += first_year_floor(origin, start, finish).unwrap();
            start = finish;
        }
        assert_eq!(sum, 12 * MONTHLY);
        assert_eq!(first_year_floor(origin, origin - WEEK, origin), Ok(0));
        assert_eq!(first_year_floor(origin, final_anniversary, i64::MAX), Ok(0));
        assert_eq!(first_year_floor(origin, origin, i64::MAX), Ok(12 * MONTHLY));
    }
}

#[test]
fn malformed_times_and_unrepresentable_calendar_anniversaries_are_rejected() {
    for (origin, start, finish) in [
        (-1, 0, 1),
        (0, -1, 1),
        (0, 2, 1),
        (i64::MAX, 0, i64::MAX),
        (8_210_266_876_800, 0, 1), // Jan 1 262143, beyond Mesh DateTime
        (8_210_235_340_800, 0, 1), // Jan 1 262142, year anniversary beyond Mesh DateTime
    ] {
        assert_eq!(
            first_year_floor(origin, start, finish),
            Err(MathError::InvalidTime)
        );
    }
    assert_eq!(first_year_floor(0, 1, 1), Ok(0));
    assert_eq!(first_year_floor(0, i64::MAX, i64::MAX), Ok(0));
    // Dec 31 262141 23:59:59 through Dec 31 262142 23:59:59 is the
    // final complete anniversary year supported by Mesh's DateTime.
    assert_eq!(
        first_year_floor(8_210_235_340_799, 8_210_235_340_799, 8_210_266_876_799),
        Ok(12 * MONTHLY),
    );
}

#[test]
fn floor_scaling_and_distribution_reject_invalid_ratios_and_overflow() {
    assert_eq!(scaled_floor(MONTHLY, 0, 0), Ok(0));
    assert_eq!(scaled_floor(MONTHLY, 200, 100), Ok(200_000_000));
    assert_eq!(
        scaled_floor(u64::MAX, 3 * u64::MAX as u128, u64::MAX),
        Ok(u64::MAX)
    );
    assert_eq!(
        scaled_floor(MONTHLY, 301, 100),
        Err(MathError::InvalidWeight)
    );
    assert_eq!(scaled_floor(MONTHLY, 1, 0), Err(MathError::InvalidWeight));
    assert_eq!(allocation(99, 0, 0, 0), Ok(0));
    assert_eq!(allocation(99, 1, 0, 0), Err(MathError::InvalidWeight));
    assert_eq!(allocation(99, 2, 1, 0), Err(MathError::InvalidWeight));
    assert_eq!(allocation(1, 1, 1, u64::MAX), Err(MathError::Overflow));
    assert_eq!(allocation(u64::MAX, 1, 1, 0), Ok(u64::MAX));
    assert_eq!(allocation(u64::MAX, u128::MAX, u128::MAX, 0), Ok(u64::MAX));
}

fn settle(
    base_floor: u64,
    posts: u64,
    signed: &[u64],
    available: u64,
    subsidy: u64,
) -> Result<(u64, u64, u64), MathError> {
    let mut required = 0u64;
    let mut total_weight = 0u128;
    for &count in signed {
        let weight = attendance_weight(count, posts)?;
        required = required
            .checked_add(scaled_floor(base_floor, weight, posts)?)
            .ok_or(MathError::Overflow)?;
        total_weight = total_weight
            .checked_add(weight)
            .ok_or(MathError::Overflow)?;
    }
    let funding = reserve_floor(available, subsidy, required)?;
    let mut allocated = 0u64;
    for &count in signed {
        let weight = attendance_weight(count, posts)?;
        let floor = scaled_floor(base_floor, weight, posts)?;
        allocated = allocated
            .checked_add(allocation(funding.remainder, weight, total_weight, floor)?)
            .ok_or(MathError::Overflow)?;
    }
    let carry = available.checked_add(funding.subsidy_used).unwrap() - allocated;
    Ok((funding.subsidy_used, allocated, carry))
}

#[test]
fn floor_reserve_only_covers_shortfall_and_insufficient_subsidy_fails() {
    assert_eq!(
        reserve_floor(100, u64::MAX, 60),
        Ok(FloorFunding {
            subsidy_used: 0,
            remainder: 40
        })
    );
    assert_eq!(
        reserve_floor(100, 60, 160),
        Ok(FloorFunding {
            subsidy_used: 60,
            remainder: 0
        })
    );
    assert_eq!(
        reserve_floor(100, 59, 160),
        Err(MathError::UnderfundedFloor)
    );
    assert_eq!(
        reserve_floor(0, u64::MAX, u64::MAX),
        Ok(FloorFunding {
            subsidy_used: u64::MAX,
            remainder: 0
        })
    );
    assert_eq!(
        reserve_floor(u64::MAX, u64::MAX, u64::MAX),
        Ok(FloorFunding {
            subsidy_used: 0,
            remainder: 0
        })
    );
}

#[test]
fn settlement_conserves_full_range_balances_and_preserves_rounding_carry() {
    let base = first_year_floor(0, 0, WEEK).unwrap();
    assert_eq!(
        settle(base, 100, &[95, 90], 100_000_000, 20_000_000),
        Ok((12_903_225, 112_903_225, 0))
    );
    assert_eq!(
        settle(base, 100, &[95, 90], 100_000_000, 10_000_000),
        Err(MathError::UnderfundedFloor)
    );
    assert_eq!(settle(0, 100, &[95, 90], 100, 999), Ok((0, 100, 0)));
    assert_eq!(
        settle(0, u64::MAX, &[u64::MAX, u64::MAX], u64::MAX, 0),
        Ok((0, u64::MAX - 1, 1))
    );
    assert_eq!(settle(base, 0, &[], 99, 999), Ok((0, 0, 99)));
    assert_eq!(settle(base, 100, &[0, 80], 99, 999), Ok((0, 0, 99)));
    assert_eq!(
        settle(u64::MAX, 100, &[100, 100], 0, u64::MAX),
        Err(MathError::Overflow)
    );

    for pot in [0, 1, 2, 99, 100_000_000, u64::MAX] {
        for counts in [&[100, 95, 90][..], &[81, 82, 94][..], &[80, 95, 100][..]] {
            let (used, allocated, carry) = settle(0, 100, counts, pot, u64::MAX).unwrap();
            assert_eq!(used, 0);
            assert_eq!(allocated as u128 + carry as u128, pot as u128);
            assert!(carry < 3);
        }
    }
}

#[test]
fn bounded_token_month_anniversaries_preserve_original_leap_date() {
    let origin = 1_706_704_496;
    for (months, expected) in [
        (0, origin),
        (1, 1_709_210_096),
        (2, 1_711_888_496),
        (12, 1_738_326_896),
        (48, 1_832_934_896),
    ] {
        assert_eq!(utc_month_anniversary(origin, months), Ok(expected));
    }
    assert_eq!(utc_month_anniversary(-1, 0), Err(MathError::InvalidTime));
    assert_eq!(
        utc_month_anniversary(origin, 49),
        Err(MathError::InvalidTime)
    );
    assert_eq!(
        utc_month_anniversary(i64::MAX, 48),
        Err(MathError::InvalidTime)
    );
}

#[test]
fn mixed_floor_uses_all_usdc_before_ceil_token_shortfalls_and_original_supply_cap() {
    let f = token_floor_funding(151, 0, 300).unwrap();
    assert_eq!(
        f,
        TokenFloorFunding {
            subsidy_used: 0,
            usd_pot: 151,
            shortfall: 149,
            remainder: 0
        }
    );
    assert_eq!(token_floor_usd(0, 100, 300, f.usd_pot), Ok(50));
    assert_eq!(token_floor_usd(100, 200, 300, f.usd_pot), Ok(101));
    assert_eq!(token_floor_usd(300, 0, 300, f.usd_pot), Ok(0));
    assert_eq!(token_floor_morse(50, 2_000_000), Ok(25));
    assert_eq!(token_floor_morse(99, 2_000_000), Ok(50));
    assert_eq!(
        token_reserve_available(75, 74),
        Err(MathError::UnderfundedFloor)
    );
    assert!(token_reserve_available(75, 75).is_ok());
    let exact = token_floor_morse(500_000, 1).unwrap();
    assert_eq!(exact, TOKEN_RESERVE_EPOCH_CAP);
    assert!(token_reserve_available(exact, exact).is_ok());
    assert_eq!(
        token_reserve_available(token_floor_morse(500_001, 1).unwrap(), u64::MAX),
        Err(MathError::UnderfundedFloor)
    );
    assert_eq!(
        token_floor_funding(0, 1, 500_001).unwrap().shortfall,
        500_000
    );
    assert_eq!(
        token_floor_funding(u64::MAX, u64::MAX, 0),
        Ok(TokenFloorFunding {
            subsidy_used: 0,
            usd_pot: u64::MAX,
            shortfall: 0,
            remainder: u64::MAX
        })
    );
    assert_eq!(token_floor_morse(0, 0), Ok(0));
    assert_eq!(token_floor_morse(1, 0), Err(MathError::DivisionByZero));
    assert_eq!(token_floor_morse(u64::MAX, 1), Err(MathError::Overflow));
    assert!(token_floor_usd(299, 2, 300, 151).is_err());
    assert!(token_floor_usd(0, 1, 300, 301).is_err());
    assert_eq!(token_floor_usd(u64::MAX - 1, 1, u64::MAX, u64::MAX), Ok(1));
}
