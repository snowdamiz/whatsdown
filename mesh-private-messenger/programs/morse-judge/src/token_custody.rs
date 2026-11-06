//! Explicit phase5 schemas. Legacy USDC handlers must never reinterpret these units.
pub use morse_token::collateral_state::*;
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address, ProgramResult};
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn wide(d: &[u8], at: usize) -> u64 {
    crate::custody::u64_at(d, at)
}

pub fn load_economics(
    program: &Address,
    account: &AccountView,
    log_id: &[u8; 32],
    writable: bool,
) -> Result<[u8; ECONOMICS_V2_LEN], ProgramError> {
    crate::processor::owned(program, account, writable)?;
    crate::processor::pda(program, &[b"economics", log_id], account)?;
    let d = account.try_borrow()?;
    decode_economics(&d)?;
    if d[4..36] != *log_id {
        return Err(invalid());
    }
    Ok(d[..].try_into().unwrap())
}

/// Lossless schema migration only. A legacy principal is always USDC.
/// Permissionless rent-free migration cannot choose a new asset or recipient.
pub(crate) fn migrate(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
) -> ProgramResult {
    let (base, rest) = accounts.split_at_mut(core::cmp::min(4, accounts.len()));
    let [log_account, economics, binding_account, bond] = base else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if rest.len() != usize::from(witness) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = crate::processor::load_log(program, log_account)?;
    let log_id: [u8; 32] = log[40..72].try_into().unwrap();
    let binding = crate::token_binding::load_binding(program, binding_account, &log_id)?;
    if binding.activated_at == 0 || binding.log != *log_account.address() {
        return Err(invalid());
    }
    let policy = load_economics(program, economics, &log_id, true)?;
    let record = if witness {
        Some(crate::witness::load_witness(program, &rest[0], &log_id)?)
    } else {
        None
    };
    let identity = record
        .as_ref()
        .map(|d| crate::witness::identity(&d[8..8 + d[4] as usize], &d[72..104]));
    let subject = identity
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    crate::processor::owned(program, bond, true)?;
    crate::processor::pda(program, &[b"bond", &log_id, subject], bond)?;
    let (mut data, legacy) = {
        let d = bond.try_borrow()?;
        if d.len() != BOND_V2_LEN {
            return Err(invalid());
        }
        let legacy = &d[..4] == b"MBD\x01";
        if !legacy && &d[..4] != b"MBD\x02" {
            return Err(invalid());
        }
        if legacy && d[6..8].iter().chain(&d[200..]).any(|v| *v != 0) {
            return Err(invalid());
        }
        let mut value: [u8; BOND_V2_LEN] = d[..].try_into().unwrap();
        value[3] = 2;
        (value, legacy)
    };
    let state = decode_bond(&data)?;
    let mint = if state.asset == 0 {
        Address::new_from_array(policy[36..68].try_into().unwrap())
    } else {
        binding.mint
    };
    let vault = Address::find_program_address(
        &[
            bond.address().as_ref(),
            pinocchio_token::ID.as_ref(),
            mint.as_ref(),
        ],
        &pinocchio_associated_token_account::ID,
    )
    .0;
    if state.witness != witness
        || data[8..40] != log_id
        || data[104..136] != *mint.as_ref()
        || data[136..168] != *vault.as_ref()
        || (legacy && state.asset != 0)
    {
        return Err(invalid());
    }
    if let Some(record) = record {
        if data[40..72] != *rest[0].address().as_ref()
            || data[72..104] != record[104..136]
            || data[136..168] != record[232..264]
            || state.status != record[5]
            || data[184..192] != record[264..272]
            || state.principal > wide(&policy, if state.asset == 0 { 148 } else { 176 })
        {
            return Err(invalid());
        }
    } else if data[40..72] != [0; 32]
        || data[72..104] != policy[68..100]
        || state.status != policy[164]
        || state.asset != policy[165]
        || state.principal != wide(&policy, if state.asset == 0 { 156 } else { 184 })
    {
        return Err(invalid());
    }
    if !legacy {
        return Ok(());
    }
    crate::custody::advance_eligibility(economics)?;
    bond.try_borrow_mut()?.copy_from_slice(&data);
    data.fill(0);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn economy() -> Vec<u8> {
        let mut d = vec![0; 192];
        d[..4].copy_from_slice(b"MEC\x02");
        d[4..100].fill(9);
        d[100..108].copy_from_slice(&10_000_000_000u64.to_le_bytes());
        d[108..116].copy_from_slice(&500_000_000_000u64.to_le_bytes());
        d[116..124].copy_from_slice(&1_700_000_000i64.to_le_bytes());
        d[156..164].copy_from_slice(&500_000_000_000u64.to_le_bytes());
        d[164] = 1;
        d[176..184].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        d
    }
    fn bond() -> Vec<u8> {
        let mut d = vec![0; 208];
        d[..4].copy_from_slice(b"MBD\x02");
        d[4] = 1;
        d[5] = 1;
        d[6] = 1;
        d[8..168].fill(7);
        d[168..176].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        d[176..184].copy_from_slice(&1_700_000_000i64.to_le_bytes());
        d
    }
    #[test]
    fn versioned_unit_schemas_refuse_legacy_and_inconsistent_asset_counters_or_statuses() {
        let d = economy();
        assert_eq!(decode_economics(&d).unwrap().witness_token, 1_000_000_000);
        for (at, value) in [(3, 1), (165, 2), (166, 1)] {
            let mut bad = d.clone();
            bad[at] = value;
            assert!(decode_economics(&bad).is_err());
        }
        let mut bad = d.clone();
        bad[184..192].copy_from_slice(&1u64.to_le_bytes());
        assert!(decode_economics(&bad).is_err());
        let mut bad = d.clone();
        bad[176..184].copy_from_slice(&(ORIGINAL_SUPPLY + 1).to_le_bytes());
        assert!(decode_economics(&bad).is_err());
        let b = bond();
        assert_eq!(decode_bond(&b).unwrap().asset, 1);
        for (at, value) in [(3, 1), (4, 5), (5, 2), (6, 2), (7, 1)] {
            let mut bad = b.clone();
            bad[at] = value;
            assert!(decode_bond(&bad).is_err());
        }
        let mut bad = b.clone();
        bad[4] = 2;
        assert!(decode_bond(&bad).is_err());
        let mut bad = b.clone();
        bad[6] = 0;
        bad[200..208].copy_from_slice(&1_700_000_100i64.to_le_bytes());
        assert!(decode_bond(&bad).is_err());
        let mut bad = b.clone();
        bad[4] = 3;
        bad[192..200].copy_from_slice(&1_700_000_100i64.to_le_bytes());
        assert!(decode_bond(&bad).is_err());
    }
    #[test]
    fn recorded_grace_is_not_restarted_by_partial_recovery_or_unrecorded_virtual_assessment() {
        let mut b = decode_bond(&bond()).unwrap();
        let target = 10_000_000_000;
        let now = 1_700_000_100;
        assert_eq!(
            assess(b, 8_000_000, target, now).unwrap(),
            BondAssessment {
                eligible: true,
                underwater_since: 0
            }
        );
        assert_eq!(
            eligible(b, 7_999_999, target, now),
            Err(ProgramError::Custom(NEEDS_ASSESSMENT))
        );
        let first = assess(b, 7_999_999, target, now).unwrap();
        assert_eq!(
            first,
            BondAssessment {
                eligible: true,
                underwater_since: now
            }
        );
        b.underwater_since = first.underwater_since;
        assert_eq!(
            assess(b, 9_000_000, target, now + GRACE_SECONDS - 1).unwrap(),
            BondAssessment {
                eligible: true,
                underwater_since: now
            }
        );
        assert!(!eligible(b, 9_000_000, target, now + GRACE_SECONDS).unwrap());
        assert_eq!(
            assess(b, 10_000_000, target, now + GRACE_SECONDS).unwrap(),
            BondAssessment {
                eligible: true,
                underwater_since: 0
            }
        );
        assert!(assess(b, 10_000_000, target, now - 1).is_err());
        b.asset = 0;
        b.underwater_since = 0;
        b.principal = target;
        assert!(eligible(b, 0, target, now).unwrap());
        assert!(
            eligible(b, 0, 0, now).unwrap(),
            "the canonical USDC pending descriptor has no token target"
        );
        b.status = 2;
        assert!(!eligible(b, 0, target, now).unwrap());
    }
}
