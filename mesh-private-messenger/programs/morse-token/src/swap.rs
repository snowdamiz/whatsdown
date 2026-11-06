//! Supported Jupiter V2 single RaydiumCP ExactIn route. No generic router authority.
use pinocchio::error::ProgramError;
#[derive(Debug, PartialEq)]
pub struct Route {
    pub input: u64,
    pub minimum_output: u64,
    pub slippage_bps: u16,
}
pub fn route(data: &[u8], input: u64, oracle_price: u64) -> Result<Route, ProgramError> {
    let invalid = || ProgramError::InvalidInstructionData;
    if input == 0
        || oracle_price == 0
        || data.len() != 39
        || data[..8] != [187, 100, 250, 204, 49, 196, 175, 20]
        || data[26..30] != [0; 4]
        || data[30..34] != 1u32.to_le_bytes()
        || data[34] != 46
        || data[35..37] != 10000u16.to_le_bytes()
        || data[37..] != [0, 1]
    {
        return Err(invalid());
    }
    let encoded = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let quoted = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let slippage = u16::from_le_bytes(data[24..26].try_into().unwrap());
    if encoded != input || quoted == 0 || slippage > 100 {
        return Err(invalid());
    }
    let minimum = (quoted as u128 * (10000 - slippage) as u128 / 10000) as u64;
    let numerator = input as u128 * 1_000_000 * 9900;
    let denominator = oracle_price as u128 * 10000;
    let oracle_minimum = numerator.div_ceil(denominator);
    if minimum == 0 || (minimum as u128) < oracle_minimum {
        return Err(invalid());
    }
    Ok(Route {
        input,
        minimum_output: minimum,
        slippage_bps: slippage,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn data(input: u64, quoted: u64, slippage: u16) -> Vec<u8> {
        let mut d = vec![187, 100, 250, 204, 49, 196, 175, 20];
        d.extend(input.to_le_bytes());
        d.extend(quoted.to_le_bytes());
        d.extend(slippage.to_le_bytes());
        d.extend([0; 4]);
        d.extend(1u32.to_le_bytes());
        d.push(46);
        d.extend(10000u16.to_le_bytes());
        d.extend([0, 1]);
        d
    }
    #[test]
    fn exactin_and_independent_oracle_bound_reject_bad_quotes_fees_multihop_and_other_dexes() {
        let d = data(100_000_000, 50_000_000, 100);
        assert_eq!(
            route(&d, 100_000_000, 2_000_000),
            Ok(Route {
                input: 100_000_000,
                minimum_output: 49_500_000,
                slippage_bps: 100
            })
        );
        for (at, value) in [
            (0, 0),
            (9, 0),
            (24, 101),
            (26, 1),
            (28, 1),
            (30, 2),
            (34, 45),
            (35, 0),
            (37, 1),
            (38, 0),
        ] {
            let mut bad = d.clone();
            bad[at] = value;
            assert!(
                route(&bad, 100_000_000, 2_000_000).is_err(),
                "accepted mutation at {at}"
            );
        }
        assert!(route(&data(100_000_000, 20_000_000, 100), 100_000_000, 2_000_000).is_err());
        assert!(route(&d, 99_000_000, 2_000_000).is_err());
        assert!(route(&d, 100_000_000, 0).is_err());
        let mut trailing = d.clone();
        trailing.push(0);
        assert!(route(&trailing, 100_000_000, 2_000_000).is_err());
        assert!(route(&data(u64::MAX, u64::MAX, 0), u64::MAX, 1).is_err());
        assert_eq!(
            route(&data(u64::MAX, u64::MAX, 0), u64::MAX, 1_000_000)
                .unwrap()
                .minimum_output,
            u64::MAX
        );
    }
}
