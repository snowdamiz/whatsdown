//! Shared pure v2 collateral wire models used by judge, rewards and reserve.
use pinocchio::error::ProgramError;
pub const ECONOMICS_V2_LEN: usize = 192;
pub const BOND_V2_LEN: usize = 208;
pub const ORIGINAL_SUPPLY: u64 = 1_000_000_000_000_000;
pub const GRACE_SECONDS: i64 = 7 * 86400;
pub const NEEDS_ASSESSMENT: u32 = 0x5001;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TokenEconomics {
    pub directory_asset: u8,
    pub directory_status: u8,
    pub witness_usdc: u64,
    pub directory_usdc: u64,
    pub witness_token: u64,
    pub directory_token: u64,
    pub revision: u64,
    pub witness_target: u64,
    pub directory_target: u64,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TokenBond {
    pub status: u8,
    pub witness: bool,
    pub asset: u8,
    pub principal: u64,
    pub bonded_at: i64,
    pub unbond_at: i64,
    pub slashed_at: i64,
    pub underwater_since: i64,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BondAssessment {
    pub eligible: bool,
    pub underwater_since: i64,
}

fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn wide(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn time(d: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
pub fn decode_economics(d: &[u8]) -> Result<TokenEconomics, ProgramError> {
    if d.len() != ECONOMICS_V2_LEN
        || &d[..4] != b"MEC\x02"
        || d[4..36] == [0; 32]
        || d[36..68] == [0; 32]
        || d[68..100] == [0; 32]
        || wide(d, 100) == 0
        || wide(d, 108) < wide(d, 100)
        || time(d, 116) < 0
        || time(d, 140) < 0
        || d[164] > 4
        || d[165] > 1
        || d[166..168] != [0; 2]
    {
        return Err(invalid());
    }
    let pending_time = time(d, 140);
    if (pending_time == 0 && d[124..140].iter().any(|x| *x != 0))
        || (pending_time > 0 && (wide(d, 124) == 0 || wide(d, 132) < wide(d, 124)))
    {
        return Err(invalid());
    }
    let usd = wide(d, 156);
    let token = wide(d, 184);
    let witness_token = wide(d, 176);
    if witness_token
        .checked_add(token)
        .is_none_or(|sum| sum > ORIGINAL_SUPPLY)
        || (d[165] == 0 && token != 0)
        || (d[165] == 1 && usd != 0)
        || (matches!(d[164], 1 | 2) && usd == 0 && token == 0)
        || (matches!(d[164], 0 | 3 | 4) && (usd != 0 || token != 0))
    {
        return Err(invalid());
    }
    Ok(TokenEconomics {
        directory_asset: d[165],
        directory_status: d[164],
        witness_usdc: wide(d, 148),
        directory_usdc: usd,
        witness_token,
        directory_token: token,
        revision: wide(d, 168),
        witness_target: wide(d, 100),
        directory_target: wide(d, 108),
    })
}
pub fn decode_bond(d: &[u8]) -> Result<TokenBond, ProgramError> {
    if d.len() != BOND_V2_LEN
        || &d[..4] != b"MBD\x02"
        || !matches!(d[4], 1..=4)
        || d[5] > 1
        || d[6] > 1
        || d[7] != 0
        || d[8..40] == [0; 32]
        || (d[5] == 1) == (d[40..72] == [0; 32])
        || d[72..104] == [0; 32]
        || d[104..136] == [0; 32]
        || d[136..168] == [0; 32]
    {
        return Err(invalid());
    }
    let principal = wide(d, 168);
    let bonded = time(d, 176);
    let unbond = time(d, 184);
    let slashed = time(d, 192);
    let underwater = time(d, 200);
    if bonded <= 0
        || unbond < 0
        || slashed < 0
        || underwater < 0
        || (d[6] == 0 && underwater != 0)
        || (d[6] == 1 && principal > ORIGINAL_SUPPLY)
        || (underwater > 0 && underwater < bonded)
        || (matches!(d[4], 1 | 2) && principal == 0)
        || (matches!(d[4], 3 | 4) && principal != 0)
        || (d[4] == 1 && (unbond != 0 || slashed != 0))
        || (matches!(d[4], 2 | 4) && (unbond < bonded || slashed != 0))
        || (d[4] == 3 && slashed < bonded)
    {
        return Err(invalid());
    }
    Ok(TokenBond {
        status: d[4],
        witness: d[5] == 1,
        asset: d[6],
        principal,
        bonded_at: bonded,
        unbond_at: unbond,
        slashed_at: slashed,
        underwater_since: underwater,
    })
}
pub fn assess(
    b: TokenBond,
    price: u64,
    target: u64,
    now: i64,
) -> Result<BondAssessment, ProgramError> {
    if b.bonded_at <= 0
        || now < b.bonded_at
        || b.underwater_since < 0
        || b.underwater_since > now
        || (b.asset == 1 && target == 0)
        || b.asset > 1
    {
        return Err(ProgramError::InvalidArgument);
    }
    if b.status != 1 {
        return Ok(BondAssessment {
            eligible: false,
            underwater_since: b.underwater_since,
        });
    }
    if b.principal == 0
        || (b.asset == 0 && b.underwater_since != 0)
        || (b.asset == 1 && (price == 0 || b.principal > ORIGINAL_SUPPLY))
    {
        return Err(ProgramError::InvalidArgument);
    }
    if b.asset == 0 {
        return Ok(BondAssessment {
            eligible: true,
            underwater_since: 0,
        });
    }
    let value = b.principal as u128 * price as u128;
    let full = target as u128 * 1_000_000;
    if value >= full {
        return Ok(BondAssessment {
            eligible: true,
            underwater_since: 0,
        });
    }
    let since = if b.underwater_since != 0 {
        b.underwater_since
    } else if value * 5 < full * 4 {
        now
    } else {
        0
    };
    let eligible = since == 0
        || now
            < since
                .checked_add(GRACE_SECONDS)
                .ok_or(ProgramError::ArithmeticOverflow)?;
    Ok(BondAssessment {
        eligible,
        underwater_since: since,
    })
}
pub fn eligible(b: TokenBond, price: u64, target: u64, now: i64) -> Result<bool, ProgramError> {
    if b.asset == 1 && price == 0 {
        return Ok(false);
    }
    let result = assess(b, price, target, now)?;
    if b.underwater_since == 0 && result.underwater_since != 0 {
        return Err(ProgramError::Custom(NEEDS_ASSESSMENT));
    }
    Ok(result.eligible)
}
