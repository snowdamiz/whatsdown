//! Token reward companions keep every legacy USDC field in its original units.
use pinocchio::{error::ProgramError, Address};
pub const TOKEN_POOL_LEN: usize = 320;
pub const TOKEN_EPOCH_HEADER: usize = 256;
pub const TOKEN_ROW_LEN: usize = 16;
pub const TOKEN_EPOCH_LEN: usize = TOKEN_EPOCH_HEADER + 64 * TOKEN_ROW_LEN;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn wide(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn key(d: &[u8], o: usize) -> Address {
    Address::new_from_array(d[o..o + 32].try_into().unwrap())
}
#[derive(Debug, PartialEq)]
pub struct TokenPool {
    pub pool: Address,
    pub binding: Address,
    pub token_program: Address,
    pub config: Address,
    pub mint: Address,
    pub oracle: Address,
    pub profile: Address,
    pub vault: Address,
    pub accounted: u64,
    pub liabilities: u64,
    pub activation_epoch: u64,
}
impl TokenPool {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != TOKEN_POOL_LEN
            || &d[..4] != b"MRT\x02"
            || d[4..260].as_chunks::<32>().0.contains(&[0; 32])
            || wide(d, 260) != wide(d, 268)
            || d[284..].iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
        Ok(Self {
            pool: key(d, 4),
            binding: key(d, 36),
            token_program: key(d, 68),
            config: key(d, 100),
            mint: key(d, 132),
            oracle: key(d, 164),
            profile: key(d, 196),
            vault: key(d, 228),
            accounted: wide(d, 260),
            liabilities: wide(d, 268),
            activation_epoch: wide(d, 276),
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct TokenEpoch {
    pub token_pool: [u8; 32],
    pub ledger: [u8; 32],
    pub epoch: u64,
    pub price: u64,
    pub source_revision: u64,
    pub snapshot_at: i64,
    pub shortfall: u64,
    pub amount: u64,
    pub claimed: u64,
    pub claimed_amount: u64,
    pub usd_committed: u64,
    pub floors: u64,
    pub status: u8,
    pub receipt: [u8; 32],
}
impl TokenEpoch {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != TOKEN_EPOCH_LEN
            || &d[..4] != b"MTE\x02"
            || d[4..36] == [0; 32]
            || d[36..68] == [0; 32]
            || d[148] > 2
            || d[149..152].iter().chain(&d[184..256]).any(|b| *b != 0)
        {
            return Err(invalid());
        }
        let v = Self {
            token_pool: d[4..36].try_into().unwrap(),
            ledger: d[36..68].try_into().unwrap(),
            epoch: wide(d, 68),
            price: wide(d, 76),
            source_revision: wide(d, 84),
            snapshot_at: i64::from_le_bytes(d[92..100].try_into().unwrap()),
            shortfall: wide(d, 100),
            amount: wide(d, 108),
            claimed: wide(d, 116),
            claimed_amount: wide(d, 124),
            usd_committed: wide(d, 132),
            floors: wide(d, 140),
            status: d[148],
            receipt: d[152..184].try_into().unwrap(),
        };
        if v.claimed_amount > v.amount
            || v.shortfall > v.floors
            || (v.status == 0 && d[76..184].iter().any(|b| *b != 0))
            || (v.status != 0 && (v.snapshot_at <= 0 || v.source_revision == 0))
            || (v.status != 2 && (v.claimed != 0 || v.claimed_amount != 0))
            || (v.status == 2 && ((v.amount == 0) != (v.receipt == [0; 32])))
        {
            return Err(invalid());
        }
        Ok(v)
    }
}
