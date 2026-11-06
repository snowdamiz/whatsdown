//! Versioned accounts. All amounts are integer units of one immutable six-decimal mint.
use pinocchio::error::ProgramError;
pub const POOL_LEN: usize = 304;
pub const MEMBER_LEN: usize = 64;
pub const LEDGER_HEADER: usize = 224;
pub const ROW_LEN: usize = 128;
pub const LEDGER_LEN: usize = LEDGER_HEADER + 64 * ROW_LEN;
pub const TIMELOCK_SECONDS: i64 = 14 * 86400;
pub const EPOCH_SECONDS: i64 = 7 * 86400;
pub fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn i64_at(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn u128_at(d: &[u8], o: usize) -> u128 {
    u128::from_le_bytes(d[o..o + 16].try_into().unwrap())
}
pub fn put64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn put128(d: &mut [u8], o: usize, v: u128) {
    d[o..o + 16].copy_from_slice(&v.to_le_bytes());
}
pub fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
#[derive(Clone, Copy)]
pub struct Pool {
    pub version: u8,
    pub governance: [u8; 32],
    pub judge: [u8; 32],
    pub log: [u8; 32],
    pub log_id: [u8; 32],
    pub mint: [u8; 32],
    pub started: i64,
    pub first_epoch: u64,
    pub next_epoch: u64,
    pub subsidy: u64,
    pub carry: u64,
    pub liabilities: u64,
    pub accounted: u64,
    pub active: u64,
    pub morse_witness: [u8; 32],
}
impl Pool {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != POOL_LEN
            || &d[..3] != b"MRP"
            || !matches!(d[3], 1 | 2)
            || d[300..].iter().any(|x| *x != 0)
        {
            return Err(invalid());
        }
        let p = Self {
            version: d[3],
            governance: d[4..36].try_into().unwrap(),
            judge: d[36..68].try_into().unwrap(),
            log: d[68..100].try_into().unwrap(),
            log_id: d[100..132].try_into().unwrap(),
            mint: d[132..164].try_into().unwrap(),
            started: i64_at(d, 164),
            first_epoch: u64_at(d, 172),
            next_epoch: u64_at(d, 180),
            subsidy: u64_at(d, 188),
            carry: u64_at(d, 196),
            liabilities: u64_at(d, 204),
            accounted: u64_at(d, 212),
            active: u64_at(d, 220),
            morse_witness: d[268..300].try_into().unwrap(),
        };
        if p.governance == [0; 32]
            || p.judge == [0; 32]
            || p.log == [0; 32]
            || p.mint == [0; 32]
            || p.morse_witness == [0; 32]
            || p.started <= 0
            || p.first_epoch != (p.started / EPOCH_SECONDS) as u64 + 1
            || p.next_epoch < p.first_epoch
            || (p.active != 0 && p.active != p.next_epoch.checked_add(1).ok_or(invalid())?)
            || p.subsidy
                .checked_add(p.carry)
                .and_then(|n| n.checked_add(p.liabilities))
                .ok_or(invalid())?
                > p.accounted
            || (i64_at(d, 260) == 0 && d[228..260].iter().any(|x| *x != 0))
        {
            return Err(invalid());
        }
        Ok(p)
    }
}
pub struct Ledger {
    pub version: u8,
    pub epoch: u64,
    pub revenue: u64,
    pub status: u8,
    pub count: u8,
    pub expected: u8,
    pub posts: u64,
    pub weight: u128,
    pub floors: u64,
    pub base: u64,
    pub revision: u64,
}
impl Ledger {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != LEDGER_LEN
            || &d[..3] != b"MRE"
            || !matches!(d[3], 1 | 2)
            || d[52] > 2
            || d[53] > 64
            || d[54] > 64
            || d[53] > d[54]
            || d[55] != 0
            || d[184..LEDGER_HEADER].iter().any(|x| *x != 0)
        {
            return Err(invalid());
        }
        Ok(Self {
            version: d[3],
            epoch: u64_at(d, 36),
            revenue: u64_at(d, 44),
            status: d[52],
            count: d[53],
            expected: d[54],
            posts: u64_at(d, 88),
            weight: u128_at(d, 96),
            floors: u64_at(d, 112),
            base: u64_at(d, 120),
            revision: u64_at(d, 176),
        })
    }
}
pub struct Member {
    pub witness: [u8; 32],
    pub status: u8,
    pub pending: u8,
    pub ready: i64,
    pub effective: i64,
}
impl Member {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != MEMBER_LEN
            || &d[..4] != b"MRM\x01"
            || d[36] > 2
            || d[37] > 2
            || d[38..40].iter().chain(&d[56..]).any(|x| *x != 0)
            || i64_at(d, 40) < 0
            || i64_at(d, 48) < 0
        {
            return Err(invalid());
        }
        Ok(Self {
            witness: d[4..36].try_into().unwrap(),
            status: d[36],
            pending: d[37],
            ready: i64_at(d, 40),
            effective: i64_at(d, 48),
        })
    }
}

pub const FUNDING_LEN: usize = 192;
/// Permanent, intent-bound transfer receipt. It has no close/refund instruction.
pub struct FundingReceipt {
    pub pool: [u8; 32],
    pub funder: [u8; 32],
    pub operation: [u8; 32],
    pub epoch: u64,
    pub kind: u8,
    pub amount: u64,
    pub source: [u8; 32],
    pub mint: [u8; 32],
    pub funded_at: i64,
}
impl FundingReceipt {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != FUNDING_LEN
            || &d[..4] != b"MRF\x01"
            || d[108] > 1
            || d[109..112].iter().any(|x| *x != 0)
            || d[68..100] == [0; 32]
            || u64_at(d, 112) == 0
            || i64_at(d, 184) <= 0
        {
            return Err(invalid());
        }
        Ok(Self {
            pool: d[4..36].try_into().unwrap(),
            funder: d[36..68].try_into().unwrap(),
            operation: d[68..100].try_into().unwrap(),
            epoch: u64_at(d, 100),
            kind: d[108],
            amount: u64_at(d, 112),
            source: d[120..152].try_into().unwrap(),
            mint: d[152..184].try_into().unwrap(),
            funded_at: i64_at(d, 184),
        })
    }
}
