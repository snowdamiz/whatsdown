//! Shared strict wire/authentication contract for the judge-issued token binding.
//! The token reserve consumes this account without introducing a crate cycle.
use crate::processor::pda;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address,
};
fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn i64_at(d: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
pub const BINDING_LEN: usize = 320;
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const WEEK: i64 = 604800;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn address(d: &[u8], at: usize) -> Address {
    Address::new_from_array(d[at..at + 32].try_into().unwrap())
}
#[derive(Clone, Debug, PartialEq)]
pub struct TokenBinding {
    pub log: Address,
    pub log_id: [u8; 32],
    pub token_program: Address,
    pub token_config: Address,
    pub mint: Address,
    pub oracle: Address,
    pub rewards_program: Address,
    pub rewards_pool: Address,
    pub ready_at: i64,
    pub activated_at: i64,
    pub activated_epoch: u64,
    pub token_slot: u64,
    pub rewards_slot: u64,
    pub source_revision: u64,
}
impl TokenBinding {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != BINDING_LEN
            || &d[..4] != b"MJB\x02"
            || d[4..260].as_chunks::<32>().0.contains(&[0; 32])
            || d[308..].iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
        let value = Self {
            log: address(d, 4),
            log_id: d[36..68].try_into().unwrap(),
            token_program: address(d, 68),
            token_config: address(d, 100),
            mint: address(d, 132),
            oracle: address(d, 164),
            rewards_program: address(d, 196),
            rewards_pool: address(d, 228),
            ready_at: i64_at(d, 260),
            activated_at: i64_at(d, 268),
            activated_epoch: u64_at(d, 276),
            token_slot: u64_at(d, 284),
            rewards_slot: u64_at(d, 292),
            source_revision: u64_at(d, 300),
        };
        if value.ready_at <= 0
            || value.activated_at < 0
            || value.source_revision == 0
            || (value.activated_at == 0 && value.activated_epoch != 0)
            || (value.activated_at > 0
                && (value.activated_at < value.ready_at
                    || value.activated_epoch != (value.activated_at / WEEK) as u64))
            || value.token_program == value.rewards_program
        {
            return Err(invalid());
        }
        Ok(value)
    }
}
pub fn load_binding(
    program: &Address,
    account: &AccountView,
    log_id: &[u8; 32],
) -> Result<TokenBinding, ProgramError> {
    if account.owner() != program || account.executable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    pda(program, &[b"token-binding", log_id], account)?;
    let value = TokenBinding::parse(&account.try_borrow()?)?;
    if value.log_id != *log_id {
        return Err(invalid());
    }
    Ok(value)
}
pub fn qualified_program_slot(
    executable: &AccountView,
    metadata: &AccountView,
) -> Result<u64, ProgramError> {
    if !executable.executable()
        || executable.owner() != &LOADER
        || metadata.owner() != &LOADER
        || metadata.executable()
    {
        return Err(invalid());
    }
    pda(&LOADER, &[executable.address().as_ref()], metadata)?;
    let image = executable.try_borrow()?;
    let d = metadata.try_borrow()?;
    if image.len() != 36
        || image[..4] != 2u32.to_le_bytes()
        || image[4..36] != *metadata.address().as_ref()
        || d.len() < 45
        || d[..4] != 3u32.to_le_bytes()
        || d[12] > 1
    {
        return Err(invalid());
    }
    let slot = u64_at(&d, 4);
    if slot > Clock::get()?.slot {
        return Err(invalid());
    }
    Ok(slot)
}
