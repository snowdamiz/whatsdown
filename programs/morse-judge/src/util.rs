use crate::error::{err, require, JudgeError};
use pinocchio::{
    account::{Ref, RefMut},
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer as SystemTransfer};
use pinocchio_token::{instructions::InitializeAccount3, state::Account as TokenAccount};

pub const SYSTEM_ID: Address = Address::new_from_array([0; 32]);
pub const TOKEN_ID: Address = pinocchio_token::ID;
pub const ATA_ID: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const LOADER_V3_ID: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
pub const TOKEN_ACCOUNT_LEN: usize = 165;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    solana_sha256_hasher::hashv(parts).to_bytes()
}

pub fn signer(acct: &AccountView) -> ProgramResult {
    if acct.is_signer() {
        Ok(())
    } else {
        Err(ProgramError::MissingRequiredSignature)
    }
}

pub fn is_program(acct: &AccountView, id: &Address) -> ProgramResult {
    require(acct.address() == id, JudgeError::WrongAccount)
}

/// Borrows a judge-owned account after checking owner, exact length and tag.
/// Accounts of a given tag are only ever created at their PDA, so owner +
/// tag identifies the account type; callers still check relationships.
pub fn load<'a>(acct: &'a AccountView, program_id: &Address, tag: u8, len: usize) -> Result<Ref<'a, [u8]>, ProgramError> {
    require(acct.owned_by(program_id) && acct.data_len() == len, JudgeError::WrongAccount)?;
    let d = acct.try_borrow()?;
    require(d[0] == tag, JudgeError::WrongAccount)?;
    Ok(d)
}

pub fn load_mut<'a>(acct: &'a mut AccountView, program_id: &Address, tag: u8, len: usize) -> Result<RefMut<'a, [u8]>, ProgramError> {
    require(acct.owned_by(program_id) && acct.data_len() == len, JudgeError::WrongAccount)?;
    require(acct.is_writable(), JudgeError::WrongAccount)?;
    let d = acct.try_borrow_mut()?;
    require(d[0] == tag, JudgeError::WrongAccount)?;
    Ok(d)
}

/// Creates `target` (a PDA signed by `seeds`) owned by `owner`. Works when
/// someone pre-funded the address (only the rent deficit is paid), so nobody
/// can block an account from being created by sending it lamports first.
pub fn create_pda(payer: &AccountView, target: &AccountView, space: usize, owner: &Address, seeds: &[Seed]) -> ProgramResult {
    require(target.owned_by(&SYSTEM_ID) && target.data_len() == 0, JudgeError::WrongAccount)?;
    let signers = [Signer::from(seeds)];
    let rent = Rent::get()?.try_minimum_balance(space)?;
    if target.lamports() == 0 {
        return CreateAccount { from: payer, to: target, lamports: rent, space: space as u64, owner }.invoke_signed(&signers);
    }
    let deficit = rent.saturating_sub(target.lamports());
    if deficit > 0 {
        SystemTransfer { from: payer, to: target, lamports: deficit }.invoke()?;
    }
    Allocate { account: target, space: space as u64 }.invoke_signed(&signers)?;
    Assign { account: target, owner }.invoke_signed(&signers)
}

/// Creates an SPL Token account at the PDA `vault` whose token authority is
/// the vault address itself, so only this program can sign for it.
pub fn create_vault(payer: &AccountView, vault: &AccountView, mint: &AccountView, seeds: &[Seed]) -> ProgramResult {
    create_pda(payer, vault, TOKEN_ACCOUNT_LEN, &TOKEN_ID, seeds)?;
    InitializeAccount3::new(vault, mint, vault.address()).invoke()
}

/// `(mint, owner, amount)` of an initialized SPL Token account.
pub fn token_account(acct: &AccountView) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    let t = TokenAccount::from_account_view(acct).map_err(|_| ProgramError::from(JudgeError::WrongAccount))?;
    require(t.is_initialized(), JudgeError::WrongAccount)?;
    Ok((t.mint().to_bytes(), t.owner().to_bytes(), t.amount()))
}

/// A vault is either not created yet (system-owned, empty) or a token account.
pub fn vault_balance(vault: &AccountView) -> Result<Option<([u8; 32], u64)>, ProgramError> {
    if vault.owned_by(&SYSTEM_ID) && vault.data_len() == 0 {
        return Ok(None);
    }
    let (mint, _, amount) = token_account(vault)?;
    Ok(Some((mint, amount)))
}

pub fn pda(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    Address::find_program_address(seeds, program_id)
}

pub fn now() -> Result<(i64, u64), ProgramError> {
    let c = pinocchio::sysvars::clock::Clock::get()?;
    Ok((c.unix_timestamp, c.slot))
}

pub fn zero(k: &[u8; 32]) -> bool {
    k.iter().all(|b| *b == 0)
}

pub fn allowed_mint(cfg: &[u8], mint: &[u8; 32]) -> ProgramResult {
    use crate::state::*;
    let usdc = key_at(cfg, CFG_USDC_MINT);
    let token = key_at(cfg, CFG_TOKEN_MINT);
    if *mint == usdc || (!zero(&token) && *mint == token) {
        Ok(())
    } else {
        err(JudgeError::MintNotAllowed)
    }
}
