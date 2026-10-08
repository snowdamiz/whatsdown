//! Config and the 14-day parameter timelock. Governance can register logs,
//! co-sign witness registrations, bond the directory, rotate a log's anchor
//! authority, and (after the timelock) change the authority, the token mint
//! (once), the rewards program and the minimum for new bonds. It has no
//! instruction that moves a vault.

use crate::error::{err, require, JudgeError};
use crate::state::*;
use crate::util::*;
use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};

/// initialize(authority32, usdc_mint32, token_mint32, rewards_program32,
/// min_bond_usdc u64, min_bond_token u64). Signed by the program's upgrade
/// authority, so nobody can front-run the deployer.
pub fn initialize(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [deployer, config, programdata, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(deployer)?;
    is_program(system, &SYSTEM_ID)?;
    require(data.len() == 144, JudgeError::InvalidData)?;
    let (expected, _) = pda(&[program_id.as_ref()], &LOADER_V3_ID);
    require(programdata.address() == &expected && programdata.owned_by(&LOADER_V3_ID), JudgeError::WrongAccount)?;
    {
        // UpgradeableLoaderState::ProgramData: u32 3 ‖ u64 slot ‖ Option<Pubkey>.
        let pd = programdata.try_borrow()?;
        let authority_is_signer = pd.len() >= 45 && u32_at(&pd, 0) == 3 && pd[12] == 1 && pd[13..45] == deployer.address().as_ref()[..];
        require(authority_is_signer, JudgeError::Unauthorized)?;
    }
    require(!zero(data[32..64].try_into().unwrap()), JudgeError::InvalidParameter)?;
    let (addr, bump) = pda(&[b"config"], program_id);
    require(config.address() == &addr, JudgeError::WrongAccount)?;
    let b = [bump];
    create_pda(deployer, config, CONFIG_LEN, program_id, &[Seed::from(b"config"), Seed::from(&b)])?;
    let mut d = config.try_borrow_mut()?;
    d[0] = TAG_CONFIG;
    d[1] = VERSION;
    d[CFG_BUMP] = bump;
    put(&mut d, CFG_AUTHORITY, &data[0..32]);
    put(&mut d, CFG_USDC_MINT, &data[32..64]);
    put(&mut d, CFG_TOKEN_MINT, &data[64..96]);
    put(&mut d, CFG_REWARDS, &data[96..128]);
    put(&mut d, CFG_MIN_BOND_USDC, &data[128..136]);
    put(&mut d, CFG_MIN_BOND_TOKEN, &data[136..144]);
    Ok(())
}

/// Checks that `acct` signed and is the Config authority.
pub fn authority(acct: &AccountView, cfg: &[u8]) -> ProgramResult {
    signer(acct)?;
    require(acct.address().as_ref() == &cfg[CFG_AUTHORITY..CFG_AUTHORITY + 32], JudgeError::Unauthorized)
}

/// propose(kind u8, value32): starts the 14-day timelock for one change.
/// Kind 0 cancels the pending change. A new proposal replaces the old one.
pub fn propose(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 33 && data[0] <= PARAM_MIN_BOND_TOKEN, JudgeError::InvalidData)?;
    let (t, _) = now()?;
    let mut d = load_mut(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
    authority(auth, &d)?;
    d[CFG_PENDING_KIND] = data[0];
    put_i64(&mut d, CFG_PENDING_AFTER, if data[0] == 0 { 0 } else { t + TIMELOCK_SECONDS });
    put(&mut d, CFG_PENDING_VALUE, if data[0] == 0 { &[0; 32] } else { &data[1..33] });
    Ok(())
}

/// apply(): anyone, once the timelock has run out.
pub fn apply(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    let [config, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (t, _) = now()?;
    let mut d = load_mut(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
    let kind = d[CFG_PENDING_KIND];
    require(kind != 0, JudgeError::NoPendingChange)?;
    require(t >= i64_at(&d, CFG_PENDING_AFTER), JudgeError::TimelockActive)?;
    let value = key_at(&d, CFG_PENDING_VALUE);
    match kind {
        PARAM_AUTHORITY => {
            require(!zero(&value), JudgeError::InvalidParameter)?;
            put(&mut d, CFG_AUTHORITY, &value);
        }
        PARAM_TOKEN_MINT => {
            // Set once: vaults bonded in the token must keep burning on slash.
            let unset = zero(&key_at(&d, CFG_TOKEN_MINT));
            require(unset && !zero(&value) && value != key_at(&d, CFG_USDC_MINT), JudgeError::InvalidParameter)?;
            put(&mut d, CFG_TOKEN_MINT, &value);
        }
        PARAM_REWARDS => put(&mut d, CFG_REWARDS, &value),
        PARAM_MIN_BOND_USDC => put(&mut d, CFG_MIN_BOND_USDC, &value[..8]),
        PARAM_MIN_BOND_TOKEN => put(&mut d, CFG_MIN_BOND_TOKEN, &value[..8]),
        _ => return err(JudgeError::InvalidData),
    }
    d[CFG_PENDING_KIND] = 0;
    put_i64(&mut d, CFG_PENDING_AFTER, 0);
    put(&mut d, CFG_PENDING_VALUE, &[0; 32]);
    Ok(())
}
