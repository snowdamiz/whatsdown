//! Explicit mixed collateral deposits. Pending units never change an earned snapshot.
use crate::{
    custody::{
        advance_eligibility, associated, mint_valid, now, token_balance, token_program, u64_at,
    },
    processor::{authority, create_pda, load_log, owned, pda},
    token_binding::{load_binding, qualified_program_slot, read_rewards_pool},
    token_custody::{decode_bond, decode_economics, load_economics, ORIGINAL_SUPPLY},
    witness::{identity, load_witness},
};
use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_associated_token_account::{instructions::CreateIdempotent, ID as ATA_ID};
use pinocchio_token::instructions::TransferChecked;

pub const PENDING_LEN: usize = 96;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PendingBond {
    pub amount: u64,
    pub opened_at: i64,
    /// The immutable USD target for this MORSE bond lifetime; USDC uses zero.
    pub target: u64,
}
pub fn decode_pending(d: &[u8]) -> Result<PendingBond, ProgramError> {
    if d.len() != PENDING_LEN
        || &d[..4] != b"MBP\x02"
        || d[4..36] == [0; 32]
        || d[36..68] == [0; 32]
        || d[92..].iter().any(|b| *b != 0)
    {
        return Err(invalid());
    }
    let value = PendingBond {
        amount: u64_at(d, 68),
        opened_at: crate::custody::i64_at(d, 76),
        target: u64_at(d, 84),
    };
    if value.opened_at < 0 || (value.amount == 0) != (value.opened_at == 0) {
        return Err(invalid());
    }
    Ok(value)
}
pub fn load_pending(
    program: &Address,
    account: &AccountView,
    bond: &Address,
    mint: &Address,
    asset: u8,
) -> Result<PendingBond, ProgramError> {
    owned(program, account, false)?;
    pda(program, &[b"bond-pending", bond.as_ref()], account)?;
    let d = account.try_borrow()?;
    let value = decode_pending(&d)?;
    if d[4..36] != *bond.as_ref()
        || d[36..68] != *mint.as_ref()
        || (asset == 0 && value.target != 0)
        || (asset == 1 && value.target == 0)
        || asset > 1
    {
        return Err(invalid());
    }
    Ok(value)
}
pub(crate) fn optional_pending(
    program: &Address,
    account: &AccountView,
    bond: &Address,
    mint: &Address,
    asset: u8,
) -> Result<Option<PendingBond>, ProgramError> {
    pda(program, &[b"bond-pending", bond.as_ref()], account)?;
    if account.owner() == program {
        return load_pending(program, account, bond, mint, asset).map(Some);
    }
    if asset != 0
        || account.owner() != &pinocchio_system::ID
        || account.data_len() != 0
        || account.executable()
    {
        return Err(invalid());
    }
    Ok(None)
}
pub(crate) struct CollateralAccounts<'a> {
    pub log: &'a mut AccountView,
    pub economy: &'a mut AccountView,
    pub binding: &'a AccountView,
    pub token: &'a AccountView,
    pub token_data: &'a AccountView,
    pub config: &'a AccountView,
    pub mint: &'a AccountView,
    pub oracle: &'a AccountView,
    pub rewards: &'a AccountView,
    pub rewards_data: &'a AccountView,
    pub pool: &'a AccountView,
}
pub(crate) struct CollateralState {
    pub log: [u8; crate::state::LOG_LEN],
    pub policy: [u8; 192],
    pub active_epoch: u64,
}
impl CollateralAccounts<'_> {
    pub(crate) fn load(&self, program: &Address) -> Result<CollateralState, ProgramError> {
        let log = load_log(program, self.log)?;
        let log_id = log[40..72].try_into().unwrap();
        let policy = load_economics(program, self.economy, &log_id, true)?;
        let binding = load_binding(program, self.binding, &log_id)?;
        if binding.activated_at == 0
            || binding.log != *self.log.address()
            || binding.token_program != *self.token.address()
            || binding.token_config != *self.config.address()
            || binding.mint != *self.mint.address()
            || binding.oracle != *self.oracle.address()
            || binding.rewards_program != *self.rewards.address()
            || binding.rewards_pool != *self.pool.address()
            || qualified_program_slot(self.token, self.token_data)? != binding.token_slot
            || qualified_program_slot(self.rewards, self.rewards_data)? != binding.rewards_slot
        {
            return Err(invalid());
        }
        morse_token::oracle::revision(self.token.address(), self.config, self.mint, self.oracle)?;
        let (_, active_epoch) = read_rewards_pool(
            program,
            self.log.address(),
            &log_id,
            self.rewards.address(),
            self.pool,
            &policy[36..68],
        )?;
        Ok(CollateralState {
            log,
            policy,
            active_epoch,
        })
    }
    pub(crate) fn price(&self, clock: i64) -> Result<u64, ProgramError> {
        morse_token::oracle::value(
            self.token.address(),
            self.config,
            self.mint,
            self.oracle,
            clock,
        )
    }
}
struct Deposit<'a> {
    operator: &'a AccountView,
    context: CollateralAccounts<'a>,
    witness: Option<&'a mut AccountView>,
    bond: &'a mut AccountView,
    pending: &'a mut AccountView,
    vault: &'a AccountView,
    source: &'a AccountView,
    mint: &'a AccountView,
    spl: &'a AccountView,
    ata: &'a AccountView,
    system: &'a AccountView,
}
pub(crate) fn subject(
    program: &Address,
    state: &CollateralState,
    morse: &Address,
    bond: &AccountView,
    witness: Option<&AccountView>,
) -> Result<[u8; 208], ProgramError> {
    subject_compatible(program, state, morse, bond, witness, false)
}
pub(crate) fn subject_compatible(
    program: &Address,
    state: &CollateralState,
    morse: &Address,
    bond: &AccountView,
    witness: Option<&AccountView>,
    legacy: bool,
) -> Result<[u8; 208], ProgramError> {
    let record = witness
        .map(|w| load_witness(program, w, &state.log[40..72]))
        .transpose()?;
    let identity = record
        .as_ref()
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let identity = identity
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    owned(program, bond, false)?;
    pda(program, &[b"bond", &state.log[40..72], identity], bond)?;
    let bytes = bond.try_borrow()?;
    if bytes.len() != 208 {
        return Err(invalid());
    }
    let mut d: [u8; 208] = bytes[..].try_into().unwrap();
    drop(bytes);
    if legacy && &d[..4] == b"MBD\x01" {
        if d[6..8].iter().chain(&d[200..]).any(|b| *b != 0) {
            return Err(invalid());
        }
        d[3] = 2;
    }
    let value = decode_bond(&d)?;
    let mint = if value.asset == 0 {
        &state.policy[36..68]
    } else {
        morse.as_ref()
    };
    let vault = Address::find_program_address(
        &[bond.address().as_ref(), pinocchio_token::ID.as_ref(), mint],
        &ATA_ID,
    )
    .0;
    if value.witness != witness.is_some()
        || d[8..40] != state.log[40..72]
        || &d[104..136] != mint
        || d[136..168] != *vault.as_ref()
    {
        return Err(invalid());
    }
    if let Some(r) = record {
        if d[40..72] != *witness.unwrap().address().as_ref()
            || d[72..104] != r[104..136]
            || d[136..168] != r[232..264]
            || d[184..192] != r[264..272]
            || value.status != r[5]
            || value.principal > u64_at(&state.policy, if value.asset == 0 { 148 } else { 176 })
        {
            return Err(invalid());
        }
    } else if d[40..72] != [0; 32]
        || d[72..104] != state.policy[68..100]
        || d[136..168] != state.log[168..200]
        || value.status != state.policy[164]
        || value.asset != state.policy[165]
        || value.principal != u64_at(&state.policy, if value.asset == 0 { 156 } else { 184 })
    {
        return Err(invalid());
    }
    Ok(d)
}
/// All tracked topups become active together. The price grace is evaluated
/// against the target recorded on entry, and never against a later minimum.
pub(crate) fn apply(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
) -> ProgramResult {
    update(program, accounts, witness, true)
}
/// A real grace transition may invalidate collection. It never activates or
/// consumes pending units, so a deposit cannot manufacture a revision change.
pub(crate) fn assess(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
) -> ProgramResult {
    update(program, accounts, witness, false)
}
fn update(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
    activate: bool,
) -> ProgramResult {
    let (base, tail) = accounts.split_at_mut(core::cmp::min(14, accounts.len()));
    let [log, economy, binding, bond, pending, vault, token, token_data, config, mint, oracle, rewards, rewards_data, pool] =
        base
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if tail.len() != usize::from(witness) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let context = CollateralAccounts {
        log,
        economy,
        binding,
        token,
        token_data,
        config,
        mint,
        oracle,
        rewards,
        rewards_data,
        pool,
    };
    let state = context.load(program)?;
    if activate && state.active_epoch != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let d = subject(program, &state, mint.address(), bond, tail.first())?;
    owned(program, bond, true)?;
    let mut b = decode_bond(&d)?;
    if b.status != 1 {
        return Err(ProgramError::InvalidArgument);
    }
    let selected = Address::new_from_array(d[104..136].try_into().unwrap());
    let p = load_pending(program, pending, bond.address(), &selected, b.asset)?;
    owned(program, pending, activate)?;
    let clock = now()?;
    if p.opened_at > clock {
        return Err(invalid());
    }
    associated(bond.address(), &selected, vault)?;
    let amount = if activate { p.amount } else { 0 };
    let principal = b
        .principal
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let tracked = b
        .principal
        .checked_add(p.amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if (b.asset == 1 && principal > ORIGINAL_SUPPLY)
        || token_balance(vault, &selected, bond.address(), true)? < tracked
    {
        return Err(invalid());
    }
    let e = decode_economics(&state.policy)?;
    let price = if b.asset == 1 || (amount != 0 && (e.witness_token != 0 || e.directory_token != 0))
    {
        context.price(clock)?
    } else {
        0
    };
    let counter = match (witness, b.asset) {
        (true, 0) => 148,
        (false, 0) => 156,
        (true, 1) => 176,
        _ => 184,
    };
    let total = u64_at(&state.policy, counter)
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if amount != 0 {
        let mut witness_value =
            e.witness_usdc as u128 * 1_000_000 + e.witness_token as u128 * price as u128;
        let mut directory_value =
            e.directory_usdc as u128 * 1_000_000 + e.directory_token as u128 * price as u128;
        let added = amount as u128
            * if b.asset == 0 {
                1_000_000
            } else {
                price as u128
            };
        if witness {
            witness_value += added;
        } else {
            directory_value += added;
        }
        if (witness && e.directory_status != 1)
            || witness_value > directory_value
            || (b.asset == 1
                && total
                    .checked_add(if witness {
                        e.directory_token
                    } else {
                        e.witness_token
                    })
                    .is_none_or(|v| v > ORIGINAL_SUPPLY))
        {
            return Err(ProgramError::InvalidArgument);
        }
    }
    b.principal = principal;
    let assessment = if b.asset == 1 {
        crate::token_custody::assess(b, price, p.target, clock)?
    } else {
        crate::token_custody::BondAssessment {
            eligible: true,
            underwater_since: 0,
        }
    };
    if amount != 0 || assessment.underwater_since != b.underwater_since {
        advance_eligibility(context.economy)?;
        context.economy.try_borrow_mut()?[counter..counter + 8]
            .copy_from_slice(&total.to_le_bytes());
        let mut d = bond.try_borrow_mut()?;
        d[168..176].copy_from_slice(&principal.to_le_bytes());
        d[200..208].copy_from_slice(&assessment.underwater_since.to_le_bytes());
        drop(d);
        if amount != 0 {
            pending.try_borrow_mut()?[68..84].fill(0);
        }
    }
    Ok(())
}
pub(crate) fn witness(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [operator, log, economy, binding, witness, bond, pending, vault, source, mint, token, token_data, config, morse, oracle, rewards, rewards_data, pool, spl, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    deposit(
        program,
        Deposit {
            operator,
            context: CollateralAccounts {
                log,
                economy,
                binding,
                token,
                token_data,
                config,
                mint: morse,
                oracle,
                rewards,
                rewards_data,
                pool,
            },
            witness: Some(witness),
            bond,
            pending,
            vault,
            source,
            mint,
            spl,
            ata,
            system,
        },
        payload,
    )
}
pub(crate) fn directory(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [governance, judge_config, operator, log, economy, binding, bond, pending, vault, source, mint, token, token_data, config, morse, oracle, rewards, rewards_data, pool, spl, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    crate::processor::check_governance(program, judge_config, governance)?;
    deposit(
        program,
        Deposit {
            operator,
            context: CollateralAccounts {
                log,
                economy,
                binding,
                token,
                token_data,
                config,
                mint: morse,
                oracle,
                rewards,
                rewards_data,
                pool,
            },
            witness: None,
            bond,
            pending,
            vault,
            source,
            mint,
            spl,
            ata,
            system,
        },
        payload,
    )
}
fn deposit(program: &Address, mut a: Deposit<'_>, payload: &[u8]) -> ProgramResult {
    if payload.len() != 9 || payload[0] > 1 || u64_at(payload, 1) == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let asset = payload[0];
    let amount = u64_at(payload, 1);
    let clock = now()?;
    let state = a.context.load(program)?;
    let policy = decode_economics(&state.policy)?;
    let log_id: &[u8; 32] = state.log[40..72].try_into().unwrap();
    if clock <= 0
        || state.log[5] != 0
        || clock < crate::custody::i64_at(&state.policy, 116)
        || a.mint.address().as_ref()
            != if asset == 0 {
                &state.policy[36..68]
            } else {
                a.context.mint.address().as_ref()
            }
        || a.source.address() == a.vault.address()
    {
        return Err(ProgramError::InvalidArgument);
    }
    token_program(a.spl)?;
    mint_valid(a.mint)?;
    if a.ata.address() != &ATA_ID || !a.ata.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let record = a
        .witness
        .as_ref()
        .map(|w| load_witness(program, w, log_id))
        .transpose()?;
    let identity = record
        .as_ref()
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let subject = identity
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    let owner = record
        .as_ref()
        .map_or(&state.policy[68..100], |r| &r[104..136]);
    authority(a.operator, owner)?;
    let bump = [pda(program, &[b"bond", log_id, subject], a.bond)?];
    let pending_bump = [pda(
        program,
        &[b"bond-pending", a.bond.address().as_ref()],
        a.pending,
    )?];
    associated(a.bond.address(), a.mint.address(), a.vault)?;
    let prior = if a.bond.owner() == program {
        owned(program, a.bond, true)?;
        let d = a.bond.try_borrow()?;
        let prior = decode_bond(&d)?;
        if !matches!(prior.status, 1 | 4)
            || prior.witness != record.is_some()
            || d[8..40] != *log_id
            || &d[72..104] != owner
            || (prior.status == 1
                && (prior.asset != asset
                    || d[104..136] != *a.mint.address().as_ref()
                    || d[136..168] != *a.vault.address().as_ref()))
            || (record.as_ref().is_some_and(|r| {
                d[40..72] != *a.witness.as_ref().unwrap().address().as_ref()
                    || d[136..168] != r[232..264]
                    || d[184..192] != r[264..272]
            }))
            || (record.is_none()
                && (d[40..72] != [0; 32]
                    || prior.status != policy.directory_status
                    || prior.asset != policy.directory_asset
                    || d[136..168] != state.log[168..200]
                    || prior.principal
                        != u64_at(&state.policy, if prior.asset == 0 { 156 } else { 184 })))
        {
            return Err(invalid());
        }
        Some(prior)
    } else {
        None
    };
    let active = prior.is_some_and(|b| b.status == 1);
    let principal = prior.map_or(0, |b| b.principal);
    if let Some(r) = &record {
        owned(program, a.witness.as_ref().unwrap(), true)?;
        if r[5] != prior.map_or(0, |b| b.status)
            || (prior.is_none() && (r[232..264] != [0; 32] || r[264..272] != [0; 8]))
        {
            return Err(invalid());
        }
    } else {
        owned(program, a.context.log, true)?;
        if prior.is_none()
            && (policy.directory_status != 0
                || policy.directory_usdc != 0
                || policy.directory_token != 0
                || state.log[168..200] != [0; 32])
        {
            return Err(invalid());
        }
    }
    let existing_pending = if a.pending.owner() == program {
        owned(program, a.pending, true)?;
        // A withdrawn bond may choose its next asset only with an empty pending account.
        let d = a.pending.try_borrow()?;
        let v = decode_pending(&d)?;
        let prior_asset = prior.map_or(asset, |b| b.asset);
        let prior_mint = if prior_asset == 0 {
            &state.policy[36..68]
        } else {
            a.context.mint.address().as_ref()
        };
        if d[4..36] != *a.bond.address().as_ref()
            || (!active && v.amount != 0)
            || &d[36..68] != prior_mint
            || (prior_asset == 0 && v.target != 0)
            || (prior_asset == 1 && v.target == 0)
            || v.opened_at > clock
        {
            return Err(invalid());
        }
        drop(d);
        if active {
            Some(load_pending(
                program,
                a.pending,
                a.bond.address(),
                a.mint.address(),
                asset,
            )?)
        } else {
            Some(v)
        }
    } else {
        None
    };
    if active && asset == 1 && existing_pending.is_none() {
        return Err(invalid());
    }
    let pending_amount = if active {
        existing_pending
            .map_or(0, |v| v.amount)
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?
    } else {
        0
    };
    let maximum = principal
        .checked_add(if active { pending_amount } else { amount })
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if asset == 1 && maximum > ORIGINAL_SUPPLY {
        return Err(ProgramError::InvalidArgument);
    }
    let target = if asset == 0 {
        0
    } else if active {
        existing_pending.unwrap().target
    } else if record.is_some() {
        policy.witness_target
    } else {
        policy.directory_target
    };
    let counter = match (record.is_some(), asset) {
        (true, 0) => 148,
        (false, 0) => 156,
        (true, 1) => 176,
        _ => 184,
    };
    let total = u64_at(&state.policy, counter)
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if !active {
        let price = if asset == 1 || policy.witness_token != 0 || policy.directory_token != 0 {
            a.context.price(clock)?
        } else {
            0
        };
        let minimum = if record.is_some() {
            policy.witness_target
        } else {
            policy.directory_target
        };
        if (asset == 0 && amount < minimum)
            || (asset == 1 && amount as u128 * (price as u128) < minimum as u128 * 1_000_000)
        {
            return Err(ProgramError::InvalidArgument);
        }
        let mut witness_value =
            policy.witness_usdc as u128 * 1_000_000 + policy.witness_token as u128 * price as u128;
        let mut directory_value = policy.directory_usdc as u128 * 1_000_000
            + policy.directory_token as u128 * price as u128;
        let added = amount as u128 * if asset == 0 { 1_000_000 } else { price as u128 };
        if record.is_some() {
            witness_value += added;
        } else {
            directory_value += added;
        }
        if (record.is_some() && policy.directory_status != 1)
            || witness_value > directory_value
            || (asset == 1
                && total
                    .checked_add(if record.is_some() {
                        policy.directory_token
                    } else {
                        policy.witness_token
                    })
                    .is_none_or(|v| v > ORIGINAL_SUPPLY))
        {
            return Err(ProgramError::InvalidArgument);
        }
    }
    let source_before = token_balance(a.source, a.mint.address(), a.operator.address(), false)?;
    if source_before < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    if prior.is_none() {
        create_pda(
            program,
            a.operator,
            a.bond,
            a.system,
            208,
            208,
            &[
                Seed::from(b"bond"),
                Seed::from(log_id),
                Seed::from(subject),
                Seed::from(&bump),
            ],
        )?;
    }
    if existing_pending.is_none() {
        create_pda(
            program,
            a.operator,
            a.pending,
            a.system,
            PENDING_LEN,
            PENDING_LEN,
            &[
                Seed::from(b"bond-pending"),
                Seed::from(a.bond.address().as_ref()),
                Seed::from(&pending_bump),
            ],
        )?;
    }
    CreateIdempotent {
        funding_account: a.operator,
        account: a.vault,
        wallet: a.bond,
        mint: a.mint,
        system_program: a.system,
        token_program: a.spl,
    }
    .invoke()?;
    let vault_before = token_balance(a.vault, a.mint.address(), a.bond.address(), true)?;
    TransferChecked::new(a.source, a.mint, a.vault, a.operator, amount, 6).invoke()?;
    if token_balance(a.source, a.mint.address(), a.operator.address(), false)?
        != source_before - amount
        || token_balance(a.vault, a.mint.address(), a.bond.address(), true)?
            != vault_before
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    if !active {
        let mut d = a.bond.try_borrow_mut()?;
        d.fill(0);
        d[..4].copy_from_slice(b"MBD\x02");
        d[4] = 1;
        d[5] = u8::from(record.is_some());
        d[6] = asset;
        d[8..40].copy_from_slice(log_id);
        if let Some(w) = a.witness.as_ref() {
            d[40..72].copy_from_slice(w.address().as_ref());
        }
        d[72..104].copy_from_slice(owner);
        d[104..136].copy_from_slice(a.mint.address().as_ref());
        d[136..168].copy_from_slice(a.vault.address().as_ref());
        d[168..176].copy_from_slice(&amount.to_le_bytes());
        d[176..184].copy_from_slice(&clock.to_le_bytes());
        drop(d);
        a.context.economy.try_borrow_mut()?[counter..counter + 8]
            .copy_from_slice(&total.to_le_bytes());
        advance_eligibility(a.context.economy)?;
        if let Some(w) = a.witness.as_mut() {
            let mut d = w.try_borrow_mut()?;
            d[5] = 1;
            d[232..264].copy_from_slice(a.vault.address().as_ref());
            d[264..272].fill(0);
        } else {
            a.context.log.try_borrow_mut()?[168..200].copy_from_slice(a.vault.address().as_ref());
            let mut d = a.context.economy.try_borrow_mut()?;
            d[164] = 1;
            d[165] = asset;
        }
    }
    let mut d = a.pending.try_borrow_mut()?;
    d.fill(0);
    d[..4].copy_from_slice(b"MBP\x02");
    d[4..36].copy_from_slice(a.bond.address().as_ref());
    d[36..68].copy_from_slice(a.mint.address().as_ref());
    d[68..76].copy_from_slice(&pending_amount.to_le_bytes());
    let opened = if pending_amount == 0 {
        0
    } else {
        existing_pending
            .filter(|v| v.amount != 0)
            .map_or(clock, |v| v.opened_at)
    };
    d[76..84].copy_from_slice(&opened.to_le_bytes());
    d[84..92].copy_from_slice(&target.to_le_bytes());
    Ok(())
}
