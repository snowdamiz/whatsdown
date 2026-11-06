use crate::{
    checkpoint::{require_ed25519, Checkpoint},
    state::{
        append_anchor, initialize_ring, RingHeader, CONFIG_LEN, LOG_LEN, RING_LEN, TIMELOCK_SECONDS,
    },
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};
use solana_sha256_hasher::hash;

pub fn process_instruction(
    program: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (tag, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => initialize_config(program, accounts, payload),
        1 => register_log(program, accounts, payload),
        2 if payload.is_empty() => grow_ring(program, accounts),
        3 => post_anchor(program, accounts, payload),
        4 => crate::witness::register(program, accounts, payload),
        5 => crate::witness::prepare_set(program, accounts, payload),
        6 if payload.is_empty() => crate::witness::activate_set(program, accounts),
        7 => crate::witness::cosign(program, accounts, payload, false),
        8 => crate::witness::cosign(program, accounts, payload, true),
        9 => crate::witness::compact_cosign(program, accounts, payload),
        10 => crate::stage::initialize(program, accounts, payload),
        11 => crate::stage::append(program, accounts, payload),
        12 if payload.is_empty() => crate::stage::seal(program, accounts),
        13 => crate::stage::verify(program, accounts, payload),
        14 if payload.is_empty() => crate::stage::close(program, accounts),
        15 => crate::custody::configure(program, accounts, payload),
        16 => crate::custody::propose_minimums(program, accounts, payload),
        17 if payload.is_empty() => crate::custody::activate_minimums(program, accounts),
        18 => crate::custody::bond_witness(program, accounts, payload),
        19 => crate::custody::bond_directory(program, accounts, payload),
        20 => crate::custody::request_unbond(program, accounts, payload),
        21 => crate::custody::withdraw(program, accounts, payload),
        22..=24 => crate::adjudication::prove(program, accounts, payload, *tag - 21),
        25 if payload.is_empty() => crate::attendance::initialize(program, accounts),
        26 if payload.is_empty() => crate::attendance::grow(program, accounts),
        27 if payload.is_empty() => crate::attendance::enable(program, accounts),
        28 => crate::attendance::open_epoch(program, accounts, payload),
        29 if payload.is_empty() => crate::attendance::seal(program, accounts),
        30 => crate::witness::compact_c2sp_cosign(program, accounts, payload),
        31 if payload.is_empty() => crate::token_binding::propose(program, accounts),
        32 if payload.is_empty() => crate::token_binding::activate(program, accounts),
        33 if payload.len() == 1 && payload[0] <= 1 => {
            crate::token_custody::migrate(program, accounts, payload[0] == 1)
        }
        34 => crate::token_deposit::witness(program, accounts, payload),
        35 => crate::token_deposit::directory(program, accounts, payload),
        36 if payload.len() == 1 && payload[0] <= 1 => {
            crate::token_deposit::apply(program, accounts, payload[0] == 1)
        }
        37 if payload.len() == 1 && payload[0] <= 1 => {
            crate::token_exit::request(program, accounts, payload[0] == 1)
        }
        38 if payload.len() == 1 && payload[0] <= 1 => {
            crate::token_exit::withdraw(program, accounts, payload[0] == 1)
        }
        39 => crate::token_exit::propose_minimums(program, accounts, payload),
        40 if payload.is_empty() => crate::token_exit::activate_minimums(program, accounts),
        41..=43 => crate::token_proof::prepare(program, accounts, payload, *tag - 40),
        44 if payload.is_empty() => crate::token_proof::settle(program, accounts),
        45 if payload.len() == 1 && payload[0] <= 1 => {
            crate::token_deposit::assess(program, accounts, payload[0] == 1)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

pub(crate) fn pda(
    program: &Address,
    seeds: &[&[u8]],
    account: &AccountView,
) -> Result<u8, ProgramError> {
    let (address, bump) =
        Address::try_find_program_address(seeds, program).ok_or(ProgramError::InvalidSeeds)?;
    if account.address() != &address {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(bump)
}

pub(crate) fn owned(program: &Address, account: &AccountView, writable: bool) -> ProgramResult {
    if account.owner() != program || account.executable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if writable && !account.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

pub(crate) fn authority(account: &AccountView, expected: &[u8]) -> ProgramResult {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if account.address().as_ref() != expected {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

// Allocate+assign handles pre-funded PDAs, so sending one lamport to a future
// account cannot permanently block initialization. No donations are refunded.
pub(crate) fn create_pda(
    program: &Address,
    payer: &AccountView,
    account: &AccountView,
    system: &AccountView,
    space: usize,
    funded_space: usize,
    seeds: &[Seed],
) -> ProgramResult {
    if system.address() != &pinocchio_system::ID
        || !system.executable()
        || account.owner() != &pinocchio_system::ID
        || account.data_len() != 0
        || account.executable()
        || !account.is_writable()
        || !payer.is_writable()
        || !payer.is_signer()
        || payer.address() == account.address()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let rent = Rent::get()?.try_minimum_balance(funded_space)?;
    if rent > account.lamports() {
        Transfer {
            from: payer,
            to: account,
            lamports: rent - account.lamports(),
        }
        .invoke()?;
    }
    let signers = [Signer::from(seeds)];
    Allocate {
        account,
        space: space as u64,
    }
    .invoke_signed(&signers)?;
    Assign {
        account,
        owner: program,
    }
    .invoke_signed(&signers)
}

fn initialize_config(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [upgrade_authority, payer, config, executable, programdata, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 32 || payload == [0; 32] {
        return Err(ProgramError::InvalidInstructionData);
    }
    let loader = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    if executable.address() != program
        || !executable.executable()
        || executable.owner() != &loader
        || programdata.owner() != &loader
        || programdata.executable()
    {
        return Err(ProgramError::InvalidAccountOwner);
    }
    pda(&loader, &[program.as_ref()], programdata)?;
    {
        let image = executable.try_borrow()?;
        let metadata = programdata.try_borrow()?;
        if image.len() != 36
            || image[..4] != 2u32.to_le_bytes()
            || &image[4..36] != programdata.address().as_ref()
            || metadata.len() < 45
            || metadata[..4] != 3u32.to_le_bytes()
            || metadata[12] != 1
        {
            return Err(ProgramError::InvalidAccountData);
        }
        authority(upgrade_authority, &metadata[13..45])?;
    }
    let bump = [pda(program, &[b"config"], config)?];
    create_pda(
        program,
        payer,
        config,
        system,
        CONFIG_LEN,
        CONFIG_LEN,
        &[Seed::from(b"config"), Seed::from(&bump)],
    )?;
    let mut bytes = config.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MCF\x01");
    bytes[4..36].copy_from_slice(payload);
    Ok(())
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn register_log(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [governance, payer, config, log, ring, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_governance(program, config, governance)?;
    let length = *payload
        .first()
        .ok_or(ProgramError::InvalidInstructionData)? as usize;
    if payload.len() < 67 + length {
        return Err(ProgramError::InvalidInstructionData);
    }
    let name = &payload[1..1 + length];
    let version = payload[1 + length];
    let service = &payload[2 + length..34 + length];
    let anchor = &payload[34 + length..66 + length];
    let origin_length = payload[66 + length] as usize;
    if !valid_name(name)
        || !matches!(version, 1 | 2)
        || payload.len() != 67 + length + origin_length
        || origin_length > 128
        || (version == 1 && origin_length != 0)
        || (version == 2 && origin_length == 0)
        || service == [0; 32]
        || anchor == [0; 32]
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let origin = &payload[67 + length..];
    if !origin.iter().all(|b| (33..=126).contains(b) && *b != b'+') {
        return Err(ProgramError::InvalidInstructionData);
    }
    let now = Clock::get()?.unix_timestamp;
    if now < 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let ready = now
        .checked_add(TIMELOCK_SECONDS)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let log_bump = [pda(program, &[b"log", name], log)?];
    let ring_bump = [pda(program, &[b"ring", name], ring)?];
    create_pda(
        program,
        payer,
        log,
        system,
        LOG_LEN,
        LOG_LEN,
        &[Seed::from(b"log"), Seed::from(name), Seed::from(&log_bump)],
    )?;
    create_pda(
        program,
        payer,
        ring,
        system,
        64,
        RING_LEN,
        &[
            Seed::from(b"ring"),
            Seed::from(name),
            Seed::from(&ring_bump),
        ],
    )?;
    let log_id = hash(name).to_bytes();
    let mut bytes = log.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MLG\x01");
    bytes[4] = version;
    bytes[6] = length as u8;
    bytes[8..8 + length].copy_from_slice(name);
    bytes[40..72].copy_from_slice(&log_id);
    bytes[72..104].copy_from_slice(service);
    bytes[104..136].copy_from_slice(anchor);
    bytes[136..168].copy_from_slice(ring.address().as_ref());
    bytes[200..208].copy_from_slice(&ready.to_le_bytes());
    bytes[210..212].copy_from_slice(&(origin_length as u16).to_le_bytes());
    bytes[212..212 + origin_length].copy_from_slice(origin);
    initialize_ring(&mut ring.try_borrow_mut()?, &log_id)
}

pub(crate) fn check_governance(
    program: &Address,
    config: &AccountView,
    governance: &AccountView,
) -> ProgramResult {
    owned(program, config, false)?;
    pda(program, &[b"config"], config)?;
    let bytes = config.try_borrow()?;
    if bytes.len() != CONFIG_LEN || &bytes[..4] != b"MCF\x01" || bytes[36..].iter().any(|b| *b != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    authority(governance, &bytes[4..36])
}

pub(crate) fn load_log(
    program: &Address,
    account: &AccountView,
) -> Result<[u8; LOG_LEN], ProgramError> {
    owned(program, account, false)?;
    let bytes = account.try_borrow()?;
    if bytes.len() != LOG_LEN
        || &bytes[..4] != b"MLG\x01"
        || !matches!(bytes[4], 1 | 2)
        || bytes[5] > 1
        || bytes[7] > 1
        || bytes[6] == 0
        || bytes[6] > 32
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let name = &bytes[8..8 + bytes[6] as usize];
    if !valid_name(name) || bytes[40..72] != hash(name).to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    pda(program, &[b"log", name], account)?;
    Ok(bytes[..].try_into().unwrap())
}

pub(crate) fn check_ring(
    program: &Address,
    log: &[u8; LOG_LEN],
    ring: &AccountView,
) -> ProgramResult {
    owned(program, ring, true)?;
    if ring.address().as_ref() != &log[136..168]
        || ring.data_len() < 64
        || ring.data_len() > RING_LEN
    {
        return Err(ProgramError::InvalidAccountData);
    }
    pda(program, &[b"ring", &log[8..8 + log[6] as usize]], ring)?;
    let bytes = ring.try_borrow()?;
    if RingHeader::parse(&bytes[..64])?.log_id != log[40..72] {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn grow_ring(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log_account, ring] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let log = load_log(program, log_account)?;
    check_ring(program, &log, ring)?;
    let current = ring.data_len();
    if current == RING_LEN {
        return Ok(());
    }
    if RingHeader::parse(&ring.try_borrow()?[..64])?.count != 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    let next = (current + 10240).min(RING_LEN);
    if ring.lamports() < Rent::get()?.try_minimum_balance(next)? {
        return Err(ProgramError::AccountNotRentExempt);
    }
    ring.resize(next)
}

fn post_anchor(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [log_account, ring, anchor, instructions, attendance @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 190 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = load_log(program, log_account)?;
    if attendance.len() != if log[7] == 1 { 2 } else { 0 } {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    check_ring(program, &log, ring)?;
    authority(anchor, &log[104..136])?;
    let clock = Clock::get()?;
    if log[5] != 0 || clock.unix_timestamp < i64::from_le_bytes(log[200..208].try_into().unwrap()) {
        return Err(ProgramError::InvalidArgument);
    }
    let checkpoint = Checkpoint::parse(&payload[2..])?;
    if checkpoint.service_key != log[72..104] || checkpoint.version != log[4] {
        return Err(ProgramError::InvalidArgument);
    }
    require_ed25519(
        instructions,
        u16::from_le_bytes(payload[..2].try_into().unwrap()),
        &checkpoint.service_key,
        &checkpoint.signature,
        &checkpoint.statement(),
    )?;
    let index = append_anchor(
        &mut ring.try_borrow_mut()?,
        &checkpoint,
        clock.slot,
        u16::from_le_bytes(log[208..210].try_into().unwrap()),
    )?;
    if log[7] == 1 {
        crate::attendance::post(program, attendance, &log[40..72], index, &clock)?;
    }
    Ok(())
}
