from Solana.Read import (
  Pubkey,
  AccountInfo,
  OptionalAccountsAtSlot,
  TokenAccount,
  pubkey,
  pubkey_equal,
  token_account
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Solana.Tx import (
  Instruction,
  AccountMeta,
  create_associated_token_idempotent_instruction,
  compute_unit_limit_instruction
)
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorBond import (
  AnchorBond,
  AnchorEconomics,
  AnchorBondAddresses,
  directory_bond_addresses,
  witness_bond_addresses
)
from Transparency.AnchorCustody import (
  AnchorCustody,
  AnchorWitnessBond,
  AnchorBondBalance,
  read_anchor_custody
)
from Transparency.AnchorLog import AnchorLog
from Transparency.AnchorRing import AnchorEntry, decode_anchor_entry
from Transparency.Relay import RelayVerification, validate_relay_submission, verify_relay_fork
from Transparency.RelayStage import RelayStagePlan, RelayStageWitness, prepare_relay_stage
from Transparency.RelayClock import RelayClock, check_relay_clock
from Transparency.RelayLookup import RelayLookupPlan, prepare_relay_lookup
from Transparency.RelayDestinations import relay_destination_address, check_relay_destination
from Transparency.SlashReceipt import slash_receipt_address
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt, find_slash_receipt
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, fork_hash
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey, checkpoint_hash

pub struct RelaySettlementPlan do
  proof :: Bytes
  program :: Pubkey
  log :: Pubkey
  submitter :: Pubkey
  mint :: Pubkey
  receipt :: Pubkey
  stage :: RelayStagePlan
  setup :: List<Instruction>
  settlement :: Instruction
  compute_budget :: Instruction
  lookup :: RelayLookupPlan
  total_slashed :: U64
  finder_amount :: U64
  directory_slashed :: U64
  clock :: RelayClock
  context_slot :: U64
end

pub type RelayAdmission do
  ReadyToSubmit(RelaySettlementPlan)
  AlreadySettled(ConfirmedSlashReceipt)
end

fn collectible(value :: AnchorWitnessBond) -> Bool do
  case value.escrow do
    None -> false
    Some(value) -> value.bond.status == 1 || value.bond.status == 2
  end
end

fn maximum(first :: U64, second :: U64) -> U64 do
  if U64.compare(first, second) > 0 do
    first
  else
    second
  end
end

fn totals(values :: List<AnchorWitnessBond>,
  amount :: U64,
  finder :: U64,
  bonded_at :: U64) -> (U64, U64, U64)!String do
  if List.length(values) == 0 do
    return Ok((amount, finder, bonded_at))
  end
  let value = case List.head(values).escrow do
    None -> return Err("relay_witness_not_collectible")
    Some(value) -> value
  end
  totals(List.tail(values),
    U64.add(amount, value.vault_amount)?,
    U64.add(finder, U64.divide(value.vault_amount, U64.parse("10")?)?)?,
    maximum(bonded_at, value.bond.bonded_at))
end

fn meta(address :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: address, signer: signer, writable: writable }
end

fn anchor_accounts(pins :: AnchorPins,
  log :: Pubkey,
  proof :: ForkProof,
  verified :: RelayVerification) -> List<AccountMeta>!String do
  case proof.second do
    SignedCheckpoint(_) -> Ok([])
    AnchorReference(_) -> do
      let entry = decode_anchor_entry(verified.anchor_entry)?
      let set = if entry.witness_generation == 0 do
        log
      else
        find_program_address(pins.program,
          [
            Bytes.from_utf8("witness-set"),
            pins.log_id,
            Bytes.write_uint_le(Int.to_string(entry.witness_generation), 2)?
          ])?.address
      end
      Ok([meta(pins.ring, false, false), meta(set, false, false)])
    end
  end
end

# Only this boundary performs admission reads. Canonical framing and signatures
# precede RPC; an existing authenticated receipt precedes ring discovery and
# age/custody work. All estimates describe the observed state, not a payout
# guarantee. The judge rechecks age, identities and balances atomically.
pub fn admit_relay_fork(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  mint :: Pubkey,
  submitter :: Pubkey,
  wire :: Bytes,
  minimum_slot :: U64) -> RelayAdmission!String do
  let proof = validate_relay_submission(service_key, version, wire)?
  if Bytes.length(mint.bytes) != 32
    || Bytes.length(submitter.bytes) != 32
    || Bytes.to_hex(mint.bytes) == String.repeat("00", 32)
    || Bytes.to_hex(submitter.bytes) == String.repeat("00", 32) do
    return Err("invalid_relay_pins")
  end
  let pins = sample_anchor_sources(pins)?
  let hash = fork_hash(proof)?
  case find_slash_receipt(pins, service_key, version, mint, hash, minimum_slot)? do
    Some(receipt) -> return Ok(AlreadySettled(receipt))
    None -> nil
  end
  let verified = verify_relay_fork(pins, service_key, version, wire, minimum_slot)?
  let custody = read_anchor_custody(pins,
    service_key,
    version,
    mint,
    verified.verdict.witnesses,
    verified.context_slot)?
  case custody.economics do
    None -> return Err("relay_custody_not_configured")
    Some(_) -> nil
  end
  let directory = case custody.directory do
    None -> return Err("relay_directory_not_collectible")
    Some(value) -> value
  end
  if directory.bond.status < 1 || directory.bond.status > 3 do
    return Err("relay_directory_not_collectible")
  end
  let directory_amount = if directory.bond.status == 3 do
    U64.parse("0")?
  else
    directory.vault_amount
  end
  # Optional signatures for already withdrawn/slashed keys stay in the FRK but
  # are not verified into this Stage's required settlement account list.
  let witnesses = List.filter(custody.witnesses, fn(value) -> collectible(value) end)
  let selected = %{verified |
    verdict: %{verified.verdict |
      witnesses: for value in witnesses do
        WitnessKey { witness_id: value.witness_id, public_key: value.public_key }
      end
    }
  }
  let stage = prepare_relay_stage(pins.program, pins.log_id, submitter, selected)?
  let (total, finder_amount, bonded_at) = totals(witnesses,
    directory_amount,
    U64.divide(directory_amount, U64.parse("10")?)?,
    directory.bond.bonded_at)?
  if total == U64.parse("0")? do
    case find_slash_receipt(pins, service_key, version, mint, hash, custody.context_slot)? do
      Some(receipt) -> return Ok(AlreadySettled(receipt))
      None -> return Err("relay_no_collectible_assets")
    end
  end
  let (second_hash, second_time) = case proof.second do
    SignedCheckpoint(second) -> (checkpoint_hash(second)?, second.timestamp)
    AnchorReference(_) -> do
      let entry = decode_anchor_entry(verified.anchor_entry)?
      (entry.checkpoint_hash, entry.timestamp)
    end
  end
  let clock = check_relay_clock(pins.endpoints,
    proof.first.timestamp,
    second_time,
    bonded_at,
    custody.context_slot)?
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  let directory_addresses = directory_bond_addresses(pins.program, pins.log_id, mint)?
  let finder = Pubkey { bytes: stage.finder }
  let locked = find_program_address(pins.program, [Bytes.from_utf8("locked"), pins.log_id])?.address
  let finder_ata = relay_destination_address(finder, mint)?
  let locked_ata = relay_destination_address(locked, mint)?
  if pubkey_equal(finder_ata, locked_ata) do
    return Err("relay_destination_alias")
  end
  let groups = for subject in stage.witnesses do
    let bond = witness_bond_addresses(pins.program,
      pins.log_id,
      mint,
      subject.key.witness_id,
      subject.key.public_key)?
    [
      meta(subject.address, false, true),
      meta(bond.bond, false, true),
      meta(bond.vault, false, true)
    ]
  end
  let vaults = [directory_addresses.vault]
    ++ for group in groups do
      List.get(group, 2).pubkey
    end
  for vault in vaults do
    if pubkey_equal(vault, finder_ata) || pubkey_equal(vault, locked_ata) do
      return Err("relay_destination_alias")
    end
  end
  let destinations = read_anchor_accounts(pins.endpoints,
    [finder_ata, locked_ata],
    clock.context_slot)?
  check_relay_destination(List.get(destinations.accounts, 0), finder, mint, finder_amount, false)?
  check_relay_destination(List.get(destinations.accounts, 1),
    locked,
    mint,
    U64.subtract(total, finder_amount)?,
    true)?
  case find_slash_receipt(pins, service_key, version, mint, hash, destinations.slot)? do
    Some(receipt) -> return Ok(AlreadySettled(receipt))
    None -> nil
  end
  let receipt = slash_receipt_address(pins.program, pins.log_id, hash)?
  let accounts = [
    meta(submitter, true, true),
    meta(addresses.log, false, true),
    meta(stage.stage, false, false),
    meta(directory_addresses.economics, false, true),
    meta(receipt, false, true),
    meta(directory_addresses.bond, false, true),
    meta(directory_addresses.vault, false, true),
    meta(finder_ata, false, true),
    meta(locked_ata, false, true),
    meta(mint, false, false),
    meta(pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?, false, false),
    meta(pubkey("11111111111111111111111111111111")?, false, false)
  ]
    ++ anchor_accounts(pins, addresses.log, proof, verified)?
    ++ List.flat_map(groups, fn(values) -> values end)
  let settlement = Instruction {
    program_id: pins.program,
    accounts: accounts,
    data: Bytes.concat(Bytes.write_uint_le(Int.to_string(21 + proof.kind), 1)?, second_hash)?
  }
  Ok(ReadyToSubmit(RelaySettlementPlan {
    proof: wire,
    program: pins.program,
    log: addresses.log,
    submitter: submitter,
    mint: mint,
    receipt: receipt,
    stage: stage,
    setup: [
      create_associated_token_idempotent_instruction(submitter, finder_ata, finder, mint)?,
      create_associated_token_idempotent_instruction(submitter, locked_ata, locked, mint)?
    ],
    settlement: settlement,
    compute_budget: compute_unit_limit_instruction(1400000)?,
    lookup: prepare_relay_lookup(submitter, settlement, clock.context_slot)?,
    total_slashed: total,
    finder_amount: finder_amount,
    directory_slashed: directory_amount,
    clock: clock,
    context_slot: destinations.slot
  }))
end
