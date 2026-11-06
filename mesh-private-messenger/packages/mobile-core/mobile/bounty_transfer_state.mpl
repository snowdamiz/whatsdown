from Bounty.Transfer import (
  BountyTransfer,
  encode_bounty_transfer,
  decode_bounty_transfer,
  validate_bounty_transfer,
  bounty_transfer_instructions,
  authenticate_bounty_transfer
)
from Mobile.Bounty import bounty_state
from Bounty.Settlement import BountyTransferSettlement
from Mobile.Codec import mobile_byte, mobile_read_u64, mobile_write_u64, mobile_utf8
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Solana.Read import Pubkey
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.BountyTransfer import store_bounty_transfer_snapshot

pub struct BountyTransferJournal do
  identity :: Bytes
  proof_identity :: Bytes
  # 0 cancelled unsigned, 1 awaiting prompt, 2 signed/unknown, 3 RPC accepted,
  # 4 finalized successful, 5 finalized failed. Missing history stays unknown.
  status :: Int
  intent :: Bytes
  payer :: Bytes
  usdc :: Bytes
  context_slot :: U64
  last_valid_block_height :: U64
  wire :: Bytes
  signature :: Bytes
  finalized_slot :: U64
  fee :: U64
  execution_error :: String
end

struct Snapshot do
  value :: Option<BountyTransferJournal>
  previous :: Bytes
end

fn label() -> String do
  "bounty-transfer/v1"
end

fn same(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

fn checked(value :: BountyTransferJournal) -> BountyTransferJournal!String do
  let intent = decode_bounty_transfer(value.intent)?
  validate_bounty_transfer(intent, value.usdc, intent.purpose, intent.issued_at)?
  bounty_transfer_instructions(intent, Pubkey { bytes: value.payer })?
  if Bytes.length(value.identity) != 32
    || Bytes.length(value.proof_identity) != 32
    || value.status < 0
    || value.status > 5
    || String.length(value.execution_error) > 256
    || (value.status < 2 && Bytes.length(value.wire) != 0)
    || (value.status < 4
      && (value.finalized_slot != U64.parse("0")?
        || value.fee != U64.parse("0")?
        || value.execution_error != ""))
    || (value.status == 4 && value.execution_error != "")
    || (value.status == 5 && value.execution_error == "") do
    return Err("invalid_bounty_transfer_journal")
  end
  let signature = if value.status >= 2 do
    authenticate_bounty_transfer(value.wire,
      intent,
      Pubkey { bytes: value.payer },
      value.usdc,
      intent.purpose)?.signature
  else
    Bytes.empty()
  end
  Ok(%{value | signature: signature})
end

fn encode(value :: BountyTransferJournal) -> Bytes!String do
  checked(value)?
  pack_credit_parts([
    Bytes.from_hex("0142574a")?,
    value.identity,
    value.proof_identity,
    mobile_byte(value.status)?,
    value.intent,
    value.payer,
    value.usdc,
    mobile_write_u64(value.context_slot)?,
    mobile_write_u64(value.last_valid_block_height)?,
    value.wire,
    mobile_write_u64(value.finalized_slot)?,
    mobile_write_u64(value.fee)?,
    Bytes.from_utf8(value.execution_error)
  ])
end

fn read(path :: String, key :: borrow StorageKey) -> Snapshot!String do
  let ciphertext = case load_blob(path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(Snapshot { value: None, previous: Bytes.empty() })
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let parts = unpack_credit_parts(open_local(ciphertext, key, local_context(label())?)?, 13, 1232)?
  if List.length(parts) != 13
    || Bytes.to_hex(List.head(parts)) != "0142574a"
    || Bytes.length(List.get(parts, 3)) != 1 do
    return Err("invalid_bounty_transfer_journal")
  end
  let value = checked(BountyTransferJournal {
    identity: List.get(parts, 1),
    proof_identity: List.get(parts, 2),
    status: Bytes.get(List.get(parts, 3), 0)?,
    intent: List.get(parts, 4),
    payer: List.get(parts, 5),
    usdc: List.get(parts, 6),
    context_slot: mobile_read_u64(List.get(parts, 7))?,
    last_valid_block_height: mobile_read_u64(List.get(parts, 8))?,
    wire: List.get(parts, 9),
    signature: Bytes.empty(),
    finalized_slot: mobile_read_u64(List.get(parts, 10))?,
    fee: mobile_read_u64(List.get(parts, 11))?,
    execution_error: mobile_utf8(List.get(parts, 12), "invalid_bounty_transfer_journal")?
  })?
  Ok(Snapshot { value: Some(value), previous: ciphertext })
end

fn selected(path :: String,
  key :: borrow StorageKey,
  value :: BountyTransferJournal) -> Bytes!String do
  let guard = load_blob(path, "fork-bounty/v1")?
  let state = bounty_state(path, key)?
  let intent = decode_bounty_transfer(value.intent)?
  if state.status != 3
    || !same(state.proof_identity, value.proof_identity)
    || !same(state.finder, intent.finder)
    || state.index != intent.index do
    return Err("bounty_transfer_selection_changed")
  end
  Ok(guard)
end

fn save(path :: String,
  key :: borrow StorageKey,
  before :: Snapshot,
  value :: BountyTransferJournal) -> BountyTransferJournal!String do
  let guard = selected(path, key, value)?
  let next = seal_local(encode(value)?, key, local_context(label())?)?
  let archive = case before.value do
    Some(previous) when previous.status == 5 && value.status == 1
    _ -> None
  end
  case archive do
    None -> store_bounty_transfer_snapshot(path, [label()], [next], before.previous, guard)?
    Some(previous) -> do
      let history = label() <> "/history/" <> Bytes.to_hex(previous.signature)
      store_bounty_transfer_snapshot(path,
        [label(), history],
        [next, seal_local(encode(previous)?, key, local_context(history)?)?],
        before.previous,
        guard)?
    end
  end
  checked(value)
end

pub fn load_bounty_transfer(path :: String,
  key :: borrow StorageKey) -> Option<BountyTransferJournal>!String do
  Ok(read(path, key)?.value)
end

fn existing(snapshot :: Snapshot, identity :: Bytes) -> BountyTransferJournal!String do
  let value = case snapshot.value do
    None -> return Err("bounty_transfer_not_started")
    Some(value) -> value
  end
  if !same(value.identity, identity) do
    return Err("bounty_transfer_identity_changed")
  end
  Ok(value)
end

pub fn prepare_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  intent :: BountyTransfer,
  payer :: Bytes,
  usdc :: Bytes,
  context_slot :: U64,
  last_valid_block_height :: U64,
  observed_height :: U64,
  now :: U64) -> BountyTransferJournal!String do
  validate_bounty_transfer(intent, usdc, intent.purpose, now)?
  let state = bounty_state(path, key)?
  if state.status != 3 || !same(state.finder, intent.finder) || state.index != intent.index do
    return Err("bounty_transfer_selection_changed")
  end
  let before = read(path, key)?
  case before.value do
    None -> nil
    Some(previous) -> do
      let old = decode_bounty_transfer(previous.intent)?
      if !same(previous.identity, identity)
        || !same(previous.proof_identity, state.proof_identity)
        || !same(previous.payer, payer)
        || !same(previous.usdc, usdc)
        || !same(old.mint, intent.mint)
        || old.amount != intent.amount
        || old.decimals != intent.decimals
        || old.purpose != intent.purpose do
        return Err("bounty_transfer_identity_changed")
      end
      if previous.status >= 2 && previous.status <= 4 do
        return Ok(previous)
      end
      if U64.compare(context_slot, previous.finalized_slot) < 0 do
        return Err("bounty_transfer_stale_blockhash")
      end
      if previous.status == 1 do
        if !same(old.destination, intent.destination) do
          return Err("bounty_transfer_destination_changed")
        end
        if U64.compare(now, old.expires_at) < 0
          && U64.compare(observed_height, previous.last_valid_block_height) <= 0 do
          return Ok(previous)
        end
        if U64.compare(context_slot, previous.context_slot) < 0
          || (U64.compare(observed_height, previous.last_valid_block_height) > 0
            && same(old.blockhash, intent.blockhash)) do
          return Err("bounty_transfer_stale_blockhash")
        end
      end
    end
  end
  if U64.compare(last_valid_block_height, observed_height) <= 0 do
    return Err("bounty_transfer_blockhash_expired")
  end
  save(path,
    key,
    before,
    BountyTransferJournal {
      identity: identity,
      proof_identity: state.proof_identity,
      status: 1,
      intent: encode_bounty_transfer(intent)?,
      payer: payer,
      usdc: usdc,
      context_slot: context_slot,
      last_valid_block_height: last_valid_block_height,
      wire: Bytes.empty(),
      signature: Bytes.empty(),
      finalized_slot: U64.parse("0")?,
      fee: U64.parse("0")?,
      execution_error: ""
    })
end

pub fn commit_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  wire :: Bytes,
  height :: U64,
  now :: U64) -> BountyTransferJournal!String do
  let before = read(path, key)?
  let current = existing(before, identity)?
  selected(path, key, current)?
  if current.status >= 2 do
    if !same(current.wire, wire) do
      return Err("bounty_transfer_packet_changed")
    end
    return Ok(current)
  end
  if current.status != 1 do
    return Err("bounty_transfer_not_prepared")
  end
  let intent = decode_bounty_transfer(current.intent)?
  validate_bounty_transfer(intent, current.usdc, intent.purpose, now)?
  if U64.compare(height, current.last_valid_block_height) > 0 do
    return Err("bounty_transfer_blockhash_expired")
  end
  let signed = authenticate_bounty_transfer(wire,
    intent,
    Pubkey { bytes: current.payer },
    current.usdc,
    intent.purpose)?
  save(path, key, before, %{current | status: 2, wire: wire, signature: signed.signature})
end

pub fn acknowledge_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  signature :: Bytes) -> BountyTransferJournal!String do
  let before = read(path, key)?
  let current = existing(before, identity)?
  selected(path, key, current)?
  if current.status < 2 || !same(current.signature, signature) do
    return Err("bounty_transfer_signature_mismatch")
  end
  if current.status >= 3 do
    return Ok(current)
  end
  save(path, key, before, %{current | status: 3})
end

pub fn cancel_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> BountyTransferJournal!String do
  let before = read(path, key)?
  let current = existing(before, identity)?
  if current.status >= 2 do
    return Err("bounty_transfer_already_signed")
  end
  save(path, key, before, %{current | status: 0})
end

# The only native caller obtains this result from independent finalized RPC
# agreement; no exported ABI accepts a caller-supplied settlement or amount.
pub fn settle_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  outcome :: BountyTransferSettlement) -> BountyTransferJournal!String do
  let before = read(path, key)?
  let current = existing(before, identity)?
  selected(path, key, current)?
  if current.status < 2
    || !same(current.signature, outcome.signature)
    || !same(Crypto.sha256(current.wire), outcome.wire_hash)
    || U64.compare(outcome.slot, current.context_slot) < 0 do
    return Err("bounty_transfer_outcome_mismatch")
  end
  let status = if outcome.execution_error == "" do
    4
  else
    5
  end
  if current.status >= 4 do
    if current.status != status
      || current.finalized_slot != outcome.slot
      || current.fee != outcome.fee
      || current.execution_error != outcome.execution_error do
      return Err("bounty_transfer_outcome_changed")
    end
    return Ok(current)
  end
  save(path,
    key,
    before,
    %{current |
      status: status,
      finalized_slot: outcome.slot,
      fee: outcome.fee,
      execution_error: outcome.execution_error
    })
end
