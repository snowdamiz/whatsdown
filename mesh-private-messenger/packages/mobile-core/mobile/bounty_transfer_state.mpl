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
from Storage.BountyTransfer import (
  store_bounty_transfer_legacy_snapshot,
  bounty_transfer_row_label,
  initialize_bounty_transfer_root,
  store_bounty_transfer_route_snapshot,
  read_bounty_transfer_rows
)

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
  target :: String
  root :: Option<BountyTransferAuthority>
  root_cipher :: Bytes
  marker :: Bytes
  custody :: Bytes
  profile :: Bytes
  asset :: Int
  binding :: Bytes
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

fn decode(wire :: Bytes) -> BountyTransferJournal!String do
  let parts = unpack_credit_parts(wire, 13, 1232)?
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
  Ok(value)
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

fn save_binding(path :: String,
  key :: borrow StorageKey,
  before :: Snapshot,
  value :: BountyTransferJournal,
  binding :: Bytes) -> BountyTransferJournal!String do
  let guard = selected(path, key, value)?
  if !same(guard, before.custody) || Bytes.length(before.profile) == 0 do
    return Err("bounty_transfer_selection_changed")
  end
  let next_plain = case before.root do
    None -> encode(value)?
    Some(root) -> encode_route(BountyTransferRoute {
      root: root,
      asset: before.asset,
      identity: value.identity,
      attempt_binding: binding,
      journal: Some(value)
    })?
  end
  let next = seal_local(next_plain, key, local_context(before.target)?)?
  let archive = case before.value do
    Some(previous) when previous.status == 5 && value.status == 1
    _ -> None
  end
  let history_label = case archive do
    None -> ""
    Some(previous) ->
      before.target <> "/history/" <> Bytes.to_hex(previous.signature)
  end
  let history_plain = case archive do
    None -> Bytes.empty()
    Some(previous) -> case before.root do
      None -> encode(previous)?
      Some(root) -> encode_route(BountyTransferRoute {
        root: root,
        asset: before.asset,
        identity: previous.identity,
        attempt_binding: before.binding,
        journal: Some(previous)
      })?
    end
  end
  let history_previous = if history_label == "" do
    Bytes.empty()
  else
    case load_blob(path, history_label) do
      Ok(ciphertext) -> do
        if !same(open_local(ciphertext, key, local_context(history_label)?)?, history_plain) do
          return Err("bounty_transfer_history_conflict")
        end
        ciphertext
      end
      Err(error) -> if error == "local_state_not_found" do
        Bytes.empty()
      else
        return Err(error)
      end
    end
  end
  let history_next = if history_label == "" do
    Bytes.empty()
  else if Bytes.length(history_previous) != 0 do
    history_previous
  else
    seal_local(history_plain, key, local_context(history_label)?)?
  end
  case before.root do
    None -> if history_label == "" do
      store_bounty_transfer_legacy_snapshot(path,
        [label()],
        [next],
        before.previous,
        guard,
        before.profile)?
    else
      store_bounty_transfer_legacy_snapshot(path,
        [label(), history_label],
        [next, history_next],
        before.previous,
        guard,
        before.profile)?
    end
    Some(root) -> store_bounty_transfer_route_snapshot(path,
      Bytes.to_hex(root.claim_id),
      before.asset,
      before.root_cipher,
      before.marker,
      before.previous,
      guard,
      before.profile,
      next,
      history_label,
      history_previous,
      history_next)?
  end
  checked(value)
end

fn save(path :: String,
  key :: borrow StorageKey,
  before :: Snapshot,
  value :: BountyTransferJournal) -> BountyTransferJournal!String do
  save_binding(path, key, before, value, before.binding)
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
  prepare_from_snapshot(path,
    key,
    read(path, key)?,
    identity,
    Bytes.empty(),
    intent,
    payer,
    usdc,
    context_slot,
    last_valid_block_height,
    observed_height,
    now)
end

fn prepare_from_snapshot(path :: String,
  key :: borrow StorageKey,
  before :: Snapshot,
  identity :: Bytes,
  binding :: Bytes,
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
  case before.root do
    None -> nil
    Some(root) -> do
      let mint = if before.asset == 2 do
        root.morse_mint
      else
        root.usdc_mint
      end
      if (before.asset != 0
        && (!same(intent.mint, mint)
          || intent.amount != units(root, before.asset)
          || Bytes.length(binding) != 32
          || U64.compare(context_slot, root.admission_slot) < 0))
        || !same(state.proof_identity, root.proof_identity)
        || !same(intent.finder, root.finder)
        || intent.index != root.index
        || intent.purpose != root.purpose
        || !same(usdc, root.usdc_mint) do
        return Err("bounty_transfer_authority_changed")
      end
    end
  end
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
      if U64.compare(context_slot, previous.finalized_slot) < 0
        || U64.compare(context_slot, previous.context_slot) < 0
        || ((previous.status == 5
          || U64.compare(observed_height, previous.last_valid_block_height) > 0)
          && same(old.blockhash, intent.blockhash)) do
        return Err("bounty_transfer_stale_blockhash")
      end
      if previous.status == 1 do
        if !same(old.destination, intent.destination) do
          return Err("bounty_transfer_destination_changed")
        end
        if U64.compare(now, old.expires_at) < 0
          && U64.compare(observed_height, previous.last_valid_block_height) <= 0 do
          if !same(before.binding, binding) do
            return save_binding(path, key, before, previous, binding)
          end
          return Ok(previous)
        end
      end
    end
  end
  if U64.compare(last_valid_block_height, observed_height) <= 0 do
    return Err("bounty_transfer_blockhash_expired")
  end
  save_binding(path,
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
    },
    binding)
end

pub fn commit_bounty_transfer(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  wire :: Bytes,
  height :: U64,
  now :: U64) -> BountyTransferJournal!String do
  commit_snapshot(path, key, read_identity(path, key, identity)?, identity, wire, height, now)
end

fn commit_snapshot(path :: String,
  key :: borrow StorageKey,
  before :: Snapshot,
  identity :: Bytes,
  wire :: Bytes,
  height :: U64,
  now :: U64) -> BountyTransferJournal!String do
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
  let before = read_identity(path, key, identity)?
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
  let before = read_identity(path, key, identity)?
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
  let before = read_identity(path, key, identity)?
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

pub struct BountyTransferAuthority do
  claim_id :: Bytes
  proof_identity :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  index :: U64
  namespace :: Bytes
  purpose :: Int
  receipt :: Bytes
  terms_hash :: Bytes
  admission_binding :: Bytes
  admission_slot :: U64
  usdc_mint :: Bytes
  usdc_units :: U64
  morse_mint :: Bytes
  morse_units :: U64
  legacy_identity :: Bytes
end

pub struct BountyTransferRoute do
  root :: BountyTransferAuthority
  asset :: Int
  identity :: Bytes
  attempt_binding :: Bytes
  journal :: Option<BountyTransferJournal>
end

pub struct BountyTransferMovement do
  root :: Option<BountyTransferAuthority>
  legacy :: Option<BountyTransferRoute>
  usdc :: Option<BountyTransferRoute>
  morse :: Option<BountyTransferRoute>
end

pub fn bounty_transfer_claim_id(proof_identity :: Bytes,
  finder :: Bytes,
  index :: U64) -> Bytes!String do
  if Bytes.length(proof_identity) != 32 || Bytes.length(finder) != 32 do
    return Err("invalid_bounty_transfer_authority")
  end
  Ok(Crypto.sha256(pack_credit_parts([
    Bytes.from_utf8("bounty-claim/v2"),
    proof_identity,
    finder,
    mobile_write_u64(index)?
  ])?))
end

fn route_identity(root :: BountyTransferAuthority, asset :: Int) -> Bytes!String do
  if asset == 0 do
    return Ok(root.legacy_identity)
  end
  Ok(Crypto.sha256(pack_credit_parts([
    Bytes.from_utf8("bounty-leg/v2"),
    root.claim_id,
    mobile_byte(asset)?
  ])?))
end

fn checked_root(root :: BountyTransferAuthority) -> BountyTransferAuthority!String do
  if !same(root.claim_id, bounty_transfer_claim_id(root.proof_identity, root.finder, root.index)?)
    || Bytes.length(root.namespace) != 32
    || Bytes.length(root.usdc_mint) != 32
    || root.purpose < 0
    || root.purpose > 1
    || U64.compare(root.index, U64.parse("2147483648")?) >= 0 do
    return Err("invalid_bounty_transfer_authority")
  end
  if Bytes.length(root.legacy_identity) != 0 do
    if Bytes.length(root.legacy_identity) != 32
      || Bytes.length(root.admission_binding) != 0
      || Bytes.length(root.proof_hash) != 0
      || Bytes.length(root.receipt) != 0
      || Bytes.length(root.terms_hash) != 0
      || Bytes.length(root.morse_mint) != 0
      || root.morse_units != U64.parse("0")? do
      return Err("invalid_bounty_transfer_authority")
    end
  else if Bytes.length(root.proof_hash) != 32
    || Bytes.length(root.receipt) != 32
    || Bytes.length(root.terms_hash) != 32
    || Bytes.length(root.admission_binding) != 32
    || Bytes.length(root.morse_mint) != 32
    || same(root.usdc_mint, root.morse_mint) do
    return Err("invalid_bounty_transfer_authority")
  end
  Ok(root)
end

fn encode_root(root :: BountyTransferAuthority) -> Bytes!String do
  checked_root(root)?
  pack_credit_parts([
    Bytes.from_utf8("BWA2"),
    root.claim_id,
    root.proof_identity,
    root.proof_hash,
    root.finder,
    mobile_write_u64(root.index)?,
    root.namespace,
    mobile_byte(root.purpose)?,
    root.receipt,
    root.terms_hash,
    root.admission_binding,
    mobile_write_u64(root.admission_slot)?,
    root.usdc_mint,
    mobile_write_u64(root.usdc_units)?,
    root.morse_mint,
    mobile_write_u64(root.morse_units)?,
    root.legacy_identity
  ])
end

fn decode_root(wire :: Bytes) -> BountyTransferAuthority!String do
  let parts = unpack_credit_parts(wire, 17, 32)?
  if List.length(parts) != 17
    || !same(List.head(parts), Bytes.from_utf8("BWA2"))
    || Bytes.length(List.get(parts, 7)) != 1 do
    return Err("invalid_bounty_transfer_authority")
  end
  checked_root(BountyTransferAuthority {
    claim_id: List.get(parts, 1),
    proof_identity: List.get(parts, 2),
    proof_hash: List.get(parts, 3),
    finder: List.get(parts, 4),
    index: mobile_read_u64(List.get(parts, 5))?,
    namespace: List.get(parts, 6),
    purpose: Bytes.get(List.get(parts, 7), 0)?,
    receipt: List.get(parts, 8),
    terms_hash: List.get(parts, 9),
    admission_binding: List.get(parts, 10),
    admission_slot: mobile_read_u64(List.get(parts, 11))?,
    usdc_mint: List.get(parts, 12),
    usdc_units: mobile_read_u64(List.get(parts, 13))?,
    morse_mint: List.get(parts, 14),
    morse_units: mobile_read_u64(List.get(parts, 15))?,
    legacy_identity: List.get(parts, 16)
  })
end

fn root_label() -> String do
  "bounty-authority/v2"
end

fn units(root :: BountyTransferAuthority, asset :: Int) -> U64 do
  if asset == 2 do
    root.morse_units
  else
    root.usdc_units
  end
end

fn checked_route(route :: BountyTransferRoute) -> BountyTransferRoute!String do
  let root = checked_root(route.root)?
  if route.asset < 0
    || route.asset > 2
    || !same(route.identity, route_identity(root, route.asset)?)
    || ((route.asset == 0) != (Bytes.length(root.legacy_identity) != 0)) do
    return Err("invalid_bounty_transfer_route")
  end
  case route.journal do
    None -> do
      if route.asset == 0 || Bytes.length(route.attempt_binding) != 0 do
        return Err("invalid_bounty_transfer_route")
      end
    end
    Some(value) -> do
      checked(value)?
      let intent = decode_bounty_transfer(value.intent)?
      if !same(value.identity, route.identity)
        || !same(value.proof_identity, root.proof_identity)
        || !same(intent.finder, root.finder)
        || intent.index != root.index
        || intent.purpose != root.purpose
        || !same(value.usdc, root.usdc_mint) do
        return Err("invalid_bounty_transfer_route")
      end
      if route.asset != 0 do
        let mint = if route.asset == 1 do
          root.usdc_mint
        else
          root.morse_mint
        end
        if !same(intent.mint, mint)
          || intent.amount != units(root, route.asset)
          || Bytes.length(route.attempt_binding) != 32
          || U64.compare(value.context_slot, root.admission_slot) < 0 do
          return Err("invalid_bounty_transfer_route")
        end
      else if Bytes.length(route.attempt_binding) != 0 do
        return Err("invalid_bounty_transfer_route")
      end
    end
  end
  Ok(route)
end

fn encode_route(route :: BountyTransferRoute) -> Bytes!String do
  checked_route(route)?
  let journal = case route.journal do
    None -> Bytes.empty()
    Some(value) -> encode(value)?
  end
  pack_credit_parts([
    Bytes.from_utf8("BWR2"),
    mobile_byte(route.asset)?,
    route.attempt_binding,
    journal
  ])
end

fn decode_route(root :: BountyTransferAuthority,
  asset :: Int,
  wire :: Bytes) -> BountyTransferRoute!String do
  let parts = unpack_credit_parts(wire, 4, 4096)?
  if List.length(parts) != 4
    || !same(List.head(parts), Bytes.from_utf8("BWR2"))
    || !same(List.get(parts, 1), mobile_byte(asset)?) do
    return Err("invalid_bounty_transfer_route")
  end
  checked_route(BountyTransferRoute {
    root: root,
    asset: asset,
    identity: route_identity(root, asset)?,
    attempt_binding: List.get(parts, 2),
    journal: if Bytes.length(List.get(parts, 3)) == 0 do
      None
    else
      Some(decode(List.get(parts, 3))?)
    end
  })
end

fn empty_route(root :: BountyTransferAuthority, asset :: Int) -> BountyTransferRoute!String do
  checked_route(BountyTransferRoute {
    root: root,
    asset: asset,
    identity: route_identity(root, asset)?,
    attempt_binding: Bytes.empty(),
    journal: None
  })
end

fn raw_root(path :: String) -> Bytes!String do
  case load_blob(path, root_label()) do
    Ok(value)
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
  end
end

fn rows(path :: String, key :: borrow StorageKey) -> List<Bytes>!String do
  let root = raw_root(path)?
  let claim = if Bytes.length(root) == 0 do
    ""
  else
    Bytes.to_hex(decode_root(open_local(root, key, local_context(root_label())?)?)?.claim_id)
  end
  let snapshot = read_bounty_transfer_rows(path, claim)?
  if !same(List.head(snapshot), root) do
    return Err("local_state_changed")
  end
  Ok(snapshot)
end

fn decoded_root(snapshot :: List<Bytes>,
  key :: borrow StorageKey) -> Option<BountyTransferAuthority>!String do
  if Bytes.length(List.head(snapshot)) == 0 do
    return Ok(None)
  end
  let root = decode_root(open_local(List.head(snapshot), key, local_context(root_label())?)?)?
  let marker = unpack_credit_parts(open_local(List.get(snapshot, 1), key, local_context(label())?)?,
    2,
    32)?
  if List.length(marker) != 2
    || !same(List.head(marker), Bytes.from_utf8("BWF2"))
    || !same(List.get(marker, 1), root.claim_id) do
    return Err("invalid_bounty_transfer_marker")
  end
  Ok(Some(root))
end

fn route_from_rows(snapshot :: List<Bytes>,
  key :: borrow StorageKey,
  root :: BountyTransferAuthority,
  asset :: Int) -> BountyTransferRoute!String do
  let ciphertext = List.get(snapshot, asset + 4)
  let row_label = bounty_transfer_row_label(Bytes.to_hex(root.claim_id), asset)?
  if Bytes.length(ciphertext) == 0 do
    if asset == 0 || units(root, asset) != U64.parse("0")? do
      return Err("invalid_bounty_transfer_route")
    end
    return empty_route(root, asset)
  end
  if asset != 0 && units(root, asset) == U64.parse("0")? do
    return Err("invalid_bounty_transfer_route")
  end
  decode_route(root, asset, open_local(ciphertext, key, local_context(row_label)?)?)
end

pub fn read_bounty_transfer_movement(path :: String,
  key :: borrow StorageKey) -> BountyTransferMovement!String do
  let snapshot = rows(path, key)?
  let root = decoded_root(snapshot, key)?
  case root do
    None -> do
      # Validate old content; corrupt/unknown bytes cannot become absence/zero.
      if Bytes.length(List.get(snapshot, 1)) > 0 do
        decode(open_local(List.get(snapshot, 1), key, local_context(label())?)?)?
      end
      Ok(BountyTransferMovement { root: None, legacy: None, usdc: None, morse: None })
    end
    Some(value) -> if Bytes.length(value.legacy_identity) != 0 do
      if Bytes.length(List.get(snapshot, 5)) != 0 || Bytes.length(List.get(snapshot, 6)) != 0 do
        return Err("invalid_bounty_transfer_route")
      end
      Ok(BountyTransferMovement {
        root: root,
        legacy: Some(route_from_rows(snapshot, key, value, 0)?),
        usdc: None,
        morse: None
      })
    else
      if Bytes.length(List.get(snapshot, 4)) != 0 do
        return Err("invalid_bounty_transfer_route")
      end
      Ok(BountyTransferMovement {
        root: root,
        legacy: None,
        usdc: Some(route_from_rows(snapshot, key, value, 1)?),
        morse: Some(route_from_rows(snapshot, key, value, 2)?)
      })
    end
  end
end

pub fn read_bounty_transfer_route(path :: String,
  key :: borrow StorageKey,
  asset :: Int) -> BountyTransferRoute!String do
  if asset < 0 || asset > 2 do
    return Err("invalid_bounty_transfer_route")
  end
  let snapshot = rows(path, key)?
  let root = case decoded_root(snapshot, key)? do
    None -> return Err("bounty_transfer_root_not_admitted")
    Some(value) -> value
  end
  if ((asset == 0) != (Bytes.length(root.legacy_identity) != 0)) do
    return Err("bounty_transfer_asset_unavailable")
  end
  route_from_rows(snapshot, key, root, asset)
end

fn verify_selection(path :: String,
  key :: borrow StorageKey,
  root :: BountyTransferAuthority,
  snapshot :: List<Bytes>) -> Result<(), String> do
  let state = bounty_state(path, key)?
  if state.status != 3
    || !same(state.proof_identity, root.proof_identity)
    || !same(state.finder, root.finder)
    || state.index != root.index
    || !same(load_blob(path, "fork-bounty/v1")?, List.get(snapshot, 2))
    || Bytes.length(List.get(snapshot, 3)) == 0 do
    return Err("bounty_transfer_selection_changed")
  end
  Ok(nil)
end

fn initialize(path :: String,
  key :: borrow StorageKey,
  root :: BountyTransferAuthority,
  snapshot :: List<Bytes>,
  legacy :: Option<BountyTransferJournal>) -> BountyTransferAuthority!String do
  checked_root(root)?
  verify_selection(path, key, root, snapshot)?
  let claim = Bytes.to_hex(root.claim_id)
  let targets = for asset in 0..3 do
    if asset == 0 do
      case legacy do
        None -> Bytes.empty()
        Some(value) ->
          seal_local(encode_route(BountyTransferRoute {
              root: root,
              asset: 0,
              identity: value.identity,
              attempt_binding: Bytes.empty(),
              journal: Some(value)
            })?,
            key,
            local_context(bounty_transfer_row_label(claim, 0)?)?)?
      end
    else if Bytes.length(root.legacy_identity) != 0 || units(root, asset) == U64.parse("0")? do
      Bytes.empty()
    else
      seal_local(encode_route(empty_route(root, asset)?)?,
        key,
        local_context(bounty_transfer_row_label(claim, asset)?)?)?
    end
  end
  initialize_bounty_transfer_root(path,
    claim,
    seal_local(encode_root(root)?, key, local_context(root_label())?)?,
    seal_local(pack_credit_parts([Bytes.from_utf8("BWF2"), root.claim_id])?,
      key,
      local_context(label())?)?,
    List.get(snapshot, 1),
    List.get(snapshot, 2),
    List.get(snapshot, 3),
    List.get(targets, 0),
    List.get(targets, 1),
    List.get(targets, 2))?
  Ok(root)
end

pub fn admit_bounty_transfer_root(path :: String,
  key :: borrow StorageKey,
  proposed :: BountyTransferAuthority) -> BountyTransferAuthority!String do
  let root = checked_root(proposed)?
  if Bytes.length(root.legacy_identity) != 0 do
    return Err("invalid_bounty_transfer_authority")
  end
  let snapshot = rows(path, key)?
  verify_selection(path, key, root, snapshot)?
  case decoded_root(snapshot, key)? do
    Some(previous) -> do
      if Bytes.length(previous.legacy_identity) != 0 do
        return Err("bounty_transfer_legacy_conflict")
      end
      let frozen = %{root |
        admission_binding: previous.admission_binding,
        admission_slot: previous.admission_slot
      }
      if !same(encode_root(frozen)?, encode_root(previous)?) do
        return Err("bounty_transfer_authority_changed")
      end
      Ok(previous)
    end
    None -> do
      if Bytes.length(List.get(snapshot, 1)) != 0 do
        decode(open_local(List.get(snapshot, 1), key, local_context(label())?)?)?
        return Err("bounty_transfer_legacy_conflict")
      end
      initialize(path, key, root, snapshot, None)
    end
  end
end

pub fn migrate_bounty_transfer_legacy(path :: String,
  key :: borrow StorageKey,
  namespace :: Bytes) -> BountyTransferAuthority!String do
  let snapshot = rows(path, key)?
  case decoded_root(snapshot, key)? do
    Some(root) -> do
      if Bytes.length(root.legacy_identity) == 0 do
        return Err("bounty_transfer_asset_unavailable")
      end
      if !same(root.namespace, namespace) do
        return Err("bounty_transfer_authority_changed")
      end
      return Ok(root)
    end
    None -> nil
  end
  if Bytes.length(List.get(snapshot, 1)) == 0 do
    return Err("bounty_transfer_not_started")
  end
  let old = decode(open_local(List.get(snapshot, 1), key, local_context(label())?)?)?
  let intent = decode_bounty_transfer(old.intent)?
  let root = BountyTransferAuthority {
    claim_id: bounty_transfer_claim_id(old.proof_identity, intent.finder, intent.index)?,
    proof_identity: old.proof_identity,
    proof_hash: Bytes.empty(),
    finder: intent.finder,
    index: intent.index,
    namespace: namespace,
    purpose: intent.purpose,
    receipt: Bytes.empty(),
    terms_hash: Bytes.empty(),
    admission_binding: Bytes.empty(),
    admission_slot: old.context_slot,
    usdc_mint: old.usdc,
    usdc_units: intent.amount,
    morse_mint: Bytes.empty(),
    morse_units: U64.parse("0")?,
    legacy_identity: old.identity
  }
  initialize(path, key, root, snapshot, Some(old))
end

fn snapshot_from_rows(snapshot :: List<Bytes>,
  key :: borrow StorageKey,
  asset :: Int) -> Snapshot!String do
  let root = decoded_root(snapshot, key)?
  let target = case root do
    None -> if asset == 0 do
      label()
    else
      return Err("bounty_transfer_root_not_admitted")
    end
    Some(value) -> bounty_transfer_row_label(Bytes.to_hex(value.claim_id), asset)?
  end
  let previous = case root do
    None -> List.get(snapshot, 1)
    Some(_) -> List.get(snapshot, asset + 4)
  end
  let route = case root do
    None
    Some(value) -> do
      if ((asset == 0) != (Bytes.length(value.legacy_identity) != 0)) do
        return Err("bounty_transfer_asset_unavailable")
      end
      Some(route_from_rows(snapshot, key, value, asset)?)
    end
  end
  let journal = case route do
    Some(value) -> value.journal
    None -> if Bytes.length(previous) == 0 do
      None
    else
      Some(decode(open_local(previous, key, local_context(label())?)?)?)
    end
  end
  let binding = case route do
    None -> Bytes.empty()
    Some(value) -> value.attempt_binding
  end
  Ok(Snapshot {
    value: journal,
    previous: previous,
    target: target,
    root: root,
    root_cipher: List.get(snapshot, 0),
    marker: List.get(snapshot, 1),
    custody: List.get(snapshot, 2),
    profile: List.get(snapshot, 3),
    asset: asset,
    binding: binding
  })
end

fn read(path :: String, key :: borrow StorageKey) -> Snapshot!String do
  snapshot_from_rows(rows(path, key)?, key, 0)
end

fn read_identity(path :: String, key :: borrow StorageKey, identity :: Bytes) -> Snapshot!String do
  let snapshot = rows(path, key)?
  case decoded_root(snapshot, key)? do
    None -> snapshot_from_rows(snapshot, key, 0)
    Some(root) -> do
      for asset in 0..3 do
        if ((asset == 0) == (Bytes.length(root.legacy_identity) != 0))
          && same(route_identity(root, asset)?, identity) do
          return snapshot_from_rows(snapshot, key, asset)
        end
      end
      Err("bounty_transfer_identity_changed")
    end
  end
end

pub fn load_bounty_transfer_identity(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> BountyTransferJournal!String do
  existing(read_identity(path, key, identity)?, identity)
end

pub fn prepare_bounty_transfer_route(path :: String,
  key :: borrow StorageKey,
  asset :: Int,
  attempt_binding :: Bytes,
  intent :: BountyTransfer,
  payer :: Bytes,
  usdc :: Bytes,
  context_slot :: U64,
  last_valid_block_height :: U64,
  observed_height :: U64,
  now :: U64) -> BountyTransferJournal!String do
  if asset < 0 || asset > 2 do
    return Err("invalid_bounty_transfer_route")
  end
  let snapshot = rows(path, key)?
  let root = case decoded_root(snapshot, key)? do
    None -> return Err("bounty_transfer_root_not_admitted")
    Some(value) -> value
  end
  if asset != 0 && units(root, asset) == U64.parse("0")? do
    return Err("bounty_transfer_zero_entitlement")
  end
  prepare_from_snapshot(path,
    key,
    snapshot_from_rows(snapshot, key, asset)?,
    route_identity(root, asset)?,
    attempt_binding,
    intent,
    payer,
    usdc,
    context_slot,
    last_valid_block_height,
    observed_height,
    now)
end

pub fn bounty_transfer_attempt_handle(route :: BountyTransferRoute) -> Bytes!String do
  let value = case route.journal do
    None -> return Err("bounty_transfer_not_prepared")
    Some(value) -> value
  end
  Ok(Crypto.sha256(pack_credit_parts([
    Bytes.from_utf8("bounty-prompt/v2"),
    route.identity,
    value.intent,
    value.payer,
    route.attempt_binding,
    mobile_write_u64(value.context_slot)?,
    mobile_write_u64(value.last_valid_block_height)?
  ])?))
end

pub fn commit_bounty_transfer_route(path :: String,
  key :: borrow StorageKey,
  asset :: Int,
  handle :: Bytes,
  wire :: Bytes,
  height :: U64,
  now :: U64) -> BountyTransferJournal!String do
  if asset < 0 || asset > 2 do
    return Err("invalid_bounty_transfer_route")
  end
  let captured = rows(path, key)?
  let root = case decoded_root(captured, key)? do
    None -> return Err("bounty_transfer_root_not_admitted")
    Some(value) -> value
  end
  let before = snapshot_from_rows(captured, key, asset)?
  let route = route_from_rows(captured, key, root, asset)?
  if !same(bounty_transfer_attempt_handle(route)?, handle) do
    return Err("bounty_transfer_attempt_changed")
  end
  # Handle validation and the final write use this exact target/root/marker/
  # custody/profile snapshot. A concurrent rebind after validation loses CAS.
  commit_snapshot(path, key, before, route.identity, wire, height, now)
end
