from Mobile.Codec import current_time, mobile_join, mobile_byte, encode_output_list
from Mobile.Platform import native_security_config, decode_native_security_config
from Mobile.OhttpContext import capture_native_ohttp_context, rpc_transport_from_context
from Transparency.RpcTransport import (
  RpcTransport,
  rpc_transport,
  require_rpc_current,
  rpc_fatal_error
)
from Mobile.Bounty import disclosable_fork
from Mobile.ForkFilingState import (
  FilingState,
  FilingClaim,
  FilingObservation,
  claim_filing,
  finish_filing,
  load_filing,
  filing_pending
)
from Mobile.ForkFilingTransport import submit_filing
from Mobile.ForkFilingPins import (
  native_filing_pin_frame,
  require_filing_pin_frame,
  filing_pin_selection,
  filing_receipt_binding
)
from Mobile.ForkFilingReceipt import mixed_filing_observation
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, open_local, local_context
from Transparency.Config import SecurityConfig, encode_security_config, witness_policy_for_log
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins, sample_anchor_sources
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import ForkProof, ForkTarget, fork_hash, decode_fork
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transparency.SlashReceipt import SlashReceipt, slash_receipt_address
from Transparency.SlashReceiptRead import SlashReceiptState, read_slash_receipt_state
from Transparency.PermanentReceipt import (
  PermanentReceiptPins,
  PermanentReceiptState,
  PermanentReceipt,
  read_permanent_receipt
)
from Transparency.AnchorContext import decode_anchor_context
from Transparency.AnchorRing import decode_anchor_entry, decode_anchor_header
from Transparency.TokenChain import token_addresses
from Solana.Read import Pubkey, pubkey, pubkey_equal

pub struct FilingPlan do
  config :: SecurityConfig
  pins :: AnchorPins
  mint :: Pubkey
  wire :: Bytes
  proof :: ForkProof
  proof_hash :: Bytes
  identity :: Bytes
  target_hash :: Bytes
  permanent :: Option<PermanentReceiptPins>
  minimum_slot :: U64
  anchor_hash :: Bytes
end

pub fn prepare_filing(config :: SecurityConfig,
  rpc :: RpcTransport,
  wire :: Bytes) -> Option<FilingPlan>!String do
  # Re-validate even callers constructing structs directly. Only native config
  # reaches the exported entry point; a directory/relay cannot supply targets.
  encode_security_config(config)?
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Ok(None)
    Some(value) -> value
  end
  if config.slash_mint == "-" do
    return Ok(None)
  end
  let mint = pubkey(config.slash_mint)?
  let candidate = decode_fork(wire)?
  witness_policy_for_log(config, candidate.first.version)?
  let proof = validate_relay_submission(config.service_public_key, candidate.first.version, wire)?
  let hash = fork_hash(proof)?
  # Preserve settlement and rate history across endpoint and policy rotation.
  # Exact wire identity also binds the local finder, which the chain hash omits.
  let identity = Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse-phone-filing-v1"),
      pins.program.bytes,
      pins.log_id,
      config.service_public_key,
      mint.bytes,
      mobile_byte(config.log_version)?,
      Crypto.sha256(wire)
    ],
    0,
    Bytes.empty())?)
  Ok(Some(FilingPlan {
    config: config,
    pins: pins,
    mint: mint,
    wire: wire,
    proof: proof,
    proof_hash: hash,
    identity: identity,
    target_hash: Crypto.sha256(Bytes.from_utf8(String.join(config.relay_urls, "\n"))),
    permanent: None,
    minimum_slot: U64.parse("0")?,
    anchor_hash: case proof.second do
      SignedCheckpoint(second) -> checkpoint_hash(second)?
      AnchorReference(_) -> Bytes.empty()
    end
  }))
end

pub fn filing_receipt_observation(plan :: FilingPlan,
  state :: SlashReceiptState,
  floor :: U64) -> FilingObservation!String do
  if U64.compare(state.context_slot, floor) < 0
    || !Bytes.secure_equals(state.proof_hash, plan.proof_hash)
    || !pubkey_equal(state.address,
      slash_receipt_address(plan.pins.program, plan.pins.log_id, plan.proof_hash)?) do
    return Err("invalid_filing_receipt")
  end
  let receipt = case state.receipt do
    None -> return filing_pending(state.context_slot)
    Some(value) -> value
  end
  let anchored = case plan.proof.second do
    SignedCheckpoint(_) -> false
    AnchorReference(_) -> true
  end
  if receipt.kind != plan.proof.kind
    || receipt.anchored != anchored
    || !Bytes.secure_equals(receipt.log_id, plan.pins.log_id)
    || !Bytes.secure_equals(receipt.proof_hash, plan.proof_hash)
    || !Bytes.secure_equals(receipt.mint, plan.mint.bytes)
    || !Bytes.secure_equals(receipt.first_checkpoint, checkpoint_hash(plan.proof.first)?) do
    return Err("invalid_filing_receipt")
  end
  case plan.proof.second do
    SignedCheckpoint(second) -> if !Bytes.secure_equals(receipt.second_checkpoint,
      checkpoint_hash(second)?) do
      return Err("invalid_filing_receipt")
    end
    AnchorReference(_) -> if Bytes.length(plan.anchor_hash) > 0
      && !Bytes.secure_equals(receipt.second_checkpoint, plan.anchor_hash) do
      return Err("invalid_filing_receipt")
    end
  end
  Ok(FilingObservation {
    status: "settled",
    context_slot: state.context_slot,
    finder: receipt.finder,
    units: receipt.finder_amount,
    morse_units: U64.parse("0")?,
    receipt_format: 1,
    receipt_binding: Bytes.empty()
  })
end

# The callbacks are I/O boundaries for the same workflow in native execution and
# tests. Production supplies the finalized quorum reader below, never a relay
# response. There is no exported callback or caller-supplied config API.
pub fn run_filing(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<SlashReceiptState, String>,
  current :: Fun() -> Bool) -> FilingState!String do
  run_observed_filing(path,
    key,
    plan,
    now,
    post,
    fn(floor :: U64) do filing_receipt_observation(plan, read(floor)?, floor) end,
    current)
end

pub fn run_observed_filing(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<FilingObservation, String>,
  current :: Fun() -> Bool) -> FilingState!String do
  require_rpc_current(plan.pins.rpc.require_current)?
  if !current() do
    return Err("filing_config_changed")
  end
  let claim = case claim_filing(path,
    key,
    plan.identity,
    plan.target_hash,
    List.length(plan.config.relay_urls),
    now)? do
    None -> return load_filing(path, key, plan.identity)
    Some(value) -> value
  end
  complete_filing(path, key, plan, claim, now, post, read, current)
end

fn complete_filing(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  claim :: FilingClaim,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<FilingObservation, String>,
  current :: Fun() -> Bool) -> FilingState!String do
  require_rpc_current(plan.pins.rpc.require_current)?
  if !current() do
    return Err("filing_config_changed")
  end
  let checked = read(claim.minimum_slot)
  let observation = case checked do
    Ok(value) -> value
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    Err(error) -> %{filing_pending(claim.minimum_slot)? |
      status: if error == "anchor_rpc_disagree" do
        "rpc_disagree"
      else
        "rpc_unavailable"
      end
    }
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  if !current() do
    return Err("filing_config_changed")
  end
  let accepted = if observation.status == "settled" || claim.targets == 0 do
    0
  else
    case post() do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      Err(_) -> 0
      Ok(value) -> value
    end
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  if !current() do
    return Err("filing_config_changed")
  end
  finish_filing(path, key, claim, now, accepted, observation)?
  load_filing(path, key, plan.identity)
end

actor filing_job(path :: String,
  plan :: FilingPlan,
  claim :: FilingClaim,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<FilingObservation, String>,
  current :: Fun() -> Bool) do
  case platform_key() do
    Err(_) -> nil
    Ok(key) ->
      let _result = complete_filing(path, key, plan, claim, now, post, read, current)
      nil
  end
end

# Host invocations are serialized. Claim before spawning, then return local
# state immediately; the actor owns all network I/O outside the embedding call.
pub fn start_filing(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<SlashReceiptState, String>,
  current :: Fun() -> Bool) -> FilingState!String do
  start_observed_filing(path,
    key,
    plan,
    now,
    post,
    fn(floor :: U64) do filing_receipt_observation(plan, read(floor)?, floor) end,
    current)
end

pub fn start_observed_filing(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  now :: U64,
  post :: Fun() -> Result<Int, String>,
  read :: Fun(U64) -> Result<FilingObservation, String>,
  current :: Fun() -> Bool) -> FilingState!String do
  require_rpc_current(plan.pins.rpc.require_current)?
  if !current() do
    return Err("filing_config_changed")
  end
  case claim_filing(path,
    key,
    plan.identity,
    plan.target_hash,
    List.length(plan.config.relay_urls),
    now)? do
    None -> nil
    Some(claim) ->
      let _worker = spawn(filing_job, path, plan, claim, now, post, read, current)
      nil
  end
  load_filing(path, key, plan.identity)
end

fn blank(status :: String) -> Bytes!String do
  encode_output_list(for value in [status, "", "", "", "0", "", "0", "0", "0", "0", "0", "0"] do
    Bytes.from_utf8(value)
  end)
end

pub fn filing_view(plan :: FilingPlan, state :: FilingState) -> Bytes!String do
  require_filing_observation_pins(plan, state.observation)?
  let expected = plan.proof.finder
  let paid = state.observation.finder
  let status = if state.observation.status == "settled"
    && Bytes.to_hex(expected) != String.repeat("00", 32)
    && !Bytes.secure_equals(expected, paid) do
    "paid_elsewhere"
  else if state.observation.status == "pending"
    && state.accepted > 0
    && Bytes.secure_equals(state.target_hash, plan.target_hash) do
    "accepted"
  else
    state.observation.status
  end
  let accepted = if Bytes.secure_equals(state.target_hash, plan.target_hash) do
    state.accepted
  else
    0
  end
  let fields = [
    status,
    Bytes.to_hex(plan.proof_hash),
    Bytes.to_base58(expected),
    if Bytes.length(paid) == 32 do
      Bytes.to_base58(paid)
    else
      ""
    end,
    U64.to_string(state.observation.units),
    plan.config.slash_mint,
    Int.to_string(accepted),
    Int.to_string(List.length(plan.config.relay_urls)),
    U64.to_string(state.checked_at),
    U64.to_string(state.next_attempt),
    U64.to_string(state.observation.context_slot),
    if Bytes.length(state.token) == 0 do
      "0"
    else
      "1"
    end
  ]
  let fields = case plan.permanent do
    None -> fields
    Some(pins) -> fields
      ++ [
        "2",
        U64.to_string(state.observation.morse_units),
        Bytes.to_base58(token_addresses(pins.token)?.mint.bytes),
        Int.to_string(state.observation.receipt_format)
      ]
  end
  encode_output_list(for value in fields do
    Bytes.from_utf8(value)
  end)
end

fn require_filing_observation_pins(plan :: FilingPlan,
  observation :: FilingObservation) -> Result<(), String> do
  let binding = observation.receipt_binding
  if Bytes.length(binding) == 0 && observation.receipt_format != 2 do
    return Ok(nil)
  end
  let pins = case plan.permanent do
    None -> return Err("filing_receipt_pins_changed")
    Some(value) -> value
  end
  if Bytes.length(binding) != 32 || binding != filing_receipt_binding(pins)? do
    Err("filing_receipt_pins_changed")
  else
    Ok(nil)
  end
end

# A queued worker must still name this device's exact frozen evidence. Account
# erasure or a changed native policy invalidates it before another network call.
pub fn native_filing_current(path :: String, config_frame :: Bytes, wire :: Bytes) -> Bool do
  let config = case native_security_config() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let frame = case encode_security_config(config) do
    Err(_) -> return false
    Ok(value) -> value
  end
  if !Bytes.secure_equals(frame, config_frame) do
    return false
  end
  let key = case platform_key() do
    Err(_) -> return false
    Ok(value) -> value
  end
  case disclosable_fork(path, key) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, wire)
  end
end

fn native_filing_context(path :: String,
  wire :: Bytes) -> (SecurityConfig, RpcTransport, Bytes)!String do
  let pin_frame = native_filing_pin_frame()?
  let context = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
  let config = decode_native_security_config(context.security_frame)?
  filing_pin_selection(pin_frame, config)?
  let frame = encode_security_config(config)?
  let captured = rpc_transport_from_context(path, context)?
  let rpc = rpc_transport(captured.sources,
    fn() do
      captured.require_current()?
      require_filing_pin_frame(pin_frame)?
      if !native_filing_current(path, frame, wire) do
        return Err("filing_config_changed")
      end
      Ok(nil)
    end)?
  require_rpc_current(rpc.require_current)?
  Ok((config, rpc, pin_frame))
end

pub fn prepare_native_filing(path :: String, wire :: Bytes) -> Option<FilingPlan>!String do
  let (config, rpc, frame) = native_filing_context(path, wire)?
  case prepare_filing(config, rpc, wire)? do
    None -> Ok(None)
    Some(plan) -> Ok(Some(native_filing_plan(path, plan, frame)?))
  end
end

fn native_filing_plan(path :: String, plan :: FilingPlan, frame :: Bytes) -> FilingPlan!String do
  let native = filing_pin_selection(frame, plan.config)?
  let (permanent, minimum) = case native do
    None -> (None, U64.parse("0")?)
    Some(native) -> (case native.collateral do
        None
        Some(selection) -> Some(PermanentReceiptPins {
          judge: selection.pins.judge,
          token: selection.pins.token,
          log_name: selection.pins.log_name,
          usdc: selection.pins.usdc,
          judge_slot: selection.pins.judge_slot,
          service_key: selection.pins.service_key,
          log_version: selection.pins.log_version
        })
      end,
      native.minimum_slot)
  end
  let anchor_hash = case plan.proof.second do
    SignedCheckpoint(second) -> checkpoint_hash(second)?
    AnchorReference(index) ->
      let key = platform_key()?
      let label = "transparency-fork-anchor/v1"
      let saved = decode_anchor_context(open_local(load_blob(path, label)?,
        key,
        local_context(label)?)?)?
      if saved.ring_index != index
        || decode_anchor_header(saved.header)?.log_id != plan.pins.log_id
        || Bytes.length(saved.fork) == 0
        || fork_hash(decode_fork(saved.fork)?)? != plan.proof_hash do
        return Err("filing_anchor_context_mismatch")
      end
      decode_anchor_entry(saved.entry)?.checkpoint_hash
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  Ok(%{plan | permanent: permanent, minimum_slot: minimum, anchor_hash: anchor_hash})
end

pub fn permanent_filing_observation(plan :: FilingPlan,
  state :: PermanentReceiptState,
  floor :: U64) -> FilingObservation!String do
  if U64.compare(state.context_slot, floor) < 0
    || state.proof_hash != plan.proof_hash
    || state.address != slash_receipt_address(plan.pins.program,
        plan.pins.log_id,
        plan.proof_hash)? do
    return Err("invalid_filing_receipt")
  end
  let pins = case plan.permanent do
    None -> return Err("invalid_filing_receipt")
    Some(value) -> value
  end
  case state.value do
    None -> if state.status == "missing" do
      filing_pending(state.context_slot)
    else
      Err("invalid_filing_receipt")
    end
    Some(LegacyReceipt(receipt)) -> if state.status == "settled" do
      let value = filing_receipt_observation(plan,
        SlashReceiptState {
          address: state.address,
          proof_hash: state.proof_hash,
          context_slot: state.context_slot,
          receipt: Some(receipt)
        },
        floor)?
      Ok(%{value | receipt_binding: filing_receipt_binding(pins)?})
    else
      Err("invalid_filing_receipt")
    end
    Some(MixedReceipt(receipt)) ->
      if receipt.usdc_mint != plan.mint.bytes
        || receipt.morse_mint != token_addresses(pins.token)?.mint.bytes do
        return Err("invalid_filing_receipt")
      end
      let value = mixed_filing_observation(plan.pins.program,
        plan.pins.log_id,
        plan.proof,
        plan.anchor_hash,
        receipt,
        state.context_slot)?
      if state.status != value.status do
        return Err("invalid_filing_receipt")
      end
      Ok(%{value | receipt_binding: filing_receipt_binding(pins)?})
  end
end

pub fn read_filing_receipt(plan :: FilingPlan, floor :: U64) -> FilingObservation!String do
  let minimum = if U64.compare(plan.minimum_slot, floor) > 0 do
    plan.minimum_slot
  else
    floor
  end
  let sampled = sample_anchor_sources(plan.pins)?
  case plan.permanent do
    Some(pins) -> permanent_filing_observation(plan,
      read_permanent_receipt(sampled.rpc, pins, plan.proof_hash, minimum)?,
      minimum)
    None -> filing_receipt_observation(plan,
      read_slash_receipt_state(sampled,
        plan.config.service_public_key,
        plan.proof.first.version,
        plan.mint,
        plan.proof_hash,
        minimum)?,
      minimum)
  end
end

pub fn check_native_filing(path :: String) -> Bytes!String do
  if String.length(path) == 0 || String.length(path) > 4096 do
    return Err("invalid_database_path")
  end
  ensure_schema(path)?
  let key = platform_key()?
  let wire = disclosable_fork(path, key)?
  if Bytes.length(wire) == 0 do
    return blank("none")
  end
  # A disabled release grants no network operation. Its local status must not
  # require an account transport context that can no longer be created.
  let release = native_security_config()?
  if release.slash_mint == "-" do
    filing_pin_selection(native_filing_pin_frame()?, release)?
    return blank("disabled")
  end
  let (config, rpc, pin_frame) = native_filing_context(path, wire)?
  let plan = case prepare_filing(config, rpc, wire) do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    Err(_) -> return blank("invalid_evidence")
    Ok(None) -> return blank("disabled")
    Ok(Some(value)) -> value
  end
  let plan = native_filing_plan(path, plan, pin_frame)?
  let frame = encode_security_config(config)?
  let state = start_observed_filing(path,
    key,
    plan,
    current_time()?,
    fn() do submit_filing(config.relay_urls, wire, plan.proof_hash) end,
    fn(floor :: U64) do read_filing_receipt(plan, floor) end,
    fn() do native_filing_current(path, frame, wire) end)?
  filing_view(plan, state)
end
