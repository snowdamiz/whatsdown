from Transparency.Config import SecurityConfig, decode_security_config
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins, sample_anchor_sources
from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.Relay import RelayVerification, verify_relay_fork, validate_relay_submission
from Transparency.RelayAdmission import admit_relay_fork
from Transparency.RelayReport import relay_admission_report
from Transparency.RelayLookupRead import (
  RelayLookupState,
  RelayLookupCooldown,
  read_relay_lookup,
  relay_lookup_report,
  read_relay_lookup_cooldown,
  relay_lookup_cooldown_report
)
from Transparency.RelayStageRead import RelayStageState, read_relay_stage, relay_stage_report
from Transparency.RelayDestinations import (
  RelayDestinationsState,
  read_relay_destinations,
  relay_destinations_report
)
from Transparency.SlashReceiptRead import (
  SlashReceiptState,
  read_slash_receipt_state,
  slash_receipt_state_report
)
from Transparency.Fork import ForkVerdict, ForkProof, fork_hash
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey

fn run() -> Result<(), String> do
  let args = Env.args()
  let recovery = List.length(args) == 8
    && (List.get(args, 1) == "--receipt-state" || List.get(args, 1) == "--destinations-state")
    && List.get(args, 2) == "--input"
    && List.get(args, 4) == "--submitter"
    && List.get(args, 6) == "--mint"
  let stage = List.length(args) == 6
    && List.get(args, 1) == "--stage-state"
    && List.get(args, 2) == "--input"
    && List.get(args, 4) == "--submitter"
  let lookup = List.length(args) == 8
    && (List.get(args, 1) == "--lookup-state" || List.get(args, 1) == "--lookup-close-state")
    && List.get(args, 2) == "--submitter"
    && List.get(args, 4) == "--slot"
    && List.get(args, 6) == "--addresses"
  let evidence = (List.length(args) == 3 || List.length(args) == 7)
    && List.get(args, 1) == "--input"
    && (List.length(args) == 3
      || (List.get(args, 3) == "--submitter" && List.get(args, 5) == "--mint"))
  if !lookup && !evidence && !stage && !recovery do
    return Err("usage: morse-fork-verifier --input evidence.frk [--submitter PUBKEY --mint MINT] | --lookup-state|--lookup-close-state --submitter PUBKEY --slot SLOT --addresses KEY,KEY,... | --stage-state --input evidence.frk --submitter PUBKEY | --receipt-state|--destinations-state --input evidence.frk --submitter PUBKEY --mint MINT")
  end
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Err("MESSENGER_SECURITY_CONFIG is required for relay preflight")
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  let pins = case configured_anchor_pins(config, webpki_rpc_transport(config.rpc_urls)?)? do
    None -> return Err("relay_requires_anchor_pins")
    Some(value) -> value
  end
  let version = case Env.get("MORSE_RELAY_LOG_VERSION", "2") do
    "1" -> 1
    "2" -> 2
    _ -> return Err("MORSE_RELAY_LOG_VERSION must be 1 or 2")
  end
  let floor = Env.get("MORSE_RELAY_MIN_CONTEXT_SLOT", "0")
  let minimum_slot = U64.parse(floor)?
  if U64.to_string(minimum_slot) != floor do
    return Err("relay_context_must_be_canonical_u64")
  end
  if lookup do
    let authority = pubkey(List.get(args, 3))?
    let slot_text = List.get(args, 5)
    let slot = U64.parse(slot_text)?
    if U64.to_string(slot) != slot_text do
      return Err("relay_context_must_be_canonical_u64")
    end
    let addresses = for key in String.split(List.get(args, 7), ",") do
      pubkey(key)?
    end
    if List.get(args, 1) == "--lookup-close-state" do
      println(relay_lookup_cooldown_report(read_relay_lookup_cooldown(pins.rpc,
        authority,
        slot,
        addresses,
        minimum_slot)?))
      return Ok(nil)
    end
    println(relay_lookup_report(read_relay_lookup(pins.rpc,
      authority,
      slot,
      addresses,
      minimum_slot)?))
    return Ok(nil)
  end
  let path = List.get(args,
    if stage || recovery do
      3
    else
      2
    end)
  let length = File.size(path)?
  if length > 8192 do
    return Err("relay_submission_too_large")
  end
  let wire = File.read_bytes(path, 0, length)?
  if recovery do
    let submitter = pubkey(List.get(args, 5))?
    let mint = pubkey(List.get(args, 7))?
    if Bytes.to_hex(submitter.bytes) == String.repeat("00", 32)
      || Bytes.to_hex(mint.bytes) == String.repeat("00", 32) do
      return Err("invalid_relay_pins")
    end
    if List.get(args, 1) == "--destinations-state" do
      println(relay_destinations_report(read_relay_destinations(pins,
        config.service_public_key,
        version,
        mint,
        submitter,
        wire,
        minimum_slot)?))
    else
      let proof = validate_relay_submission(config.service_public_key, version, wire)?
      println(slash_receipt_state_report(read_slash_receipt_state(sample_anchor_sources(pins)?,
        config.service_public_key,
        version,
        mint,
        fork_hash(proof)?,
        minimum_slot)?))
    end
    return Ok(nil)
  end
  if stage do
    let submitter = pubkey(List.get(args, 5))?
    println(relay_stage_report(read_relay_stage(pins,
      config.service_public_key,
      version,
      submitter,
      wire,
      minimum_slot)?))
    return Ok(nil)
  end
  if List.length(args) == 7 do
    let submitter = pubkey(List.get(args, 4))?
    let mint = pubkey(List.get(args, 6))?
    println(relay_admission_report(admit_relay_fork(pins,
      config.service_public_key,
      version,
      mint,
      submitter,
      wire,
      minimum_slot)?))
    return Ok(nil)
  end
  let result = verify_relay_fork(pins, config.service_public_key, version, wire, minimum_slot)?
  let witnesses = String.join(for key in result.verdict.witnesses do
      "{\"witness_id\":"
        <> Json.encode_string(key.witness_id)
        <> ",\"public_key\":\"#{Bytes.to_hex(key.public_key)}\"}"
    end,
    ",")
  println("{\"version\":1,\"verified\":true,\"log\":"
    <> Json.encode_string(pins.log_name)
    <> ",\"log_version\":#{version},\"proof_hash\":\"#{Bytes.to_hex(result.proof_hash)}\""
    <> ",\"finder\":\"#{Bytes.to_base58(result.finder)}\",\"finder_is_zero\":#{Bytes.to_hex(result.finder) == String.repeat("00",
        32)}"
    <> ",\"service_public_key\":\"#{Bytes.to_hex(result.verdict.service_public_key)}\",\"service_slashed\":#{result.service_slashed}"
    <> ",\"context_slot\":\"#{U64.to_string(result.context_slot)}\",\"witness_scope\":"
    <> Json.encode_string(result.witness_scope)
    <> ",\"witnesses\":[#{witnesses}],\"proof_hex\":\"#{Bytes.to_hex(result.proof)}\""
    <> ",\"anchor_header_hex\":\"#{Bytes.to_hex(result.anchor_header)}\",\"anchor_entry_hex\":\"#{Bytes.to_hex(result.anchor_entry)}\""
    <> ",\"witness_set_hex\":\"#{Bytes.to_hex(result.witness_set)}\"}")
  Ok(nil)
end

fn main() do
  case run() do
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
    Ok(_) -> nil
  end
end
