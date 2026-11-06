# Test-only embedding host. Production exports accept only the app database;
# this fixture seeds signed evidence and substitutes loopback transport origins.
from Mobile.ForkFiling import (
  FilingPlan,
  prepare_filing,
  start_filing,
  filing_view,
  prepare_native_filing,
  start_observed_filing,
  read_filing_receipt,
  native_filing_current
)
from Mobile.ForkFilingTransport import submit_filing
from Mobile.Platform import native_security_config, decode_native_security_config
from Mobile.OhttpContext import capture_native_ohttp_context, rpc_transport_from_context
from Storage.Blobs import load_blob, ensure_schema
from Solana.Read import pubkey, Pubkey, Hash
from Solana.Tx import compile_legacy_message, serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction
from Bounty.Transfer import BountyTransfer, bounty_transfer_instructions
from Mobile.Bounty import bounty_state, set_bounty_enabled, commit_bounty_address, disclosable_fork
from Mobile.BountyTransferState import prepare_bounty_transfer, commit_bounty_transfer
from Transparency.Relay import validate_relay_submission
from Mobile.TransparencySafety import retain_fork, retained_fork
from Mobile.Codec import mobile_utf8, encode_output_list
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_session
from Transparency.Config import SecurityConfig, encode_security_config
from Transparency.Fork import ForkProof, ForkTarget, decode_fork, fork_hash
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Transparency.RpcTransport import webpki_rpc_transport, rpc_transport
from Transparency.SlashReceiptRead import read_slash_receipt_state, slash_receipt_state_report
from MobileCore import fork_filing_export, transparency_fork_export, initialize

@export("phone_fixture_seed")
pub fn seed(request :: Bytes) -> Bytes!String do
  seed_exact(request)
end

@export("phone_fixture_start")
pub fn start(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let config = native_security_config()?
  let plan = case prepare_filing(config,
    webpki_rpc_transport(config.rpc_urls)?,
    retained_fork(path, key)?)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let ports = String.split(Env.get("MORSE_PHONE_FILING_PORTS", ""), ",")
  let origins = for port in ports do
    "http://127.0.0.1:" <> port
  end
  let local = webpki_rpc_transport(origins)?
  let pins = %{plan.pins | rpc: rpc_transport(local.sources, plan.pins.rpc.require_current)?}
  let state = start_filing(path,
    key,
    plan,
    U64.parse(File.read(path <> ".now")?)?,
    fn() do submit_filing(origins, plan.wire, plan.proof_hash) end,
    fn(floor :: U64) do read_slash_receipt_state(pins,
      config.service_public_key,
      config.log_version,
      plan.mint,
      plan.proof_hash,
      floor) end,
    fn() -> true end)?
  filing_view(plan, state)
end

# A migrated retained fork is an existing supported native custody boundary.
# Preserve its admitted finder exactly, rather than exercising wallet selection.
# This seed grants no receipt authority; every observed account still crosses
# the captured native TLS RPC boundary below and in the production export.
@export("phone_fixture_seed_exact")
pub fn seed_exact(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  ensure_schema(path)?
  let key = platform_key()?
  let wire = Bytes.from_hex(File.read(path <> ".wire")?)?
  let config = native_security_config()?
  let decoded = decode_fork(wire)?
  validate_relay_submission(config.service_public_key, decoded.first.version, wire)?
  let label = "transparency-fork/v1"
  store_updated_session(path, label, seal_local(wire, key, local_context(label)?)?)?
  retained_fork(path, key)
end

# Isolate the archived production reader from the separate old legacy-policy
# admission bug. No callback supplies account bytes, RPC replies, or authority.
@export("phone_fixture_native_legacy_read")
pub fn native_legacy_read(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let wire = retained_fork(path, key)?
  let proof = decode_fork(wire)?
  let context = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
  let config = decode_native_security_config(context.security_frame)?
  let rpc = rpc_transport_from_context(path, context)?
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let receipt = read_slash_receipt_state(pins,
    config.service_public_key,
    proof.first.version,
    pubkey(config.slash_mint)?,
    fork_hash(proof)?,
    U64.parse("0")?)?
  Ok(Bytes.from_utf8(slash_receipt_state_report(receipt)))
end

# Deterministic scheduling only: admission and receipt I/O are the production
# implementation captured from native resources. Relay acknowledgments traverse
# a real local HTTP route and cannot supply payment observations.
@export("phone_fixture_native_start")
pub fn native_start(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let wire = retained_fork(path, key)?
  let plan = case prepare_native_filing(path, wire)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let origins = String.split(Env.get("MORSE_PHONE_FILING_ORIGINS", ""), ",")
  let frame = encode_security_config(plan.config)?
  let state = start_observed_filing(path,
    key,
    plan,
    U64.parse(File.read(path <> ".now")?)?,
    fn() do submit_filing(origins, plan.wire, plan.proof_hash) end,
    fn(floor :: U64) do read_filing_receipt(plan, floor) end,
    fn() do native_filing_current(path, frame, wire) end)?
  filing_view(plan, state)
end

@export("phone_fixture_native_read")
pub fn native_read(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let plan = case prepare_native_filing(path, retained_fork(path, key)?)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let result = read_filing_receipt(plan, U64.parse(File.read(path <> ".floor")?)?)?
  encode_output_list(for field in [result.status,
      Bytes.to_base58(result.finder),
      U64.to_string(result.units),
      U64.to_string(result.morse_units),
      Int.to_string(result.receipt_format),
      U64.to_string(result.context_slot)] do
    Bytes.from_utf8(field)
  end)
end

@export("phone_fixture_seed_selected")
pub fn seed_selected(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let wire = Bytes.from_hex(File.read(path <> ".wire")?)?
  let proof = decode_fork(wire)?
  set_bounty_enabled(path, key, true)?
  retain_fork(path, key, proof)?
  let state = bounty_state(path, key)?
  commit_bounty_address(path,
    key,
    state.proof_identity,
    Bytes.concat(Bytes.from_hex("0300000000000000")?, proof.finder)?)?
  disclosable_fork(path, key)
end

# Seed a cryptographically valid historical signed journal, not a paid receipt.
# Recovery must preserve this signature when finalized history returns None,
# even when the current native filing policy selects the v2 receipt reader.
@export("phone_fixture_seed_pending_bounty")
pub fn seed_pending_bounty(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_path")?
  let key = platform_key()?
  let payer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture_key_generation")
    Ok(value) -> value
  end
  let finder = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture_key_generation")
    Ok(value) -> value
  end
  let wire = Bytes.from_hex(File.read(path <> ".wire")?)?
  set_bounty_enabled(path, key, true)?
  retain_fork(path, key, decode_fork(wire)?)?
  let selected = bounty_state(path, key)?
  commit_bounty_address(path,
    key,
    selected.proof_identity,
    Bytes.concat(Bytes.from_hex("0300000000000000")?, finder.public_key.bytes)?)?
  let plan = case prepare_native_filing(path, disclosable_fork(path, key)?)? do
    None -> return Err("disabled_fixture")
    Some(value) -> value
  end
  let intent = BountyTransfer {
    index: U64.parse("3")?,
    finder: finder.public_key.bytes,
    destination: payer.public_key.bytes,
    mint: plan.mint.bytes,
    amount: U64.parse("7")?,
    blockhash: Bytes.from_hex(String.repeat("08", 32))?,
    issued_at: U64.parse("1000")?,
    expires_at: U64.parse("1300")?,
    purpose: 1,
    decimals: 6
  }
  prepare_bounty_transfer(path,
    key,
    plan.identity,
    intent,
    payer.public_key.bytes,
    plan.mint.bytes,
    U64.parse("50")?,
    U64.parse("90")?,
    U64.parse("60")?,
    intent.issued_at)?
  let message = compile_legacy_message(Pubkey { bytes: payer.public_key.bytes },
    Hash { bytes: intent.blockhash },
    bounty_transfer_instructions(intent, Pubkey { bytes: payer.public_key.bytes })?)?
  let body = serialize_legacy_message(message)?
  let p = case Crypto.sign(payer.private_key, body) do
    Err(_) -> return Err("fixture_signing")
    Ok(value) -> value
  end
  let f = case Crypto.sign(finder.private_key, body) do
    Err(_) -> return Err("fixture_signing")
    Ok(value) -> value
  end
  let packet = serialize_signed_legacy_transaction(message, [p, f])?
  let signed = commit_bounty_transfer(path,
    key,
    plan.identity,
    packet,
    U64.parse("70")?,
    U64.parse("1100")?)?
  encode_output_list([plan.identity, signed.signature])
end
