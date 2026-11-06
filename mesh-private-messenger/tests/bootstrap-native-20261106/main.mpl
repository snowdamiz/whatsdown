##! Local synthetic bootstrap fixture. Production exports are imported unchanged.
from MobileCore import initialize
from Mobile.Codec import current_time, mobile_join, mobile_byte, mobile_write_u64, mobile_zeroes, encode_output_list
from Mobile.Platform import native_security_config
from Mobile.TransparencyCache import cached_transparency_bytes
from Mobile.AnchorCheck import anchor_identity, load_anchor_observation, anchor_observation_output, check_anchor_at, anchor_service_refused
from Mobile.AnchorSchedule import load_anchor_schedule
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Transparency.Config import decode_security_config, encode_security_config
from Transparency.AnchorChain import anchor_addresses, configured_anchor_pins
from Transparency.RpcTransport import rpc_transport, webpki_rpc_transport
from Transparency.AnchorBatch import read_anchor_accounts
from Mobile.NativeRpcTls import native_rpc_tls_frame, decode_native_rpc_tls
from Transparency.AnchorLog import decode_anchor_log
from Transparency.AnchorRing import decode_anchor_header, decode_anchor_entry
from Transparency.C2spText import checkpoint_note_text
from Transparency.Merkle import (
  WitnessAttestation, TransparencyCheckpoint, checkpoint_hash, leaf_hash_for,
  merkle_root_for, sign_tree_checkpoint_for, compact_inclusion_proof_for,
  compact_consistency_proof_for
)
from Transparency.Wire import (
  TransparencyEvidence, encode_transparency_evidence, encode_checkpoint,
  decode_transparency_lookup
)
from Solana.Read import pubkey

fn join(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(parts, 0, Bytes.empty())
end

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture_signer")
    Ok(value)
  end
end

fn little(value :: Int, width :: Int) -> Bytes!String do
  if width == 0 do
    Ok(Bytes.empty())
  else
    join([mobile_byte(value % 256)?, little(value / 256, width - 1)?])
  end
end

fn witness(key :: borrow SigningPrivateKey,
  id :: String,
  checkpoint :: TransparencyCheckpoint) -> WitnessAttestation!String do
  let seconds = U64.divide(checkpoint.timestamp, U64.parse("1000")?)?
  let statement = Bytes.from_utf8("cosignature/v1\ntime " <> U64.to_string(seconds)
    <> "\n" <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signature = case Crypto.sign(key, statement) do
    Err(_) -> return Err("fixture_cosignature")
    Ok(value) -> value.bytes
  end
  Ok(WitnessAttestation {
    witness_id: id,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: join([mobile_write_u64(seconds)?, signature])?
  })
end

fn save(root :: String, name :: String, bytes :: Bytes) -> Result<(), String> do
  File.write(root <> "/" <> name, Bytes.to_hex(bytes))
end

@export("bootstrap_generate")
pub fn bootstrap_generate_impl(input :: Bytes) -> Bytes!String do
  let root = Bytes.to_utf8(input)?
  let entry = case decode_directory_entry(Bytes.from_hex(File.read(root <> "/entry.hex")?)?) do
    Err(_) -> return Err("fixture_directory_entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture_account_identity")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1, username: entry.username, account_identity: entry.account_identity,
    sequence: account.directory_sequence, devices: [entry], revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture_device_set")
    Ok(value) -> value
  end
  let signer = pair()?
  let a = pair()?
  let b = pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture_delivery")
    Ok(value) -> value
  end
  let program_text = String.repeat("1", 32)
  let name = "morse-local-canary"
  let addresses = anchor_addresses(pubkey(program_text)?, name)?
  let pins = ["witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Local",
    "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Local"]
  let config = Bytes.from_utf8(String.join([
      "4", Bytes.to_hex(signer.public_key.bytes), Bytes.to_hex(delivery.public_key.bytes),
      "1", "2", "2"
    ] ++ pins ++ [Bytes.to_base58(addresses.ring.bytes), "3"]
      ++ String.split(File.read(root <> "/rpc-origins" )?, "\n")
      ++ ["-", "2", "2", "2"] ++ pins ++ [program_text, name], "\n"))
  let canonical = encode_security_config(decode_security_config(config)?)?
  File.write(root <> "/security", Bytes.to_utf8(canonical)?)?
  let network = Bytes.from_utf8(File.read(root <> "/network")?)
  File.write(root <> "/ohttp", "1\n" <> Bytes.to_hex(Crypto.sha256(network))
    <> "\n" <> Bytes.to_hex(Crypto.sha256(canonical)) <> "\n1\noff\n0")?
  let leaves = [leaf_hash_for(2, devices)?]
  let now = current_time()?
  let checkpoint = sign_tree_checkpoint_for(2, signer.private_key, signer.public_key.bytes,
    U64.parse("1")?, U64.parse("1")?, merkle_root_for(2, leaves)?, mobile_zeroes(32)?, now)?
  let signatures = [witness(a.private_key, "witness-a", checkpoint)?,
    witness(b.private_key, "witness-b", checkpoint)?]
  for old in 0..2 do
    let proof = TransparencyEvidence {
      entry_bytes: devices, inclusion: compact_inclusion_proof_for(2, leaves, 0)?,
      consistency: compact_consistency_proof_for(2, if old == 0 do [] else leaves end, leaves)?,
      checkpoint: checkpoint, witnesses: signatures
    }
    save(root, "evidence-#{old}.hex", encode_transparency_evidence(proof)?)?
    # Keep valid framing, tree and witness material; corrupt only the signed checkpoint signature.
    let forged = %{checkpoint | signature: mobile_zeroes(64)?}
    save(root, "forged-#{old}.hex", encode_transparency_evidence(%{proof | checkpoint: forged})?)?
  end
  save(root, "checkpoint.hex", encode_checkpoint(checkpoint)?)?
  save(root, "devices.hex", devices)?
  let header = join([Bytes.from_utf8("MRG"), little(1, 1)?, addresses.log_id,
    little(0, 2)?, little(1, 2)?, little(1, 8)?, little(1, 8)?, little(500, 8)?])?
  let ring_entry = join([little(1, 8)?, little(1, 8)?, checkpoint.tree_root,
    checkpoint_hash(checkpoint)?, little(U64.to_int(now)?, 8)?, little(500, 8)?,
    little(0, 2)?, little(2, 1)?, little(0, 1)?, little(0, 2)?, little(0, 2)?])?
  let log = join([Bytes.from_utf8("MLG"), little(1, 1)?, little(2, 1)?, little(0, 1)?,
    little(String.length(name), 1)?, little(0, 1)?, Bytes.from_utf8(name),
    mobile_zeroes(32 - String.length(name))?, addresses.log_id, signer.public_key.bytes,
    a.public_key.bytes, addresses.ring.bytes, b.public_key.bytes, little(1, 8)?,
    little(0, 2)?, little(String.length(name), 2)?, Bytes.from_utf8(name),
    mobile_zeroes(140 - String.length(name))?])?
  decode_anchor_header(header)?
  decode_anchor_entry(ring_entry)?
  decode_anchor_log(log)?
  save(root, "header.hex", header)?
  save(root, "ring-entry.hex", ring_entry)?
  save(root, "log.hex", log)?
  File.write(root <> "/ring-address", Bytes.to_base58(addresses.ring.bytes))?
  File.write(root <> "/log-address", Bytes.to_base58(addresses.log.bytes))?
  File.write(root <> "/block-time", U64.to_string(U64.divide(now, U64.parse("1000")?)?))?
  Ok(devices)
end

# A separate fixture process serves this export. Native orchestration forwards bytes
# without interpreting lookup frames, selecting proof versions or signing anything.
@export("bootstrap_lookup_response")
pub fn bootstrap_lookup_response_impl(input :: Bytes) -> Bytes!String do
  let root = Env.get("BOOTSTRAP_FIXTURE", "")
  let (stamp, body) = decode_stamped_request(input, 76)?
  if !verify_request_stamp("mesh-msg/v1/work/resolve", body, stamp, current_time()?,
    U64.parse("300000")?, 1)? do
    return Err("fixture_bad_request_stamp")
  end
  let lookup = decode_transparency_lookup(body)?
  if lookup.username != "morse-canary-1" do
    return Err("fixture_unexpected_lookup")
  end
  File.append(root <> "/lookup-history", Int.to_string(lookup.previous_tree_size) <> "\n")?
  let mode = File.read(root <> "/lookup-mode")?
  let name = if mode == "forged" do "forged" else "evidence" end
  let previous = if lookup.previous_tree_size == 0 do 0 else 1 end
  Bytes.from_hex(File.read(root <> "/#{name}-#{previous}.hex")?)
end

@export("bootstrap_cache_snapshot")
pub fn bootstrap_cache_snapshot_impl(input :: Bytes) -> Bytes!String do
  let path = Bytes.to_utf8(input)?
  let key = platform_key()?
  encode_output_list(for label in ["transparency-checkpoint/v1", "transparency-view/v1",
    "transparency-witnesses/v2", "transparency-leaf/v1", "transparency-origin/v1"] do
    cached_transparency_bytes(path, key, label)?
  end)
end

@export("bootstrap_schedule_snapshot")
pub fn bootstrap_schedule_snapshot_impl(input :: Bytes) -> Bytes!String do
  let path = Bytes.to_utf8(input)?
  let config = native_security_config()?
  # Identity observation must remain usable when the companion is malformed.
  # This transport is never sent; the public identity deliberately excludes it.
  let pins = case configured_anchor_pins(config, webpki_rpc_transport(config.rpc_urls)?)? do
    None -> return Err("fixture_anchor_disabled")
    Some(value) -> value
  end
  let key = platform_key()?
  let identity = anchor_identity(pins, config.service_public_key, config.log_version)?
  let state = load_anchor_schedule(path, key, identity)?
  encode_output_list([Bytes.from_utf8(U64.to_string(state.next_daily)),
    Bytes.from_utf8(U64.to_string(state.next_allowed)),
    Bytes.from_utf8(U64.to_string(state.last_started)),
    Bytes.from_utf8(U64.to_string(state.last_completed)), state.active_token,
    state.last_result, anchor_observation_output(load_anchor_observation(path, key, identity)?)?])
end

# Supplementary shared-reader proof. Primary acceptance always calls the
# unchanged production resolver and anchor C ABI above.
@export("bootstrap_batch")
pub fn bootstrap_batch_impl(input :: Bytes) -> Bytes!String do
  let config = native_security_config()?
  let frame = native_rpc_tls_frame()?
  let rpc = rpc_transport(decode_native_rpc_tls(frame, config)?, fn() do Ok(nil) end)?
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Err("fixture_anchor_disabled")
    Some(value) -> value
  end
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  let batch = read_anchor_accounts(rpc, [addresses.ring, addresses.log], U64.parse("501")?)?
  if List.length(batch.accounts) != 2 do
    return Err("fixture_batch")
  end
  Ok(Bytes.from_utf8(U64.to_string(batch.slot)))
end

# Explicit injected time on the public Mesh checker; this is not a native
# clock or a claim that the production C ABI's next-day boundary was executed.
@export("bootstrap_anchor_due")
pub fn bootstrap_anchor_due_impl(input :: Bytes) -> Bytes!String do
  let config = native_security_config()?
  let rpc = rpc_transport(decode_native_rpc_tls(native_rpc_tls_frame()?, config)?,
    fn() do Ok(nil) end)?
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Err("fixture_anchor_disabled")
    Some(value) -> value
  end
  anchor_observation_output(check_anchor_at(Bytes.to_utf8(input)?, platform_key()?, pins,
    config.service_public_key, config.log_version,
    U64.add(current_time()?, U64.parse("86400001")?)?, false)?)
end

@export("bootstrap_service_refused")
pub fn bootstrap_service_refused_impl(input :: Bytes) -> Bytes!String do
  let refused = anchor_service_refused(Bytes.to_utf8(input)?, platform_key()?)?
  Ok(Bytes.from_utf8(if refused do "refused" else "allowed" end))
end

@export("bootstrap_tls_pool")
pub fn bootstrap_tls_pool_impl(input :: Bytes) -> Bytes!String do
  let origin = Bytes.to_utf8(input)?
  bootstrap_tls_control_impl(input)?
  let default = (Http.build(:get, origin <> "/ready")
    |> Http.timeout(2000) |> Http.max_redirects(0) |> Http.send())
  case default do
    Ok(_) -> return Err("fixture_default_root_polluted")
    Err(_) -> nil
  end
  let wrong = Bytes.from_utf8(File.read(Env.get("BOOTSTRAP_FIXTURE", "") <> "/wrong-ca.pem")?)
  let refused = (Http.build(:get, origin <> "/ready")
    |> Http.trust_root_pem(wrong) |> Http.timeout(2000)
    |> Http.max_redirects(0) |> Http.send())
  case refused do
    Ok(_) -> Err("fixture_wrong_root_polluted")
    Err(_) -> Ok(Bytes.from_utf8("isolated"))
  end
end

@export("bootstrap_tls_control")
pub fn bootstrap_tls_control_impl(input :: Bytes) -> Bytes!String do
  let origin = Bytes.to_utf8(input)?
  let root = Bytes.from_utf8(File.read(Env.get("BOOTSTRAP_FIXTURE", "") <> "/ca.pem")?)
  let response = (Http.build(:get, origin <> "/ready")
    |> Http.trust_root_pem(root)
    |> Http.timeout(2000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(32)
    |> Http.send())?
  if response.status != 200 || response.body != "bootstrap-local-ready" do
    Err("fixture_tls_control_failed")
  else
    Ok(Bytes.from_utf8(response.body))
  end
end
