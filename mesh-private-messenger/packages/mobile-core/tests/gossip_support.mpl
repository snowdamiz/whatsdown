import File
from MobileCore import (
  load_history_export,
  load_profile_export,
  outbox_ack_export,
  outbox_page_export,
  receive_initial_export,
  receive_message_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export,
  verify_transparency_export
)
from Mobile.GossipRun import gossip_check_at
from Mobile.GossipState import GossipState, gossip_control_type, gossip_received, gossip_state_load
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Storage.Keys import platform_key
from Tests.AnchorSupport import (
  AnchorTrace,
  FakeAnswer,
  drive_steps,
  fake_directory,
  fake_relay,
  finder_address,
  relay_urls,
  seeded
)
from Tests.GroupConsistencySupport import ConsistencyAccount, account_fixture, request, wide
from Tests.Support import evidence_v2, output_list_items, read_u32, repeated, write_u32
from Transparency.CompactWire import transparency_decode_leaf_query
from Transparency.Fork import ForkLog, fork_decode, fork_verify
from Transparency.Gossip import GossipHint, gossip_hint_extension
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  sign_checkpoint,
  sign_witness
)
from Transport.Packet import decode_client_profile

##! Two phones that message each other, and what checkpoint gossip tests do
##! with them: deliver what one queued to the other, run a gossip step the way
##! the app does, and hand a phone a message a hostile contact made up.

pub struct GossipPair do
  ann :: ConsistencyAccount
  bea :: ConsistencyAccount
  ann_profile :: Bytes
  bea_profile :: Bytes
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn profile_of(account :: ConsistencyAccount) -> Bytes!String do
  load_profile_export(Bytes.from_utf8(account.path))
end

pub fn gossip_pair(label :: String) -> GossipPair!String do
  let ann = account_fixture(label <> "-ann", "ann")?
  let bea = account_fixture(label <> "-bea", "bea")?
  Ok(GossipPair {
    ann: ann,
    bea: bea,
    ann_profile: profile_of(ann)?,
    bea_profile: profile_of(bea)?
  })
end

pub fn forget_pair(pair :: GossipPair) -> Result<(), String> do
  File.delete(pair.ann.path)?
  File.delete(pair.bea.path)?
  Ok(nil)
end

fn acknowledge(path :: String, envelope :: Bytes) -> Result<(), String> do
  outbox_ack_export(request([Bytes.from_utf8(path), envelope])?)?
  Ok(nil)
end

# Ann writes first and Bea accepts: both now listen to each other. Says how
# many gossip notes Bea took while the conversation was still a request.

pub fn introduce(pair :: GossipPair) -> Int!String do
  let hello = start_conversation_export(request([
    Bytes.from_utf8(pair.ann.path),
    pair.bea_profile,
    Bytes.from_utf8("hello bea")
  ])?)?
  acknowledge(pair.ann.path, hello)?
  receive_initial_export(request([Bytes.from_utf8(pair.bea.path), hello])?)?
  let heard = pending(pair.bea.path)?
  update_conversation_export(request([
    Bytes.from_utf8(pair.bea.path),
    pair.ann_profile,
    byte(1)?,
    write_u32(0)?
  ])?)?
  Ok(heard)
end

# A chat message from `path` to the peer, taken out of the outbox as the app
# would once the service accepted it.

pub fn say(path :: String, peer_profile :: Bytes, text :: String) -> Bytes!String do
  let envelope = send_message_export(request([
    Bytes.from_utf8(path),
    peer_profile,
    Bytes.from_utf8(text)
  ])?)?
  acknowledge(path, envelope)?
  Ok(envelope)
end

pub fn hear(path :: String, envelope :: Bytes) -> Bytes!String do
  receive_message_export(request([Bytes.from_utf8(path), envelope])?)
end

fn outbox_from(path :: String, offset :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  let page = output_list_items(outbox_page_export(request([
    Bytes.from_utf8(path),
    write_u32(offset)?
  ])?)?)?
  if List.length(page) == 0 do
    Ok(output)
  else
    outbox_from(path, offset + List.length(page), List.concat(output, page))
  end
end

# Everything queued, acknowledged as sent.

pub fn drain(path :: String) -> List<Bytes>!String do
  let queued = outbox_from(path, 0, List.new())?
  for envelope in queued do
    acknowledge(path, envelope)?
  end
  Ok(queued)
end

pub fn deliver(from_path :: String, to_path :: String) -> Int!String do
  let queued = drain(from_path)?
  for envelope in queued do
    hear(to_path, envelope)?
  end
  Ok(List.length(queued))
end

# One gossip run to the end with the clock moved `offset_ms` ahead.

pub fn gossip_run(path :: String,
  offset_ms :: Int,
  respond :: Fun(Int, String, String, Bytes) -> FakeAnswer) -> List<AnchorTrace>!String do
  drive_steps(path, fn input -> gossip_check_at(input, offset_ms) end, respond)
end

pub fn asked_count(traces :: List<AnchorTrace>, kind :: Int, target :: String) -> Int do
  List.length(List.filter(traces,
    fn trace -> trace.kind == kind && (target == "" || trace.target == target) end))
end

pub fn consistency_asks(traces :: List<AnchorTrace>) -> Int do
  asked_count(traces, 2, "/v1/transparency/consistency")
end

# An honest directory over `leaves`, relays, and a finder address per proof.

pub fn honest(leaves :: List<Bytes>,
  kind :: Int,
  tag :: String,
  target :: String,
  body :: Bytes) -> FakeAnswer do
  if kind == 2 do
    fake_directory(leaves, false, target, body)
  else if kind == 3 do
    fake_relay(target, body, true)
  else if kind == 4 do
    FakeAnswer { status: 200, body: finder_address(tag) }
  else
    FakeAnswer { status: 0, body: Bytes.empty() }
  end
end

fn leaf_size(body :: Bytes) -> Int do
  case transparency_decode_leaf_query(body) do
    Ok(query) -> query.tree_size
    Err(_) -> 0
  end
end

# A directory keeping a split view: it serves each version's leaves at that
# version's size, and consistency only within the larger one.

pub fn split(small :: List<Bytes>,
  large :: List<Bytes>,
  kind :: Int,
  tag :: String,
  target :: String,
  body :: Bytes) -> FakeAnswer do
  if kind == 2 && target == "/v1/transparency/leaf" && leaf_size(body) <= List.length(small) do
    fake_directory(small, false, target, body)
  else
    honest(large, kind, tag, target, body)
  end
end

pub fn account_id(profile :: Bytes) -> Bytes!String do
  Ok(decode_client_profile(profile)?.account_id)
end

fn device_id(profile :: Bytes) -> Bytes!String do
  Ok(decode_client_profile(profile)?.device_id)
end

fn envelope_from(sender :: Bytes,
  recipient :: Bytes,
  message_type :: Int,
  body :: Bytes,
  extensions :: List<ProtocolExtension>) -> InnerEnvelope!String do
  let random = case Crypto.random_bytes(16) do
    Err(_) -> Err("test random failed")
    Ok(value)
  end?
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: account_id(sender)?,
    sender_device_id: device_id(sender)?,
    recipient_device_id: device_id(recipient)?,
    conversation_id: repeated(3, 16)?,
    client_message_id: random,
    client_timestamp: wide(DateTime.to_unix_ms(DateTime.utc_now()))?,
    message_type: message_type,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: extensions
  })
end

# What the receive path notes for an authenticated message from `sender`,
# made up here as a hostile contact would make it.

pub fn noted(path :: String,
  sender :: Bytes,
  recipient :: Bytes,
  inner :: InnerEnvelope) -> Result<(), String> do
  let wrapping_key = platform_key()?
  gossip_received(path, wrapping_key, true, account_id(sender)?, device_id(sender)?, inner)
  Ok(nil)
end

pub fn invented_hint(path :: String,
  sender :: Bytes,
  recipient :: Bytes,
  hint :: GossipHint) -> Result<(), String> do
  noted(path,
    sender,
    recipient,
    envelope_from(sender, recipient, 1, Bytes.from_utf8("hi"), [gossip_hint_extension(hint)?])?)
end

pub fn raw_extension(path :: String,
  sender :: Bytes,
  recipient :: Bytes,
  extensions :: List<ProtocolExtension>) -> Result<(), String> do
  noted(path,
    sender,
    recipient,
    envelope_from(sender, recipient, 1, Bytes.from_utf8("hi"), extensions)?)
end

pub fn control(path :: String,
  sender :: Bytes,
  recipient :: Bytes,
  body :: Bytes) -> Result<(), String> do
  noted(path,
    sender,
    recipient,
    envelope_from(sender, recipient, gossip_control_type(), body, List.new())?)
end

pub fn pending(path :: String) -> Int!String do
  let state = gossip_state_load(path, platform_key()?)?
  Ok(List.length(state.pending))
end

pub fn history_count(path :: String, peer_profile :: Bytes) -> Int!String do
  let listed = load_history_export(request([Bytes.from_utf8(path), peer_profile])?)?
  case Bytes.slice(listed, 4, 4) do
    Err(_) -> Err("history count failed")
    Ok(count) -> read_u32(count)
  end
end

# A proof checked as the judge (and every relay) checks it: the implicated
# witnesses, or the reason it is no fork.

pub fn frk_implicated(bytes :: Bytes,
  service_key :: Bytes,
  witnesses :: List<WitnessKey>) -> List<String>!String do
  fork_verify(fork_decode(bytes)?,
    ForkLog { service_public_key: service_key, witnesses: witnesses },
    None)
end

pub fn frk_finder(bytes :: Bytes) -> Bytes!String do
  Ok(fork_decode(bytes)?.finder)
end

pub fn witness_key(id :: String, seed :: Int) -> WitnessKey!String do
  Ok(WitnessKey { witness_id: id, public_key: seeded(seed)?.public_key.bytes })
end

# The canary log (plan §11.3): its own service key and witnesses T1-T3, run by
# Morse, relays pinned, and no chain anchor, so the phone's anchor check is off.

pub fn canary_key() -> Bytes!String do
  Ok(seeded(71)?.public_key.bytes)
end

pub fn canary_witness_id(index :: Int) -> String do
  "canary-t#{index + 1}"
end

pub fn canary_witnesses() -> List<WitnessKey>!String do
  Ok([
    witness_key(canary_witness_id(0), 72)?,
    witness_key(canary_witness_id(1), 73)?,
    witness_key(canary_witness_id(2), 74)?
  ])
end

pub fn install_canary_config() -> Bool!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  let witnesses = for key in canary_witnesses()? do
    SecurityWitness { witness_id: key.witness_id, public_key: key.public_key, label: "Morse" }
  end
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: canary_key()?,
    delivery_public_key: delivery.public_key.bytes,
    abuse_difficulty: 8,
    threshold: 2,
    witnesses: witnesses,
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: relay_urls(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

pub fn canary_checkpoint(sequence :: Int, leaves :: List<Bytes>) -> TransparencyCheckpoint!String do
  let signer = seeded(71)?
  sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(sequence)?,
    leaves,
    repeated(0, 32)?,
    wide(DateTime.to_unix_ms(DateTime.utc_now()))?)
end

fn canary_attestation(index :: Int,
  checkpoint :: TransparencyCheckpoint) -> WitnessAttestation!String do
  let signer = seeded(72 + index)?
  sign_witness(canary_witness_id(index), signer.private_key, checkpoint)
end

# The phone verifies `username` at `index` of `leaves` under `checkpoint`,
# cosigned by the canary witnesses at `signers`.

pub fn canary_lookup(path :: String,
  username :: String,
  entry_bytes :: Bytes,
  leaves :: List<Bytes>,
  index :: Int,
  old_size :: Int,
  checkpoint :: TransparencyCheckpoint,
  signers :: List<Int>) -> Bytes!String do
  let attestations = for signer in signers do
    canary_attestation(signer, checkpoint)?
  end
  let evidence = evidence_v2(entry_bytes, leaves, index, old_size, checkpoint, attestations)?
  verify_transparency_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username), evidence])?)
end
