from Mobile.Codec import random_bytes, mobile_zeroes
from Mobile.GossipState import (
  GossipState,
  load_gossip_state,
  save_gossip_state,
  queued_gossip_writes
)
from Mobile.Sessions import load_session_ids, find_peer_session
from Mobile.Types import MobileLoadedSession, MobileSessionRecord
from Mobile.Platform import native_security_config
from Mobile.Transparency import transparency_checkpoint_bytes
from Mobile.TransparencySafety import retain_fork
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local
from Transparency.Config import SecurityConfig, LogWitnessPolicy, witness_policy_for_log
from Transparency.Fork import ForkProof, ForkTarget, fork_same_size, fork_rollback
from Transparency.Gossip import (
  CheckpointHint,
  GossipControl,
  encode_hint,
  decode_hint,
  encode_gossip,
  decode_gossip
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  ConsistencyProof,
  verify_checkpoint,
  verify_consistency,
  verify_witnesses
)
from Transparency.Wire import (
  decode_checkpoint,
  decode_witnesses,
  decode_consistency_proof,
  encode_consistency_range
)

fn own_checkpoint(path :: String,
  key :: borrow StorageKey) -> Option<TransparencyCheckpoint>!String do
  let bytes = transparency_checkpoint_bytes(path, key)?
  if Bytes.length(bytes) == 0 do
    return Ok(None)
  end
  let checkpoint = decode_checkpoint(bytes)?
  let config = native_security_config()?
  if !verify_checkpoint(checkpoint, SigningPublicKey { bytes: config.service_public_key })? do
    # A native pin change can leave a checkpoint from the previous log in the
    # cache. It cannot participate in gossip under the new trust policy; it
    # also must not prevent an existing ratchet from receiving its messages.
    return Ok(None)
  end
  case witness_policy_for_log(config, checkpoint.version) do
    Err(_) -> return Ok(None)
    Ok(_) -> nil
  end
  Ok(Some(checkpoint))
end

fn hint_for(checkpoint :: TransparencyCheckpoint) -> Bytes!String do
  encode_hint(CheckpointHint { tree_size: checkpoint.tree_size, tree_root: checkpoint.tree_root })
end

pub fn outgoing_gossip_hint(path :: String, key :: borrow StorageKey) -> Bytes!String do
  case own_checkpoint(path, key)? do
    None -> Ok(Bytes.empty())
    Some(checkpoint) -> hint_for(checkpoint)
  end
end

fn own_witnesses(path :: String, key :: borrow StorageKey) -> List<WitnessAttestation>!String do
  let label = "transparency-witnesses/v2"
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_witnesses(open_local(blob, key, local_context(label)?)?)
  end
end

pub fn pending_gossip(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes) -> Result<(Bytes, Bytes), String> do
  let state = load_gossip_state(path, key, peer)?
  if Bytes.length(state.pending_group) > 0 do
    Ok((Bytes.empty(), Bytes.empty()))
  else
    Ok((state.pending_device, state.pending_body))
  end
end

# The sender commits these writes together with its advanced ratchet and outbox.
pub fn clear_gossip_writes(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes) -> Result<(List<String>, List<Bytes>), String> do
  let state = load_gossip_state(path, key, peer)?
  queued_gossip_writes(path,
    key,
    peer,
    %{state |
      pending_body: Bytes.empty(),
      pending_device: Bytes.empty(),
      pending_group: Bytes.empty()
    })
end

fn deadline(now :: U64, interval :: String) -> U64!String do
  U64.add(now, U64.parse(interval)?)
end

fn check_consistency(path :: String,
  key :: borrow StorageKey,
  own :: TransparencyCheckpoint,
  hint :: CheckpointHint) -> Bool!String do
  if U64.compare(own.tree_size, hint.tree_size) == 0 do
    return Ok(Bytes.secure_equals(own.tree_root, hint.tree_root))
  end
  # Hint sizes are untrusted u64 values; network requests and proof depth stay
  # within the directory's u32 tree limit.
  let limit = U64.parse("4294967295")?
  if U64.compare(hint.tree_size, limit) > 0 || U64.compare(own.tree_size, limit) > 0 do
    return Ok(false)
  end
  let origin_label = "transparency-origin/v1"
  let origin_blob = case load_blob(path, origin_label) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(false)
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let origin = Bytes.to_utf8(open_local(origin_blob, key, local_context(origin_label)?)?)?
  let (old_size, old_root, new_size, new_root) = if U64.compare(own.tree_size,
    hint.tree_size) < 0 do
    (own.tree_size, own.tree_root, hint.tree_size, hint.tree_root)
  else
    (hint.tree_size, hint.tree_root, own.tree_size, own.tree_root)
  end
  let route = if own.version == 2 do
    "/v2/transparency/consistency"
  else
    "/v1/transparency/consistency"
  end
  let response = case (Http.build(:post, origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(encode_consistency_range(U64.to_int(old_size)?, U64.to_int(new_size)?)?)
    |> Http.timeout(3000)
    |> Http.max_response_bytes(1070)
    |> Http.max_redirects(0)
    |> Http.send()) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  if response.status != 200 do
    return Ok(false)
  end
  let proof = case decode_consistency_proof(response.body_bytes) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  if proof.version != own.version + 1
    || proof.old_tree_size != U64.to_int(old_size)?
    || proof.new_tree_size != U64.to_int(new_size)? do
    return Ok(false)
  end
  case verify_consistency(old_root, new_root, proof) do
    Err(_) -> Ok(false)
    Ok(value)
  end
end

fn observe_hint(path :: String,
  key :: borrow StorageKey,
  inner :: InnerEnvelope,
  own :: TransparencyCheckpoint,
  bytes :: Bytes,
  now :: U64,
  group :: Bytes) -> Result<(), String> do
  let hint = case decode_hint(bytes) do
    Err(_) -> return Ok(nil)
    Ok(value) -> value
  end
  let state = load_gossip_state(path, key, inner.sender_account_id)?
  if Bytes.secure_equals(bytes, hint_for(own)?) || Bytes.secure_equals(bytes, state.known_hint) do
    return Ok(nil)
  end
  # One direct conversation per account pair; using the account as the limiter
  # also covers legacy aliases and sibling devices without multiplying traffic.
  if U64.compare(now, state.next_check) < 0 || Bytes.length(state.pending_body) > 0 do
    return Ok(nil)
  end
  let checked = %{state | next_check: deadline(now, "3600000")?}
  # Persist the budget before the network attempt. A crash cannot reset it.
  save_gossip_state(path, key, inner.sender_account_id, checked)?
  if check_consistency(path, key, own, hint)? do
    return save_gossip_state(path, key, inner.sender_account_id, %{checked | known_hint: bytes})
  end
  if U64.compare(now, state.next_request) < 0 do
    return Ok(nil)
  end
  let id = random_bytes(16)?
  save_gossip_state(path,
    key,
    inner.sender_account_id,
    %{checked |
      next_request: deadline(now, "86400000")?,
      request_id: id,
      pending_device: inner.sender_device_id,
      pending_group: group,
      pending_body: encode_gossip(CheckpointRequest(id, hint))?
    })
end

fn matching_attestation(checkpoint :: TransparencyCheckpoint,
  signatures :: List<WitnessAttestation>,
  pin :: WitnessKey) -> Option<WitnessAttestation>!String do
  for value in signatures do
    if verify_witnesses(checkpoint, [value], [pin], 1)? do
      return Ok(Some(value))
    end
  end
  Ok(None)
end

fn paired_attestations(own :: TransparencyCheckpoint,
  other :: TransparencyCheckpoint,
  ours :: List<WitnessAttestation>,
  theirs :: List<WitnessAttestation>,
  pins :: List<WitnessKey>,
  index :: Int,
  output :: List<WitnessAttestation>) -> List<WitnessAttestation>!String do
  if index >= List.length(pins) || List.length(output) >= 32 do
    return Ok(output)
  end
  let pin = List.get(pins, index)
  let next = case matching_attestation(own, ours, pin)? do
    None -> output
    Some(first) -> case matching_attestation(other, theirs, pin)? do
      None -> output
      Some(second) -> output ++ [first, second]
    end
  end
  paired_attestations(own, other, ours, theirs, pins, index + 1, next)
end

fn signed_conflict(path :: String,
  key :: borrow StorageKey,
  own :: TransparencyCheckpoint,
  other :: TransparencyCheckpoint,
  theirs :: List<WitnessAttestation>) -> Result<(), String> do
  # The RFC transition deliberately restarts sequence and tree size. Its bridge
  # is checked by normal lookup, never treated as a fork by a 40-byte hint.
  if own.version != other.version do
    return Ok(nil)
  end
  let config = native_security_config()?
  let policy = witness_policy_for_log(config, own.version)?
  let log = SigningPublicKey { bytes: config.service_public_key }
  let proof = ForkProof {
    kind: 1,
    finder: mobile_zeroes(32)?,
    service_public_key: config.service_public_key,
    first: own,
    second: SignedCheckpoint(other),
    contradiction: None,
    attestations: paired_attestations(own,
      other,
      own_witnesses(path, key)?,
      theirs,
      policy.keys,
      0,
      List.new())?
  }
  case fork_same_size(proof, log, policy.keys) do
    Ok(_) -> return retain_fork(path, key, proof)
    Err(_) -> nil
  end
  let rollback = %{proof | kind: 3}
  case fork_rollback(rollback, log, policy.keys) do
    Ok(_) -> retain_fork(path, key, rollback)
    Err(_) -> Ok(nil)
  end
end

fn observe_control(path :: String,
  key :: borrow StorageKey,
  inner :: InnerEnvelope,
  own :: TransparencyCheckpoint,
  now :: U64,
  group :: Bytes) -> Result<(), String> do
  let control = case decode_gossip(inner.body) do
    Err(_) -> return Ok(nil)
    Ok(value) -> value
  end
  let state = load_gossip_state(path, key, inner.sender_account_id)?
  case control do
    CheckpointRequest(id, _) -> do
      if U64.compare(now, state.next_answer) < 0 || Bytes.length(state.pending_body) > 0 do
        return Ok(nil)
      end
      save_gossip_state(path,
        key,
        inner.sender_account_id,
        %{state |
          next_answer: deadline(now, "86400000")?,
          reply_id: id,
          pending_device: inner.sender_device_id,
          pending_group: group,
          pending_body: encode_gossip(CheckpointAnswer(id, own, own_witnesses(path, key)?, true))?
        })
    end
    CheckpointAnswer(id, other, attestations, request_peer) -> do
      let expected_request = Bytes.secure_equals(id, state.request_id)
      if !expected_request && !Bytes.secure_equals(id, state.reply_id) do
        return Ok(nil)
      end
      let config = native_security_config()?
      if !verify_checkpoint(other, SigningPublicKey { bytes: config.service_public_key })? do
        return Ok(nil)
      end
      signed_conflict(path, key, own, other, attestations)?
      let cleared = %{state |
        request_id: if expected_request do
          Bytes.empty()
        else
          state.request_id
        end,
        reply_id: if Bytes.secure_equals(id, state.reply_id) do
          Bytes.empty()
        else
          state.reply_id
        end
      }
      if expected_request && request_peer && Bytes.length(state.pending_body) == 0 do
        save_gossip_state(path,
          key,
          inner.sender_account_id,
          %{cleared |
            pending_device: inner.sender_device_id,
            pending_group: group,
            pending_body: encode_gossip(CheckpointAnswer(id,
              own,
              own_witnesses(path, key)?,
              false))?
          })
      else
        save_gossip_state(path, key, inner.sender_account_id, cleared)
      end
    end
  end
end

# Called only after envelope identity authentication and blocked-contact checks.
# These idempotent public-evidence writes can survive a failed message commit:
# the queue is consumed only with an established ratchet's durable send.
pub fn observe_gossip(path :: String,
  key :: borrow StorageKey,
  inner :: InnerEnvelope,
  now :: U64) -> Result<(), String> do
  observe_routed_gossip(path, key, inner, now, Bytes.empty())
end

pub fn gossip_peer_blocked(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes) -> Bool!String do
  case find_peer_session(path, key, peer, load_session_ids(path, key)?, 0) do
    Err(error) -> if error == "session_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok(session) -> Ok(session.record.blocked)
  end
end

# The group caller has verified the sender's roster identity and ciphertext.
pub fn observe_group_gossip(path :: String,
  key :: borrow StorageKey,
  inner :: InnerEnvelope,
  now :: U64) -> Result<(), String> do
  if gossip_peer_blocked(path, key, inner.sender_account_id)? do
    return Ok(nil)
  end
  observe_routed_gossip(path, key, inner, now, inner.conversation_id)
end

fn observe_routed_gossip(path :: String,
  key :: borrow StorageKey,
  inner :: InnerEnvelope,
  now :: U64,
  group :: Bytes) -> Result<(), String> do
  let own = case own_checkpoint(path, key)? do
    None -> return Ok(nil)
    Some(value) -> value
  end
  if inner.message_type == 5 do
    return observe_control(path, key, inner, own, now, group)
  end
  for extension in inner.extensions do
    if extension.id == 2 && !extension.mandatory do
      return observe_hint(path, key, inner, own, extension.value, now, group)
    end
  end
  Ok(nil)
end
