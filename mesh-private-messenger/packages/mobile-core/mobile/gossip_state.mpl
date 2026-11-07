from Binary.Reader import reader, finish
from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  mobile_join,
  mobile_vector,
  mobile_write_u64,
  mobile_read_u64,
  take_vector,
  take_optional_vector
)
from Mobile.Types import MobileReadBytes
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import store_updated_blobs

pub struct GossipState do
  next_check :: U64
  next_request :: U64
  next_answer :: U64
  request_id :: Bytes
  reply_id :: Bytes
  known_hint :: Bytes
  pending_device :: Bytes
  pending_body :: Bytes
  pending_group :: Bytes
end

fn label(peer :: Bytes) -> String!String do
  if Bytes.length(peer) != 32 do
    Err("invalid_gossip_peer")
  else
    Ok("checkpoint-gossip/v1/#{Bytes.to_hex(peer)}")
  end
end

pub fn load_gossip_state(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes) -> GossipState!String do
  let name = label(peer)?
  let blob = case load_blob(path, name) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(GossipState {
        next_check: U64.parse("0")?,
        next_request: U64.parse("0")?,
        next_answer: U64.parse("0")?,
        request_id: Bytes.empty(),
        reply_id: Bytes.empty(),
        known_hint: Bytes.empty(),
        pending_device: Bytes.empty(),
        pending_body: Bytes.empty(),
        pending_group: Bytes.empty()
      })
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  decode_gossip_state(open_local(blob, key, local_context(name)?)?)
end

pub fn decode_gossip_state(input :: Bytes) -> GossipState!String do
  let state = mobile_reader(input, 3200, "invalid_gossip_state")?
  let check = take_vector(state, 8)?
  let request = take_vector(check.state, 8)?
  let answer = take_vector(request.state, 8)?
  let id = take_vector(answer.state, 16)?
  let reply = take_vector(id.state, 16)?
  let hint = take_vector(reply.state, 40)?
  let device = take_vector(hint.state, 16)?
  let body = take_vector(device.state, 2987)?
  let group = take_optional_vector(body.state, 32, "invalid_gossip_state")?
  mobile_finish(group.state, "invalid_gossip_state")?
  if (Bytes.length(id.value) != 0 && Bytes.length(id.value) != 16)
    || (Bytes.length(reply.value) != 0 && Bytes.length(reply.value) != 16)
    || (Bytes.length(hint.value) != 0 && Bytes.length(hint.value) != 40)
    || (Bytes.length(body.value) > 0 && Bytes.length(device.value) != 16)
    || (Bytes.length(group.value) != 0 && Bytes.length(group.value) != 32) do
    return Err("invalid_gossip_state")
  end
  Ok(GossipState {
    next_check: mobile_read_u64(check.value)?,
    next_request: mobile_read_u64(request.value)?,
    next_answer: mobile_read_u64(answer.value)?,
    request_id: id.value,
    reply_id: reply.value,
    known_hint: hint.value,
    pending_device: device.value,
    pending_body: body.value,
    pending_group: group.value
  })
end

pub fn gossip_state_writes(key :: borrow StorageKey,
  peer :: Bytes,
  state :: GossipState) -> Result<(List<String>, List<Bytes>), String> do
  let name = label(peer)?
  let bytes = mobile_join(for value in [
      mobile_write_u64(state.next_check)?,
      mobile_write_u64(state.next_request)?,
      mobile_write_u64(state.next_answer)?,
      state.request_id,
      state.reply_id,
      state.known_hint,
      state.pending_device,
      state.pending_body,
      state.pending_group
    ] do
      mobile_vector(value)?
    end,
    0,
    Bytes.empty())?
  Ok(([name], [seal_local(bytes, key, local_context(name)?)?]))
end

pub fn save_gossip_state(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes,
  state :: GossipState) -> Result<(), String> do
  let (labels, blobs) = queued_gossip_writes(path, key, peer, state)?
  store_updated_blobs(path, labels, blobs)
end

# Only queued group controls need an index: they may have no direct session.
# Entries and the peer record are sealed and committed together.
pub fn queued_group_peers(path :: String, key :: borrow StorageKey) -> List<Bytes>!String do
  let name = "checkpoint-gossip/group-pending/v1"
  let blob = case load_blob(path, name) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok([])
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let bytes = open_local(blob, key, local_context(name)?)?
  if Bytes.length(bytes) > 8192 || Bytes.length(bytes) % 32 != 0 do
    return Err("invalid_gossip_queue")
  end
  let peers = for index in 0..(Bytes.length(bytes) / 32) do
    Bytes.slice(bytes, index * 32, 32)?
  end
  for index in 0..List.length(peers) do
    let peer = List.get(peers, index)
    if List.any(List.take(peers, index), fn(value) do Bytes.secure_equals(value, peer) end) do
      return Err("invalid_gossip_queue")
    end
  end
  Ok(peers)
end

pub fn queued_gossip_writes(path :: String,
  key :: borrow StorageKey,
  peer :: Bytes,
  state :: GossipState) -> Result<(List<String>, List<Bytes>), String> do
  let previous = queued_group_peers(path, key)?
  let remaining = List.filter(previous, fn(value) do !Bytes.secure_equals(value, peer) end)
  let wants_group = Bytes.length(state.pending_group) == 32 && Bytes.length(state.pending_body) > 0
  let admitted = !wants_group || List.length(remaining) < 256
  let effective = if admitted do
    state
  else
    %{state |
      pending_group: Bytes.empty(),
      pending_device: Bytes.empty(),
      pending_body: Bytes.empty()
    }
  end
  let next = if wants_group && admitted do
    List.append(remaining, peer)
  else
    remaining
  end
  let (labels, blobs) = gossip_state_writes(key, peer, effective)?
  if List.length(previous) == 0 && List.length(next) == 0 do
    return Ok((labels, blobs))
  end
  let name = "checkpoint-gossip/group-pending/v1"
  let bytes = mobile_join(next, 0, Bytes.empty())?
  Ok((List.append(labels, name), List.append(blobs, seal_local(bytes, key, local_context(name)?)?)))
end
