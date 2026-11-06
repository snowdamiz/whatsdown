from Transparency.RpcTransport import RpcEndpoint, RpcTransport, rpc_urls, rpc_transport
from Transparency.AnchorRpc import (
  AnchorAgreement,
  read_anchor_quorum,
  read_anchor_time_quorum,
  validate_anchor_sources
)
from Solana.Read import Pubkey, pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.Config import SecurityConfig, valid_witness_id
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorWitnessSet import AnchorWitnessSet, decode_anchor_witness_set
from Transparency.AnchorRing import (
  AnchorHeader,
  AnchorEntry,
  decode_anchor_header,
  decode_anchor_entry,
  anchor_entry_offset,
  anchor_entry_in_header
)

# Supplied by native release configuration, never a directory response.
# The log ID is SHA-256 of the UTF-8 registry log name, e.g. "morse-main".
pub struct AnchorPins do
  ring :: Pubkey
  program :: Pubkey
  log_name :: String
  log_id :: Bytes
  rpc :: RpcTransport
end

pub struct AnchorAddresses do
  log :: Pubkey
  ring :: Pubkey
  log_id :: Bytes
end

pub fn configured_anchor_pins(config :: SecurityConfig, rpc :: RpcTransport) -> Option<AnchorPins>!String do
  if rpc_urls(rpc) != config.rpc_urls do
    return Err("rpc_tls_config_invalid")
  end
  rpc_transport(rpc.sources, rpc.require_current)?
  if config.version >= 1 && config.version <= 3 do
    return Ok(None)
  end
  if config.version != 4 && config.version != 5 do
    return Err("invalid_anchor_pins")
  end
  if config.anchor_address == "-" do
    return Ok(None)
  end
  let program = pubkey(config.anchor_program)?
  let addresses = anchor_addresses(program, config.anchor_log_name)?
  let pins = AnchorPins {
    program: program,
    ring: pubkey(config.anchor_address)?,
    log_name: config.anchor_log_name,
    log_id: addresses.log_id,
    rpc: rpc
  }
  validate_pins(pins)?
  validate_anchor_sources(rpc_urls(pins.rpc))?
  Ok(Some(pins))
end

pub fn anchor_addresses(program :: Pubkey, name :: String) -> AnchorAddresses!String do
  let bytes = Bytes.from_utf8(name)
  if !valid_witness_id(name) || Bytes.length(bytes) > 32 do
    return Err("invalid_anchor_pins")
  end
  let log = find_program_address(program, [Bytes.from_utf8("log"), bytes])?
  let ring = find_program_address(program, [Bytes.from_utf8("ring"), bytes])?
  Ok(AnchorAddresses { log: log.address, ring: ring.address, log_id: Crypto.sha256(bytes) })
end

fn validate_pins(pins :: AnchorPins) -> AnchorAddresses!String do
  let derived = anchor_addresses(pins.program, pins.log_name)?
  if !Bytes.secure_equals(derived.ring.bytes, pins.ring.bytes)
    || !Bytes.secure_equals(derived.log_id, pins.log_id) do
    Err("invalid_anchor_pins")
  else
    Ok(derived)
  end
end

pub struct AnchorSnapshot do
  header :: AnchorHeader
  bytes :: Bytes
  context_slot :: U64
end

pub struct AnchorFreshness do
  block_time_seconds :: Int
  age_seconds :: Int
  stale :: Bool
end

pub struct AnchorRecord do
  entry :: AnchorEntry
  bytes :: Bytes
end

pub struct AnchorWitnessRecord do
  set :: AnchorWitnessSet
  bytes :: Bytes
end

# Call after read_anchor_header, using the same sampled providers. A stale,
# unavailable or conflicting clock is only a notice, never fork evidence or
# grounds to block messaging. Checkpoint timestamps are service-controlled and
# do not participate in this verdict.
pub fn read_anchor_freshness(pins :: AnchorPins,
  snapshot :: AnchorSnapshot,
  now_seconds :: Int) -> AnchorFreshness!String do
  validate_pins(pins)?
  if !Bytes.secure_equals(snapshot.header.log_id, pins.log_id)
    || U64.compare(snapshot.header.last_slot, snapshot.context_slot) > 0 do
    return Err("invalid_anchor_header")
  end
  if now_seconds < 0 do
    return Err("invalid_anchor_clock")
  end
  if snapshot.header.count == 0 do
    return Err("anchor_empty")
  end
  let time = read_anchor_time_quorum(pins.rpc, snapshot.header.last_slot)?
  if time > now_seconds do
    return Err("anchor_clock_skew")
  end
  let age = now_seconds - time
  Ok(AnchorFreshness { block_time_seconds: time, age_seconds: age, stale: age > 7200 })
end

# Program, log name, service key and log version come from the same native release as
# the ring pins. Account state carries the slash flag; no directory may supply
# or override these trust inputs.
pub fn read_anchor_log(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  minimum_slot :: U64) -> AnchorLog!String do
  let (log, _) = read_anchor_log_context(pins, service_key, version, minimum_slot)?
  Ok(log)
end

pub fn read_anchor_log_context(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  minimum_slot :: U64) -> (AnchorLog, U64)!String do
  if Bytes.length(service_key) != 32
    || Bytes.length(pins.log_id) != 32
    || (version != 1 && version != 2) do
    return Err("invalid_anchor_pins")
  end
  let addresses = validate_pins(pins)?
  let result = read_anchor_quorum(pins.rpc,
    addresses.log,
    pins.program,
    0,
    352,
    minimum_slot)?
  let log = decode_anchor_log(result.data)?
  if log.version != version
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes) do
    Err("anchor_log_mismatch")
  else
    Ok((log, result.context_slot))
  end
end

# The expected generation comes from an authenticated ring entry (not the
# current Log pointer); its canonical PDA is derived locally in Mesh.
# This record attributes signatures; native release pins still decide trust.
pub fn read_anchor_witness_set(pins :: AnchorPins,
  generation :: Int,
  minimum_slot :: U64) -> AnchorWitnessSet!String do
  Ok(read_anchor_witness_record(pins, generation, minimum_slot)?.set)
end

pub fn read_anchor_witness_record(pins :: AnchorPins,
  generation :: Int,
  minimum_slot :: U64) -> AnchorWitnessRecord!String do
  if Bytes.length(pins.log_id) != 32 || generation <= 0 || generation > 65535 do
    return Err("invalid_anchor_pins")
  end
  validate_pins(pins)?
  let encoded_generation = case Bytes.from_list([generation % 256, generation / 256]) do
    Err(_) -> return Err("invalid_anchor_pins")
    Ok(value) -> value
  end
  let address = find_program_address(pins.program,
    [Bytes.from_utf8("witness-set"), pins.log_id, encoded_generation])?.address
  let result = read_anchor_quorum(pins.rpc, address, pins.program, 0, 2752, minimum_slot)?
  let set = decode_anchor_witness_set(result.data)?
  if set.generation != generation || !Bytes.secure_equals(set.log_id, pins.log_id) do
    Err("anchor_witness_set_mismatch")
  else
    Ok(AnchorWitnessRecord { set: set, bytes: result.data })
  end
end

# A fresh, unbiased ordered sample without replacement. Preserve this sample
# across the header and entry reads of one check.
pub fn sample_anchor_sources(pins :: AnchorPins) -> AnchorPins!String do
  validate_pins(pins)?
  validate_anchor_sources(rpc_urls(pins.rpc))?
  Ok(%{pins | rpc: rpc_transport(sample(pins.rpc.sources, List.new())?, pins.rpc.require_current)?})
end

fn sample(remaining :: List<RpcEndpoint>, selected :: List<RpcEndpoint>) -> List<RpcEndpoint>!String do
  if List.length(selected) == 3 do
    return Ok(selected)
  end
  let count = List.length(remaining)
  let random = case Crypto.random_bytes(1) do
    Err(_) -> return Err("random_generation_failed")
    Ok(value) -> value
  end
  let byte = Bytes.get(random, 0)?
  if byte >= 256 - (256 % count) do
    return sample(remaining, selected)
  end
  let index = byte % count
  sample(List.take(remaining, index) ++ List.drop(remaining, index + 1),
    List.append(selected, List.get(remaining, index)))
end

pub fn read_anchor_header(pins :: AnchorPins, minimum_slot :: U64) -> AnchorSnapshot!String do
  validate_pins(pins)?
  if Bytes.length(pins.log_id) != 32 do
    return Err("invalid_anchor_pins")
  end
  let result = read_anchor_quorum(pins.rpc, pins.ring, pins.program, 0, 64, minimum_slot)?
  let header = decode_anchor_header(result.data)?
  if !Bytes.secure_equals(header.log_id, pins.log_id)
    || U64.compare(header.last_slot, result.context_slot) > 0 do
    return Err("invalid_anchor_header")
  end
  Ok(AnchorSnapshot { header: header, bytes: result.data, context_slot: result.context_slot })
end

pub fn read_anchor_entry(pins :: AnchorPins,
  snapshot :: AnchorSnapshot,
  distance :: Int) -> AnchorEntry!String do
  Ok(read_anchor_record(pins, snapshot, distance)?.entry)
end

pub fn read_anchor_record(pins :: AnchorPins,
  snapshot :: AnchorSnapshot,
  distance :: Int) -> AnchorRecord!String do
  validate_pins(pins)?
  if !Bytes.secure_equals(snapshot.header.log_id, pins.log_id) do
    return Err("invalid_anchor_pins")
  end
  let offset = anchor_entry_offset(snapshot.header, distance)?
  let result = read_anchor_quorum(pins.rpc,
    pins.ring,
    pins.program,
    offset,
    104,
    snapshot.context_slot)?
  let entry = decode_anchor_entry(result.data)?
  if !anchor_entry_in_header(snapshot.header, entry, distance) do
    return Err("anchor_snapshot_changed")
  end
  # A ring position can be overwritten between RPC calls. Only publish the
  # entry if a second quorum still observes this header at or after the entry
  # read. Cosignatures may change without changing the header.
  let current = read_anchor_header(pins, result.context_slot)?
  if !Bytes.secure_equals(current.bytes, snapshot.bytes) do
    Err("anchor_snapshot_changed")
  else
    Ok(AnchorRecord { entry: entry, bytes: result.data })
  end
end

# Monitor catch-up reads at most 32 consecutive postings per batch. A wrapped
# range uses two bounded slices; a final header check prevents combining two
# versions of a ring. Results are oldest to newest, never sorted by sequence.
pub fn read_anchor_batch(pins :: AnchorPins,
  snapshot :: AnchorSnapshot,
  first_distance :: Int,
  count :: Int) -> List<AnchorRecord>!String do
  validate_pins(pins)?
  if count < 1
    || count > 32
    || first_distance < count - 1
    || !Bytes.secure_equals(snapshot.header.log_id, pins.log_id) do
    return Err("invalid_anchor_batch")
  end
  let offset = anchor_entry_offset(snapshot.header, first_distance)?
  let index = (offset - 64) / 104
  let first_count = if index + count > 4096 do
    4096 - index
  else
    count
  end
  let first = read_anchor_quorum(pins.rpc,
    pins.ring,
    pins.program,
    offset,
    first_count * 104,
    snapshot.context_slot)?
  let combined = if first_count < count do
    let rest = read_anchor_quorum(pins.rpc,
      pins.ring,
      pins.program,
      64,
      (count - first_count) * 104,
      first.context_slot)?
    AnchorAgreement { data: Bytes.concat(first.data, rest.data)?, context_slot: rest.context_slot }
  else
    first
  end
  let records = for position in 0..count do
    let bytes = Bytes.slice(combined.data, position * 104, 104)?
    let entry = decode_anchor_entry(bytes)?
    if !anchor_entry_in_header(snapshot.header, entry, first_distance - position) do
      return Err("anchor_snapshot_changed")
    end
    AnchorRecord { entry: entry, bytes: bytes }
  end
  let current = read_anchor_header(pins, combined.context_slot)?
  if !Bytes.secure_equals(current.bytes, snapshot.bytes) do
    Err("anchor_snapshot_changed")
  else
    Ok(records)
  end
end
