##! Canonical CFS1 versions1/2 and CFP1 public local metadata/pending bytes.
##! No secret serialization or epoch-output journal.
from Session.BraidResponder import BraidScope, braid_valid_scope
from Session.Spqr import SpqrSlot
from Session.SpqrStore import SpqrSaved, spqr_storage_context
from Binary.Reader import BinaryReader
from Mobile.Types import MobileReadBytes
from Mobile.Codec import (
  mobile_byte,
  mobile_write_u32,
  mobile_write_u64,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_reader,
  mobile_finish,
  take_fixed
)
from Storage.FanoutCommit import FanoutSnapshot

pub struct BraidSpqrMetadata do
  scope :: BraidScope
  direction :: Int
  phase :: Int
  kernel_tag :: Int
  epoch :: U64
  revision :: U64
  transition :: Bytes
  local_epoch :: U64
  knowledge :: U64
  cursors :: List<Int>
  partial_kind :: Int
  partial_indices :: List<Int>
  partial_words :: List<Bytes>
  header :: Bytes
  vector :: Bytes
  first :: Bytes
  second :: Bytes
  local_receipt :: Bytes
  peer_ack :: Bytes
  hashes :: List<Bytes>
  pending_identity :: Bytes
  slots :: List<SpqrSlot>
  skipped_index :: Bytes
  local_attempt :: Bytes
  inbound_result :: Bytes
end

pub struct BraidSpqrPending do
  transition :: Bytes
  envelope_id :: Bytes
  recipient :: Bytes
  envelope :: Bytes
end

pub fn braid_spqr_labels(scope :: BraidScope) -> List<String> do
  let p = "c1/braid-spqr/v1/#{Bytes.to_hex(scope.session_id)}/#{Bytes.to_hex(scope.configuration)}"
  [
    p <> "/metadata",
    p <> "/authenticator",
    p <> "/epoch-private",
    p <> "/continuation",
    p <> "/spqr-chains",
    p <> "/spqr-skipped",
    p <> "/pending-head",
    p <> "/pending-tail"
  ]
end

fn check(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("invalid_c1_spqr_state")
  end
end

fn zero(count :: Int) -> Bytes!String do
  case Bytes.repeat(0, count) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_state")
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 8192) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_state")
  end
end

fn short(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_state")
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  join([short(Bytes.length(value))?, value])
end

fn flag(value :: Bool) -> Bytes!String do
  mobile_byte(if value do
    1
  else
    0
  end)
end

fn scope_bytes(scope :: BraidScope) -> Bytes!String do
  join([
    mobile_byte(Bytes.length(scope.protocol_info))?,
    scope.protocol_info,
    scope.configuration,
    scope.account_id,
    scope.device_id,
    scope.peer_account_id,
    scope.peer_device_id,
    scope.session_id
  ])
end

fn same_scope(a :: BraidScope, b :: BraidScope) -> Bool do
  Bytes.secure_equals(scope_bytes(a)
      |> Result.unwrap_or(Bytes.empty()),
    scope_bytes(b)
      |> Result.unwrap_or(Bytes.empty()))
end

fn record(value :: Bytes, length :: Int) -> Result<(), String> do
  check(Bytes.length(value) == length)?
  let present = mobile_read_byte(Bytes.slice(value, 0, 1)?)?
  check(present == 1 || (present == 0 && Bytes.secure_equals(value, zero(length)?)))
end

## Reserved B0 profile; matching this public shape alone grants no entry authority.
pub fn braid_spqr_bootstrap_scope(scope :: BraidScope) -> Bool do
  Bytes.length(scope.protocol_info) == 82
    && Bytes.secure_equals(scope.protocol_info,
      join([
        Bytes.from_utf8("mesh-msg/braid/v1"),
        zero(1)
          |> Result.unwrap_or(Bytes.empty()),
        scope.configuration,
        scope.session_id
      ])
        |> Result.unwrap_or(Bytes.empty()))
end

fn validate_v2(value :: BraidSpqrMetadata) -> Result<(), String> do
  let z = U64.parse("0")?
  let one = U64.parse("1")?
  let second_kernel_tag = if value.phase == 8 do
    7
  else
    8
  end
  let second_ciphertext_length = if value.phase == 8 do
    0
  else
    160
  end
  check(braid_spqr_bootstrap_scope(value.scope)
    && braid_valid_scope(value.scope, value.epoch)
    && U64.compare(value.epoch, one) == 0
    && U64.compare(value.knowledge, z) == 0
    && U64.compare(value.revision, one) > 0
    && Bytes.length(value.transition) == 32
    && (value.direction == 0 || value.direction == 1)
    && List.length(value.cursors) == 4
    && List.length(value.hashes) == 7)?
  for n in value.cursors do
    check(n >= 0 && n <= 65536)?
  end
  for h in value.hashes do
    check(Bytes.length(h) == 32)?
  end
  check(List.length(value.partial_indices) == List.length(value.partial_words)
    && List.length(value.partial_indices) <= 17)?
  for i in 0..List.length(value.partial_indices) do
    let n = List.get(value.partial_indices, i)
    check(n >= 0 && n <= 65535 && Bytes.length(List.get(value.partial_words, i)) == 64)?
    if i > 0 do
      check(List.get(value.partial_indices, i - 1) < n)?
    end
  end
  check(Bytes.secure_equals(value.local_receipt, zero(73)?)
    && Bytes.length(value.pending_identity) == 80)?
  record(value.peer_ack, 105)?
  record(value.local_attempt, 105)?
  record(value.inbound_result, 82)?
  let pending = mobile_read_byte(Bytes.slice(value.local_attempt, 0, 1)?)? == 1
  let inbound = mobile_read_byte(Bytes.slice(value.inbound_result, 0, 1)?)? == 1
  if pending do
    let source = mobile_read_u64(Bytes.slice(value.local_attempt, 1, 8)?)?
    check(U64.compare(source, z) > 0
      && U64.compare(source, value.revision) < 0
      && U64.compare(U64.add(source, one)?, value.revision) <= 0)?
  else
    check(Bytes.secure_equals(value.pending_identity, zero(80)?))?
  end
  if inbound do
    let source = mobile_read_u64(Bytes.slice(value.inbound_result, 33, 8)?)?
    let kind = mobile_read_byte(Bytes.slice(value.inbound_result, 41, 1)?)?
    check(U64.compare(source, z) > 0
      && U64.compare(source, value.revision) < 0
      && kind >= 3
      && kind <= 7
      && U64.compare(mobile_read_u64(Bytes.slice(value.inbound_result, 74, 8)?)?, one) == 0)?
  end
  let ack = mobile_read_byte(Bytes.slice(value.peer_ack, 0, 1)?)? == 1
  if ack do
    check(U64.compare(mobile_read_u64(Bytes.slice(value.peer_ack, 1, 8)?)?, one) == 0
      && Bytes.secure_equals(Bytes.slice(value.peer_ack, 9, 32)?, Crypto.sha256(value.first)))?
  end
  if value.phase == 10 do
    check(value.direction == 1
      && value.kernel_tag == 0
      && U64.compare(value.local_epoch, z) == 0
      && List.length(value.slots) == 0
      && Bytes.length(value.skipped_index) == 0
      && value.partial_kind == 0
      && List.length(value.partial_indices) == 0
      && Bytes.length(value.header) == 0
      && Bytes.length(value.vector) == 0
      && Bytes.length(value.first) == 0
      && Bytes.length(value.second) == 0
      && !pending
      && !ack)?
  else
    spqr_storage_context(SpqrSaved {
        scope: value.scope,
        direction: value.direction,
        epoch: value.local_epoch,
        knowledge: value.knowledge,
        slots: value.slots,
        skipped_index: value.skipped_index,
        revision: value.revision,
        transition: value.transition,
        descriptor: zero(32)?,
        chains: Bytes.empty(),
        skipped: Bytes.empty()
      },
      24)?
    if value.phase == 0 do
      check(value.direction == 0
        && value.kernel_tag == 3
        && U64.compare(value.local_epoch, z) == 0
        && value.partial_kind == 0
        && List.length(value.partial_indices) == 0
        && Bytes.length(value.header) == 96
        && Bytes.length(value.vector) == 1152
        && Bytes.length(value.first) == 0
        && Bytes.length(value.second) == 0
        && pending
        && !ack
        && !inbound
        && List.get(value.cursors, 0) > 0)?
    else
      check(value.direction == 1 && List.get(value.cursors, 0) == 0)?
      if value.phase == 4 do
        check(value.kernel_tag == 0
          && U64.compare(value.local_epoch, z) == 0
          && value.partial_kind == 1
          && List.length(value.partial_indices) <= 1
          && Bytes.length(value.header) == 0
          && Bytes.length(value.vector) == 0
          && Bytes.length(value.first) == 0
          && Bytes.length(value.second) == 0
          && !pending
          && !ack)?
      else if value.phase == 5 do
        check(value.kernel_tag == 1
          && U64.compare(value.local_epoch, z) == 0
          && value.partial_kind == 0
          && List.length(value.partial_indices) == 0
          && Bytes.length(value.header) == 96
          && Bytes.length(value.vector) == 0
          && Bytes.length(value.first) == 0
          && Bytes.length(value.second) == 0
          && !pending
          && !ack)?
      else if value.phase >= 6 && value.phase <= 9 do
        check(U64.compare(value.local_epoch, one) == 0
          && Bytes.length(value.header) == 96
          && Bytes.length(value.first) == 960
          && pending
          && List.get(value.cursors, 2) > 0)?
        if value.phase == 6 || value.phase == 7 do
          check(value.kernel_tag == 6
            && value.partial_kind == 2
            && Bytes.length(value.vector) == 0
            && Bytes.length(value.second) == 0
            && ack == (value.phase == 7))?
        else
          check(value.partial_kind == 0
            && List.length(value.partial_indices) == 0
            && Bytes.length(value.vector) == 1152
            && value.kernel_tag == second_kernel_tag
            && Bytes.length(value.second) == second_ciphertext_length
            && ack == (value.phase == 9))?
        end
      else
        return Err("invalid_c1_spqr_state")
      end
    end
  end
  check(List.get(value.cursors, 1) == 0
    && (value.phase >= 6 && value.phase <= 9 || List.get(value.cursors, 2) == 0)
    && (value.phase == 9 || List.get(value.cursors, 3) == 0)
    && (value.phase == 0 || List.get(value.cursors, 0) == 0))?
  Ok(nil)
end

fn validate(value :: BraidSpqrMetadata) -> Result<(), String> do
  if Bytes.length(value.local_attempt) == 105 do
    validate_v2(value)
  else
    validate_v1(value)
  end
end

fn validate_v1(value :: BraidSpqrMetadata) -> Result<(), String> do
  let z = U64.parse("0")?
  check(braid_valid_scope(value.scope, value.epoch)
    && (value.direction == 0 || value.direction == 1)
    && U64.compare(value.revision, z) > 0
    && Bytes.length(value.transition) == 32
    && List.length(value.cursors) == 4
    && List.length(value.hashes) == 7)?
  for n in value.cursors do
    check(n >= 0 && n <= 65536)?
  end
  for h in value.hashes do
    check(Bytes.length(h) == 32)?
  end
  check(List.length(value.partial_indices) == List.length(value.partial_words)
    && List.length(value.partial_indices) <= 17)?
  for i in 0..List.length(value.partial_indices) do
    let n = List.get(value.partial_indices, i)
    check(n >= 0 && n <= 65535 && Bytes.length(List.get(value.partial_words, i)) == 64)?
    if i > 0 do
      check(List.get(value.partial_indices, i - 1) < n)?
    end
  end
  check(Bytes.length(value.header) <= 96
    && Bytes.length(value.vector) == 0
    && Bytes.length(value.first) <= 960
    && Bytes.length(value.second) == 0
    && Bytes.secure_equals(value.local_receipt, zero(73)?)
    && Bytes.secure_equals(value.peer_ack, zero(105)?)
    && Bytes.length(value.pending_identity) == 80)?
  record(value.local_attempt, 73)?
  record(value.inbound_result, 82)?
  if mobile_read_byte(Bytes.slice(value.inbound_result, 0, 1)?)? == 1 do
    check(U64.compare(mobile_read_u64(Bytes.slice(value.inbound_result, 33, 8)?)?, z) > 0
      && U64.compare(mobile_read_u64(Bytes.slice(value.inbound_result, 74, 8)?)?,
        value.epoch) == 0)?
    let kind = mobile_read_byte(Bytes.slice(value.inbound_result, 41, 1)?)?
    check(kind == 1 || kind == 2)?
  end
  check(U64.compare(value.knowledge, value.local_epoch) <= 0
    && U64.compare(U64.subtract(value.local_epoch, value.knowledge)?, U64.parse("1")?) <= 0)?
  if value.phase == 10 do
    check(value.kernel_tag == 0
      && List.length(value.slots) == 0
      && Bytes.length(value.skipped_index) == 0
      && value.partial_kind == 0
      && List.length(value.partial_indices) == 0
      && Bytes.length(value.header) == 0
      && Bytes.length(value.first) == 0)?
  else
    let saved = SpqrSaved {
      scope: value.scope,
      direction: value.direction,
      epoch: value.local_epoch,
      knowledge: value.knowledge,
      slots: value.slots,
      skipped_index: value.skipped_index,
      revision: value.revision,
      transition: value.transition,
      descriptor: zero(32)?,
      chains: Bytes.empty(),
      skipped: Bytes.empty()
    }
    spqr_storage_context(saved, 24)?
    if value.phase == 0 do
      check(value.kernel_tag == 2
        && value.direction == 0
        && value.partial_kind == 0
        && List.length(value.partial_indices) == 0
        && Bytes.length(value.header) == 0
        && Bytes.length(value.first) == 0
        && U64.compare(value.epoch, U64.parse("1")?) == 0
        && U64.compare(value.revision, U64.parse("1")?) == 0
        && U64.compare(value.local_epoch, z) == 0
        && U64.compare(value.knowledge, z) == 0
        && List.length(value.slots) == 1
        && U64.compare(List.head(value.slots).send_count, z) == 0
        && U64.compare(List.head(value.slots).receive_count, z) == 0
        && Bytes.length(value.skipped_index) == 0)?
    else if value.phase == 4 do
      check(value.kernel_tag == 0
        && value.partial_kind == 1
        && List.length(value.partial_indices) <= 1
        && Bytes.length(value.header) == 0
        && Bytes.length(value.first) == 0)?
    else if value.phase == 5 do
      check(value.kernel_tag == 1
        && value.partial_kind == 0
        && List.length(value.partial_indices) == 0
        && Bytes.length(value.header) == 96
        && Bytes.length(value.first) == 0)?
    else if value.phase == 6 do
      check(value.kernel_tag == 6
        && value.partial_kind == 0
        && List.length(value.partial_indices) == 0
        && Bytes.length(value.header) == 96
        && Bytes.length(value.first) == 960)?
    else
      return Err("invalid_c1_spqr_state")
    end
  end
  check(List.get(value.cursors, 0) == 0
    && List.get(value.cursors, 1) == 0
    && List.get(value.cursors, 3) == 0
    && List.get(value.cursors, 2) == (if value.phase == 6 do
        1
      else
        0
      end))?
  if value.phase == 0 do
    check(mobile_read_byte(Bytes.slice(value.local_attempt, 0, 1)?)? == 1
      && U64.compare(mobile_read_u64(Bytes.slice(value.local_attempt, 1, 8)?)?, z) == 0
      && Bytes.secure_equals(Bytes.slice(value.pending_identity, 48, 32)?, value.transition))?
  else if value.phase == 6 do
    check(mobile_read_byte(Bytes.slice(value.local_attempt, 0, 1)?)? == 1
      && U64.compare(mobile_read_u64(Bytes.slice(value.local_attempt, 1, 8)?)?,
        U64.subtract(value.revision, U64.parse("1")?)?) == 0
      && Bytes.secure_equals(Bytes.slice(value.pending_identity, 48, 32)?, value.transition))?
  else
    check(Bytes.secure_equals(value.pending_identity, zero(80)?)
      && Bytes.secure_equals(value.local_attempt, zero(73)?))?
  end
  Ok(nil)
end

pub fn braid_spqr_metadata_bytes(value :: BraidSpqrMetadata) -> Bytes!String do
  validate(value)?
  let pairs = for i in 0..List.length(value.partial_indices) do
    join([short(List.get(value.partial_indices, i))?, List.get(value.partial_words, i)])?
  end
  let slots = for s in value.slots do
    join([
      mobile_write_u64(s.epoch)?,
      flag(s.send_present)?,
      mobile_write_u64(s.send_count)?,
      flag(s.receive_present)?,
      mobile_write_u64(s.receive_count)?
    ])?
  end
  join([
    Bytes.from_utf8("CFS1"),
    mobile_byte(if Bytes.length(value.local_attempt) == 105 do
      2
    else
      1
    end)?,
    scope_bytes(value.scope)?,
    mobile_byte(value.direction)?,
    mobile_byte(value.phase)?,
    mobile_byte(value.kernel_tag)?,
    mobile_write_u64(value.epoch)?,
    mobile_write_u64(value.revision)?,
    value.transition,
    mobile_write_u64(value.local_epoch)?,
    mobile_write_u64(value.knowledge)?
  ]
    ++ (for n in value.cursors do
      mobile_write_u32(n)?
    end)
    ++ [mobile_byte(value.partial_kind)?, mobile_byte(List.length(value.partial_indices))?]
    ++ pairs
    ++ [
      vector(value.header)?,
      vector(value.vector)?,
      vector(value.first)?,
      vector(value.second)?,
      value.local_receipt,
      value.peer_ack
    ]
    ++ value.hashes
    ++ [value.pending_identity, mobile_byte(List.length(value.slots))?]
    ++ slots
    ++ [
      mobile_byte(Bytes.length(value.skipped_index) / 16)?,
      value.skipped_index,
      value.local_attempt,
      value.inbound_result
    ])
end

struct BraidSpqrReadInt do
  state :: BinaryReader
  value :: Int
end

struct BraidSpqrReadWide do
  state :: BinaryReader
  value :: U64
end

fn u8(state :: BinaryReader) -> BraidSpqrReadInt!String do
  let p = take_fixed(state, 1)?
  Ok(BraidSpqrReadInt { state: p.state, value: mobile_read_byte(p.value)? })
end

fn u16(state :: BinaryReader) -> BraidSpqrReadInt!String do
  let p = take_fixed(state, 2)?
  let n = case Bytes.read_u16_be(p.value, 0) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_state")
  end
  Ok(BraidSpqrReadInt { state: p.state, value: n })
end

fn u32(state :: BinaryReader) -> BraidSpqrReadInt!String do
  let p = take_fixed(state, 4)?
  Ok(BraidSpqrReadInt { state: p.state, value: mobile_read_u32(p.value)? })
end

fn u64(state :: BinaryReader) -> BraidSpqrReadWide!String do
  let p = take_fixed(state, 8)?
  Ok(BraidSpqrReadWide { state: p.state, value: mobile_read_u64(p.value)? })
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes!String do
  let length = u16(state)?
  check(length.value <= maximum)?
  take_fixed(length.state, length.value)
end

fn read_pairs(state :: BinaryReader,
  remaining :: Int,
  indices :: List<Int>,
  words :: List<Bytes>) -> (BinaryReader, List<Int>, List<Bytes>)!String do
  if remaining == 0 do
    return Ok((state, indices, words))
  end
  let n = u16(state)?
  let w = take_fixed(n.state, 64)?
  read_pairs(w.state, remaining - 1, List.append(indices, n.value), List.append(words, w.value))
end

fn read_slots(state :: BinaryReader,
  remaining :: Int,
  slots :: List<SpqrSlot>) -> (BinaryReader, List<SpqrSlot>)!String do
  if remaining == 0 do
    return Ok((state, slots))
  end
  let e = u64(state)?
  let sp = u8(e.state)?
  let sc = u64(sp.state)?
  let rp = u8(sc.state)?
  let rc = u64(rp.state)?
  check(sp.value <= 1 && rp.value <= 1)?
  read_slots(rc.state,
    remaining - 1,
    List.append(slots,
      SpqrSlot {
        epoch: e.value,
        send_present: sp.value == 1,
        send_count: sc.value,
        receive_present: rp.value == 1,
        receive_count: rc.value
      }))
end

pub fn decode_braid_spqr_metadata(bytes :: Bytes,
  scope :: BraidScope) -> BraidSpqrMetadata!String do
  let magic = take_fixed(mobile_reader(bytes, 8192, "invalid_c1_spqr_state")?, 4)?
  check(Bytes.secure_equals(magic.value, Bytes.from_utf8("CFS1")))?
  let version = u8(magic.state)?
  check(version.value == 1 || version.value == 2)?
  let length = u8(version.state)?
  check(length.value > 0 && length.value <= 128)?
  let info = take_fixed(length.state, length.value)?
  let config = take_fixed(info.state, 32)?
  let account = take_fixed(config.state, 32)?
  let device = take_fixed(account.state, 16)?
  let peer_account = take_fixed(device.state, 32)?
  let peer_device = take_fixed(peer_account.state, 16)?
  let session = take_fixed(peer_device.state, 32)?
  let actual = BraidScope {
    protocol_info: info.value,
    configuration: config.value,
    account_id: account.value,
    device_id: device.value,
    peer_account_id: peer_account.value,
    peer_device_id: peer_device.value,
    session_id: session.value
  }
  check(same_scope(actual, scope))?
  let direction = u8(session.state)?
  let phase = u8(direction.state)?
  let tag = u8(phase.state)?
  let epoch = u64(tag.state)?
  let revision = u64(epoch.state)?
  let transition = take_fixed(revision.state, 32)?
  let local = u64(transition.state)?
  let knowledge = u64(local.state)?
  let c0 = u32(knowledge.state)?
  let c1 = u32(c0.state)?
  let c2 = u32(c1.state)?
  let c3 = u32(c2.state)?
  let kind = u8(c3.state)?
  let count = u8(kind.state)?
  check(count.value <= 17)?
  let (after_pairs, indices, words) = read_pairs(count.state, count.value, [], [])?
  let header = take_vector(after_pairs, 96)?
  let public_vector = take_vector(header.state, 1152)?
  let first = take_vector(public_vector.state, 960)?
  let second = take_vector(first.state, 160)?
  let receipt = take_fixed(second.state, 73)?
  let ack = take_fixed(receipt.state, 105)?
  let hashes = take_fixed(ack.state, 224)?
  let pending = take_fixed(hashes.state, 80)?
  let slot_count = u8(pending.state)?
  check(slot_count.value <= 3)?
  let (after_slots, slots) = read_slots(slot_count.state, slot_count.value, [])?
  let skip_count = u8(after_slots)?
  check(skip_count.value <= 64)?
  let index = take_fixed(skip_count.state, skip_count.value * 16)?
  let attempt = take_fixed(index.state,
    if version.value == 1 do
      73
    else
      105
    end)?
  let inbound = take_fixed(attempt.state, 82)?
  mobile_finish(inbound.state, "invalid_c1_spqr_state")?
  let value = BraidSpqrMetadata {
    scope: actual,
    direction: direction.value,
    phase: phase.value,
    kernel_tag: tag.value,
    epoch: epoch.value,
    revision: revision.value,
    transition: transition.value,
    local_epoch: local.value,
    knowledge: knowledge.value,
    cursors: [c0.value, c1.value, c2.value, c3.value],
    partial_kind: kind.value,
    partial_indices: indices,
    partial_words: words,
    header: header.value,
    vector: public_vector.value,
    first: first.value,
    second: second.value,
    local_receipt: receipt.value,
    peer_ack: ack.value,
    hashes: for i in 0..7 do
      Bytes.slice(hashes.value, i * 32, 32)?
    end,
    pending_identity: pending.value,
    slots: slots,
    skipped_index: index.value,
    local_attempt: attempt.value,
    inbound_result: inbound.value
  }
  check(Bytes.secure_equals(braid_spqr_metadata_bytes(value)?, bytes))?
  Ok(value)
end

pub fn braid_spqr_descriptor(value :: BraidSpqrMetadata) -> Bytes!String do
  Ok(Crypto.sha256(braid_spqr_metadata_bytes(%{value |
    hashes: for i in 0..7 do
      zero(32)?
    end
  })?))
end

struct BraidSpqrBasisRow do
  label :: String
  ciphertext :: Bytes
end

fn row_order(a :: BraidSpqrBasisRow, b :: BraidSpqrBasisRow) -> Int do
  if a.label < b.label do
    -1
  else if a.label == b.label do
    0
  else
    1
  end
end

fn source_digest(before :: FanoutSnapshot) -> Bytes!String do
  check(List.length(before.bases) > 0 && List.length(before.bases) <= 8)?
  let profile = List.head(before.bases).profile
  let rows = List.flatten(for basis in before.bases do
    check(Bytes.secure_equals(basis.profile, profile)
      && List.length(basis.labels) == List.length(basis.records))?
    for i in 0..List.length(basis.labels) do
      BraidSpqrBasisRow { label: List.get(basis.labels, i), ciphertext: List.get(basis.records, i) }
    end
  end)
  check(List.length(rows) <= 256)?
  let sorted = List.sort(rows, row_order)
  let encoded = for i in 0..List.length(sorted) do
    let row = List.get(sorted, i)
    let label = Bytes.from_utf8(row.label)
    check(Bytes.length(label) > 0 && Bytes.length(label) <= 256 && row.label != "profile/v1")?
    if i > 0 do
      check(row.label != List.get(sorted, i - 1).label)?
    end
    join([
      short(Bytes.length(label))?,
      label,
      mobile_write_u32(Bytes.length(row.ciphertext))?,
      Crypto.sha256(row.ciphertext)
    ])?
  end
  # A bounded source set can exceed the metadata parser cap; hash a bounded 80KiB public preimage.
  let preimage = case Bytes.concat_many([
      Bytes.from_utf8("morse/c1/braid-spqr/basis/v1"),
      mobile_byte(0)?,
      mobile_write_u32(Bytes.length(profile))?,
      Crypto.sha256(profile),
      short(List.length(sorted))?
    ]
      ++ encoded,
    81920) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_state")
  end
  Ok(Crypto.sha256(preimage))
end

# Operation4 commits only explicit acceptance's empty v2 Bob successor. This
# public commitment primitive does not grant policy or bootstrap authority.
fn acceptance_candidate(value :: BraidSpqrMetadata) -> Result<(), String> do
  let z = U64.parse("0")?
  check(Bytes.length(value.local_attempt) == 105
    && U64.compare(value.revision, U64.parse("2")?) == 0
    && value.direction == 1
    && value.phase == 4
    && value.kernel_tag == 0
    && U64.compare(value.epoch, U64.parse("1")?) == 0
    && U64.compare(value.local_epoch, z) == 0
    && U64.compare(value.knowledge, z) == 0
    && List.length(value.cursors) == 4
    && List.all(value.cursors, fn(n) -> n == 0 end)
    && value.partial_kind == 1
    && List.length(value.partial_indices) == 0
    && List.length(value.partial_words) == 0
    && Bytes.length(value.header) == 0
    && Bytes.length(value.vector) == 0
    && Bytes.length(value.first) == 0
    && Bytes.length(value.second) == 0
    && Bytes.secure_equals(value.local_receipt, zero(73)?)
    && Bytes.secure_equals(value.peer_ack, zero(105)?)
    && Bytes.secure_equals(value.local_attempt, zero(105)?)
    && Bytes.secure_equals(value.pending_identity, zero(80)?)
    && Bytes.secure_equals(value.inbound_result, zero(82)?)
    && List.length(value.slots) == 1
    && Bytes.length(value.skipped_index) == 0)?
  let slot = List.head(value.slots)
  check(U64.compare(slot.epoch, z) == 0
    && slot.send_present
    && slot.receive_present
    && U64.compare(slot.send_count, z) == 0
    && U64.compare(slot.receive_count, z) == 0)
end

pub fn braid_spqr_transition(value :: BraidSpqrMetadata,
  before :: FanoutSnapshot,
  operation :: Int,
  input_commitment :: Bytes) -> Bytes!String do
  check(operation >= 1 && operation <= 4 && Bytes.length(input_commitment) == 32)?
  if operation == 4 do
    acceptance_candidate(value)?
  end
  let candidate = %{value |
    transition: zero(32)?,
    hashes: for i in 0..7 do
      zero(32)?
    end,
    local_receipt: join([Bytes.slice(value.local_receipt, 0, 41)?, zero(32)?])?,
    pending_identity: if Bytes.length(value.local_attempt) == 105 && operation != 2 do
      value.pending_identity
    else
      join([Bytes.slice(value.pending_identity, 0, 48)?, zero(32)?])?
    end,
    inbound_result: join([
      Bytes.slice(value.inbound_result, 0, 42)?,
      zero(32)?,
      Bytes.slice(value.inbound_result, 74, 8)?
    ])?
  }
  Ok(Crypto.sha256(join([
    Bytes.from_utf8("morse/c1/braid-spqr/transition/v1"),
    mobile_byte(0)?,
    scope_bytes(value.scope)?,
    mobile_write_u64(value.revision)?,
    source_digest(before)?,
    mobile_byte(operation)?,
    input_commitment,
    Crypto.sha256(braid_spqr_metadata_bytes(candidate)?)
  ])?))
end

pub fn split_braid_spqr_pending(value :: BraidSpqrPending) -> (Bytes, Bytes)!String do
  let n = Bytes.length(value.envelope)
  check(Bytes.length(value.transition) == 32
    && Bytes.length(value.envelope_id) == 16
    && Bytes.length(value.recipient) == 32
    && n > 0
    && n <= 65606)?
  let count = if n > 65447 do
    65447
  else
    n
  end
  let head = case Bytes.concat_many([
      Bytes.from_utf8("CFP1"),
      mobile_byte(1)?,
      value.transition,
      value.envelope_id,
      value.recipient,
      mobile_write_u32(n)?,
      Bytes.slice(value.envelope, 0, count)?
    ],
    65536) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_pending")
  end
  Ok((head, Bytes.slice(value.envelope, count, n - count)?))
end

pub fn join_braid_spqr_pending(head :: Bytes, tail :: Bytes) -> BraidSpqrPending!String do
  check(Bytes.length(head) >= 90
    && Bytes.length(head) <= 65536
    && Bytes.length(tail) <= 159
    && Bytes.secure_equals(Bytes.slice(head, 0, 4)?, Bytes.from_utf8("CFP1"))
    && mobile_read_byte(Bytes.slice(head, 4, 1)?)? == 1)?
  let n = mobile_read_u32(Bytes.slice(head, 85, 4)?)?
  let count = if n > 65447 do
    65447
  else
    n
  end
  check(n > 0 && n <= 65606 && Bytes.length(head) == 89 + count && Bytes.length(tail) == n - count)?
  let envelope = case Bytes.concat_many([Bytes.slice(head, 89, count)?, tail], 65606) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_pending")
  end
  Ok(BraidSpqrPending {
    transition: Bytes.slice(head, 5, 32)?,
    envelope_id: Bytes.slice(head, 37, 16)?,
    recipient: Bytes.slice(head, 53, 32)?,
    envelope: envelope
  })
end
