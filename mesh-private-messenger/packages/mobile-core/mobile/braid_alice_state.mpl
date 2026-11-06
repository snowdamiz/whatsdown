##! Bounded local Alice header journal. No production wire or output schema.
from Session.BraidResponder import BraidScope
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  bilateral_saved_metadata,
  bilateral_saved_shape
)
from Binary.Reader import BinaryReader, reader, read_vector, finish
from Mobile.Codec import (
  mobile_join,
  mobile_vector,
  mobile_byte,
  mobile_read_byte,
  mobile_write_u64,
  mobile_read_u64
)
from Storage.FanoutCommit import FanoutSnapshot

pub struct AliceHeaderMetadata do
  saved :: BraidBilateralSaved
  secrets_hash :: Bytes
  epoch_key_hash :: Bytes
  pending_hash :: Bytes
  pending_id :: Bytes
  envelope_hash :: Bytes
end

pub fn alice_header_labels(scope :: BraidScope) -> List<String> do
  let p = "c1/braid-alice-header/v1/#{Bytes.to_hex(scope.session_id)}/#{Bytes.to_hex(scope.configuration)}"
  [p <> "/metadata", p <> "/secrets", p <> "/epoch-key", p <> "/pending"]
end

pub fn alice_captured(before :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in before.bases do
    for i in 0..List.length(basis.labels) do
      if List.get(basis.labels, i) == label do
        return Ok(List.get(basis.records, i))
      end
    end
  end
  Err("invalid_c1_alice_source_set")
end

pub fn alice_same_scope(a :: BraidScope, b :: BraidScope) -> Bool do
  Bytes.secure_equals(a.configuration, b.configuration)
    && Bytes.secure_equals(a.protocol_info, b.protocol_info)
    && Bytes.secure_equals(a.account_id, b.account_id)
    && Bytes.secure_equals(a.device_id, b.device_id)
    && Bytes.secure_equals(a.peer_account_id, b.peer_account_id)
    && Bytes.secure_equals(a.peer_device_id, b.peer_device_id)
    && Bytes.secure_equals(a.session_id, b.session_id)
end

pub fn alice_check(value :: Bool, reason :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(reason)
  end
end

fn read_fields(state :: BinaryReader,
  remaining :: Int,
  fields :: List<Bytes>) -> List<Bytes>!String do
  if remaining == 0 do
    case finish(state) do
      Ok(_) -> Ok(fields)
      Err(_) -> Err("invalid_c1_alice_journal")
    end
  else
    let (next, value) = case read_vector(state, 1152) do
      Ok(v) -> v
      Err(_) -> return Err("invalid_c1_alice_journal")
    end
    read_fields(next, remaining - 1, List.append(fields, value))
  end
end

pub fn alice_metadata_bytes(value :: AliceHeaderMetadata) -> Bytes!String do
  let s = value.saved
  alice_check(bilateral_saved_shape(s) && s.role == 1 && (s.substate == 0 || s.substate == 1),
    "invalid_c1_alice_journal")?
  let fields = [
    Bytes.from_utf8("BAJ1"),
    s.scope.configuration,
    s.scope.protocol_info,
    s.scope.account_id,
    s.scope.device_id,
    s.scope.peer_account_id,
    s.scope.peer_device_id,
    s.scope.session_id,
    mobile_byte(s.role)?,
    mobile_byte(s.substate)?,
    mobile_write_u64(s.epoch)?,
    mobile_write_u64(s.revision)?,
    s.transition,
    mobile_write_u64(s.output_epoch)?,
    s.header,
    s.vector,
    value.secrets_hash,
    value.epoch_key_hash,
    value.pending_hash,
    value.pending_id,
    value.envelope_hash
  ]
  let bytes = mobile_join(for f in fields do
      mobile_vector(f)?
    end,
    0,
    Bytes.empty())?
  alice_check(Bytes.length(bytes) <= 4096, "invalid_c1_alice_journal")?
  Ok(bytes)
end

pub fn decode_alice_metadata(value :: Bytes, scope :: BraidScope) -> AliceHeaderMetadata!String do
  let state = case reader(value, 4096) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_alice_journal")
  end
  let f = read_fields(state, 21, [])?
  alice_check(Bytes.secure_equals(List.get(f, 0), Bytes.from_utf8("BAJ1")),
    "invalid_c1_alice_journal")?
  for i in [1, 3, 5, 7, 12, 16, 17, 18, 20] do
    alice_check(Bytes.length(List.get(f, i)) == 32, "invalid_c1_alice_journal")?
  end
  for i in [4, 6, 19] do
    alice_check(Bytes.length(List.get(f, i)) == 16, "invalid_c1_alice_journal")?
  end
  for i in [10, 11, 13] do
    alice_check(Bytes.length(List.get(f, i)) == 8, "invalid_c1_alice_journal")?
  end
  alice_check(Bytes.length(List.get(f, 8)) == 1 && Bytes.length(List.get(f, 9)) == 1,
    "invalid_c1_alice_journal")?
  let actual = BraidScope {
    configuration: List.get(f, 1),
    protocol_info: List.get(f, 2),
    account_id: List.get(f, 3),
    device_id: List.get(f, 4),
    peer_account_id: List.get(f, 5),
    peer_device_id: List.get(f, 6),
    session_id: List.get(f, 7)
  }
  alice_check(alice_same_scope(actual, scope), "c1_alice_scope_changed")?
  let saved = BraidBilateralSaved {
    scope: actual,
    role: mobile_read_byte(List.get(f, 8))?,
    substate: mobile_read_byte(List.get(f, 9))?,
    epoch: mobile_read_u64(List.get(f, 10))?,
    revision: mobile_read_u64(List.get(f, 11))?,
    transition: List.get(f, 12),
    output_epoch: mobile_read_u64(List.get(f, 13))?,
    header: List.get(f, 14),
    vector: List.get(f, 15),
    first: Bytes.empty(),
    wire: Bytes.empty(),
    secrets: Bytes.empty(),
    epoch_key: Bytes.empty(),
    continuation: Bytes.empty()
  }
  alice_check(bilateral_saved_metadata(saved)
      && saved.role == 1
      && (saved.substate == 0 || saved.substate == 1),
    "invalid_c1_alice_journal")?
  Ok(AliceHeaderMetadata {
    saved: saved,
    secrets_hash: List.get(f, 16),
    epoch_key_hash: List.get(f, 17),
    pending_hash: List.get(f, 18),
    pending_id: List.get(f, 19),
    envelope_hash: List.get(f, 20)
  })
end
