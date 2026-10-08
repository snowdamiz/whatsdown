from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig
from Binary.Reader import BinaryReader, reader
from Mobile.Platform import native_security_config
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_blobs
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.Fork import fork_proof_hash
from Transparency.Merkle import TransparencyCheckpoint

##! Mobile.TrustAlarm: this device's record that Morse's key log is in question,
##! shared by the anchor check (Mobile.Anchor) and checkpoint gossip.
##!
##! Kinds: 1 anchor_mismatch (the phone's view does not match the public
##! record), 2 service_slashed (the judge slashed the log's service key),
##! 3 contact_fork (gossip found two signed checkpoints that cannot both be
##! true). While an alarm for the pinned service key is active, new sessions
##! and key changes fail with `trust_alarm_active`; existing chats keep working
##! (plan §6.7, §10). The public record running behind and RPC providers
##! disagreeing are anchor check results, never alarms: they never block.
##!
##! Each alarm keeps its evidence: the two versions it compared and the FRK
##! proofs built from them, with where each was filed (every pinned relay:
##! pending retry, sent, or refused) and, once the phone has seen it on chain,
##! which address the judge paid. Everything is sealed on the device and
##! nothing is reported to Morse.
##!
##! Local frame "trust-alarms/v1": u8 1 || "TAL" || u8 count || count x
##! vector32(alarm); alarm = u8 kind || u8 active || u64 raised_at_ms ||
##! service_key32 || summary || summary || u8 n || n x vector32(frk record);
##! summary = u8 present || u64 sequence || u64 tree_size || root32; frk record
##! = vector32(FRK) || u8 complete || u8 landed || paid_to32 || u64 slot ||
##! u8 r || r x (vector32(relay URL) || u8 status || reported proof_hash32).

pub struct TrustSummary do
  present :: Bool
  sequence :: Int
  tree_size :: Int
  root :: Bytes
end

pub struct TrustRelay do
  url :: String
  status :: Int
  proof_hash :: Bytes
end

pub struct TrustFrk do
  bytes :: Bytes
  complete :: Bool
  landed :: Bool
  paid_to :: Bytes
  slot :: Int
  relays :: List<TrustRelay>
end

pub struct TrustAlarm do
  kind :: Int
  active :: Bool
  raised_at :: Int
  service_key :: Bytes
  first :: TrustSummary
  second :: TrustSummary
  frks :: List<TrustFrk>
end

struct ReadSummary do
  state :: BinaryReader
  value :: TrustSummary
end

pub fn trust_alarm_anchor_mismatch() -> Int do
  1
end

pub fn trust_alarm_service_slashed() -> Int do
  2
end

pub fn trust_alarm_contact_fork() -> Int do
  3
end

# Relay filing states.

pub fn trust_relay_pending() -> Int do
  0
end

pub fn trust_relay_sent() -> Int do
  1
end

pub fn trust_relay_refused() -> Int do
  2
end

fn label() -> String do
  "trust-alarms/v1"
end

fn limit() -> Int do
  8
end

fn zeros(length :: Int) -> Bytes!String do
  case Bytes.repeat(0, length) do
    Err(_) -> Err("invalid_trust_alarm")
    Ok(value)
  end
end

pub fn trust_summary_none() -> TrustSummary!String do
  Ok(TrustSummary { present: false, sequence: 0, tree_size: 0, root: zeros(32)? })
end

pub fn trust_summary_of(checkpoint :: TransparencyCheckpoint) -> TrustSummary!String do
  let sequence = case U64.to_int(checkpoint.sequence) do
    Err(_) -> Err("invalid_trust_alarm")
    Ok(value)
  end?
  let size = case U64.to_int(checkpoint.tree_size) do
    Err(_) -> Err("invalid_trust_alarm")
    Ok(value)
  end?
  Ok(TrustSummary {
    present: true,
    sequence: sequence,
    tree_size: size,
    root: checkpoint.tree_root
  })
end

# A proof not yet sent anywhere: every pinned relay starts pending.

pub fn trust_frk(bytes :: Bytes, complete :: Bool) -> TrustFrk!String do
  let config = native_security_config()?
  let empty = zeros(32)?
  Ok(TrustFrk {
    bytes: bytes,
    complete: complete,
    landed: false,
    paid_to: empty,
    slot: 0,
    relays: for url in config.config.relays do
      TrustRelay { url: url, status: 0, proof_hash: empty }
    end
  })
end

# What checkpoint gossip raises when two service-signed checkpoints cannot both
# be true: `first` is the version this device holds, `second` the contact's,
# `frks` the FRK proofs built from them (Transparency.Fork). Pass the result to
# `trust_alarm_raise`; the next anchor check run files the proofs.

pub fn trust_alarm_for_fork(first :: TransparencyCheckpoint,
  second :: TransparencyCheckpoint,
  frks :: List<Bytes>) -> TrustAlarm!String do
  let config = native_security_config()?
  let proofs = for frk in frks do
    trust_frk(frk, true)?
  end
  Ok(TrustAlarm {
    kind: trust_alarm_contact_fork(),
    active: true,
    raised_at: DateTime.to_unix_ms(DateTime.utc_now()),
    service_key: config.transparency_service_public_key,
    first: trust_summary_of(first)?,
    second: trust_summary_of(second)?,
    frks: proofs
  })
end

fn flag(value :: Bool) -> Bytes!String do
  tcodec_u8(if value do
    1
  else
    0
  end)
end

fn encode_summary(value :: TrustSummary) -> Bytes!String do
  if Bytes.length(value.root) != 32 do
    Err("invalid_trust_alarm")
  else
    tcodec_join([
      flag(value.present)?,
      tcodec_u64(value.sequence)?,
      tcodec_u64(value.tree_size)?,
      value.root
    ])
  end
end

fn encode_relay(value :: TrustRelay) -> Bytes!String do
  tcodec_join([
    tcodec_vector(Bytes.from_utf8(value.url))?,
    tcodec_u8(value.status)?,
    value.proof_hash
  ])
end

fn encode_frk(value :: TrustFrk, with_hash :: Bool) -> Bytes!String do
  let relays = for relay in value.relays do
    encode_relay(relay)?
  end
  let hash = if with_hash do
    [fork_proof_hash(value.bytes)?]
  else
    List.new()
  end
  tcodec_join([tcodec_vector(value.bytes)?]
    ++ hash
    ++ [
      flag(value.complete)?,
      flag(value.landed)?,
      value.paid_to,
      tcodec_u64(value.slot)?,
      tcodec_u8(List.length(value.relays))?
    ]
    ++ relays)
end

fn encode_alarm(value :: TrustAlarm, details :: Bool) -> Bytes!String do
  let frks = for frk in value.frks do
    tcodec_vector(encode_frk(frk, details)?)?
  end
  let key = if details do
    List.new()
  else
    [value.service_key]
  end
  tcodec_join([tcodec_u8(value.kind)?, flag(value.active)?, tcodec_u64(value.raised_at)?]
    ++ key
    ++ [
      encode_summary(value.first)?,
      encode_summary(value.second)?,
      tcodec_u8(List.length(value.frks))?
    ]
    ++ frks)
end

fn encode_alarms(values :: List<TrustAlarm>, tag :: String, details :: Bool) -> Bytes!String do
  let alarms = for alarm in values do
    tcodec_vector(encode_alarm(alarm, details)?)?
  end
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8(tag), tcodec_u8(List.length(values))?] ++ alarms)
end

fn take_summary(state :: BinaryReader) -> ReadSummary!String do
  let present = tcodec_take_u8(state)?
  let sequence = tcodec_take_u64(present.state)?
  let size = tcodec_take_u64(sequence.state)?
  let root = tcodec_take_fixed(size.state, 32)?
  Ok(ReadSummary {
    state: root.state,
    value: TrustSummary {
      present: present.value == 1,
      sequence: sequence.value,
      tree_size: size.value,
      root: root.value
    }
  })
end

fn take_relays(state :: BinaryReader,
  count :: Int,
  output :: List<TrustRelay>) -> (BinaryReader, List<TrustRelay>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let url = tcodec_take_vector(state, 2048)?
    let status = tcodec_take_u8(url.state)?
    let hash = tcodec_take_fixed(status.state, 32)?
    let text = case Bytes.to_utf8(url.value) do
      Err(_) -> Err("invalid_trust_alarm")
      Ok(value)
    end?
    take_relays(hash.state,
      count,
      List.append(output, TrustRelay { url: text, status: status.value, proof_hash: hash.value }))
  end
end

fn decode_frk(input :: Bytes) -> TrustFrk!String do
  let state = case reader(input, 65536) do
    Err(_) -> Err("invalid_trust_alarm")
    Ok(value)
  end?
  let bytes = tcodec_take_vector(state, 8192)?
  let complete = tcodec_take_u8(bytes.state)?
  let landed = tcodec_take_u8(complete.state)?
  let paid_to = tcodec_take_fixed(landed.state, 32)?
  let slot = tcodec_take_u64(paid_to.state)?
  let count = tcodec_take_u8(slot.state)?
  let (rest, relays) = take_relays(count.state, count.value, List.new())?
  tcodec_done(rest)?
  Ok(TrustFrk {
    bytes: bytes.value,
    complete: complete.value == 1,
    landed: landed.value == 1,
    paid_to: paid_to.value,
    slot: slot.value,
    relays: relays
  })
end

fn take_frks(state :: BinaryReader,
  count :: Int,
  output :: List<TrustFrk>) -> (BinaryReader, List<TrustFrk>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let record = tcodec_take_vector(state, 65536)?
    take_frks(record.state, count, List.append(output, decode_frk(record.value)?))
  end
end

fn decode_alarm(input :: Bytes) -> TrustAlarm!String do
  let state = case reader(input, 1048576) do
    Err(_) -> Err("invalid_trust_alarm")
    Ok(value)
  end?
  let kind = tcodec_take_u8(state)?
  let active = tcodec_take_u8(kind.state)?
  let raised = tcodec_take_u64(active.state)?
  let key = tcodec_take_fixed(raised.state, 32)?
  let first = take_summary(key.state)?
  let second = take_summary(first.state)?
  let count = tcodec_take_u8(second.state)?
  let (rest, frks) = take_frks(count.state, count.value, List.new())?
  tcodec_done(rest)?
  Ok(TrustAlarm {
    kind: kind.value,
    active: active.value == 1,
    raised_at: raised.value,
    service_key: key.value,
    first: first.value,
    second: second.value,
    frks: frks
  })
end

fn take_alarms(state :: BinaryReader,
  count :: Int,
  output :: List<TrustAlarm>) -> List<TrustAlarm>!String do
  if List.length(output) >= count do
    tcodec_done(state)?
    Ok(output)
  else
    let record = tcodec_take_vector(state, 1048576)?
    take_alarms(record.state, count, List.append(output, decode_alarm(record.value)?))
  end
end

pub fn trust_alarms_load(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<TrustAlarm>!String do
  case load_blob(database_path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> do
      let frame = open_local(blob, wrapping_key, local_context(label())?)?
      let state = tcodec_start(frame, 8388608, 1, "TAL")?
      let count = tcodec_take_u8(state)?
      take_alarms(count.state, count.value, List.new())
    end
  end
end

# The newest alarms are kept; past the limit the oldest inactive one goes
# first, and an active one is never dropped for an inactive one.

fn pruned(values :: List<TrustAlarm>) -> List<TrustAlarm> do
  if List.length(values) <= limit() do
    values
  else
    case List.find(values, fn value -> !value.active end) do
      Some(oldest) -> pruned(List.filter(values,
        fn value -> !(value.raised_at == oldest.raised_at
          && value.kind == oldest.kind
          && !value.active) end))
      None -> List.drop(values, List.length(values) - limit())
    end
  end
end

pub fn trust_alarms_store(database_path :: String, values :: List<TrustAlarm>) -> ()!String do
  let wrapping_key = platform_key()?
  let blob = seal_local(encode_alarms(pruned(values), "TAL", false)?,
    wrapping_key,
    local_context(label())?)?
  store_updated_blobs(database_path, [label()], [blob])
end

fn same_summary(left :: TrustSummary, right :: TrustSummary) -> Bool do
  left.present == right.present
    && left.sequence == right.sequence
    && left.tree_size == right.tree_size
    && Bytes.secure_equals(left.root, right.root)
end

fn same_frk(left :: TrustFrk, right :: TrustFrk) -> Bool do
  Bytes.secure_equals(left.bytes, right.bytes)
end

# Raising is idempotent. An active anchor mismatch stays the one on record (it
# gains proofs only if it had none); a slashed service key is recorded once;
# a contact fork with the same two versions gains any new proofs.

fn merged(values :: List<TrustAlarm>, alarm :: TrustAlarm) -> List<TrustAlarm> do
  let same = fn value -> value.kind == alarm.kind
    && Bytes.secure_equals(value.service_key, alarm.service_key)
    && (alarm.kind == trust_alarm_service_slashed()
      || (alarm.kind == trust_alarm_anchor_mismatch() && value.active)
      || (same_summary(value.first, alarm.first) && same_summary(value.second, alarm.second))) end
  case List.find(values, same) do
    None -> List.append(values, alarm)
    Some(existing) -> List.map(values,
      fn value -> if same(value) do
        %{value | active: value.active || alarm.active, frks: merged_frks(value, alarm)}
      else
        value
      end end)
  end
end

fn merged_frks(existing :: TrustAlarm, alarm :: TrustAlarm) -> List<TrustFrk> do
  if existing.kind == trust_alarm_anchor_mismatch() && List.length(existing.frks) > 0 do
    existing.frks
  else
    existing.frks
      ++ List.filter(alarm.frks,
        fn frk -> !List.any(existing.frks, fn old -> same_frk(old, frk) end) end)
  end
end

pub fn trust_alarm_raise(database_path :: String, alarm :: TrustAlarm) -> ()!String do
  ensure_schema(database_path)?
  let wrapping_key = platform_key()?
  trust_alarms_store(database_path, merged(trust_alarms_load(database_path, wrapping_key)?, alarm))
end

# An anchor mismatch is cleared when a later check proves the view consistent
# with the public record: both versions are then prefixes of one log, so the
# alarm was not a fork (a real fork can never pass later). Its evidence and
# filing history stay on record.

pub fn trust_alarm_clear_mismatch(database_path :: String) -> ()!String do
  let alarms = trust_alarms_load(database_path, platform_key()?)?
  if List.any(alarms,
    fn value -> value.active && value.kind == trust_alarm_anchor_mismatch() end) do
    trust_alarms_store(database_path,
      List.map(alarms,
        fn value -> if value.kind == trust_alarm_anchor_mismatch() do
          %{value | active: false}
        else
          value
        end end))
  else
    Ok(nil)
  end
end

# The blocking alarm for the pinned service key, if any: a slashed key first,
# then a mismatch, then a contact's fork.

pub fn trust_alarm_active(database_path :: String) -> Option<TrustAlarm>!String do
  let active = List.filter(trust_alarms_load(database_path, platform_key()?)?,
    fn value -> value.active end)
  if List.length(active) == 0 do
    return Ok(None)
  end
  let config = native_security_config()?
  let alarms = List.filter(active,
    fn value -> Bytes.secure_equals(value.service_key, config.transparency_service_public_key) end)
  let ranked = List.filter(alarms, fn value -> value.kind == trust_alarm_service_slashed() end)
    ++ List.filter(alarms, fn value -> value.kind == trust_alarm_anchor_mismatch() end)
    ++ List.filter(alarms, fn value -> value.kind == trust_alarm_contact_fork() end)
  case ranked do
    [] -> Ok(None)
    first :: _ -> Ok(Some(first))
  end
end

# New sessions and key changes call this: it fails with `trust_alarm_active`
# while the pinned service key is in question.

pub fn trust_alarm_gate(database_path :: String) -> ()!String do
  case trust_alarm_active(database_path)? do
    None -> Ok(nil)
    Some(_) -> Err("trust_alarm_active")
  end
end

# Details: u8 1 || "TAD" || u8 count || count x vector32(alarm), each alarm as
# stored without the service key and with each FRK's proof hash after its
# bytes: vector32(FRK) || proof_hash32 || u8 complete || u8 landed ||
# paid_to32 || u64 slot || u8 r || r x (vector32(url) || u8 status || hash32).

pub fn trust_alarm_details(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    return Err("invalid_database_path")
  end
  ensure_schema(database_path)?
  let config = native_security_config()?
  let alarms = List.filter(trust_alarms_load(database_path, platform_key()?)?,
    fn value -> Bytes.secure_equals(value.service_key, config.transparency_service_public_key) end)
  encode_alarms(alarms, "TAD", true)
end
