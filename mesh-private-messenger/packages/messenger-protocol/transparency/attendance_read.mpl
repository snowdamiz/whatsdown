from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  pubkey_equal,
  pubkey_string
)
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.AnchorRpc import read_anchor_rpc_response
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.Attendance import (
  AttendanceClock,
  AttendanceEpoch,
  AttendanceRow,
  AttendanceAddresses,
  attendance_addresses,
  decode_attendance_clock,
  decode_attendance_epoch
)

pub struct AttendanceState do
  status :: String
  log_name :: String
  log_id :: Bytes
  log_address :: Pubkey
  clock_address :: Pubkey
  epoch_address :: Pubkey
  epoch_number :: U64
  context_slot :: U64
  enabled :: Bool
  clock :: Option<AttendanceClock>
  record :: Option<AttendanceEpoch>
end

struct AttendanceObservation do
  snapshot :: OptionalAccountSlicesAtSlot
  state :: AttendanceState
end

fn authenticated(value :: Option<AccountSlice>,
  program :: Pubkey,
  space :: String,
  length :: Int) -> AccountSlice!String do
  let account = case value do
    None -> return Err("attendance_account_missing")
    Some(value) -> value
  end
  if account.info.executable
    || !pubkey_equal(account.info.owner, program)
    || account.info.lamports == U64.parse("0")?
    || account.space != U64.parse(space)?
    || Bytes.length(account.info.data) != length do
    return Err("attendance_account_mismatch")
  end
  Ok(account)
end

fn absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(value) -> !value.info.executable
      && U64.to_string(value.space) == "0"
      && Bytes.length(value.info.data) == 0
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
  end
end

# This decoder expects the ordered slices requested by read_attendance from one
# finalized provider batch. The reader additionally checks the minimum context
# and independent-provider agreement. Decoding alone is not RPC authentication.
pub fn decode_attendance_snapshot(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  epoch :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> AttendanceState!String do
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  if Bytes.length(service_key) != 32
    || (version != 1 && version != 2)
    || !Bytes.secure_equals(addresses.log_id, pins.log_id)
    || !pubkey_equal(addresses.ring, pins.ring)
    || List.length(snapshot.accounts) != 3 do
    return Err("invalid_attendance_pins")
  end
  let attendance = attendance_addresses(pins.program, pins.log_id, epoch)?
  let log_account = authenticated(List.get(snapshot.accounts, 0), pins.program, "352", 352)?
  let log = decode_anchor_log(log_account.info.data)?
  if log.version != version
    || log.name != pins.log_name
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes) do
    return Err("attendance_log_mismatch")
  end
  let initial = AttendanceState {
    status: "disabled",
    log_name: pins.log_name,
    log_id: pins.log_id,
    log_address: addresses.log,
    clock_address: attendance.clock,
    epoch_address: attendance.epoch,
    epoch_number: epoch,
    context_slot: snapshot.slot,
    enabled: log.attendance_enabled,
    clock: None,
    record: None
  }
  if !log.attendance_enabled do
    return Ok(initial)
  end
  # One 2640-byte slice bounds the whole batch, including the large companion
  # clock. RPC space authenticates its full allocation before the 80-byte header
  # is decoded; an 80-byte initialized-but-not-enabled account cannot pass.
  let clock_account = authenticated(List.get(snapshot.accounts, 1), pins.program, "65616", 2640)?
  let clock = decode_attendance_clock(Bytes.slice(clock_account.info.data, 0, 80)?)?
  let zero = U64.parse("0")?
  if !Bytes.secure_equals(clock.log_id, pins.log_id)
    || clock.activated_at == zero
    || U64.compare(clock.activated_slot, snapshot.slot) > 0 do
    return Err("attendance_clock_mismatch")
  end
  let state = %{initial | status: "missing", clock: Some(clock)}
  if absent(List.get(snapshot.accounts, 2)) do
    return Ok(state)
  end
  let epoch_account = authenticated(List.get(snapshot.accounts, 2), pins.program, "2640", 2640)?
  let record = decode_attendance_epoch(epoch_account.info.data)?
  let activation_epoch = U64.subtract(clock.first_full_epoch, U64.parse("1")?)?
  if !Bytes.secure_equals(record.log_id, pins.log_id)
    || record.epoch != epoch
    || U64.compare(record.epoch, activation_epoch) < 0
    || U64.compare(record.max_post_slot, snapshot.slot) > 0
    || (record.posts != zero
      && (U64.compare(record.max_post_slot, clock.activated_slot) < 0
        || U64.compare(record.epoch, clock.latest_post_epoch) > 0)) do
    return Err("attendance_epoch_mismatch")
  end
  if record.sealed && record.posts != zero do
    let last_signing_slot = U64.add(record.max_post_slot, U64.parse("1500")?)?
    if U64.compare(snapshot.slot, last_signing_slot) <= 0 do
      return Err("attendance_epoch_context_mismatch")
    end
  end
  Ok(%{state |
    status: if record.sealed do
      "sealed"
    else
      "unsealed"
    end,
    record: Some(record)
  })
end

fn observe(endpoint :: String,
  pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  epoch :: U64,
  minimum_slot :: U64) -> AttendanceObservation!String do
  let log = anchor_addresses(pins.program, pins.log_name)?.log
  let attendance = attendance_addresses(pins.program, pins.log_id, epoch)?
  let request = get_multiple_accounts_slice_request(1,
    [log, attendance.clock, attendance.epoch],
    "finalized",
    0,
    2640,
    Some(minimum_slot))?
  let response = read_anchor_rpc_response(endpoint, request, 16384)?
  let snapshot = optional_accounts_slice_from_response(response)?
  if U64.compare(snapshot.slot, minimum_slot) < 0 do
    return Err("attendance_stale_context")
  end
  let state = decode_attendance_snapshot(pins, service_key, version, epoch, snapshot)?
  Ok(AttendanceObservation { snapshot: snapshot, state: state })
end

fn same_snapshot(first :: OptionalAccountSlicesAtSlot,
  second :: OptionalAccountSlicesAtSlot) -> Bool do
  if List.length(first.accounts) != List.length(second.accounts) do
    return false
  end
  for index in 0..List.length(first.accounts) do
    case (List.get(first.accounts, index), List.get(second.accounts, index)) do
      (None, None) -> nil
      (Some(a), Some(b)) -> if a.space != b.space
        || a.info.executable != b.info.executable
        || a.info.lamports != b.info.lamports
        || !pubkey_equal(a.info.owner, b.info.owner)
        || !Bytes.secure_equals(a.info.data, b.info.data) do
        return false
      end
      _ -> return false
    end
  end
  true
end

fn agree(first :: AttendanceObservation!String,
  second :: AttendanceObservation!String) -> Option<AttendanceState> do
  case (first, second) do
    (Ok(a), Ok(b)) -> if same_snapshot(a.snapshot, b.snapshot) do
      Some(%{a.state |
        context_slot: if U64.compare(a.snapshot.slot, b.snapshot.slot) < 0 do
          a.snapshot.slot
        else
          b.snapshot.slot
        end
      })
    else
      None
    end
    _ -> None
  end
end

# Counts are retained judge observations only. Rows identify Witness PDAs; this
# reader does not authenticate Witness/Bond registry identity, independence,
# eligibility, settlement duration, funding or payments.
pub fn read_attendance(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  epoch :: U64,
  minimum_slot :: U64) -> AttendanceState!String do
  if Bytes.length(service_key) != 32 || (version != 1 && version != 2) do
    return Err("invalid_attendance_pins")
  end
  let pins = sample_anchor_sources(pins)?
  let first = observe(List.get(pins.endpoints, 0), pins, service_key, version, epoch, minimum_slot)
  let second = observe(List.get(pins.endpoints, 1), pins, service_key, version, epoch, minimum_slot)
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = observe(List.get(pins.endpoints, 2), pins, service_key, version, epoch, minimum_slot)
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let valid = List.filter([first, second, third],
    fn(value) do
      case value do
        Ok(_) -> true
        Err(_) -> false
      end
    end)
  if List.length(valid) >= 2 do
    Err("anchor_rpc_disagree")
  else
    Err("anchor_rpc_unavailable")
  end
end

pub fn attendance_report(value :: AttendanceState) -> String do
  let (first, partial) = case value.clock do
    None -> ("null", false)
    Some(clock) -> do
      let partial = case U64.parse("1") do
        Err(_) -> false
        Ok(one) -> case U64.add(value.epoch_number, one) do
          Err(_) -> false
          Ok(next) -> next == clock.first_full_epoch
        end
      end
      (Json.encode_string(U64.to_string(clock.first_full_epoch)), partial)
    end
  end
  let (posts, max_slot, sealed, rows) = case value.record do
    None -> ("null", "null", "null", "")
    Some(record) -> (Json.encode_string(U64.to_string(record.posts)),
      Json.encode_string(U64.to_string(record.max_post_slot)),
      if record.sealed do
        "true"
      else
        "false"
      end,
      String.join(for row in record.rows do
          """{"witness":#{Json.encode_string(Bytes.to_base58(row.witness))},"signed":"#{U64.to_string(row.signed)}"}"""
        end,
        ","))
  end
  """{"schema_version":1,"status":#{Json.encode_string(value.status)},"log_name":#{Json.encode_string(value.log_name)},"log_id":"#{Bytes.to_hex(value.log_id)}","log_address":#{Json.encode_string(pubkey_string(value.log_address))},"clock_address":#{Json.encode_string(pubkey_string(value.clock_address))},"epoch_address":#{Json.encode_string(pubkey_string(value.epoch_address))},"epoch":"#{U64.to_string(value.epoch_number)}","context_slot":"#{U64.to_string(value.context_slot)}","attendance_enabled":#{value.enabled},"first_full_epoch":#{first},"activation_partial":#{partial},"sealed":#{sealed},"posts":#{posts},"max_post_slot":#{max_slot},"rows":[#{rows}]}"""
end
