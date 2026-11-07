from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  pubkey_string
)
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.Attendance import (
  AttendanceClock,
  AttendanceEpoch,
  AttendanceRow,
  attendance_addresses
)
from Transparency.AttendanceRead import (
  AttendanceState,
  decode_attendance_snapshot,
  read_attendance,
  attendance_report
)

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn wide(value :: String) -> Bytes!String do
  Bytes.write_uint_le(value, 8)
end

fn patch(bytes :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  cat([
    Bytes.slice(bytes, 0, offset)?,
    replacement,
    Bytes.slice(bytes,
      offset + Bytes.length(replacement),
      Bytes.length(bytes) - offset - Bytes.length(replacement))?
  ])
end

fn log_wire(pins :: AnchorPins, enabled :: Bool) -> Bytes!String do
  cat([
    Bytes.from_hex(if enabled do
      "4d4c470101000a01"
    else
      "4d4c470101000a00"
    end)?,
    Bytes.from_utf8("morse-main"),
    Bytes.from_hex(String.repeat("00", 22))?,
    pins.log_id,
    Bytes.from_hex(String.repeat("11", 32))?,
    Bytes.from_hex(String.repeat("22", 32))?,
    pins.ring.bytes,
    Bytes.from_hex(String.repeat("33", 32))?,
    Bytes.from_hex(String.repeat("00", 152))?
  ])
end

fn clock_wire(pins :: AnchorPins) -> Bytes!String do
  cat([
    Bytes.from_hex("4d414301")?,
    pins.log_id,
    wide("6048010")?,
    wide("100")?,
    wide("11")?,
    wide("11")?,
    Bytes.from_hex(String.repeat("00", 2572))?
  ])
end

fn epoch_wire(pins :: AnchorPins, epoch :: String, sealed :: Bool) -> Bytes!String do
  cat([
    Bytes.from_hex("4d414501")?,
    pins.log_id,
    wide(epoch)?,
    wide("4100")?,
    wide("4200")?,
    Bytes.from_hex(if sealed do
      "020001"
    else
      "020000"
    end)?,
    Bytes.from_hex(String.repeat("00", 17))?,
    Bytes.from_hex(String.repeat("07", 32))?,
    wide("4100")?,
    Bytes.from_hex(String.repeat("08", 32))?,
    wide("3280")?,
    Bytes.from_hex(String.repeat("00", 62 * 40))?
  ])
end

fn account(pins :: AnchorPins, bytes :: Bytes, space :: String) -> AccountSlice!String do
  Ok(AccountSlice {
    info: AccountInfo {
      owner: pins.program,
      data: bytes,
      executable: false,
      lamports: U64.parse("10000")?,
      rent_epoch: U64.parse("0")?
    },
    space: U64.parse(space)?
  })
end

fn expect_invalid(pins :: AnchorPins,
  accounts :: List<Option<AccountSlice>>,
  slot :: String) -> Bool!String do
  case decode_attendance_snapshot(pins,
    Bytes.from_hex(String.repeat("11", 32))?,
    1,
    U64.parse("11")?,
    OptionalAccountSlicesAtSlot { slot: U64.parse(slot)?, accounts: accounts }) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

fn proof() -> Bool!String do
  let program = pubkey("11111111111111111111111111111111")?
  let derived = anchor_addresses(program, "morse-main")?
  let pins = AnchorPins {
    program: program,
    ring: derived.ring,
    log_id: derived.log_id,
    log_name: "morse-main",
    rpc: webpki_rpc_transport(["https://one.invalid", "https://two.invalid", "https://three.invalid"])?
  }
  let log = account(pins, log_wire(pins, true)?, "352")?
  let clock = account(pins, clock_wire(pins)?, "65616")?
  let epoch = account(pins, epoch_wire(pins, "11", true)?, "2640")?
  let snapshot = OptionalAccountSlicesAtSlot {
    slot: U64.parse("9007199254740993")?,
    accounts: [Some(log), Some(clock), Some(epoch)]
  }
  let key = Bytes.from_hex(String.repeat("11", 32))?
  let value = decode_attendance_snapshot(pins, key, 1, U64.parse("11")?, snapshot)?
  assert(value.status == "sealed" && value.clock != None && value.record != None)
  let report = Json.parse(attendance_report(value))?
  assert(Json.as_string(Json.object_get(report, "context_slot")?)? == "9007199254740993")
  assert(Json.as_string(Json.object_get(report, "first_full_epoch")?)? == "11")
  assert(Json.as_string(Json.object_get(report, "posts")?)? == "4100")
  assert(Json.array_length(Json.object_get(report, "rows")?)? == 2)
  assert(!String.contains(Json.encode(report), "eligible")
    && !String.contains(Json.encode(report), "reward"))
  let open = %{epoch | info: %{epoch.info | data: epoch_wire(pins, "11", false)?}}
  assert(decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("11")?,
    %{snapshot | accounts: [Some(log), Some(clock), Some(open)]})?.status == "unsealed")
  let missing = decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("11")?,
    %{snapshot | accounts: [Some(log), Some(clock), None]})?
  assert(missing.status == "missing" && missing.record == None)
  assert(Json.is_null(Json.object_get(Json.parse(attendance_report(missing))?, "posts")?))
  let empty_bytes = cat([
    Bytes.slice(epoch.info.data, 0, 44)?,
    Bytes.from_hex(String.repeat("00", 18) <> "01" <> String.repeat("00", 2577))?
  ])?
  let empty = %{epoch | info: %{epoch.info | data: empty_bytes}}
  let value = decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("11")?,
    %{snapshot | accounts: [Some(log), Some(clock), Some(empty)]})?
  assert(value.status == "sealed")
  let report = Json.parse(attendance_report(value))?
  assert(Json.as_string(Json.object_get(report, "posts")?)? == "0")
  assert(Json.array_length(Json.object_get(report, "rows")?)? == 0)
  let future = decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("18446744073709551615")?,
    %{snapshot | accounts: [Some(log), Some(clock), None]})?
  assert(!Json.as_bool(Json.object_get(Json.parse(attendance_report(future))?,
    "activation_partial")?)?)
  let disabled = %{log | info: %{log.info | data: log_wire(pins, false)?}}
  let value = decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("11")?,
    %{snapshot | accounts: [Some(disabled), None, None]})?
  assert(value.status == "disabled" && value.clock == None && value.record == None)
  let partial = %{epoch | info: %{epoch.info | data: epoch_wire(pins, "10", true)?}}
  let value = decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("10")?,
    %{snapshot | accounts: [Some(log), Some(clock), Some(partial)]})?
  assert(Json.as_bool(Json.object_get(Json.parse(attendance_report(value))?,
    "activation_partial")?)?)
  let zero_owner = Pubkey { bytes: Bytes.from_hex(String.repeat("00", 32))? }
  let prefunded = %{epoch |
    space: U64.parse("0")?,
    info: %{epoch.info | owner: zero_owner, data: Bytes.empty()}
  }
  assert(decode_attendance_snapshot(pins,
    key,
    1,
    U64.parse("11")?,
    %{snapshot | accounts: [Some(log), Some(clock), Some(prefunded)]})?.status == "missing")
  for bad in [
    %{clock | space: U64.parse("80")?},
    %{clock | info: %{clock.info | data: Bytes.slice(clock.info.data, 0, 80)?}},
    %{clock | info: %{clock.info | executable: true}},
    %{clock | info: %{clock.info | lamports: U64.parse("0")?}},
    %{clock | info: %{clock.info | owner: derived.log}},
    %{clock |
      info: %{clock.info |
        data: patch(clock.info.data, 4, Bytes.from_hex(String.repeat("12", 32))?)?
      }
    },
    %{clock | info: %{clock.info | data: patch(clock.info.data, 36, wide("0")?)?}},
    %{clock | info: %{clock.info | data: patch(clock.info.data, 52, wide("12")?)?}}
  ] do
    expect_invalid(pins, [Some(log), Some(bad), Some(epoch)], "9007199254740993")?
  end
  for bad in [
    %{epoch | space: U64.parse("2641")?},
    %{epoch | info: %{epoch.info | executable: true}},
    %{epoch | info: %{epoch.info | owner: derived.log}},
    %{epoch | info: %{epoch.info | lamports: U64.parse("0")?}},
    %{epoch |
      info: %{epoch.info |
        data: patch(epoch.info.data, 4, Bytes.from_hex(String.repeat("12", 32))?)?
      }
    },
    %{epoch | info: %{epoch.info | data: patch(epoch.info.data, 36, wide("10")?)?}},
    %{epoch | info: %{epoch.info | data: patch(epoch.info.data, 52, wide("99")?)?}},
    %{epoch | info: %{epoch.info | data: patch(epoch.info.data, 36, wide("12")?)?}}
  ] do
    expect_invalid(pins, [Some(log), Some(clock), Some(bad)], "9007199254740993")?
  end
  expect_invalid(pins, [Some(log), None, Some(epoch)], "9007199254740993")?
  expect_invalid(pins, [None, Some(clock), Some(epoch)], "9007199254740993")?
  expect_invalid(pins, [Some(log), Some(clock)], "9007199254740993")?
  expect_invalid(pins, [Some(log), Some(clock), Some(epoch)], "4200")?
  expect_invalid(pins, [Some(log), Some(clock), Some(epoch)], "5700")?
  expect_invalid(%{pins | ring: derived.log},
    [Some(log), Some(clock), Some(epoch)],
    "9007199254740993")?
  expect_invalid(%{pins | log_id: Bytes.from_hex(String.repeat("12", 32))?},
    [Some(log), Some(clock), Some(epoch)],
    "9007199254740993")?
  Ok(true)
end

test("attendance binds log, full clock allocation, epoch identity and finalized context before reporting counts") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn test_pins(endpoints :: List<String>) -> AnchorPins!String do
  let program = pubkey("11111111111111111111111111111111")?
  let derived = anchor_addresses(program, "morse-main")?
  Ok(AnchorPins {
    program: program,
    ring: derived.ring,
    log_id: derived.log_id,
    log_name: "morse-main",
    rpc: webpki_rpc_transport(endpoints)?
  })
end

fn rpc_account(pins :: AnchorPins, bytes :: Bytes, space :: String, mode :: String) -> String do
  let owner = if mode == "foreign" do
    Bytes.to_base58(pins.ring.bytes)
  else
    pubkey_string(pins.program)
  end
  let space = if mode == "space-string" do
    Json.encode_string(space)
  else
    space
  end
  let executable = if mode == "executable-string" do
    "\"false\""
  else
    "false"
  end
  let lamports = if mode == "zero-rent" do
    "0"
  else
    "10000"
  end
  """{"data":["#{Bytes.to_base64(bytes)}","base64"],"owner":"#{owner}","executable":#{executable},"lamports":#{lamports},"rentEpoch":0,"space":#{space}}"""
end

fn rpc_reply(request :: Request) -> String!String do
  let mode = case Request.param(request, "mode") do
    None -> return Err("missing mode")
    Some(value) -> value
  end
  if mode == "down" do
    return Err("offline")
  end
  let pins = test_pins([])?
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  let attendance = attendance_addresses(pins.program, pins.log_id, U64.parse("11")?)?
  let body = Json.parse(Request.body(request))?
  let params = Json.object_get(body, "params")?
  let keys = Json.array_get(params, 0)?
  let options = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(body, "method")?)? == "getMultipleAccounts")
  assert(Json.array_length(keys)? == 3)
  assert(Json.as_string(Json.array_get(keys, 0)?)? == pubkey_string(addresses.log))
  assert(Json.as_string(Json.array_get(keys, 1)?)? == pubkey_string(attendance.clock))
  assert(Json.as_string(Json.array_get(keys, 2)?)? == pubkey_string(attendance.epoch))
  assert(Json.as_string(Json.object_get(options, "commitment")?)? == "finalized")
  assert(Json.encode(Json.object_get(options, "minContextSlot")?) == "9007199254740993")
  let slice = Json.object_get(options, "dataSlice")?
  assert(Json.as_int(Json.object_get(slice, "offset")?)? == 0)
  assert(Json.as_int(Json.object_get(slice, "length")?)? == 2640)
  let log = log_wire(pins, mode != "disabled")?
  let log = if mode == "wrong-service" do
    patch(log, 72, Bytes.from_hex(String.repeat("12", 32))?)?
  else
    log
  end
  let clock = clock_wire(pins)?
  let clock = if mode == "changed-clock" do
    patch(clock, 60, wide("12")?)?
  else if mode == "short-clock" do
    Bytes.slice(clock, 0, 80)?
  else if mode == "inactive-clock" do
    patch(clock, 36, Bytes.from_hex(String.repeat("00", 32))?)?
  else
    clock
  end
  let epoch = epoch_wire(pins,
    if mode == "wrong-epoch" do
      "12"
    else
      "11"
    end,
    mode != "unsealed")?
  let epoch = if mode == "changed" do
    patch(epoch, 44, wide("4101")?)?
  else
    epoch
  end
  let clock_space = if mode == "clock-space" do
    "80"
  else
    "65616"
  end
  let epoch_space = if mode == "epoch-space" do
    "2641"
  else
    "2640"
  end
  let log = rpc_account(pins, log, "352", mode)
  let clock = if mode == "disabled" || mode == "missing-clock" do
    "null"
  else
    rpc_account(pins, clock, clock_space, mode)
  end
  let epoch = if mode == "disabled" || mode == "missing" do
    "null"
  else
    rpc_account(pins, epoch, epoch_space, mode)
  end
  let values = if mode == "swapped" do
    "[#{clock},#{log},#{epoch}]"
  else
    "[#{log},#{clock},#{epoch}]"
  end
  let values = if mode == "values-string" do
    Json.encode_string(values)
  else
    values
  end
  let values = if mode == "short-batch" do
    "[#{log},#{clock}]"
  else
    values
  end
  let slot = if mode == "stale" do
    "9007199254740992"
  else if mode == "high-context" do
    "9007199254741093"
  else if mode == "quoted-slot" do
    "\"9007199254740993\""
  else
    "9007199254740993"
  end
  let context = if mode == "context-string" do
    Json.encode_string("{\"slot\":#{slot}}")
  else
    "{\"slot\":#{slot}}"
  end
  let result = "{\"context\":#{context},\"value\":#{values}}"
  let result = if mode == "result-string" do
    Json.encode_string(result)
  else
    result
  end
  let id = if mode == "wrong-id" do
    "2"
  else
    "1"
  end
  Ok("{\"jsonrpc\":\"2.0\",\"id\":#{id},\"result\":#{result}}")
end

actor rpc_server(port :: Int) do
  let router = HTTP.on_post(HTTP.router(),
    "/:mode",
    fn(request :: Request) do
      case rpc_reply(request) do
        Ok(body) -> HTTP.response(200, body)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn read_modes(modes :: List<String>) -> AttendanceState!String do
  let endpoints = for index in 0..3 do
    "http://127.0.0.1:#{20311 + index}/#{List.get(modes, index)}"
  end
  read_attendance(test_pins(endpoints)?,
    Bytes.from_hex(String.repeat("11", 32))?,
    1,
    U64.parse("11")?,
    U64.parse("9007199254740993")?)
end

fn provider_proof() -> Bool!String do
  let _one = spawn(rpc_server, 20311)
  let _two = spawn(rpc_server, 20312)
  let _three = spawn(rpc_server, 20313)
  Timer.sleep(100)
  for mode in ["valid", "unsealed", "disabled", "missing"] do
    let expected = if mode == "valid" do
      "sealed"
    else
      mode
    end
    assert(read_modes([mode, mode, mode])?.status == expected)
    assert(read_modes(["down", mode, mode])?.status == expected)
  end
  assert(read_modes([
    "valid",
    "high-context",
    "down"
  ])?.context_slot == U64.parse("9007199254740993")?)
  assert(read_modes(["valid", "valid", "changed"])?.status == "sealed")
  for mode in [
    "foreign",
    "space-string",
    "executable-string",
    "zero-rent",
    "wrong-service",
    "short-clock",
    "inactive-clock",
    "clock-space",
    "epoch-space",
    "wrong-epoch",
    "missing-clock",
    "swapped",
    "values-string",
    "short-batch",
    "stale",
    "quoted-slot",
    "context-string",
    "result-string",
    "wrong-id"
  ] do
    case read_modes([mode, mode, mode]) do
      Ok(_) -> do
        println("accepted invalid attendance mode #{mode}")
        assert(false)
      end
      Err(_) -> nil
    end
    assert(read_modes([mode, "valid", "valid"])?.status == "sealed")
  end
  for modes in [
    ["valid", "changed", "down"],
    ["valid", "changed", "changed-clock"],
    ["valid", "missing", "down"]
  ] do
    assert(read_modes(modes) == Err("anchor_rpc_disagree"))
  end
  assert(read_modes(["down", "valid", "down"]) == Err("anchor_rpc_unavailable"))
  let same_provider = test_pins([
    "https://same.invalid/a",
    "https://same.invalid/b",
    "https://other.invalid"
  ])?
  assert(read_attendance(same_provider,
    Bytes.from_hex(String.repeat("11", 32))?,
    1,
    U64.parse("11")?,
    U64.parse("9007199254740993")?) == Err("invalid_anchor_sources"))
  Ok(true)
end

test("attendance requires two independent strict whole-batch finalized provider observations") do
  case provider_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
