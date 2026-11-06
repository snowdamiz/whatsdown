from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Mobile.AnchorCheck import (
  AnchorObservation,
  check_anchor_at,
  anchor_identity,
  load_anchor_observation
)
from Mobile.Codec import mobile_join, mobile_append, mobile_byte
from Mobile.AnchorSchedule import (
  AnchorClaim,
  AnchorSchedule,
  load_anchor_schedule,
  claim_anchor_check,
  finish_anchor_check
)
from Solana.Read import Pubkey, pubkey
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Mobile.TransparencySafety import require_log_changes_allowed
from Tests.Support import database_path, repeated

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn little(value :: Int, count :: Int) -> Bytes!String do
  if count == 0 do
    return Ok(Bytes.empty())
  end
  mobile_append(mobile_byte(value % 256)?, little(value / 256, count - 1)?)
end

fn account_bytes(mode :: String, log :: Bool) -> Bytes!String do
  let id = Crypto.sha256(Bytes.from_utf8("morse-main"))
  if !log do
    let empty = mode == "empty"
    return mobile_join([
        Bytes.from_utf8("MRG"),
        mobile_byte(1)?,
        id,
        little(0, 2)?,
        little(if empty do
            0
          else
            1
          end,
          2)?,
        little(if empty do
            0
          else
            5
          end,
          8)?,
        little(if empty do
            0
          else
            8
          end,
          8)?,
        little(if empty do
            0
          else
            500
          end,
          8)?
      ],
      0,
      Bytes.empty())
  end
  let address = anchor_addresses(pubkey(String.repeat("1", 32))?, "morse-main")?
  mobile_join([
      Bytes.from_utf8("MLG"),
      mobile_byte(1)?,
      mobile_byte(2)?,
      mobile_byte(if mode == "slashed" do
        1
      else
        0
      end)?,
      mobile_byte(10)?,
      mobile_byte(0)?,
      Bytes.from_utf8("morse-main"),
      repeated(0, 22)?,
      id,
      repeated(17, 32)?,
      repeated(2, 32)?,
      address.ring.bytes,
      repeated(3, 32)?,
      little(100, 8)?,
      little(0, 2)?,
      little(10, 2)?,
      Bytes.from_utf8("morse-main"),
      repeated(0, 130)?
    ],
    0,
    Bytes.empty())
end

fn response(request :: Request, mode_file :: String, calls :: String) -> Response do
  File.append(calls, "x")
  let mode = File.read(mode_file).unwrap_or("down")
  if mode == "down" do
    return HTTP.response(503, "down")
  end
  let body = Request.body(request)
  if String.contains(body, "getBlockTime") do
    let value = if mode == "stale" do
      "1000"
    else if mode == "future" do
      "10000"
    else
      "8000"
    end
    return HTTP.response(200, """{"jsonrpc":"2.0","id":1,"result":#{value}}""")
  end
  let log = String.contains(body, "\"length\":352")
  let expected = if log do
    "2he32vXesDyeZVeYbuxNKJKYX3354iWmhuijN92XMky7"
  else
    "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb"
  end
  if !String.contains(body, expected) do
    return HTTP.response(400, "unexpected account")
  end
  case account_bytes(mode, log) do
    Err(error) -> HTTP.response(500, error)
    Ok(bytes) -> HTTP.response(200,
      """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":501},"value":{"data":["#{Bytes.to_base64(bytes)}","base64"],"executable":false,"lamports":1,"owner":"11111111111111111111111111111111","rentEpoch":0}}}""")
  end
end

actor server(port :: Int, mode :: String, calls :: String) do
  HTTP.router()
    |> HTTP.on_post("/", fn(r :: Request) do response(r, mode, calls) end)
    |> HTTP.serve(port)
end

fn pins() -> AnchorPins!String do
  let program = pubkey(String.repeat("1", 32))?
  let addresses = anchor_addresses(program, "morse-main")?
  Ok(AnchorPins {
    program: program,
    ring: addresses.ring,
    log_name: "morse-main",
    log_id: addresses.log_id,
    endpoints: ["http://127.0.0.1:19061/", "http://127.0.0.1:19062/", "http://127.0.0.1:19063/"]
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("anchor-check")?
  ensure_schema(path)?
  let mode = path <> ".mode"
  let calls = for port in 19061..19064 do
    path <> ".#{port}"
  end
  File.write(mode, "good")?
  for index in 0..3 do
    File.write(List.get(calls, index), "")?
    let _server = spawn(server, 19061 + index, mode, List.get(calls, index))
  end
  Timer.sleep(100)
  let pinned = pins()?
  let service_key = repeated(17, 32)?
  let identity = anchor_identity(pinned, service_key, 2)?
  let config_frame = Bytes.from_utf8(String.join([
      "4",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "8",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      String.repeat("1", 32),
      "morse-main"
    ],
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), config_frame))
  let observed = check_anchor_at(path, key, pinned, service_key, 2, wide("9000000")?, false)?
  assert(observed.status == "observed")
  require_log_changes_allowed(path, key)?
  let completed_result = load_anchor_schedule(path, key, identity)?.last_result
  let pending_path = database_path("anchor-pending")?
  ensure_schema(pending_path)?
  let pending = case claim_anchor_check(pending_path, key, identity, wide("9000000")?, false)? do
    Some(value) -> value
    None -> return Err("missing pending claim")
  end
  case require_log_changes_allowed(pending_path, key) do
    Err(error) -> assert(error == "anchor_check_pending")
    Ok(_) -> assert(false)
  end
  # A result that could not be committed must not silently reopen new trust.
  let db = Sqlite.open(pending_path)?
  Sqlite.execute(db,
    "CREATE TRIGGER refuse_completion BEFORE UPDATE ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'fixture'); END",
    [])?
  Sqlite.close(db)
  case finish_anchor_check(pending_path, key, pending, wide("9000001")?, false, completed_result) do
    Err(error) -> assert(error == "database_write_failed")
    Ok(_) -> assert(false)
  end
  case require_log_changes_allowed(pending_path, key) do
    Err(error) -> assert(error == "anchor_check_pending")
    Ok(_) -> assert(false)
  end
  let db2 = Sqlite.open(pending_path)?
  Sqlite.execute(db2, "DROP TRIGGER refuse_completion", [])?
  Sqlite.close(db2)
  finish_anchor_check(pending_path, key, pending, wide("9000001")?, false, completed_result)?
  require_log_changes_allowed(pending_path, key)?
  File.delete(pending_path)?
  assert(U64.to_string(observed.context_slot) == "501"
    && U64.to_string(observed.posted_slot) == "500")
  let counts = for name in calls do
    File.read(name)?
  end
  assert(List.length(List.filter(counts, fn(value) do String.length(value) > 0 end)) == 2)
  assert(List.reduce(counts, 0, fn(sum, value) do sum + String.length(value) end) == 6)
  # Neither foreground refreshes nor a key change may read again during the hour.
  File.write(mode, "slashed")?
  assert(check_anchor_at(path,
    key,
    pinned,
    service_key,
    2,
    wide("9000001")?,
    true)?.status == "observed")
  assert(check_anchor_at(path,
    key,
    pinned,
    service_key,
    2,
    wide("12600000")?,
    false)?.status == "observed")
  assert((for name in calls do
    File.read(name)?
  end) == counts)
  let refused = check_anchor_at(path, key, pinned, service_key, 2, wide("12600000")?, true)?
  assert(refused.status == "service_slashed")
  assert(load_anchor_observation(path, key, identity)?.status == "service_slashed")
  case require_log_changes_allowed(path, key) do
    Err(error) -> assert(error == "anchor_service_slashed")
    Ok(_) -> assert(false)
  end
  # A later outage or an unslashed response cannot erase an authenticated slash.
  File.write(mode, "down")?
  let after_slash = for name in calls do
    File.read(name)?
  end
  assert(check_anchor_at(path,
    key,
    pinned,
    service_key,
    2,
    wide("99000000")?,
    false)?.status == "service_slashed")
  assert((for name in calls do
    File.read(name)?
  end) == after_slash)
  # Each independent local state exercises a notice and retry without a pause.
  for setting in ["stale", "future", "down", "empty"] do
    File.write(mode, setting)?
    let other = database_path(setting)?
    ensure_schema(other)?
    let result = check_anchor_at(other, key, pinned, service_key, 2, wide("9000000")?, false)?
    let expected = if setting == "future" do
      "clock_unavailable"
    else if setting == "down" do
      "rpc_unavailable"
    else
      setting
    end
    assert(result.status == expected)
    if setting != "down" do
      assert(U64.to_string(result.context_slot) == "501")
    end
    require_log_changes_allowed(other, key)?
    let state = load_anchor_schedule(other, key, identity)?
    assert(U64.to_string(state.next_allowed) == "12600000")
    assert(U64.to_string(state.next_daily) == "9000000")
    File.delete(other)?
  end
  File.delete(path)?
  File.delete(mode)?
  for name in calls do
    File.delete(name)?
  end
  Ok(true)
end

test("native anchor observations reserve before RPC, retain slash refusals and retry notices hourly") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
