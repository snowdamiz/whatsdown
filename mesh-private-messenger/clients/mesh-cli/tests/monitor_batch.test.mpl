from Transparency.AnchorChain import (
  AnchorPins,
  AnchorSnapshot,
  AnchorRecord,
  anchor_addresses,
  read_anchor_batch
)
from Transparency.AnchorRing import decode_anchor_header
from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import pubkey

fn zeroes(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", count))
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), join(List.tail(parts))?)
  end
end

fn header(changed :: Bool) -> Bytes!String do
  join([
    Bytes.from_hex("4d524701")?,
    Crypto.sha256(Bytes.from_utf8("morse-main")),
    Bytes.from_hex("01000010")?,
    Bytes.write_uint_le(if changed do
        "5"
      else
        "4"
      end,
      8)?,
    Bytes.write_uint_le("4", 8)?,
    Bytes.write_uint_le("400", 8)?
  ])
end

fn entry(number :: Int) -> Bytes!String do
  join([
    Bytes.write_uint_le(Int.to_string(number), 8)?,
    Bytes.write_uint_le(Int.to_string(number), 8)?,
    zeroes(64)?,
    Bytes.write_uint_le("1700000000000", 8)?,
    Bytes.write_uint_le(Int.to_string(number * 100), 8)?,
    Bytes.from_hex("0000020000000000")?
  ])
end

fn reply_bytes(request :: Request, changed :: Bool) -> Bytes!String do
  let document = Json.parse(Request.body(request))?
  let params = Json.object_get(document, "params")?
  let options = Json.array_get(params, 1)?
  let slice = Json.object_get(options, "dataSlice")?
  let offset = Json.as_int(Json.object_get(slice, "offset")?)?
  let length = Json.as_int(Json.object_get(slice, "length")?)?
  let data = if offset == 0 && length == 64 do
    header(changed)?
  else if offset == 64 + 4094 * 104 && length == 208 do
    join([entry(1)?, entry(2)?])?
  else if offset == 64 && length == 208 do
    join([entry(3)?, entry(4)?])?
  else
    return Err("unexpected slice")
  end
  Ok(data)
end

fn respond(request :: Request, changed :: Bool) -> Response do
  case reply_bytes(request, changed) do
    Err(_) -> HTTP.response(400, "invalid request")
    Ok(data) -> HTTP.response(200,
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":500},\"value\":{\"data\":[\"#{Bytes.to_base64(data)}\",\"base64\"],\"executable\":false,\"lamports\":1,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":0}}}")
  end
end

actor server(port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/stable", fn(request :: Request) do respond(request, false) end)
    |> HTTP.on_post("/changed", fn(request :: Request) do respond(request, true) end)
    |> HTTP.serve(port)
end

fn proof() -> Bool!String do
  let _one = spawn(server, 19111)
  let _two = spawn(server, 19112)
  let _three = spawn(server, 19113)
  Timer.sleep(100)
  let program = pubkey("11111111111111111111111111111111")?
  let addresses = anchor_addresses(program, "morse-main")?
  let pins = AnchorPins {
    program: program,
    ring: addresses.ring,
    log_name: "morse-main",
    log_id: addresses.log_id,
    rpc: webpki_rpc_transport(for port in [19111, 19112, 19113] do
      "http://127.0.0.1:#{port}/stable"
    end)?
  }
  let bytes = header(false)?
  let snapshot = AnchorSnapshot {
    bytes: bytes,
    header: decode_anchor_header(bytes)?,
    context_slot: U64.parse("500")?
  }
  let values = read_anchor_batch(pins, snapshot, 3, 4)?
  assert(List.length(values) == 4)
  for index in 0..4 do
    assert(U64.to_string(List.get(values, index).entry.sequence) == Int.to_string(index + 1))
  end
  let moving = %{pins |
    rpc: webpki_rpc_transport(for port in [19111, 19112, 19113] do
      "http://127.0.0.1:#{port}/changed"
    end)?
  }
  case read_anchor_batch(moving, snapshot, 3, 4) do
    Err(error) -> assert(error == "anchor_snapshot_changed")
    Ok(_) -> assert(false)
  end
  for (distance, count) in [(3, 0), (33, 33), (2, 4), (4096, 1)] do
    case read_anchor_batch(pins, snapshot, distance, count) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  Ok(true)
end

test("monitor batch reads cross ring wrap in posting order and reject a changing snapshot") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
