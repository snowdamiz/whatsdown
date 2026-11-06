from Receipt import read_receipt, receipt_keys, decode_receipt_snapshot
from Tests.RelayMpr2Fixture import fixture_receipt
from Transparency.RpcTransport import RpcEndpoint, RpcTls, webpki_rpc_transport

fn boundaries() -> Bool!String do
  let (pins, hash, snapshot) = fixture_receipt("mixed-proof-settled")?
  let raw = Json.parse(Env.get("MORSE_MPR2_RPC_SOURCES", ""))?
  let urls = for index in 0..3 do
    Json.as_string(Json.array_get(raw, index)?)?
  end
  let rpc = webpki_rpc_transport(urls)?
  assert(read_receipt(rpc, pins, hash, snapshot.slot)?.status == "settled")
  let last = "https://127.0.0.1:1"
  let poisoned = %{rpc |
    sources: List.take(rpc.sources, 2)
      ++ [RpcEndpoint { url: last, tls: OriginRoots(last, Bytes.from_utf8("invalid PEM")) }]
  }
  assert(read_receipt(poisoned, pins, hash, snapshot.slot) == Err("rpc_tls_config_invalid"))
  let marker = Env.get("MORSE_MPR2_RPC_GUARD", "")
  File.write(marker, "armed")?
  let guarded = %{rpc |
    require_current: fn() do
      case File.read(marker) do
        Ok("armed") -> Ok(nil)
        _ -> Err("receipt_owner_retired")
      end
    end
  }
  assert(read_receipt(guarded,
    pins,
    hash,
    snapshot.slot) == Err("rpc_context_changed:receipt_owner_retired"))
  # These operator-only pins must be checked even though permanent reads do not
  # fetch governance, oracle, economics or bond accounts.
  let invalid = %{pins | source_revision: U64.parse("0")?}
  assert(receipt_keys(invalid, hash) == Err("collateral_operator_pins"))
  assert(decode_receipt_snapshot(invalid,
    hash,
    snapshot.slot,
    snapshot) == Err("collateral_operator_pins"))
  assert(read_receipt(rpc, invalid, hash, snapshot.slot) == Err("collateral_operator_pins"))
  for sources in [
    List.take(rpc.sources, 2),
    rpc.sources ++ [List.get(rpc.sources, 0)],
    [List.get(rpc.sources, 0), List.get(rpc.sources, 0), List.get(rpc.sources, 2)],
    [%{List.get(rpc.sources, 0) | url: List.get(urls, 0) <> "/rpc"}] ++ List.drop(rpc.sources, 1)
  ] do
    assert(read_receipt(%{rpc | sources: sources},
      pins,
      hash,
      snapshot.slot) == Err("collateral_operator_sources"))
  end
  Ok(true)
end

test("actual matching HTTP receipts cannot override fatal third-origin roots or retired authority") do
  case boundaries() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end
