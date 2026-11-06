from Transparency.AnchorChain import AnchorPins, anchor_addresses
from Transparency.AnchorRegistry import read_collectible_witnesses
from Transparency.AttendanceRead import read_attendance
from Transparency.RewardsRead import read_rewards, read_rewards_account_slices
from Transparency.RelayClock import check_relay_clock
from Transparency.RelayLookupRead import read_relay_lookup_cooldown
from Transparency.RpcTransport import (
  RpcTls, RpcEndpoint, RpcTransport, rpc_endpoint, rpc_transport,
  webpki_rpc_transport, rpc_urls, rpc_fatal_error
)
from Transparency.AnchorRpc import read_anchor_rpc_response, read_anchor_time_quorum, read_anchor_quorum
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorHttp import fetch_anchor_proof
from Solana.Read import get_block_time_request, pubkey

fn current() -> Result<(), String> do
  Ok(nil)
end

fn refuses() -> Result<(), String> do
  Err("account_state_changed")
end

fn boundaries() -> Result<(), String> do
  let one = rpc_endpoint("http://127.0.0.1:19991/rpc?key=one", WebPki)?
  let rpc = rpc_transport([one], current)?
  let request = get_block_time_request(1, U64.parse("1")?)?
  let forged = %{one | url: "http://127.0.0.1:19992/rpc"}
  assert(read_anchor_rpc_response(rpc, forged, request, 1024) == Err("rpc_tls_config_invalid"))
  let changed = %{one | tls: OriginRoots("https://127.0.0.1:19991", Bytes.from_utf8("invalid"))}
  assert(read_anchor_rpc_response(rpc, changed, request, 1024) == Err("rpc_tls_config_invalid"))
  let guarded = rpc_transport([one], refuses)?
  assert(read_anchor_rpc_response(guarded, one, request, 1024)
    == Err("rpc_context_changed:account_state_changed"))
  let urls = ["http://127.0.0.1:19991/a", "http://127.0.0.1:19992/b", "http://127.0.0.1:19993/c"]
  let web = webpki_rpc_transport(urls)?
  assert(rpc_urls(web) == urls)
  let blocked = %{web | require_current: refuses}
  assert(read_anchor_time_quorum(blocked, U64.parse("1")?)
    == Err("rpc_context_changed:account_state_changed"))
  assert(read_anchor_accounts(blocked, [pubkey("11111111111111111111111111111111")?], U64.parse("0")?)
    == Err("rpc_context_changed:account_state_changed"))
  assert(fetch_anchor_proof("http://127.0.0.1:19991", "/proof", Bytes.empty(), 1024, refuses)
    == Err("rpc_context_changed:account_state_changed"))
  let malformed = rpc_endpoint("https://127.0.0.1:19991/rpc",
    OriginRoots("https://127.0.0.1:19991", Bytes.from_utf8("bad PEM")))?
  let poisoned = rpc_transport([malformed], current)?
  let forged_roots = %{malformed | tls: OriginRoots("https://127.0.0.1:19991", Bytes.from_utf8("other roots"))}
  assert(read_anchor_rpc_response(poisoned, forged_roots, request, 1024) == Err("rpc_tls_config_invalid"))
  let stripped = %{malformed | tls: WebPki}
  assert(read_anchor_rpc_response(poisoned, stripped, request, 1024) == Err("rpc_tls_config_invalid"))
  assert(read_anchor_rpc_response(poisoned, malformed, request, 1024) == Err("rpc_tls_config_invalid"))
  assert(rpc_endpoint("https://one.example/rpc", OriginRoots("https://two.example", Bytes.from_utf8("pem")))
    == Err("rpc_tls_config_invalid"))
  assert(rpc_fatal_error("rpc_tls_config_invalid"))
  assert(rpc_fatal_error("rpc_context_changed:account_state_changed"))
  assert(!rpc_fatal_error("anchor_rpc_unavailable"))
  Ok(nil)
end

test("paired RPC boundaries refuse membership changes, guard retirement and malformed attempted roots") do
  assert(boundaries() == Ok(nil))
end

# Each independent quorum family must retain refusal errors before optional or
# two-of-three combination can turn them into an unavailable/accepted result.
fn fatal_readers(rpc :: RpcTransport, expected :: String) -> Result<(), String> do
  let address = pubkey("11111111111111111111111111111111")?
  let other = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let derived = anchor_addresses(address, "morse-main")?
  let pins = AnchorPins { program: address, ring: derived.ring, log_name: "morse-main", log_id: derived.log_id, rpc: rpc }
  let key = Bytes.from_hex(String.repeat("01", 32))?
  let zero = U64.parse("0")?
  case read_anchor_quorum(rpc, address, address, 0, 4, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case read_collectible_witnesses(pins, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case read_attendance(pins, key, 1, zero, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case read_rewards(pins, key, 1, other, other, zero, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case read_rewards_account_slices(pins, [address], 4, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case check_relay_clock(rpc, zero, zero, zero, zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  case read_relay_lookup_cooldown(rpc, address, zero, [other], zero) do
    Err(error) -> assert(error == expected)
    Ok(_) -> assert(false)
  end
  Ok(nil)
end

fn fatal_quorums() -> Result<(), String> do
  let guarded = rpc_transport(for port in 19991..19994 do
      rpc_endpoint("http://127.0.0.1:#{port}/rpc", WebPki)?
    end,
    refuses)?
  assert(fatal_readers(guarded, "rpc_context_changed:account_state_changed") == Ok(nil))
  let poisoned = rpc_transport(for port in 19991..19994 do
      rpc_endpoint("https://127.0.0.1:#{port}/rpc", OriginRoots("https://127.0.0.1:#{port}", Bytes.from_utf8("invalid PEM")))?
    end,
    current)?
  assert(fatal_readers(poisoned, "rpc_tls_config_invalid") == Ok(nil))
  Ok(nil)
end

test("all shared account, optional registry, attendance, rewards, clock and cooldown quorums preserve fatal refusal") do
  assert(fatal_quorums() == Ok(nil))
end
