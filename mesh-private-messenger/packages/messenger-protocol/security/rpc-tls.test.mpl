from Transparency.RpcTransport import (
  RpcTls, RpcEndpoint, RpcTransport, rpc_endpoint, rpc_transport, rpc_urls,
  webpki_rpc_transport, rpc_fatal_error
)
from Transparency.AnchorRpc import read_anchor_rpc_response, read_anchor_account, read_anchor_quorum, read_anchor_time_quorum
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorChain import AnchorPins, anchor_addresses, sample_anchor_sources, configured_anchor_pins
from Transparency.AnchorHttp import fetch_anchor_proof
from Transparency.Config import SecurityConfig
from Solana.Read import pubkey, get_block_time_request

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn current() -> Result<(), String> do
  Ok(nil)
end

fn proof(path :: String) -> Result<(), String> do
  let fixture = Json.parse(File.read(path)?)?
  let rows = Json.object_get(fixture, "sources")?
  let sources = for index in 0..3 do
    let row = Json.array_get(rows, index)?
    rpc_endpoint(text(row, "url")?, OriginRoots(text(row, "origin")?, Bytes.from_hex(text(row, "pem_hex")?)?))?
  end
  let rpc = rpc_transport(sources, current)?
  let slot = U64.parse("12")?
  let zero = U64.parse("0")?
  let address = pubkey("11111111111111111111111111111111")?
  let request = get_block_time_request(1, slot)?
  assert(read_anchor_time_quorum(rpc, slot) == Ok(1700000000))
  let account = read_anchor_account(rpc, List.head(sources), address, address, 0, 4, zero)?
  assert(account.slot == slot && Bytes.to_hex(account.account.data) == "01020304")
  let agreed = read_anchor_quorum(rpc, address, address, 0, 4, zero)?
  assert(Bytes.to_hex(agreed.data) == "01020304" && agreed.context_slot == slot)
  let batch = read_anchor_accounts(rpc, [address, address], zero)?
  assert(List.length(batch.accounts) == 2 && batch.slot == slot)
  # Roots stay attached while sampling; all sources are independently checked
  # because two distinct authorities sign the three local TLS peers.
  let derived = anchor_addresses(address, "morse-main")?
  let pins = AnchorPins { program: address, ring: derived.ring, log_name: "morse-main", log_id: derived.log_id, rpc: rpc }
  let sampled = sample_anchor_sources(pins)?
  assert(read_anchor_time_quorum(sampled.rpc, slot) == Ok(1700000000))
  let config = SecurityConfig {
    version: 4, wire_version: 4, minimum_session_suite: 1,
    service_public_key: Bytes.empty(), delivery_public_key: Bytes.empty(),
    abuse_difficulty: 0, threshold: 0, witnesses: [], set_id: Bytes.empty(),
    anchor_address: "11111111111111111111111111111111", anchor_program: "11111111111111111111111111111111",
    anchor_log_name: "morse-main", rpc_urls: rpc_urls(rpc), issuer_origin: "-",
    log_version: 1, legacy_threshold: 0, legacy_witnesses: [], relay_urls: [], slash_mint: "-"
  }
  let reversed = rpc_transport(List.reverse(sources), current)?
  case configured_anchor_pins(config, reversed) do
    Err(error) -> assert(error == "rpc_tls_config_invalid")
    Ok(_) -> assert(false)
  end
  let first = List.head(sources)
  let first_origin = Http.url_origin(first.url)?
  let wrong_pem = Bytes.from_hex(text(fixture, "wrong_pem_hex")?)?
  let wrong = %{first | tls: OriginRoots(first_origin, wrong_pem)}
  let wrong_rpc = rpc_transport([wrong, List.get(sources, 1), List.get(sources, 2)], current)?
  assert(read_anchor_rpc_response(wrong_rpc, wrong, request, 1024) == Err("anchor_rpc_unavailable"))
  assert(read_anchor_time_quorum(wrong_rpc, slot) == Ok(1700000000))
  assert(read_anchor_accounts(wrong_rpc, [address, address], zero)?.slot == slot)
  # Valid explicit roots cannot poison the following default-root request pool.
  let web = webpki_rpc_transport([first.url])?
  assert(read_anchor_rpc_response(web, List.head(web.sources), request, 1024) == Err("anchor_rpc_unavailable"))
  let malformed = %{first | tls: OriginRoots(first_origin, Bytes.from_utf8("invalid PEM"))}
  let poisoned = rpc_transport([malformed, List.get(sources, 1), List.get(sources, 2)], current)?
  assert(read_anchor_time_quorum(poisoned, slot) == Err("rpc_tls_config_invalid"))
  assert(read_anchor_accounts(poisoned, [address, address], zero) == Err("rpc_tls_config_invalid"))
  let poisoned_second = rpc_transport([first, %{List.get(sources, 1) | tls: OriginRoots(Http.url_origin(List.get(sources, 1).url)?, Bytes.from_utf8("invalid PEM"))}, List.get(sources, 2)], current)?
  assert(read_anchor_time_quorum(poisoned_second, slot) == Err("rpc_tls_config_invalid"))
  for route in ["redirect", "wrong-id", "oversized"] do
    let endpoint = %{first | url: first_origin <> "/" <> route}
    let restricted = rpc_transport([endpoint], current)?
    case read_anchor_rpc_response(restricted, endpoint, request, 1024) do
      Err(error) -> assert(!rpc_fatal_error(error))
      Ok(_) -> assert(false)
    end
  end
  # The server changes the marker after receiving the POST and before returning
  # either response bytes or a disconnected socket. This is an HTTP barrier.
  let marker = text(fixture, "marker")?
  for route in ["retire-success", "retire-error"] do
    File.write(marker, "current")?
    let guard = fn() do
      if File.read(marker)? == "current" do Ok(nil) else Err("account_state_changed") end
    end
    let endpoint = %{first | url: first_origin <> "/" <> route}
    let guarded = rpc_transport([endpoint], guard)?
    assert(read_anchor_rpc_response(guarded, endpoint, request, 1024)
      == Err("rpc_context_changed:account_state_changed"))
    assert(fetch_anchor_proof(text(fixture, "directory")?, "/never", Bytes.empty(), 1024, guard)
      == Err("rpc_context_changed:account_state_changed"))
  end
  # Directory proof HTTP shares the guard only, and never inherits RPC roots.
  let (unavailable, _) = fetch_anchor_proof(first_origin, "/proof", Bytes.empty(), 1024, current)?
  assert(unavailable == "proof_unavailable")
  for route in ["retire-success", "retire-error"] do
    File.write(marker, "current")?
    let guard = fn() do
      if File.read(marker)? == "current" do Ok(nil) else Err("account_state_changed") end
    end
    assert(fetch_anchor_proof(text(fixture, "directory")?, "/" <> route, Bytes.empty(), 1024, guard)
      == Err("rpc_context_changed:account_state_changed"))
  end
  Ok(nil)
end

test("owned TLS peers exercise the shared paired RPC sender and refusal guards") do
  let path = Env.get("MORSE_RPC_TLS_FIXTURE", "")
  if path != "" do
    case proof(path) do
      Ok(_) -> nil
      Err(error) -> do println(error); assert(false) end
    end
  end
end
