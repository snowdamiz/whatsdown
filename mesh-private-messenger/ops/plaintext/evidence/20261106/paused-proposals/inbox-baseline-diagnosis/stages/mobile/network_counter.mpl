from Mobile.NetworkCounterHistory import (
  NetworkSlashFact,
  load_counter_slashes,
  retain_counter_slashes,
  counter_history_mask
)

##! Optional native Settings counter. It never writes an anchor observation,
##! anchor scheduler, transparency checkpoint, profile or session record.
from Mobile.NetworkCounterPins import (
  NetworkCounterPins,
  decode_network_counter_pins,
  counter_integer
)
from Mobile.NetworkCounterState import (
  counter_fresh,
  NetworkBondObservation,
  network_counter_keys,
  decode_network_bonds
)
from Mobile.Platform import native_security_config
from Mobile.Codec import current_time
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import compare_and_swap_blobs
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Solana.Read import (
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_request_json,
  rpc_response
)

pub struct NetworkCounterCache do
  ciphertext :: Bytes
  wire :: Bytes
  checked :: U64
  slot :: U64
  slash_mask :: Int
end

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn u(value :: U64) -> String do
  q(U64.to_string(value))
end

fn maybe(value :: Option<U64>) -> String do
  case value do
    None -> "null"
    Some(n) -> u(n)
  end
end

fn maybe_address(value :: Option<Bytes>) -> String do
  case value do
    None -> "null"
    Some(bytes) -> q(Bytes.to_base58(bytes))
  end
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn power_two(index :: Int) -> Int do
  if index == 0 do
    1
  else
    2 * power_two(index - 1)
  end
end

pub fn counter_slash_mask(value :: NetworkBondObservation) -> Int do
  let indices = for index in 0..List.length(value.rows) do
    index
  end
  List.reduce(indices,
    if value.service_slashed do
      1
    else
      0
    end,
    fn(mask, index) do
      if index > 0 && List.get(value.rows, index).status == 3 do
        mask + power_two(index)
      else
        mask
      end
    end)
end

pub fn counter_preserves_slash(previous :: Int, current :: Int) -> Bool do
  if previous == 0 do
    true
  else if previous % 2 == 1 && current % 2 == 0 do
    false
  else
    counter_preserves_slash(previous / 2, current / 2)
  end
end

pub fn network_counter_output(pins :: NetworkCounterPins,
  value :: NetworkBondObservation,
  checked :: U64) -> Bytes!String do
  let rows = for index in 0..List.length(value.rows) do
    let row = List.get(value.rows, index)
    let operator = if index == 0 do
      "Morse"
    else
      List.get(pins.security.witnesses, index - 1).operator_label
    end
    let dollars = case row.usd_micros do
      None -> "null"
      Some(n) -> q(U128.to_string(n))
    end
    """{"witness_id":#{q(row.witness_id)},"operator_label":#{q(operator)},"public_key":#{q(Bytes.to_hex(row.public_key))},"address":#{q(Bytes.to_base58(row.address.bytes))},"owner":#{q(Bytes.to_base58(row.owner))},"mint":#{maybe_address(row.mint)},"vault":#{maybe_address(row.vault)},"asset":#{q(row.asset)},"layout":#{row.layout},"status":#{row.status},"principal_units":#{maybe(row.principal)},"pending_units":#{maybe(row.pending)},"pending_recorded_units":#{maybe(row.pending_recorded)},"balance_units":#{maybe(row.balance)},"donation_units":#{maybe(row.donation)},"opposite_balance_units":#{maybe(row.opposite_balance)},"usdc_vault_units":#{maybe(row.usdc_vault)},"morse_vault_units":#{maybe(row.morse_vault)},"bonded_at":#{u(row.bonded_at)},"unbond_at":#{u(row.unbond_at)},"slashed_at":#{u(row.slashed_at)},"underwater_since":#{u(row.underwater_since)},"usd_micros":#{dollars}}"""
  end
  Ok(Bytes.from_utf8("NCR1"
    <> """{"schema_version":1,"status":"available","reason":"fresh-finalized-quorum","config_id":#{q(Bytes.to_hex(pins.identity))},"checked_at":#{u(checked)},"slash_mask":#{counter_slash_mask(value)},"slash_history":[],"observation":{"context_slot":#{u(value.slot)},"bank_time":#{u(value.timestamp)},"observed_at":#{u(checked)},"service_slashed":#{flag(value.service_slashed)},"witnesses_slashed":#{value.witnesses_slashed},"digest":#{q(Bytes.to_hex(value.digest))},"log_name":"morse-main","judge":#{q(pins.security.anchor_program)},"valuation":#{q(value.valuation)},"twap_usd_micros":#{maybe(value.twap)},"rows":[#{String.join(rows,
      ",")}]}}"""))
end

pub fn counter_unavailable(status :: String,
  reason :: String,
  identity :: String,
  checked :: U64) -> Bytes do
  Bytes.from_utf8("NCR1"
    <> """{"schema_version":1,"status":#{q(status)},"reason":#{q(reason)},"config_id":#{q(identity)},"checked_at":#{u(checked)},"slash_mask":0,"slash_history":[],"observation":null}""")
end

fn root(wire :: Bytes) -> Json!String do
  if Bytes.length(wire) < 5
    || Bytes.length(wire) > 32768
    || Bytes.to_utf8(Bytes.slice(wire, 0, 4)?)? != "NCR1" do
    return Err("invalid_network_counter_cache")
  end
  Json.parse(Bytes.to_utf8(Bytes.slice(wire, 4, Bytes.length(wire) - 4)?)?)
end

pub fn counter_historical(previous :: Bytes, reason :: String, checked :: U64) -> Bytes!String do
  let value = root(previous)?
  let observation = Json.object_get(value, "observation")?
  let identity = Json.as_string(Json.object_get(value, "config_id")?)?
  let mask = Json.as_int(Json.object_get(value, "slash_mask")?)?
  Ok(Bytes.from_utf8("NCR1"
    <> """{"schema_version":1,"status":"historical","reason":#{q(reason)},"config_id":#{q(identity)},"checked_at":#{u(checked)},"slash_mask":#{mask},"slash_history":#{Json.encode(Json.object_get(value,
      "slash_history")?)},"observation":#{Json.encode(observation)}}"""))
end

pub fn counter_observe(pins :: NetworkCounterPins,
  endpoint :: String,
  minimum :: U64,
  checked :: U64) -> NetworkBondObservation!String do
  let keys = network_counter_keys(pins)?
  if List.length(keys) > 100 do
    return Err("counter_account_bound")
  end
  let rpc = get_multiple_accounts_slice_request(1, keys, "finalized", 0, 8416, Some(minimum))?
  let request = Http.build(:post, endpoint)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(rpc_request_json(rpc))
    |> Http.timeout(5000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(524288)
  let request = case pins.tls_root do
    None -> request
    Some(pem) -> Http.trust_root_pem(request, pem)
  end
  let response = Http.send(request)?
  if response.status != 200 do
    return Err("counter_rpc_unavailable")
  end
  let decoded = rpc_response(response.body)?
  if decoded.id != 1 do
    return Err("counter_rpc_id")
  end
  decode_network_bonds(pins, optional_accounts_slice_from_response(decoded)?, minimum, checked)
end

fn agreement(a :: NetworkBondObservation!String,
  b :: NetworkBondObservation!String) -> Option<NetworkBondObservation> do
  case (a, b) do
    (Ok(first), Ok(second)) -> if first.digest == second.digest do
      Some(first)
    else
      None
    end
    _ -> None
  end
end

pub fn read_network_counter(pins :: NetworkCounterPins,
  minimum :: U64,
  checked :: U64) -> NetworkBondObservation!String do
  # Endpoints were authenticated as part of the exact security frame. No URL
  # comes from a JS request or the optional frame itself.
  let sources = pins.security.rpc_urls
  let a = counter_observe(pins, List.get(sources, 0), minimum, checked)
  let b = counter_observe(pins, List.get(sources, 1), minimum, checked)
  let c = counter_observe(pins, List.get(sources, 2), minimum, checked)
  for value in [agreement(a, b), agreement(a, c), agreement(b, c)] do
    case value do
      Some(observation) -> return Ok(observation)
      None -> nil
    end
  end
  let good = List.length(List.filter([a, b, c], fn(value) -> Result.is_ok(value) end))
  Err(if good >= 2 do
    "counter_rpc_disagreed"
  else
    "counter_rpc_unavailable"
  end)
end

fn cache_label(pins :: NetworkCounterPins) -> String do
  "network-counter/v1/" <> Bytes.to_hex(pins.identity)
end

pub fn load_network_counter_cache(path :: String,
  pins :: NetworkCounterPins,
  key :: borrow StorageKey) -> NetworkCounterCache!String do
  let ciphertext = case load_blob(path, cache_label(pins)) do
    Err(error) -> if error == "local_state_not_found" do
      Bytes.empty()
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  if Bytes.length(ciphertext) == 0 do
    return Ok(NetworkCounterCache {
      ciphertext: ciphertext,
      wire: Bytes.empty(),
      checked: U64.parse("0")?,
      slot: U64.parse("0")?,
      slash_mask: 0
    })
  end
  let wire = open_local(ciphertext, key, local_context(cache_label(pins))?)?
  let decoded = root(wire)?
  if Json.as_int(Json.object_get(decoded, "schema_version")?)? != 1
    || Json.as_string(Json.object_get(decoded, "config_id")?)? != Bytes.to_hex(pins.identity) do
    return Err("invalid_network_counter_cache")
  end
  let mask = Json.as_int(Json.object_get(decoded, "slash_mask")?)?
  if mask < 0 || mask >= power_two(List.length(pins.security.witnesses) + 1) do
    return Err("invalid_network_counter_cache")
  end
  let observation = Json.object_get(decoded, "observation")?
  let slot = case Json.object_get(observation, "context_slot") do
    Err(_) -> U64.parse("0")?
    Ok(value) -> counter_integer(Json.as_string(value)?)?
  end
  Ok(NetworkCounterCache {
    ciphertext: ciphertext,
    wire: wire,
    checked: counter_integer(Json.as_string(Json.object_get(decoded, "checked_at")?)?)?,
    slot: slot,
    slash_mask: mask
  })
end

pub fn attach_counter_history(wire :: Bytes,
  facts :: List<NetworkSlashFact>,
  pins :: NetworkCounterPins) -> Bytes!String do
  let value = root(wire)?
  let current = Json.as_int(Json.object_get(value, "slash_mask")?)?
  let history = for fact in facts do
    let id = if fact.index == 0 do
      ""
    else
      List.get(pins.security.witnesses, fact.index - 1).witness_id
    end
    let public_key = if fact.index == 0 do
      String.repeat("00", 32)
    else
      Bytes.to_hex(List.get(pins.security.witnesses, fact.index - 1).public_key)
    end
    """{"index":#{fact.index},"witness_id":#{q(id)},"public_key":#{q(public_key)},"context_slot":#{u(fact.slot)},"bank_time":#{u(fact.timestamp)},"digest":#{q(Bytes.to_hex(fact.digest))}}"""
  end
  let prior_status = Json.as_string(Json.object_get(value, "status")?)?
  let contradiction = prior_status == "available"
    && !counter_preserves_slash(counter_history_mask(facts), current)
  let status = if contradiction || (List.length(facts) > 0 && prior_status == "unavailable") do
    "historical"
  else
    prior_status
  end
  let reason = if contradiction do
    "slash-contradiction"
  else
    Json.as_string(Json.object_get(value, "reason")?)?
  end
  # A contradictory current record is not retained history. Discard its
  # financial/status rows; only independently authenticated prior facts remain.
  let observation = if contradiction do
    "null"
  else
    Json.encode(Json.object_get(value, "observation")?)
  end
  let current_mask = if contradiction do
    0
  else
    current
  end
  Ok(Bytes.from_utf8("NCR1"
    <> """{"schema_version":1,"status":#{q(status)},"reason":#{q(reason)},"config_id":#{Json.encode(Json.object_get(value,
      "config_id")?)},"checked_at":#{Json.encode(Json.object_get(value,
      "checked_at")?)},"slash_mask":#{current_mask},"slash_history":[#{String.join(history,
      ",")}],"observation":#{observation}}"""))
end

pub fn refresh_network_counter(path :: String,
  pins :: NetworkCounterPins,
  key :: borrow StorageKey,
  checked :: U64) -> Bytes!String do
  ensure_schema(path)?
  let cached = load_network_counter_cache(path, pins, key)
  let retained = load_counter_slashes(path, pins, key)
  let history = case retained do
    Ok(values) -> values
    Err(_) -> case cached do
      Ok(previous) -> if previous.slot != U64.parse("0")? do
        return counter_historical(previous.wire, "counter-history-unavailable", checked)
      else
        return Err("counter_local_state")
      end
      Err(_) -> return Err("counter_local_state")
    end
  end
  let cache = case cached do
    Ok(value) -> value
    Err(_) -> return attach_counter_history(counter_unavailable("unavailable",
        "counter-local-state",
        Bytes.to_hex(pins.identity),
        checked),
      history,
      pins)
  end
  if Bytes.length(cache.wire) > 0 do
    if U64.compare(checked, cache.checked) < 0 do
      let previous = if cache.slot == U64.parse("0")? do
        counter_unavailable("unavailable", "clock-rollback", Bytes.to_hex(pins.identity), checked)
      else
        counter_historical(cache.wire, "clock-rollback", checked)?
      end
      return attach_counter_history(previous, history, pins)
    end
    if U64.compare(U64.subtract(checked, cache.checked)?, U64.parse("60000")?) < 0 do
      let cached_value = root(cache.wire)?
      if Json.as_string(Json.object_get(cached_value, "status")?)? == "available"
        && cache.slot != U64.parse("0")? do
        let observed = Json.object_get(cached_value, "observation")?
        let bank_time = counter_integer(Json.as_string(Json.object_get(observed, "bank_time")?)?)?
        if !counter_fresh(bank_time, checked)? do
          return attach_counter_history(counter_historical(cache.wire,
              "counter-stale-cache",
              checked)?,
            history,
            pins)
        end
      end
      return attach_counter_history(cache.wire, history, pins)
    end
  end
  let minimum = List.reduce(history,
    if U64.compare(cache.slot, pins.minimum_slot) > 0 do
      cache.slot
    else
      pins.minimum_slot
    end,
    fn(slot, fact) do
      if U64.compare(fact.slot, slot) > 0 do
        fact.slot
      else
        slot
      end
    end)
  let fresh = read_network_counter(pins, minimum, checked)
  let result = case fresh do
    Ok(value) -> do
      retain_counter_slashes(path, pins, key, value)?
      network_counter_output(pins, value, checked)?
    end
    Err(error) -> if Bytes.length(cache.wire) > 0 && cache.slot != U64.parse("0")? do
      counter_historical(cache.wire, error, checked)?
    else
      counter_unavailable("unavailable", error, Bytes.to_hex(pins.identity), checked)
    end
  end
  let facts = load_counter_slashes(path, pins, key)?
  let result = attach_counter_history(result, facts, pins)?
  let sealed = seal_local(result, key, local_context(cache_label(pins))?)?
  case compare_and_swap_blobs(path, [cache_label(pins)], [sealed], cache.ciphertext) do
    Ok(_) -> Ok(result)
    Err(error) -> if error == "local_state_changed" do
      # Immutable slash facts commit before the display CAS. Even the losing
      # request's proven slash survives and is reattached to the winning cache.
      attach_counter_history(load_network_counter_cache(path, pins, key)?.wire,
        load_counter_slashes(path, pins, key)?,
        pins)
    else
      Err(error)
    end
  end
end

pub fn native_network_counter(path :: String) -> Bytes!String do
  let checked = current_time()?
  let security = case native_security_config() do
    Err(_) -> return Ok(counter_unavailable("unavailable", "security-configuration", "", checked))
    Ok(value) -> value
  end
  let frame = case Host.push_get_token(Bytes.from_utf8("messenger/network-counter/v1")) do
    Err(_) -> return Ok(counter_unavailable("unconfigured", "counter-not-configured", "", checked))
    Ok(value) -> if Bytes.length(value) == 0 do
      return Ok(counter_unavailable("unconfigured", "counter-not-configured", "", checked))
    else
      value
    end
  end
  let pins = case decode_network_counter_pins(frame, security) do
    Err(_) -> return Ok(counter_unavailable("unavailable", "counter-configuration", "", checked))
    Ok(value) -> value
  end
  let key = platform_key()?
  let result = refresh_network_counter(path, pins, key, checked)
  Secret.destroy(key)
  case result do
    Err(_) -> Ok(counter_unavailable("unavailable",
      "counter-local-state",
      Bytes.to_hex(pins.identity),
      checked))
    Ok(value) -> finish_network_counter(value, checked, current_time()?)
  end
end

# The production entry samples this after all RPC/storage work. Replay readers
# keep their explicit clock. This only downgrades an available observation and
# preserves the exact authenticated rows and immutable historical slash facts.
pub fn finish_network_counter(wire :: Bytes, started :: U64, completed :: U64) -> Bytes!String do
  let value = root(wire)?
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 1 do
    return Err("invalid_network_counter_cache")
  end
  let status = Json.as_string(Json.object_get(value, "status")?)?
  let checked = counter_integer(Json.as_string(Json.object_get(value, "checked_at")?)?)?
  if !List.contains(["available", "historical", "unavailable", "unconfigured"], status) do
    return Err("invalid_network_counter_cache")
  end
  if status != "available" do
    return Ok(wire)
  end
  if U64.compare(completed, started) < 0 || U64.compare(completed, checked) < 0 do
    return counter_historical(wire, "clock-rollback", completed)
  end
  let observation = Json.object_get(value, "observation")?
  let timestamp = counter_integer(Json.as_string(Json.object_get(observation, "bank_time")?)?)?
  if !counter_fresh(timestamp, completed)? do
    return counter_historical(wire, "counter-stale-completion", completed)
  end
  Ok(wire)
end
