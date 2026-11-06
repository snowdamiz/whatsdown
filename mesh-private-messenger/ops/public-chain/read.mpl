from HistoryLegacyReport import read_legacy_public_report
from HistoryReport import parse_public_history, read_public_history_report
from Transparency.TokenBurnRead import TokenBurnReadPins, token_burn_rpc_sources
from Transparency.TokenBurnCarryRead import TokenBurnCarryState, read_token_burn_carry_from
from Solana.Read import pubkey
from CollateralPins import parse_collateral
from CollateralRead import read_public_bonds, read_public_slashes
from Report import burn_snapshot_report, unavailable_burn_report

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn canonical(value :: String) -> U64!String do
  let parsed = U64.parse(value)?
  if U64.to_string(parsed) != value do
    Err("noncanonical_report_integer")
  else
    Ok(parsed)
  end
end

fn agree(first :: TokenBurnCarryState!String,
  second :: TokenBurnCarryState!String) -> Option<TokenBurnCarryState> do
  case first do
    Err(_) -> None
    Ok(a) -> case second do
      Err(_) -> None
      Ok(b) -> if a.digest == b.digest do
        Some(a)
      else
        None
      end
    end
  end
end

fn valid(value :: TokenBurnCarryState!String) -> Int do
  case value do
    Err(_) -> 0
    Ok(_) -> 1
  end
end

fn read_epoch(client :: Int,
  sources :: List<String>,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> String!String do
  let first = read_token_burn_carry_from(client, List.get(sources, 0), pins, epoch, minimum)
  let second = read_token_burn_carry_from(client, List.get(sources, 1), pins, epoch, minimum)
  let third = read_token_burn_carry_from(client, List.get(sources, 2), pins, epoch, minimum)
  for pair in [agree(first, second), agree(first, third), agree(second, third)] do
    case pair do
      None -> nil
      Some(value) -> return burn_snapshot_report(pins, epoch, value)
    end
  end
  Ok(unavailable_burn_report(epoch,
    if valid(first) + valid(second) + valid(third) >= 2 do
      "disagreed"
    else
      "unavailable"
    end))
end

pub fn read_public_report(input :: String) -> String!String do
  if String.length(input) > 32768 do
    return Err("report_input_too_large")
  end
  let root = Json.parse(input)?
  if Json.as_int(Json.object_get(root, "schema_version")?)? != 1 do
    return Err("invalid_report_schema")
  end
  let scope = text(root, "scope")?
  if scope != "local-fixture" && scope != "configured-rpc" do
    return Err("invalid_report_scope")
  end
  case Json.object_get(root, "legacy_collateral") do
    Ok(_) -> return read_legacy_public_report(root)
    Err(_) -> nil
  end
  let p = Json.object_get(root, "pins")?
  let pins = TokenBurnReadPins {
    program: pubkey(text(p, "program")?)?,
    governance: pubkey(text(p, "governance")?)?,
    program_slot: canonical(text(p, "program_slot")?)?,
    usdc: pubkey(text(p, "usdc")?)?,
    treasury: pubkey(text(p, "treasury")?)?,
    factory: pubkey(text(p, "factory")?)?
  }
  let sources_json = Json.object_get(root, "endpoints")?
  if Json.array_length(sources_json)? != 3 do
    return Err("invalid_report_sources")
  end
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(sources_json, index)?)?
  end
  token_burn_rpc_sources(sources, scope == "local-fixture")?
  let history = parse_public_history(root)?
  let epochs_json = Json.object_get(root, "epochs")?
  let count = Json.array_length(epochs_json)?
  if (count < 1 && history == None) || count > 16 do
    return Err("invalid_report_epoch_count")
  end
  let epochs = for index in 0..count do
    canonical(Json.as_string(Json.array_get(epochs_json, index)?)?)?
  end
  for index in 0..count do
    for previous in 0..index do
      if List.get(epochs, index) == List.get(epochs, previous) do
        return Err("duplicate_report_epoch")
      end
    end
  end
  let minimum = canonical(text(root, "minimum_context_slot")?)?
  let generated = canonical(text(root, "generated_at_unix")?)?
  let age = canonical(text(root, "max_age_seconds")?)?
  if age == U64.parse("0")? || U64.compare(age, U64.parse("86400")?) > 0 do
    return Err("invalid_report_max_age")
  end
  let collateral = parse_collateral(root, pins)?
  let client = Http.client()
  let result = for epoch in epochs do
    read_epoch(client, sources, pins, epoch, minimum)
  end
  let bonds = case collateral do
    None -> Ok("""{"availability":"unavailable","reason":"v2-finalized-custody-adapter-not-qualified"}""")
    Some(value) -> read_public_bonds(client, sources, value, minimum)
  end
  let slashes = case collateral do
    None -> Ok("""{"availability":"unavailable","reason":"v2-finalized-receipt-adapter-and-public-index-not-qualified"}""")
    Some(value) -> read_public_slashes(client, sources, value, minimum)
  end
  let indexed = case history do
    None -> Ok("")
    Some(options) -> read_public_history_report(client,
      sources,
      scope == "local-fixture",
      pins,
      collateral,
      minimum,
      options)
  end
  Http.client_close(client)
  let index_report = indexed?
  let completeness = if history == None do
    "selected-epochs-only"
  else
    "bounded-filtered-index-with-separate-value-pages"
  end
  let history_field = if history == None do
    ""
  else
    ",\"history\":" <> index_report
  end
  let bonds_json = bonds?
  let slashes_json = slashes?
  let rows = for value in result do
    value?
  end
  Ok("""{"schema_version":1,"scope":#{Json.encode_string(scope)},"generated_at_unix":#{Json.encode_string(U64.to_string(generated))},"max_age_seconds":#{Json.encode_string(U64.to_string(age))},"provider_independence":"not-established","history_completeness":#{Json.encode_string(completeness)},"phase5_complete":false,"burns":[#{String.join(rows,
    ",")}],"bonds":#{bonds_json},"slashes":#{slashes_json}#{history_field}}""")
end
