from HistoryIndex import PublicHistoryRecord
from HistoryRead import PublicHistoryDiscovery, read_public_history_index
from CollateralPins import CollateralSelection
from CollateralRead import read_public_bonds, read_public_slashes
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnCarryRead import TokenBurnCarryState, read_token_burn_carry_from
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey_string
from Report import burn_snapshot_report, unavailable_burn_report

pub struct PublicHistoryOptions do
  maximum :: Int
  page_size :: Int
end

pub fn parse_public_history(root :: Json) -> Option<PublicHistoryOptions>!String do
  let value = case Json.object_get(root, "history") do
    Err(_) -> return Ok(None)
    Ok(value) -> value
  end
  let maximum = Json.as_int(Json.object_get(value, "maximum_records")?)?
  let size = Json.as_int(Json.object_get(value, "page_size")?)?
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 1
    || maximum < 1
    || maximum > 128
    || size < 1
    || size > 16 do
    return Err("public_history_options")
  end
  Ok(Some(PublicHistoryOptions { maximum: maximum, page_size: size }))
end

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn units(value :: U64) -> String do
  q(U64.to_string(value))
end

fn applicable(kind :: Int, row :: PublicHistoryRecord) -> Bool do
  row.verification == "supported" && (kind != 1 || row.registry_status > 0)
end

fn record_report(kind :: Int, row :: PublicHistoryRecord) -> String do
  let epoch = case row.epoch do
    None -> "null"
    Some(value) -> units(value)
  end
  let key = if Bytes.length(row.public_key) == 0 do
    "null"
  else
    q(Bytes.to_hex(row.public_key))
  end
  let proof = if Bytes.length(row.proof_hash) == 0 do
    "null"
  else
    q(Bytes.to_hex(row.proof_hash))
  end
  let status = if applicable(kind, row) do
    "requested"
  else if row.verification == "legacy" do
    "legacy-unrendered"
  else if row.verification == "supported" do
    "registry-only"
  else
    "unsupported"
  end
  """{"address":#{q(pubkey_string(row.address))},"version":#{row.version},"verification":#{q(row.verification)},"canonical_identity":#{flag(row.verification == "supported"
    || row.verification == "legacy")},"epoch":#{epoch},"witness_id":#{q(row.witness_id)},"public_key":#{key},"proof_hash":#{proof},"registry_status":#{row.registry_status},"value_status":#{q(status)}}"""
end

fn agree(a :: TokenBurnCarryState!String,
  b :: TokenBurnCarryState!String) -> Option<TokenBurnCarryState> do
  case a do
    Err(_) -> None
    Ok(first) -> case b do
      Err(_) -> None
      Ok(second) -> if first.digest == second.digest do
        Some(first)
      else
        None
      end
    end
  end
end

fn funded(value :: TokenBurnCarryState!String) -> TokenBurnCarryState!String do
  let state = value?
  if state.frame == None do
    Err("indexed_burn_record_missing")
  else
    Ok(state)
  end
end

fn burn_value(client :: Int,
  sources :: List<String>,
  base :: TokenBurnReadPins,
  row :: PublicHistoryRecord,
  minimum :: U64) -> String!String do
  let epoch = case row.epoch do
    None -> return Err("indexed_burn_identifier_missing")
    Some(value) -> value
  end
  let a = funded(read_token_burn_carry_from(client, List.get(sources, 0), base, epoch, minimum))
  let b = funded(read_token_burn_carry_from(client, List.get(sources, 1), base, epoch, minimum))
  let c = funded(read_token_burn_carry_from(client, List.get(sources, 2), base, epoch, minimum))
  for value in [agree(a, b), agree(a, c), agree(b, c)] do
    case value do
      None -> nil
      Some(state) -> return burn_snapshot_report(base, epoch, state)
    end
  end
  let count = List.reduce([a, b, c],
    0,
    fn(total, value) do total
      + case value do
        Err(_) -> 0
        Ok(_) -> 1
      end end)
  Ok(unavailable_burn_report(epoch,
    if count >= 2 do
      "disagreed"
    else
      "unavailable"
    end))
end

fn available(value :: String) -> Bool!String do
  Ok(Json.as_string(Json.object_get(Json.parse(value)?, "availability")?)? == "available")
end

fn page(client :: Int,
  sources :: List<String>,
  base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  discovery :: PublicHistoryDiscovery,
  kind :: Int,
  page_index :: Int,
  rows :: List<PublicHistoryRecord>) -> (String, Bool)!String do
  let requested = for row in rows do
    q(pubkey_string(row.address))
  end
  if kind == 0 do
    let values = for row in rows do
      burn_value(client, sources, base, row, discovery.index.slot)?
    end
    let checks = for value in values do
      available(value)?
    end
    let all = List.all(checks, fn(value) do value end)
    return Ok(("""{"page":#{page_index},"requested_addresses":[#{String.join(requested,
        ",")}],"bank_scope":"per-burn-record","complete":#{flag(all)},"values":[#{String.join(values,
        ",")}] }""",
      all))
  end
  let original = case selected do
    None -> return Err("public_history_collateral_not_configured")
    Some(value) -> value
  end
  let selection = if kind == 1 do
    CollateralSelection {
      pins: original.pins,
      witnesses: for row in rows do
        WitnessKey { witness_id: row.witness_id, public_key: row.public_key }
      end,
      proofs: []
    }
  else
    CollateralSelection {
      pins: original.pins,
      witnesses: [],
      proofs: for row in rows do
        row.proof_hash
      end
    }
  end
  let value = if kind == 1 do
    read_public_bonds(client, sources, selection, discovery.index.slot)?
  else
    read_public_slashes(client, sources, selection, discovery.index.slot)?
  end
  let all = available(value)?
  if all do
    let parsed = Json.parse(value)?
    let output = Json.object_get(parsed,
      if kind == 1 do
        "rows"
      else
        "receipts"
      end)?
    if Json.array_length(output)? != List.length(rows)
        + (if kind == 1 do
          1
        else
          0
        end) do
      return Err("public_history_page_incomplete")
    end
    for index in 0..List.length(rows) do
      let expected = List.get(rows, index)
      let actual = Json.array_get(output,
        index
          + (if kind == 1 do
            1
          else
            0
          end))?
      if kind == 1 do
        if Json.as_string(Json.object_get(actual, "witness_id")?)? != expected.witness_id
          || Json.as_string(Json.object_get(actual,
            "public_key")?)? != Bytes.to_hex(expected.public_key) do
          return Err("public_history_page_identifier")
        end
      else if Json.as_string(Json.object_get(actual,
        "address")?)? != pubkey_string(expected.address)
        || Json.as_string(Json.object_get(actual,
          "proof_hash")?)? != Bytes.to_hex(expected.proof_hash) do
        return Err("public_history_page_identifier")
      end
    end
  end
  Ok(("""{"page":#{page_index},"requested_addresses":[#{String.join(requested,
      ",")}],"bank_scope":"this-value-page-only","complete":#{flag(all)},"values":#{value}}""",
    all))
end

fn section(client :: Int,
  sources :: List<String>,
  test_mode :: Bool,
  base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  kind :: Int,
  minimum :: U64,
  options :: PublicHistoryOptions) -> String!String do
  let result = read_public_history_index(client,
    sources,
    test_mode,
    base,
    selected,
    kind,
    minimum,
    options.maximum)?
  let discovery = case result.observation do
    None -> return Ok("""{"availability":#{q(result.availability)},"reason":"no-complete-agreeing-index-at-authenticated-bank","upper_bound":#{options.maximum}}""")
    Some(value) -> value
  end
  let records = for row in discovery.index.records do
    record_report(kind, row)
  end
  let eligible = List.filter(discovery.index.records, fn(row) do applicable(kind, row) end)
  let pages = for index in 0..((List.length(eligible) + options.page_size - 1)
    / options.page_size) do
    page(client,
      sources,
      base,
      selected,
      discovery,
      kind,
      index,
      List.take(List.drop(eligible, index * options.page_size), options.page_size))?
  end
  let complete = discovery.index.supported_layouts_complete
    && List.all(discovery.index.records, fn(row) do row.verification != "legacy" end)
    && List.all(pages,
      fn(item) do
        let (_, valid) = item
        valid
      end)
  let bodies = for item in pages do
    let (body, _) = item
    body
  end
  let observed = Bytes.to_hex(discovery.digest)
  let token_release = """{"program":#{q(pubkey_string(base.program))},"deployment_slot":#{units(base.program_slot)}}"""
  let releases = case selected do
    None -> [token_release]
    Some(value) -> [
      token_release,
      """{"program":#{q(pubkey_string(value.pins.judge))},"deployment_slot":#{units(value.pins.judge_slot)}}""",
      """{"program":#{q(pubkey_string(value.pins.rewards))},"deployment_slot":#{units(value.pins.rewards_slot)}}"""
    ]
  end
  Ok("""{"availability":"available","discovery_scope":"complete-returned-filtered-family-at-index-bank","index_slot":#{units(discovery.index.slot)},"source_time_unix":#{units(discovery.timestamp)},"snapshot_digest":#{q(observed)},"program":#{q(pubkey_string(discovery.scope.program))},"binding":#{q(Bytes.to_hex(discovery.scope.binding))},"code_current":#{flag(discovery.code_current)},"release_pins":[#{String.join(releases,
    ",")}],"upper_bound":#{options.maximum},"record_count":#{List.length(records)},"supported_layouts_complete":#{flag(discovery.index.supported_layouts_complete)},"value_completeness":#{q(if complete do
    "complete-for-applicable-supported-records"
  else
    "incomplete"
  end)},"value_bank_scope":"separate-from-discovery-and-other-pages","legacy_rendering":"proof-v1-identifiers-only","records":[#{String.join(records,
    ",")}],"pages":[#{String.join(bodies, ",")}]}""")
end

pub fn read_public_history_report(client :: Int,
  sources :: List<String>,
  test_mode :: Bool,
  base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  minimum :: U64,
  options :: PublicHistoryOptions) -> String!String do
  let values = for kind in 0..3 do
    section(client, sources, test_mode, base, selected, kind, minimum, options)?
  end
  Ok("""{"schema_version":1,"scope":"bounded-filtered-family-discovery","global_totals":null,"provider_independence":"not-established","bank_scope":"per-discovery-section-and-value-page","burns":#{List.get(values,
    0)},"witnesses":#{List.get(values, 1)},"proofs":#{List.get(values, 2)}}""")
end
