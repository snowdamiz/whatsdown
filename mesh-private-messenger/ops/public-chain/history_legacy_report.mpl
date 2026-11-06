from HistoryLegacyPins import LegacyHistoryPins, parse_legacy_history, legacy_number
from HistoryLegacyRead import read_legacy_discovery, read_legacy_values
from HistoryReport import PublicHistoryOptions, parse_public_history
from HistoryIndex import PublicHistoryRecord
from Solana.Read import pubkey_string
from Transparency.TokenBurnRead import token_burn_rpc_sources

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn units(value :: U64) -> String do
  q(U64.to_string(value))
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn applicable(kind :: Int, row :: PublicHistoryRecord) -> Bool do
  (row.verification == "supported" || row.verification == "legacy")
    && (kind != 1 || row.registry_status > 0)
end

fn record(kind :: Int, row :: PublicHistoryRecord) -> String do
  let known = row.verification == "supported" || row.verification == "legacy"
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
  else if known do
    "registry-only"
  else
    "unsupported"
  end
  """{"address":#{q(pubkey_string(row.address))},"version":#{row.version},"verification":#{q(row.verification)},"canonical_identity":#{flag(known)},"epoch":null,"witness_id":#{q(row.witness_id)},"public_key":#{key},"proof_hash":#{proof},"registry_status":#{row.registry_status},"value_status":#{q(status)}}"""
end

fn section(client :: Int,
  sources :: List<String>,
  pins :: LegacyHistoryPins,
  kind :: Int,
  minimum :: U64,
  options :: PublicHistoryOptions) -> String!String do
  let result = read_legacy_discovery(client, sources, pins, kind, minimum, options.maximum)?
  let discovery = case result.observation do
    None -> return Ok("""{"availability":#{q(result.availability)},"reason":"no-complete-agreeing-legacy-index-at-authenticated-bank","upper_bound":#{options.maximum}}""")
    Some(value) -> value
  end
  let rows = discovery.index.records
  let selected = List.filter(rows, fn(row) do applicable(kind, row) end)
  let pages = for index in 0..((List.length(selected) + options.page_size - 1)
    / options.page_size) do
    let records = List.take(List.drop(selected, index * options.page_size), options.page_size)
    let requested = for row in records do
      q(pubkey_string(row.address))
    end
    let values = read_legacy_values(client, sources, pins, kind, records, discovery.index.slot)?
    let complete = Json.as_string(Json.object_get(Json.parse(values)?,
      "availability")?)? == "available"
    ("""{"page":#{index},"requested_addresses":[#{String.join(requested,
        ",")}],"bank_scope":"this-value-page-only","complete":#{flag(complete)},"values":#{values}}""",
      complete)
  end
  let complete = discovery.index.supported_layouts_complete
    && List.all(pages,
      fn(item) do
        let (_, okay) = item
        okay
      end)
  let page_bodies = for item in pages do
    let (body, _) = item
    body
  end
  let records = for row in rows do
    record(kind, row)
  end
  Ok("""{"availability":"available","context_kind":"legacy-v1","discovery_scope":"complete-returned-filtered-family-at-index-bank","index_slot":#{units(discovery.index.slot)},"source_time_unix":#{units(discovery.timestamp)},"snapshot_digest":#{q(Bytes.to_hex(discovery.digest))},"program":#{q(pubkey_string(pins.judge))},"binding":#{q(Bytes.to_hex(discovery.scope.binding))},"mint":#{q(pubkey_string(pins.mint))},"asset_scope":"configured-legacy-mint","code_current":#{flag(discovery.code_current)},"release_pins":[{"program":#{q(pubkey_string(pins.judge))},"deployment_slot":#{units(pins.judge_slot)}}],"upper_bound":#{options.maximum},"record_count":#{List.length(rows)},"supported_layouts_complete":#{flag(discovery.index.supported_layouts_complete)},"value_completeness":#{q(if complete do
    "complete-for-applicable-supported-records"
  else
    "incomplete"
  end)},"value_bank_scope":"separate-from-discovery-and-other-pages","legacy_rendering":"versioned-single-mint-v1-values","records":[#{String.join(records,
    ",")}],"pages":[#{String.join(page_bodies, ",")}]}""")
end

fn history(client :: Int,
  sources :: List<String>,
  pins :: LegacyHistoryPins,
  minimum :: U64,
  options :: PublicHistoryOptions) -> String!String do
  let witnesses = section(client, sources, pins, 1, minimum, options)?
  let proofs = section(client, sources, pins, 2, minimum, options)?
  Ok("""{"schema_version":1,"context_kind":"legacy-v1","scope":"bounded-filtered-family-discovery","global_totals":null,"provider_independence":"not-established","bank_scope":"per-discovery-section-and-value-page","burns":{"availability":"not-configured","reason":"legacy-context-has-no-token-program","upper_bound":#{options.maximum}},"witnesses":#{witnesses},"proofs":#{proofs}}""")
end

pub fn read_legacy_public_report(root :: Json) -> String!String do
  let pins = parse_legacy_history(root)?
  let scope = text(root, "scope")?
  if scope != "local-fixture" && scope != "configured-rpc" do
    return Err("invalid_report_scope")
  end
  let endpoints = Json.object_get(root, "endpoints")?
  if Json.array_length(endpoints)? != 3
    || Json.array_length(Json.object_get(root, "epochs")?)? != 0 do
    return Err("legacy_history_sources_or_epochs")
  end
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(endpoints, index)?)?
  end
  token_burn_rpc_sources(sources, scope == "local-fixture")?
  let options = case parse_public_history(root)? do
    None -> return Err("legacy_history_explicit_index_required")
    Some(value) -> value
  end
  let minimum = legacy_number(text(root, "minimum_context_slot")?)?
  let generated = legacy_number(text(root, "generated_at_unix")?)?
  let age = legacy_number(text(root, "max_age_seconds")?)?
  if age == U64.parse("0")? || U64.compare(age, U64.parse("86400")?) > 0 do
    return Err("invalid_report_max_age")
  end
  let client = Http.client()
  let result = history(client, sources, pins, minimum, options)
  Http.client_close(client)
  let value = result?
  Ok("""{"schema_version":1,"scope":#{q(scope)},"generated_at_unix":#{units(generated)},"max_age_seconds":#{units(age)},"provider_independence":"not-established","history_completeness":"bounded-filtered-index-with-separate-value-pages","phase5_complete":false,"burns":[],"bonds":{"availability":"unavailable","reason":"legacy-values-are-explicitly-versioned-in-history-pages"},"slashes":{"availability":"unavailable","reason":"legacy-values-are-explicitly-versioned-in-history-pages"},"history":#{value}}""")
end
