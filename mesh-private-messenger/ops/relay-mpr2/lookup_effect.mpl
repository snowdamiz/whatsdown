##! Old lookup recipes are interpreted in Mesh, never by the Node scheduler.
from Input import RelayConfig, LookupRequest, text, wide
from Lookup import retained_lookup
from Transparency.RelayLookupRead import read_relay_lookup, read_relay_lookup_cooldown
from Solana.Read import pubkey, pubkey_string
from Solana.Tx import Instruction, instruction_report_json

fn equal_report(report :: Json, expected :: Instruction) -> Bool!String do
  let canonical = Json.parse(instruction_report_json(expected))?
  for field in ["programId", "accountKeys", "signerKeys", "writableKeys", "dataBase64"] do
    if Json.encode(Json.object_get(report, field)?) != Json.encode(Json.object_get(canonical,
        field)?) do
      return Ok(false)
    end
  end
  Ok(true)
end

pub fn lookup_effect(config :: RelayConfig, descriptor :: Json, minimum :: U64) -> String!String do
  let kind = text(descriptor, "kind")?
  let raw = Json.object_get(descriptor, "lookup")?
  let values = Json.object_get(raw, "addresses")?
  let count = Json.array_length(values)?
  if count < 1 || count > 63 do
    return Err("relay_lookup_bounds")
  end
  let requested = LookupRequest {
    creation_slot: wide(raw, "recent_slot")?,
    addresses: for index in 0..count do
      pubkey(Json.as_string(Json.array_get(values, index)?)?)?
    end
  }
  let plan = retained_lookup(config, requested)?
  if text(raw, "address")? != pubkey_string(plan.table) do
    return Err("relay_lookup_effect_binding")
  end
  let reports = Json.object_get(descriptor, "instructions")?
  if Json.array_length(reports)? != 1 do
    return Err("relay_lookup_effect_instruction")
  end
  let report = Json.array_get(reports, 0)?
  let expected = if kind == "create-table" do
    plan.create
  else if kind == "deactivate-table" do
    plan.deactivate
  else if kind == "close-table" do
    plan.close
  else if kind == "extend-table" do
    let matches = for index in 0..List.length(plan.extend) when text(descriptor,
      "stepId")? == "extend-table/#{index}" do
      index
    end
    if List.length(matches) != 1 do
      return Err("relay_lookup_effect_step")
    end
    List.get(plan.extend, List.head(matches))
  else
    return Err("relay_lookup_effect_kind")
  end
  if !equal_report(report, expected)? do
    return Err("relay_lookup_effect_instruction")
  end
  let view = if kind == "deactivate-table" || kind == "close-table" do
    read_relay_lookup_cooldown(config.operator.sources,
      config.submitter,
      requested.creation_slot,
      requested.addresses,
      minimum)?.table
  else
    read_relay_lookup(config.operator.sources,
      config.submitter,
      requested.creation_slot,
      requested.addresses,
      minimum)?
  end
  let present = if kind == "create-table" do
    view.status != "missing"
  else if kind == "deactivate-table" do
    List.contains(["missing", "cooling", "closable"], view.status)
  else if kind == "close-table" do
    view.status == "missing"
  else
    let data = expected.data
    let appended = U64.to_int(U64.parse(Bytes.read_uint_le(data, 4, 8)?)?)?
    let prior = case String.to_int(String.replace(text(descriptor, "stepId")?,
      "extend-table/",
      "")) do
      Some(value) -> value * 20
      None -> return Err("relay_lookup_effect_step")
    end
    List.length(view.addresses) >= prior + appended
  end
  Ok("""{"schema_version":2,"state":"#{if present do
    "present"
  else
    "absent"
  end}","slot":"#{U64.to_string(view.context_slot)}"}""")
end
