from Transparency.NetworkCollateralPins import CollateralSelection, CollateralPins
from Transparency.TokenBurnRead import TokenBurnReadPins, token_burn_rpc_sources
from Transparency.Config import valid_witness_id
from Transparency.Merkle import WitnessKey
from Transparency.TokenChain import token_addresses
from Solana.Read import pubkey

pub struct BondsV2Options do
  selection :: CollateralSelection
  sources :: List<String>
  scope :: String
  minimum :: U64
  max_age :: U64
end

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn canonical(value :: String) -> U64!String do
  let result = U64.parse(value)?
  if U64.to_string(result) != value do
    Err("invalid_collateral_integer")
  else
    Ok(result)
  end
end

fn nonzero(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

fn hash(value :: String) -> Bytes!String do
  let result = Bytes.from_hex(value)?
  if !nonzero(result) || Bytes.to_hex(result) != value do
    Err("invalid_collateral_identifier")
  else
    Ok(result)
  end
end

pub fn parse_collateral(root :: Json,
  base :: TokenBurnReadPins) -> Option<CollateralSelection>!String do
  let value = case Json.object_get(root, "collateral") do
    Err(_) -> return Ok(None)
    Ok(value) -> value
  end
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 2 do
    return Err("invalid_collateral_schema")
  end
  let pins = CollateralPins {
    token: base.program,
    token_governance: base.governance,
    token_slot: base.program_slot,
    usdc: base.usdc,
    morse: pubkey(text(value, "morse_mint")?)?,
    judge: pubkey(text(value, "judge")?)?,
    judge_slot: canonical(text(value, "judge_slot")?)?,
    rewards: pubkey(text(value, "rewards")?)?,
    rewards_slot: canonical(text(value, "rewards_slot")?)?,
    rewards_governance: pubkey(text(value, "rewards_governance")?)?,
    log_name: text(value, "log_name")?,
    log_version: Json.as_int(Json.object_get(value, "log_version")?)?,
    service_key: hash(text(value, "service_public_key")?)?,
    network_started: canonical(text(value, "network_started")?)?
  }
  for key in [
    pins.token,
    pins.token_governance,
    pins.usdc,
    pins.morse,
    pins.judge,
    pins.rewards,
    pins.rewards_governance
  ] do
    if !nonzero(key.bytes) do
      return Err("invalid_collateral_pins")
    end
  end
  if pins.token == pins.judge
    || pins.token == pins.rewards
    || pins.judge == pins.rewards
    || pins.usdc == pins.morse
    || pins.morse != token_addresses(pins.token)?.mint
    || !valid_witness_id(pins.log_name)
    || String.length(pins.log_name) > 32
    || (pins.log_version != 1 && pins.log_version != 2)
    || pins.network_started == U64.parse("0")? do
    return Err("invalid_collateral_pins")
  end
  let selected = Json.object_get(value, "witnesses")?
  let proofs_json = Json.object_get(value, "proofs")?
  let count = Json.array_length(selected)?
  let proof_count = Json.array_length(proofs_json)?
  if count > 16 || proof_count > 16 do
    return Err("invalid_collateral_selection")
  end
  let witnesses = for index in 0..count do
    let item = Json.array_get(selected, index)?
    let id = text(item, "witness_id")?
    if !valid_witness_id(id) do
      return Err("invalid_collateral_selection")
    end
    WitnessKey { witness_id: id, public_key: hash(text(item, "public_key")?)? }
  end
  let proofs = for index in 0..proof_count do
    hash(Json.as_string(Json.array_get(proofs_json, index)?)?)?
  end
  for index in 0..count do
    for before in 0..index do
      let a = List.get(witnesses, index)
      let b = List.get(witnesses, before)
      if a.witness_id == b.witness_id && a.public_key == b.public_key do
        return Err("duplicate_collateral_selection")
      end
    end
  end
  for index in 0..proof_count do
    for before in 0..index do
      if List.get(proofs, before) == List.get(proofs, index) do
        return Err("duplicate_collateral_selection")
      end
    end
  end
  Ok(Some(CollateralSelection { pins: pins, witnesses: witnesses, proofs: proofs }))
end

pub fn parse_bonds_v2_options(input :: String, name :: String) -> BondsV2Options!String do
  if Bytes.length(Bytes.from_utf8(input)) > 32768 do
    return Err("bonds_v2_config_capacity")
  end
  let root = Json.parse(input)?
  if Json.as_int(Json.object_get(root, "schema_version")?)? != 1 do
    return Err("bonds_v2_schema")
  end
  case Json.object_get(root, "legacy_collateral") do
    Ok(_) -> return Err("bonds_v2_legacy_config_refused")
    Err(_) -> nil
  end
  let scope = text(root, "scope")?
  if scope != "configured-rpc" && scope != "local-fixture" do
    return Err("bonds_v2_scope")
  end
  let p = Json.object_get(root, "pins")?
  let base = TokenBurnReadPins {
    program: pubkey(text(p, "program")?)?,
    governance: pubkey(text(p, "governance")?)?,
    program_slot: canonical(text(p, "program_slot")?)?,
    usdc: pubkey(text(p, "usdc")?)?,
    treasury: pubkey(text(p, "treasury")?)?,
    factory: pubkey(text(p, "factory")?)?
  }
  let selection = case parse_collateral(root, base)? do
    Some(value) -> value
    None -> return Err("bonds_v2_collateral_required")
  end
  if selection.pins.log_name != name do
    return Err("bonds_v2_log_mismatch")
  end
  let values = Json.object_get(root, "endpoints")?
  if Json.array_length(values)? != 3 do
    return Err("bonds_v2_three_sources_required")
  end
  let sources = for i in 0..3 do
    Json.as_string(Json.array_get(values, i)?)?
  end
  token_burn_rpc_sources(sources, scope == "local-fixture")?
  let age = canonical(text(root, "max_age_seconds")?)?
  if age == U64.parse("0")? || U64.compare(age, U64.parse("86400")?) > 0 do
    return Err("bonds_v2_max_age")
  end
  Ok(BondsV2Options {
    selection: selection,
    sources: sources,
    scope: scope,
    minimum: canonical(text(root, "minimum_context_slot")?)?,
    max_age: age
  })
end
