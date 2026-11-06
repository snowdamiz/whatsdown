from Request import CollateralOperatorConfig, parse_collateral_operator_config
from Transparency.Merkle import WitnessKey
from Transparency.TokenCollateralWrite import token_collateral_addresses
from Solana.Read import Pubkey, pubkey

pub struct RelayConfig do
  operator :: CollateralOperatorConfig
  submitter :: Pubkey
  fee_payer :: Pubkey
  witnesses :: List<WitnessKey>
end

pub struct LookupRequest do
  creation_slot :: U64
  addresses :: List<Pubkey>
end

pub struct RelayRequest do
  method :: String
  minimum :: U64
  lookup :: Option<LookupRequest>
  effect :: Option<Json>
end

pub fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

pub fn wide(value :: Json, name :: String) -> U64!String do
  let raw = text(value, name)?
  let number = U64.parse(raw)?
  if U64.to_string(number) != raw do
    return Err("relay_request_integer")
  end
  Ok(number)
end

pub fn parse_config(value :: Json) -> RelayConfig!String do
  let operator = parse_collateral_operator_config(value)?
  case Json.object_get(value, "morse_mint") do
    Err(_) -> nil
    Ok(raw) -> if pubkey(Json.as_string(raw)?)? != token_collateral_addresses(operator.pins.context)?.morse_mint do
      return Err("relay_morse_mint_pin")
    end
  end
  let raw = Json.object_get(value, "witnesses")?
  let count = Json.array_length(raw)?
  if count > 16 do
    return Err("relay_witness_bounds")
  end
  let witnesses = for index in 0..count do
    let row = Json.array_get(raw, index)?
    let hex = text(row, "public_key")?
    let key = Bytes.from_hex(hex)?
    if Bytes.length(key) != 32 || Bytes.to_hex(key) != hex do
      return Err("relay_witness_key")
    end
    WitnessKey { witness_id: text(row, "witness_id")?, public_key: key }
  end
  Ok(RelayConfig {
    operator: operator,
    submitter: pubkey(text(value, "submitter")?)?,
    fee_payer: pubkey(text(value, "fee_payer")?)?,
    witnesses: witnesses
  })
end

pub fn parse_request(value :: Json) -> RelayRequest!String do
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 2 do
    return Err("relay_request_version")
  end
  let method = text(value, "method")?
  if !List.contains([
      "admit",
      "resume",
      "stage",
      "receipt",
      "effect",
      "close",
      "lookup-plan",
      "lookup",
      "lookup-close",
      "legacy-admit",
      "legacy-stage",
      "legacy-destinations",
      "legacy-receipt"
    ],
    method) do
    return Err("relay_request_method")
  end
  let lookup = case Json.object_get(value, "lookup") do
    Err(_) -> None
    Ok(raw) ->
      let addresses = Json.object_get(raw, "addresses")?
      let count = Json.array_length(addresses)?
      if count < 1 || count > 63 do
        return Err("relay_lookup_bounds")
      end
      Some(LookupRequest {
        creation_slot: wide(raw, "creation_slot")?,
        addresses: for index in 0..count do
          pubkey(Json.as_string(Json.array_get(addresses, index)?)?)?
        end
      })
  end
  Ok(RelayRequest {
    method: method,
    minimum: wide(value, "min_context_slot")?,
    lookup: lookup,
    effect: case Json.object_get(value, "effect") do
      Ok(v) -> Some(v)
      Err(_) -> None
    end
  })
end
