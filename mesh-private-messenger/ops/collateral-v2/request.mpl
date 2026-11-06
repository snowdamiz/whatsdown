##! Local operator configuration and unsigned intent parsing. No secrets accepted.
from Read import (
  CollateralOperatorPins,
  validate_collateral_operator_pins,
  validate_collateral_operator_sources
)
from Plan import CollateralOperation
from ProofRead import CollateralProofIntent
from CloseRead import CollateralStageCloseIntent
from Transparency.TokenCollateralWrite import TokenCollateralContext, TokenCollateralSubject
from Transparency.Merkle import WitnessKey
from Solana.Read import Pubkey, pubkey

pub struct CollateralOperatorConfig do
  pins :: CollateralOperatorPins
  sources :: List<String>
end

pub type CollateralOperatorRequest do
  CollateralRequest(CollateralOperation, U64)
  CollateralProofRequest(CollateralProofIntent, U64)
  CollateralStageCloseRequest(CollateralStageCloseIntent, U64)
end

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn wide(value :: Json, key :: String) -> U64!String do
  let string = text(value, key)?
  let number = U64.parse(string)?
  if U64.to_string(number) != string do
    Err("collateral_request_integer")
  else
    Ok(number)
  end
end

fn bytes(value :: Json, key :: String, count :: Int) -> Bytes!String do
  let string = text(value, key)?
  let raw = Bytes.from_hex(string)?
  if Bytes.length(raw) != count || Bytes.to_hex(raw) != string do
    Err("collateral_request_bytes")
  else
    Ok(raw)
  end
end

fn witness(value :: Json) -> WitnessKey!String do
  Ok(WitnessKey {
    witness_id: text(value, "witness_id")?,
    public_key: bytes(value, "public_key", 32)?
  })
end

pub fn parse_collateral_operator_config(value :: Json) -> CollateralOperatorConfig!String do
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 1 do
    return Err("collateral_config_version")
  end
  let p = CollateralOperatorPins {
    context: TokenCollateralContext {
      judge: pubkey(text(value, "judge")?)?,
      token: pubkey(text(value, "token")?)?,
      rewards: pubkey(text(value, "rewards")?)?,
      log_name: text(value, "log_name")?,
      usdc_mint: pubkey(text(value, "usdc_mint")?)?
    },
    governance: pubkey(text(value, "governance")?)?,
    service_key: bytes(value, "service_public_key", 32)?,
    log_version: Json.as_int(Json.object_get(value, "log_version")?)?,
    network_started: wide(value, "network_started")?,
    judge_slot: wide(value, "judge_slot")?,
    token_slot: wide(value, "token_slot")?,
    rewards_slot: wide(value, "rewards_slot")?,
    source_program: pubkey(text(value, "source_program")?)?,
    source: pubkey(text(value, "source")?)?,
    feed: bytes(value, "feed", 32)?,
    source_revision: wide(value, "source_revision")?
  }
  let raw = Json.object_get(value, "endpoints")?
  if Json.array_length(raw)? != 3 do
    return Err("collateral_operator_sources")
  end
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(raw, index)?)?
  end
  validate_collateral_operator_pins(p)?
  validate_collateral_operator_sources(sources)?
  Ok(CollateralOperatorConfig { pins: p, sources: sources })
end

pub fn parse_collateral_operator_request(value :: Json) -> CollateralOperatorRequest!String do
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 1 do
    return Err("collateral_request_version")
  end
  let minimum = wide(value, "min_context_slot")?
  let fee = pubkey(text(value, "fee_payer")?)?
  let action = text(value, "action")?
  if action == "collateral" do
    let raw = Json.object_get(value, "subject")?
    let kind = text(raw, "kind")?
    let subject = if kind == "directory" do
      CollateralDirectory
    else if kind == "witness" do
      CollateralWitness(witness(raw)?)
    else
      return Err("collateral_request_subject")
    end
    return Ok(CollateralRequest(CollateralOperation {
        tag: Json.as_int(Json.object_get(value, "tag")?)?,
        fee_payer: fee,
        operator: pubkey(text(value, "operator")?)?,
        subject: subject,
        asset: Json.as_int(Json.object_get(value, "asset")?)?,
        amount: wide(value, "amount")?,
        witness_minimum: wide(value, "witness_minimum")?,
        directory_minimum: wide(value, "directory_minimum")?
      },
      minimum))
  end
  if action == "close" do
    return Ok(CollateralStageCloseRequest(CollateralStageCloseIntent {
        fee_payer: fee,
        submitter: pubkey(text(value, "submitter")?)?,
        full_hash: bytes(value, "full_hash", 32)?
      },
      minimum))
  end
  if action != "proof" do
    return Err("collateral_request_action")
  end
  let raw = Json.object_get(value, "witnesses")?
  let count = Json.array_length(raw)?
  if count > 16 do
    return Err("collateral_proof_bounds")
  end
  let witnesses = for index in 0..count do
    witness(Json.array_get(raw, index)?)?
  end
  let wire = text(value, "wire_hex")?
  let wire_bytes = Bytes.from_hex(wire)?
  if Bytes.length(wire_bytes) > 8009 || Bytes.to_hex(wire_bytes) != wire do
    return Err("collateral_proof_bounds")
  end
  Ok(CollateralProofRequest(CollateralProofIntent {
      fee_payer: fee,
      submitter: pubkey(text(value, "submitter")?)?,
      wire: wire_bytes,
      witnesses: witnesses,
      close: Json.as_bool(Json.object_get(value, "close")?)?
    },
    minimum))
end
