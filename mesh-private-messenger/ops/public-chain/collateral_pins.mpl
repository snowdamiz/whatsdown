from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Transparency.Config import valid_witness_id
from Transparency.Merkle import WitnessKey
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorBond import bond_witness_identity
from Transparency.TokenChain import token_addresses, token_payout_address
from Transparency.TokenCustody import token_pending_address
from Transparency.TokenBurnRead import TokenBurnReadPins

pub struct CollateralPins do
  token :: Pubkey
  token_governance :: Pubkey
  token_slot :: U64
  usdc :: Pubkey
  morse :: Pubkey
  judge :: Pubkey
  judge_slot :: U64
  rewards :: Pubkey
  rewards_slot :: U64
  rewards_governance :: Pubkey
  log_name :: String
  log_version :: Int
  service_key :: Bytes
  network_started :: U64
end

pub struct CollateralSelection do
  pins :: CollateralPins
  witnesses :: List<WitnessKey>
  proofs :: List<Bytes>
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

pub fn collateral_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
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

# Fourteen fixed roles. The two sections sample independent finalized banks.
pub fn collateral_context_keys(pins :: CollateralPins) -> List<Pubkey>!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let token = token_addresses(pins.token)?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  Ok([
    anchor.log,
    collateral_pda(pins.judge, [Bytes.from_utf8("economics"), anchor.log_id])?,
    collateral_pda(pins.judge, [Bytes.from_utf8("token-binding"), anchor.log_id])?,
    token.config,
    pins.usdc,
    pins.morse,
    collateral_pda(pins.rewards, [Bytes.from_utf8("pool")])?,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    pins.judge,
    collateral_pda(loader, [pins.judge.bytes])?,
    pins.token,
    collateral_pda(loader, [pins.token.bytes])?,
    pins.rewards,
    collateral_pda(loader, [pins.rewards.bytes])?
  ])
end

fn bond_keys(pins :: CollateralPins, identity :: Bytes) -> List<Pubkey>!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let bond = collateral_pda(pins.judge, [Bytes.from_utf8("bond"), anchor.log_id, identity])?
  Ok([
    bond,
    token_pending_address(pins.judge, bond)?,
    token_payout_address(bond, pins.usdc)?,
    token_payout_address(bond, pins.morse)?
  ])
end

pub fn collateral_bond_keys(selection :: CollateralSelection) -> List<Pubkey>!String do
  let p = selection.pins
  let anchor = anchor_addresses(p.judge, p.log_name)?
  let directory = bond_keys(p, Bytes.from_utf8("directory"))?
  let rows = for key in selection.witnesses do
    let identity = bond_witness_identity(key.witness_id, key.public_key)?
    let witness = collateral_pda(p.judge, [Bytes.from_utf8("witness"), anchor.log_id, identity])?
    [witness] ++ bond_keys(p, identity)?
  end
  Ok(collateral_context_keys(p)? ++ directory ++ List.flatten(rows))
end

pub fn collateral_receipt_keys(selection :: CollateralSelection) -> List<Pubkey>!String do
  let p = selection.pins
  let anchor = anchor_addresses(p.judge, p.log_name)?
  let keys = for hash in selection.proofs do
    collateral_pda(p.judge, [Bytes.from_utf8("proof"), anchor.log_id, hash])?
  end
  Ok(collateral_context_keys(p)? ++ keys)
end
