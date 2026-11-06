from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Transparency.AnchorChain import anchor_addresses
from Transparency.Config import valid_witness_id
from Transparency.AnchorBond import (
  directory_bond_addresses,
  witness_bond_addresses,
  bond_witness_identity
)
from Transparency.Merkle import WitnessKey

# Explicit v1 economic context. Never inferred after a v2 binding failure.
pub struct LegacyHistoryPins do
  judge :: Pubkey
  judge_slot :: U64
  governance :: Pubkey
  anchor_authority :: Pubkey
  log_name :: String
  log_version :: Int
  service_key :: Bytes
  mint :: Pubkey
end

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn nonzero(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

pub fn legacy_number(value :: String) -> U64!String do
  let result = U64.parse(value)?
  if U64.to_string(result) != value do
    Err("legacy_history_integer")
  else
    Ok(result)
  end
end

pub fn legacy_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

pub fn parse_legacy_history(root :: Json) -> LegacyHistoryPins!String do
  # A caller must choose one context. Presence of both is an error, not fallback.
  for name in ["pins", "collateral"] do
    case Json.object_get(root, name) do
      Ok(_) -> return Err("legacy_history_context_conflict")
      Err(_) -> nil
    end
  end
  let value = Json.object_get(root, "legacy_collateral")?
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 1 do
    return Err("legacy_history_schema")
  end
  let pins = LegacyHistoryPins {
    judge: pubkey(text(value, "judge")?)?,
    judge_slot: legacy_number(text(value, "judge_slot")?)?,
    governance: pubkey(text(value, "governance")?)?,
    anchor_authority: pubkey(text(value, "anchor_authority")?)?,
    log_name: text(value, "log_name")?,
    log_version: Json.as_int(Json.object_get(value, "log_version")?)?,
    service_key: Bytes.from_hex(text(value, "service_public_key")?)?,
    mint: pubkey(text(value, "mint")?)?
  }
  for key in [pins.judge, pins.governance, pins.anchor_authority, pins.mint] do
    if !nonzero(key.bytes) do
      return Err("legacy_history_pins")
    end
  end
  if !nonzero(pins.service_key)
    || Bytes.to_hex(pins.service_key) != text(value, "service_public_key")?
    || !valid_witness_id(pins.log_name)
    || String.length(pins.log_name) > 32
    || (pins.log_version != 1 && pins.log_version != 2) do
    return Err("legacy_history_pins")
  end
  Ok(pins)
end

pub fn legacy_context_keys(pins :: LegacyHistoryPins) -> List<Pubkey>!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let directory = directory_bond_addresses(pins.judge, anchor.log_id, pins.mint)?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  Ok([
    anchor.log,
    directory.economics,
    pins.mint,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    pins.judge,
    legacy_pda(loader, [pins.judge.bytes])?,
    legacy_pda(pins.judge, [Bytes.from_utf8("config")])?
  ])
end

pub fn legacy_bond_keys(pins :: LegacyHistoryPins,
  witnesses :: List<WitnessKey>) -> List<Pubkey>!String do
  if List.length(witnesses) > 16 do
    return Err("legacy_history_page_bound")
  end
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let directory = directory_bond_addresses(pins.judge, anchor.log_id, pins.mint)?
  let base = List.concat(legacy_context_keys(pins)?,
    [
      directory.bond,
      legacy_pda(pins.judge, [Bytes.from_utf8("bond-pending"), directory.bond.bytes])?,
      directory.vault
    ])
  List.reduce(witnesses,
    Ok(base),
    fn(result, key) do
      let addresses = witness_bond_addresses(pins.judge,
        anchor.log_id,
        pins.mint,
        key.witness_id,
        key.public_key)?
      let witness = legacy_pda(pins.judge,
        [
          Bytes.from_utf8("witness"),
          anchor.log_id,
          bond_witness_identity(key.witness_id, key.public_key)?
        ])?
      Ok(List.concat(result?,
        [
          witness,
          addresses.bond,
          legacy_pda(pins.judge, [Bytes.from_utf8("bond-pending"), addresses.bond.bytes])?,
          addresses.vault
        ]))
    end)
end
