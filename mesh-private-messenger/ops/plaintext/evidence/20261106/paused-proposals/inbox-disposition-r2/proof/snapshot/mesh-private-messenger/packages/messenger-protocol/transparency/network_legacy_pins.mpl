##! Explicit legacy v1 pins; never a fallback from v2.
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

pub fn legacy_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
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
