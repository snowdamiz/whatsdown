from HistoryLegacyPins import LegacyHistoryPins, legacy_context_keys, legacy_pda
from CollateralAccounts import (
  collateral_required,
  collateral_owned,
  collateral_number,
  collateral_zeroes
)
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey, mint, clock_sysvar
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorBond import (
  AnchorEconomics,
  decode_anchor_economics,
  directory_bond_addresses
)

pub struct LegacyHistoryContext do
  slot :: U64
  timestamp :: U64
  code_current :: Bool
  log :: AnchorLog
  economics :: AnchorEconomics
end

pub fn legacy_code(snapshot :: OptionalAccountSlicesAtSlot,
  pins :: LegacyHistoryPins) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = collateral_required(snapshot, 4, loader, U64.parse("36")?, 36, true)?.info.data
  let address = legacy_pda(loader, [pins.judge.bytes])?
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != address.bytes do
    return Err("legacy_history_executable")
  end
  let account = case List.get(snapshot.accounts, 5) do
    None -> return Err("legacy_history_program_data_missing")
    Some(value) -> value
  end
  if U64.compare(account.space, U64.parse("45")?) < 0
    || U64.compare(account.space, U64.parse("10485760")?) > 0 do
    return Err("legacy_history_program_data")
  end
  let length = if U64.compare(account.space, U64.parse("8416")?) > 0 do
    8416
  else
    U64.to_int(account.space)?
  end
  let data = collateral_required(snapshot, 5, loader, account.space, length, false)?.info.data
  let slot = collateral_number(data, 4)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    return Err("legacy_history_program_data")
  end
  Ok(slot)
end

pub fn legacy_context(pins :: LegacyHistoryPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> LegacyHistoryContext!String do
  if List.length(snapshot.accounts) < 7 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("legacy_history_context")
  end
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let directory = directory_bond_addresses(pins.judge, anchor.log_id, pins.mint)?
  let log = decode_anchor_log(collateral_owned(snapshot, 0, pins.judge, 352)?)?
  # Exact MECv1 decoder. MECv2 is a refusal here, never an implicit mode switch.
  let economics = decode_anchor_economics(collateral_owned(snapshot, 1, pins.judge, 192)?)?
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let asset = mint(collateral_required(snapshot, 2, spl, U64.parse("82")?, 82, false)?.info)?
  let clock = clock_sysvar(collateral_required(snapshot,
    3,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    U64.parse("40")?,
    40,
    false)?.info)?
  let config = collateral_owned(snapshot, 6, pins.judge, 40)?
  if Bytes.to_hex(Bytes.slice(config, 0, 4)?) != "4d434601"
    || Bytes.slice(config, 4, 32)? != pins.governance.bytes
    || !collateral_zeroes(config, 36, 4)?
    || !asset.initialized
    || asset.decimals != 6
    || clock.slot != snapshot.slot
    || clock.unix_timestamp <= 0 do
    return Err("legacy_history_config_mint_clock")
  end
  if log.name != pins.log_name
    || log.version != pins.log_version
    || log.log_id != anchor.log_id
    || log.service_public_key != pins.service_key
    || log.anchor_authority != pins.anchor_authority.bytes
    || log.ring_address != anchor.ring.bytes
    || economics.log_id != anchor.log_id
    || economics.mint != pins.mint.bytes
    || (economics.directory_status == 0
      && Bytes.to_hex(log.directory_bond_vault) != String.repeat("00", 32))
    || (economics.directory_status != 0 && log.directory_bond_vault != directory.vault.bytes) do
    return Err("legacy_history_identity")
  end
  Ok(LegacyHistoryContext {
    slot: snapshot.slot,
    timestamp: U64.parse(Int.to_string(clock.unix_timestamp))?,
    code_current: legacy_code(snapshot, pins)? == pins.judge_slot,
    log: log,
    economics: economics
  })
end

# Every returned account field and the exact observed bank are part of agreement.
pub fn legacy_digest(keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot,
  domain :: String) -> Bytes!String do
  if List.length(keys) != List.length(snapshot.accounts) do
    return Err("legacy_history_batch_length")
  end
  let parts = for index in 0..List.length(keys) do
    let body = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(value) -> List.reduce([
          Bytes.from_hex(if value.info.executable do
            "0101"
          else
            "0100"
          end)?,
          value.info.owner.bytes,
          Bytes.write_uint_le(U64.to_string(value.space), 8)?,
          Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?,
          Bytes.write_uint_le(U64.to_string(value.info.rent_epoch), 8)?,
          Crypto.sha256(value.info.data)
        ],
        Ok(Bytes.empty()),
        fn(result, part) do Bytes.concat(result?, part) end)?
    end
    Bytes.concat(List.get(keys, index).bytes, body)?
  end
  let header = Bytes.concat(Bytes.from_utf8(domain),
    Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?)?
  Ok(Crypto.sha256(List.reduce(parts,
    Ok(header),
    fn(result, part) do Bytes.concat(result?, part) end)?))
end
