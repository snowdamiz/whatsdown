from Transparency.TokenCustody import decode_token_collateral_binding

##! Typed native accounting. No USD peg assumption, no status inference from
##! an asset price, and no v2-to-legacy fallback.
from Mobile.NetworkCounterPins import NetworkCounterPins
from Transparency.NetworkCollateralPins import CollateralSelection, collateral_bond_keys
from Transparency.NetworkCollateralState import decode_public_bond_row
from Transparency.NetworkCollateralAccounts import (
  collateral_owned,
  collateral_required,
  collateral_absent,
  collateral_vault,
  collateral_zeroes,
  collateral_number,
  collateral_digest,
  collateral_context
)
from Transparency.NetworkLegacyPins import LegacyHistoryPins, legacy_bond_keys
from Transparency.NetworkLegacyContext import legacy_context, legacy_digest
from Transparency.AnchorBond import decode_anchor_bond
from Transparency.AnchorChain import anchor_addresses
from Transparency.TokenChain import token_addresses, decode_token_oracle, token_oracle_twap
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey
from Transparency.Config import pinned_witness_keys

pub struct NetworkBondRow do
  witness_id :: String
  public_key :: Bytes
  address :: Pubkey
  owner :: Bytes
  mint :: Option<Bytes>
  vault :: Option<Bytes>
  asset :: String
  layout :: Int
  status :: Int
  principal :: Option<U64>
  pending :: Option<U64>
  pending_recorded :: Option<U64>
  balance :: Option<U64>
  donation :: Option<U64>
  opposite_balance :: Option<U64>
  usdc_vault :: Option<U64>
  morse_vault :: Option<U64>
  bonded_at :: U64
  unbond_at :: U64
  slashed_at :: U64
  underwater_since :: U64
  usd_micros :: Option<U128>
end

pub struct NetworkBondObservation do
  slot :: U64
  timestamp :: U64
  service_slashed :: Bool
  witnesses_slashed :: Int
  rows :: List<NetworkBondRow>
  digest :: Bytes
  valuation :: String
  twap :: Option<U64>
end

pub fn network_legacy_pins(pins :: NetworkCounterPins) -> LegacyHistoryPins!String do
  let s = pins.security
  Ok(LegacyHistoryPins {
    judge: case pins.collateral do
      Some(value) -> value.pins.judge
      None -> (from_base58_judge(s.anchor_program))?
    end,
    judge_slot: pins.judge_slot,
    governance: case pins.legacy_governance do
      Some(value) -> value
      None -> return Err("counter_legacy_pins")
    end,
    anchor_authority: case pins.legacy_authority do
      Some(value) -> value
      None -> return Err("counter_legacy_pins")
    end,
    mint: case pins.legacy_mint do
      Some(value) -> value
      None -> return Err("counter_legacy_pins")
    end,
    log_name: "morse-main",
    log_version: pins.log_version,
    service_key: s.service_public_key
  })
end

fn from_base58_judge(text :: String) -> Pubkey!String do
  pubkey(text)
end

pub fn network_counter_keys(pins :: NetworkCounterPins) -> List<Pubkey>!String do
  case pins.collateral do
    Some(value) -> do
      let keys = collateral_bond_keys(value)?
      case pins.oracle do
        None -> Ok(keys)
        Some(_) -> Ok(keys ++ [token_addresses(value.pins.token)?.oracle])
      end
    end
    None -> legacy_bond_keys(network_legacy_pins(pins)?, pinned_witness_keys(pins.security))
  end
end

pub fn counter_fresh(timestamp :: U64, checked_ms :: U64) -> Bool!String do
  let now = U64.divide(checked_ms, U64.parse("1000")?)?
  if U64.compare(timestamp, now) > 0 do
    return Ok(false)
  end
  Ok(U64.compare(U64.subtract(now, timestamp)?, U64.parse("120")?) <= 0)
end

# Exact base-unit value, rounded down. Full-width arithmetic avoids u64
# multiplication overflow; this is a valuation, never an onchain eligibility.
pub fn network_token_value(principal :: U64, price :: U64) -> U128!String do
  U128.multiply_divide(U128.parse(U64.to_string(principal))?,
    U128.parse(U64.to_string(price))?,
    U128.parse("1000000")?)
end

fn current_twap(pins :: NetworkCounterPins,
  selected :: CollateralSelection,
  snapshot :: OptionalAccountSlicesAtSlot,
  timestamp :: U64) -> Option<U64>!String do
  let expected = case pins.oracle do
    None -> return Ok(None)
    Some(value) -> value
  end
  let raw = collateral_owned(snapshot,
    List.length(snapshot.accounts) - 1,
    selected.pins.token,
    5728)?
  let value = decode_token_oracle(raw)?
  # The activated judge binding and immutable program releases authenticate the
  # token oracle's source configuration. No RPC-supplied price is promoted.
  let binding = from_binding(snapshot, selected)?
  if value.config != token_addresses(selected.pins.token)?.config
    || value.mint != selected.pins.morse
    || value.receiver != expected.receiver
    || value.source != expected.source
    || value.feed != expected.feed
    || value.revision != expected.revision
    || binding != expected.revision
    || U64.compare(value.last_slot, snapshot.slot) > 0 do
    return Ok(None)
  end
  case token_oracle_twap(raw, timestamp) do
    Err(_) -> Ok(None)
    Ok(price) -> Ok(Some(price))
  end
end

fn from_binding(snapshot :: OptionalAccountSlicesAtSlot,
  selected :: CollateralSelection) -> U64!String do
  Ok(decode_token_collateral_binding(collateral_owned(snapshot,
    2,
    selected.pins.judge,
    320)?)?.source_revision)
end

fn decode_v2(pins :: NetworkCounterPins,
  selected :: CollateralSelection,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> NetworkBondObservation!String do
  let count = List.length(collateral_bond_keys(selected)?)
  let base = %{snapshot | accounts: List.take(snapshot.accounts, count)}
  let context = collateral_context(selected.pins, base, minimum)?
  if !context.code_current do
    return Err("counter_code_changed")
  end
  let price = case current_twap(pins, selected, snapshot, context.timestamp) do
    Err(_) -> None
    Ok(value) -> value
  end
  let keys = collateral_bond_keys(selected)?
  let rows = for index in 0..(List.length(selected.witnesses) + 1) do
    let at = if index == 0 do
      14
    else
      19 + (index - 1) * 5
    end
    if collateral_absent(List.get(base.accounts, at)) do
      unbonded_v2(pins, selected, base, at, index)?
    else
      let r = decode_public_bond_row(selected, base, context, keys, at, index - 1)?
      let b = r.bond
      NetworkBondRow {
        witness_id: r.witness_id,
        public_key: r.public_key,
        address: r.address,
        owner: b.owner,
        mint: Some(b.mint),
        vault: Some(b.vault),
        asset: if b.asset == 0 do
          "USDC"
        else
          "MORSE"
        end,
        layout: Bytes.get(collateral_owned(base, at, selected.pins.judge, 208)?, 3)?,
        status: b.status,
        principal: Some(b.principal),
        pending: Some(r.pending_liability),
        pending_recorded: Some(r.pending_recorded),
        balance: Some(r.balance),
        donation: Some(r.donation),
        opposite_balance: r.opposite_balance,
        usdc_vault: if b.asset == 0 do
          Some(r.balance)
        else
          r.opposite_balance
        end,
        morse_vault: if b.asset == 1 do
          Some(r.balance)
        else
          r.opposite_balance
        end,
        bonded_at: b.bonded_at,
        unbond_at: b.unbond_at,
        slashed_at: b.slashed_at,
        underwater_since: b.underwater_since,
        usd_micros: case price do
          Some(value) -> if b.asset == 1 do
            Some(network_token_value(b.principal, value)?)
          else
            None
          end
          None
        end
      }
    end
  end
  for asset in ["USDC", "MORSE"] do
    let total = List.reduce(rows,
      U64.parse("0"),
      fn(result, row) do
        let sum = result?
        case row.principal do
          Some(value) -> if row.witness_id != "" && row.asset == asset do
            U64.add(sum, value)
          else
            Ok(sum)
          end
          None -> Ok(sum)
        end
      end)?
    let limit = if asset == "USDC" do
      context.economics.witness_usdc
    else
      context.economics.witness_morse
    end
    if U64.compare(total, limit) > 0 do
      return Err("counter_selected_principal")
    end
  end
  Ok(NetworkBondObservation {
    slot: context.slot,
    timestamp: context.timestamp,
    service_slashed: context.log.service_slashed,
    witnesses_slashed: List.length(List.filter(List.drop(rows, 1), fn(row) -> row.status == 3 end)),
    rows: rows,
    digest: collateral_digest(network_counter_keys(pins)?,
      snapshot,
      "morse-native-network-bonds-v1")?,
    valuation: case pins.oracle do
      None -> "unconfigured"
      Some(_) -> if price == None do
        "unavailable"
      else
        "available"
      end
    end,
    twap: price
  })
end

fn unbonded_v2(pins :: NetworkCounterPins,
  selected :: CollateralSelection,
  snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  index :: Int) -> NetworkBondRow!String do
  let context = collateral_context(selected.pins, snapshot, pins.minimum_slot)?
  if !collateral_absent(List.get(snapshot.accounts, at + 1)) do
    return Err("counter_unbonded_pending")
  end
  let zero = U64.parse("0")?
  let empty = Bytes.from_hex(String.repeat("00", 32))?
  let owner = if index == 0 do
    if context.economics.directory_status != 0
      || context.economics.directory_usdc != zero
      || context.economics.directory_morse != zero
      || context.log.directory_bond_vault != empty
      || context.log.service_slashed do
      return Err("counter_directory_missing")
    end
    context.economics.directory_owner
  else
    let raw = collateral_owned(snapshot, at - 1, selected.pins.judge, 320)?
    let who = List.get(selected.witnesses, index - 1)
    let expected = LegacyHistoryPins {
      judge: selected.pins.judge,
      judge_slot: selected.pins.judge_slot,
      governance: selected.pins.token_governance,
      anchor_authority: selected.pins.token_governance,
      mint: selected.pins.usdc,
      log_name: "morse-main",
      log_version: selected.pins.log_version,
      service_key: selected.pins.service_key
    }
    let owner = Bytes.slice(raw, 104, 32)?
    if owner == empty do
      return Err("counter_witness_binding")
    end
    registry(expected, snapshot, at - 1, who.witness_id, who.public_key, 0, owner, empty, zero)?
    owner
  end
  let keys = collateral_bond_keys(selected)?
  # Authenticate both optional ATAs even though no collateral asset is selected.
  let usdc_vault = collateral_vault(snapshot, at + 2, selected.pins.usdc, List.get(keys, at))?
  let morse_vault = collateral_vault(snapshot, at + 3, selected.pins.morse, List.get(keys, at))?
  Ok(NetworkBondRow {
    witness_id: if index == 0 do
      ""
    else
      List.get(selected.witnesses, index - 1).witness_id
    end,
    public_key: if index == 0 do
      empty
    else
      List.get(selected.witnesses, index - 1).public_key
    end,
    address: List.get(keys, at),
    owner: owner,
    mint: None,
    vault: None,
    asset: "unassigned",
    layout: 2,
    status: 0,
    principal: None,
    pending: None,
    pending_recorded: None,
    balance: None,
    donation: None,
    opposite_balance: None,
    usdc_vault: usdc_vault,
    morse_vault: morse_vault,
    bonded_at: zero,
    unbond_at: zero,
    slashed_at: zero,
    underwater_since: zero,
    usd_micros: None
  })
end

fn registry(pins :: LegacyHistoryPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  id :: String,
  key :: Bytes,
  status :: Int,
  owner :: Bytes,
  vault :: Bytes,
  unbond :: U64) -> Bool!String do
  let raw = collateral_owned(snapshot, at, pins.judge, 320)?
  if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "4d574901"
    || Bytes.get(raw, 4)? != String.length(id)
    || Bytes.get(raw, 5)? != status
    || Bytes.get(raw, 6)? > 1
    || !collateral_zeroes(raw, 7, 1)?
    || Bytes.to_utf8(Bytes.slice(raw, 8, String.length(id))?)? != id
    || !collateral_zeroes(raw, 8 + String.length(id), 64 - String.length(id))?
    || Bytes.slice(raw, 72, 32)? != key
    || Bytes.slice(raw, 104, 32)? != owner
    || collateral_zeroes(raw, 136, 32)?
    || Bytes.slice(raw, 200, 32)? != Crypto.sha256(Bytes.from_utf8("morse-main"))
    || Bytes.slice(raw, 232, 32)? != vault
    || collateral_number(raw, 264)? != unbond
    || !collateral_zeroes(raw, 272, 48)? do
    return Err("counter_witness_binding")
  end
  Ok(true)
end

fn decode_legacy(pins :: NetworkCounterPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> NetworkBondObservation!String do
  let p = network_legacy_pins(pins)?
  let keys = network_counter_keys(pins)?
  let state = legacy_context(p, snapshot, minimum)?
  if !state.code_current do
    return Err("counter_code_changed")
  end
  let witnesses = pinned_witness_keys(pins.security)
  let zero = U64.parse("0")?
  let rows = for index in 0..(List.length(witnesses) + 1) do
    let at = if index == 0 do
      7
    else
      11 + (index - 1) * 4
    end
    if !collateral_absent(List.get(snapshot.accounts, at + 1)) do
      return Err("counter_legacy_pending_layout")
    end
    let bond = decode_anchor_bond(collateral_owned(snapshot, at, p.judge, 208)?)?
    if bond.log_id != state.log.log_id
      || bond.mint != p.mint.bytes
      || bond.vault != List.get(keys, at + 2).bytes
      || U64.compare(bond.bonded_at, state.timestamp) > 0
      || U64.compare(bond.unbond_at, state.timestamp) > 0
      || U64.compare(bond.slashed_at, state.timestamp) > 0 do
      return Err("counter_legacy_bond_binding")
    end
    let id = if index == 0 do
      ""
    else
      List.get(witnesses, index - 1).witness_id
    end
    let public_key = if index == 0 do
      Bytes.from_hex(String.repeat("00", 32))?
    else
      List.get(witnesses, index - 1).public_key
    end
    if index == 0 do
      if bond.kind != 0
        || bond.owner != state.economics.directory_owner
        || bond.status != state.economics.directory_status
        || bond.principal != state.economics.directory_principal
        || bond.vault != state.log.directory_bond_vault
        || state.log.service_slashed != (bond.status == 3) do
        return Err("counter_directory_binding")
      end
    else
      if bond.kind != 1 || bond.witness != List.get(keys, at - 1).bytes do
        return Err("counter_witness_binding")
      end
      registry(p,
        snapshot,
        at - 1,
        id,
        public_key,
        bond.status,
        bond.owner,
        bond.vault,
        bond.unbond_at)?
      nil
    end
    let amount = case collateral_vault(snapshot, at + 2, p.mint, List.get(keys, at)) do
      Ok(Some(value)) -> value
      _ -> return Err("counter_legacy_vault")
    end
    if U64.compare(amount, bond.principal) < 0 do
      return Err("counter_underfunded")
    end
    NetworkBondRow {
      witness_id: id,
      public_key: public_key,
      address: List.get(keys, at),
      owner: bond.owner,
      mint: Some(bond.mint),
      vault: Some(bond.vault),
      asset: "legacy",
      layout: 1,
      status: bond.status,
      principal: Some(bond.principal),
      pending: None,
      pending_recorded: None,
      balance: Some(amount),
      donation: Some(U64.subtract(amount, bond.principal)?),
      opposite_balance: None,
      usdc_vault: None,
      morse_vault: None,
      bonded_at: bond.bonded_at,
      unbond_at: bond.unbond_at,
      slashed_at: bond.slashed_at,
      underwater_since: zero,
      usd_micros: None
    }
  end
  Ok(NetworkBondObservation {
    slot: state.slot,
    timestamp: state.timestamp,
    service_slashed: state.log.service_slashed,
    witnesses_slashed: List.length(List.filter(List.drop(rows, 1), fn(row) -> row.status == 3 end)),
    rows: rows,
    digest: legacy_digest(keys, snapshot, "morse-native-network-legacy-v1")?,
    valuation: "unconfigured",
    twap: None
  })
end

pub fn decode_network_bonds(pins :: NetworkCounterPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64,
  checked_ms :: U64) -> NetworkBondObservation!String do
  if List.length(snapshot.accounts) != List.length(network_counter_keys(pins)?) do
    return Err("counter_role_count")
  end
  let value = case pins.collateral do
    Some(selected) -> decode_v2(pins, selected, snapshot, minimum)?
    None -> decode_legacy(pins, snapshot, minimum)?
  end
  if !counter_fresh(value.timestamp, checked_ms)? do
    return Err("counter_stale")
  end
  Ok(value)
end
