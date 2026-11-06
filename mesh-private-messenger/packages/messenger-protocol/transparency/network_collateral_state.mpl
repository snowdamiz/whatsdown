##! Derived from qualified ops/public-chain/collateral_state.mpl; raw snapshot authentication only.
from Transparency.NetworkCollateralPins import (
  CollateralSelection
)
from Transparency.NetworkCollateralAccounts import (
  CollateralContext,
  collateral_context,
  collateral_owned,
  collateral_required,
  collateral_number,
  collateral_zeroes,
  collateral_absent,
  collateral_vault,
  collateral_digest
)
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey
from Transparency.TokenCustody import (
  TokenCollateralBond,
  decode_token_collateral_bond,
  decode_token_collateral_pending
)
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorBond import decode_anchor_bond

pub struct PublicBondRow do
  kind :: String
  witness_id :: String
  public_key :: Bytes
  address :: Pubkey
  bond :: TokenCollateralBond
  pending_recorded :: U64
  pending_liability :: U64
  pending_target_usd :: U64
  balance :: U64
  donation :: U64
  opposite_balance :: Option<U64>
end

# Explicit, authenticated mixed migration layouts. A v1 bond is always the
# pinned USDC asset under the already-activated v2 context, never MORSE units.
fn compatible_bond(raw :: Bytes) -> TokenCollateralBond!String do
  if Bytes.get(raw, 3)? == 2 do
    return decode_token_collateral_bond(raw)
  end
  let v = decode_anchor_bond(raw)?
  Ok(TokenCollateralBond {
    asset: 0,
    status: v.status,
    witness: v.kind == 1,
    log_id: v.log_id,
    witness_address: v.witness,
    owner: v.owner,
    mint: v.mint,
    vault: v.vault,
    principal: v.principal,
    bonded_at: v.bonded_at,
    unbond_at: v.unbond_at,
    slashed_at: v.slashed_at,
    underwater_since: U64.parse("0")?
  })
end

pub fn decode_public_bond_row(selection :: CollateralSelection,
  snapshot :: OptionalAccountSlicesAtSlot,
  context :: CollateralContext,
  keys :: List<Pubkey>,
  index :: Int,
  witness_index :: Int) -> PublicBondRow!String do
  let pins = selection.pins
  let bond = compatible_bond(collateral_owned(snapshot, index, pins.judge, 208)?)?
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let zero = U64.parse("0")?
  let address = List.get(keys, index)
  let selected_mint = if bond.asset == 0 do
    pins.usdc
  else
    pins.morse
  end
  let selected_vault = List.get(keys, index + 2 + bond.asset)
  if bond.log_id != anchor.log_id
    || bond.mint != selected_mint.bytes
    || bond.vault != selected_vault.bytes
    || bond.witness != (witness_index >= 0)
    || U64.compare(bond.bonded_at, context.timestamp) > 0
    || U64.compare(bond.unbond_at, context.timestamp) > 0
    || U64.compare(bond.slashed_at, context.timestamp) > 0
    || U64.compare(bond.underwater_since, context.timestamp) > 0 do
    return Err("public_collateral_bond_binding")
  end
  let label = if witness_index < 0 do
    ""
  else
    List.get(selection.witnesses, witness_index).witness_id
  end
  let public_key = if witness_index < 0 do
    Bytes.from_hex(String.repeat("00", 32))?
  else
    List.get(selection.witnesses, witness_index).public_key
  end
  if witness_index < 0 do
    let e = context.economics
    let expected = if bond.asset == 0 do
      e.directory_usdc
    else
      e.directory_morse
    end
    if bond.owner != e.directory_owner
      || bond.status != e.directory_status
      || bond.asset != e.directory_asset
      || bond.principal != expected
      || context.log.directory_bond_vault != bond.vault
      || context.log.service_slashed != (bond.status == 3) do
      return Err("public_collateral_directory_binding")
    end
  else
    let record = collateral_owned(snapshot, index - 1, pins.judge, 320)?
    let id_length = Bytes.get(record, 4)?
    if Bytes.to_hex(Bytes.slice(record, 0, 4)?) != "4d574901"
      || id_length != String.length(label)
      || Bytes.get(record, 5)? != bond.status
      || Bytes.get(record, 6)? > 1
      || !collateral_zeroes(record, 7, 1)?
      || Bytes.to_utf8(Bytes.slice(record, 8, id_length)?)? != label
      || !collateral_zeroes(record, 8 + id_length, 64 - id_length)?
      || Bytes.slice(record, 72, 32)? != public_key
      || Bytes.slice(record, 104, 32)? != bond.owner
      || collateral_zeroes(record, 136, 32)?
      || Bytes.slice(record, 200, 32)? != anchor.log_id
      || Bytes.slice(record, 232, 32)? != bond.vault
      || collateral_number(record, 264)? != bond.unbond_at
      || !collateral_zeroes(record, 272, 48)?
      || bond.witness_address != List.get(keys, index - 1).bytes do
      return Err("public_collateral_witness_binding")
    end
  end
  let absent = collateral_absent(List.get(snapshot.accounts, index + 1))
  if absent && bond.asset != 0 do
    return Err("public_collateral_pending_missing")
  end
  let pending = if absent do
    zero
  else
    let value = decode_token_collateral_pending(collateral_owned(snapshot,
      index + 1,
      pins.judge,
      96)?)?
    if value.bond != address.bytes
      || value.mint != selected_mint.bytes
      || U64.compare(value.opened_at, context.timestamp) > 0
      || (bond.asset == 0 && value.target_usd != zero)
      || (bond.asset == 1 && value.target_usd == zero) do
      return Err("public_collateral_pending_binding")
    end
    value.amount
  end
  let target = if absent do
    zero
  else
    collateral_number(collateral_owned(snapshot, index + 1, pins.judge, 96)?, 84)?
  end
  let dollars = collateral_vault(snapshot, index + 2, pins.usdc, address)?
  let morse = collateral_vault(snapshot, index + 3, pins.morse, address)?
  let selected_balance = if bond.asset == 0 do
    dollars
  else
    morse
  end
  let balance = case selected_balance do
    None -> return Err("public_collateral_selected_vault_missing")
    Some(value) -> value
  end
  let liability = if bond.status == 3 do
    zero
  else
    pending
  end
  let tracked = U64.add(bond.principal, liability)?
  if U64.compare(balance, tracked) < 0 do
    return Err("public_collateral_underfunded_vault")
  end
  Ok(PublicBondRow {
    kind: if witness_index < 0 do
      "directory"
    else
      "witness"
    end,
    witness_id: label,
    public_key: public_key,
    address: address,
    bond: bond,
    pending_recorded: pending,
    pending_liability: liability,
    pending_target_usd: target,
    balance: balance,
    donation: U64.subtract(balance, tracked)?,
    opposite_balance: if bond.asset == 0 do
      morse
    else
      dollars
    end
  })
end
