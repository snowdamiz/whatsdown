from Read import CollateralOperatorPins, collateral_operator_keys
from Transparency.TokenCollateralWrite import (
  TokenCollateralContext,
  TokenCollateralSubject,
  collateral_derived,
  token_collateral_addresses
)
from Transparency.TokenChain import decode_token_oracle
from ProofRead import CollateralProofAnchor
from Transparency.Fork import decode_fork
from Transparency.Merkle import WitnessKey
from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountSliceAtSlot,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  pubkey_string
)

pub fn operator_fixture_text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

pub fn operator_fixture_raw(accounts :: Json, key :: Pubkey) -> Bytes!String do
  Bytes.from_hex(operator_fixture_text(Json.object_get(accounts, pubkey_string(key))?, "data_hex")?)
end

pub fn operator_fixture_pins(row :: Json) -> CollateralOperatorPins!String do
  let r = Json.object_get(row, "context")?
  let c = TokenCollateralContext {
    judge: pubkey(operator_fixture_text(r, "judge")?)?,
    token: pubkey(operator_fixture_text(r, "token")?)?,
    rewards: pubkey(operator_fixture_text(r, "rewards")?)?,
    log_name: operator_fixture_text(r, "log_name")?,
    usdc_mint: pubkey(operator_fixture_text(r, "usdc_mint")?)?
  }
  let a = token_collateral_addresses(c)?
  let accounts = Json.object_get(row, "accounts")?
  let log = operator_fixture_raw(accounts, a.log)?
  let pinned_oracle = case Json.object_get(row, "oracle_pin_data_hex") do
    Ok(value) -> Bytes.from_hex(Json.as_string(value)?)?
    Err(_) -> operator_fixture_raw(accounts, a.oracle)?
  end
  let oracle = decode_token_oracle(pinned_oracle)?
  let pool = operator_fixture_raw(accounts, a.pool)?
  Ok(CollateralOperatorPins {
    context: c,
    governance: pubkey(operator_fixture_text(row, "governance")?)?,
    service_key: Bytes.slice(log, 72, 32)?,
    log_version: Bytes.get(log, 4)?,
    network_started: U64.parse(Bytes.read_uint_le(pool, 164, 8)?)?,
    judge_slot: U64.parse(Bytes.read_uint_le(operator_fixture_raw(accounts, a.judge_data)?,
      4,
      8)?)?,
    token_slot: U64.parse(Bytes.read_uint_le(operator_fixture_raw(accounts, a.token_data)?,
      4,
      8)?)?,
    rewards_slot: U64.parse(Bytes.read_uint_le(operator_fixture_raw(accounts, a.rewards_data)?,
      4,
      8)?)?,
    source_program: oracle.receiver,
    source: oracle.source,
    feed: oracle.feed,
    source_revision: oracle.revision
  })
end

pub fn operator_fixture_subject(row :: Json) -> TokenCollateralSubject!String do
  let s = Json.object_get(row, "subject")?
  case Json.object_get(s, "witness_id") do
    Err(_) -> Ok(CollateralDirectory)
    Ok(_) -> Ok(CollateralWitness(WitnessKey {
      witness_id: operator_fixture_text(s, "witness_id")?,
      public_key: Bytes.from_hex(operator_fixture_text(s, "public_key")?)?
    }))
  end
end

pub fn operator_fixture_snapshot(row :: Json,
  pins :: CollateralOperatorPins,
  s :: TokenCollateralSubject,
  operator :: Pubkey) -> OptionalAccountSlicesAtSlot!String do
  operator_fixture_snapshot_for_keys(row, collateral_operator_keys(pins, s, operator)?)
end

pub fn operator_fixture_snapshot_for_keys(row :: Json,
  keys :: List<Pubkey>) -> OptionalAccountSlicesAtSlot!String do
  operator_fixture_snapshot_from_accounts(row, keys, Json.object_get(row, "accounts")?)
end

pub fn operator_fixture_snapshot_from_accounts(row :: Json,
  keys :: List<Pubkey>,
  accounts :: Json) -> OptionalAccountSlicesAtSlot!String do
  let values = for key in keys do
    let value = Json.object_get(accounts, pubkey_string(key))?
    case Json.object_get(value, "missing") do
      Ok(_) -> None
      Err(_) -> Some(AccountSlice {
        info: AccountInfo {
          owner: pubkey(operator_fixture_text(value, "owner")?)?,
          lamports: U64.parse(operator_fixture_text(value, "lamports")?)?,
          rent_epoch: U64.parse(operator_fixture_text(value, "rent_epoch")?)?,
          executable: Json.as_bool(Json.object_get(value, "executable")?)?,
          data: Bytes.from_hex(operator_fixture_text(value, "data_hex")?)?
        },
        space: U64.parse(operator_fixture_text(value, "space")?)?
      })
    end
  end
  Ok(OptionalAccountSlicesAtSlot {
    slot: U64.parse(operator_fixture_text(row, "clock_slot")?)?,
    accounts: values
  })
end

# Exact observed same-bank public auxiliary slices, with canonical addresses.
pub fn operator_fixture_anchor(row :: Json,
  pins :: CollateralOperatorPins,
  wire :: Bytes) -> Option<CollateralProofAnchor>!String do
  let index = case decode_fork(wire)?.second do
    SignedCheckpoint(_) -> return Ok(None)
    AnchorReference(value) -> value
  end
  let generation = Json.as_int(Json.object_get(row, "anchor_generation")?)?
  let a = token_collateral_addresses(pins.context)?
  let set = collateral_derived(pins.context.judge,
    [Bytes.from_utf8("witness-set"), a.log_id, Bytes.write_uint_le(Int.to_string(generation), 2)?])?
  let snapshot = operator_fixture_snapshot_for_keys(row, [a.ring, set])?
  let ring = case List.get(snapshot.accounts, 0) do
    None -> return Err("actual anchor absent")
    Some(value) -> value
  end
  let witnesses = case List.get(snapshot.accounts, 1) do
    None -> return Err("actual witness set absent")
    Some(value) -> value
  end
  Ok(Some(CollateralProofAnchor {
    header: AccountSliceAtSlot {
      slot: snapshot.slot,
      account: Some(%{ring | info: %{ring.info | data: Bytes.slice(ring.info.data, 0, 64)?}})
    },
    entry: AccountSliceAtSlot {
      slot: snapshot.slot,
      account: Some(%{ring |
        info: %{ring.info | data: Bytes.slice(ring.info.data, 64 + index * 104, 104)?}
      })
    },
    witnesses: AccountSliceAtSlot { slot: snapshot.slot, account: Some(witnesses) }
  }))
end
