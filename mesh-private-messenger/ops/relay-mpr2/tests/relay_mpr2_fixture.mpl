from Read import CollateralOperatorPins
from Request import parse_collateral_operator_config
from Solana.Read import AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

pub fn fixture_receipt(name :: String) -> (CollateralOperatorPins, Bytes, OptionalAccountSlicesAtSlot)!String do
  let root = Json.parse(File.read(Env.get("MORSE_MPR2_TEST_FIXTURE", ""))?)?
  let row = Json.object_get(root, name)?
  let pins = parse_collateral_operator_config(Json.object_get(row, "config")?)?.pins
  let raw = Json.object_get(row, "accounts")?
  let accounts = for index in 0..Json.array_length(raw)? do
    let a = Json.array_get(raw, index)?
    Some(AccountSlice {
      info: AccountInfo {
        owner: pubkey(Json.as_string(Json.object_get(a, "owner")?)?)?,
        executable: Json.as_bool(Json.object_get(a, "executable")?)?,
        lamports: U64.parse(Json.as_string(Json.object_get(a, "lamports")?)?)?,
        rent_epoch: U64.parse("0")?,
        data: Bytes.from_hex(Json.as_string(Json.object_get(a, "data_hex")?)?)?
      },
      space: U64.parse(Json.as_string(Json.object_get(a, "space")?)?)?
    })
  end
  Ok((pins,
    Bytes.from_hex(Json.as_string(Json.object_get(row, "proof_hash")?)?)?,
    OptionalAccountSlicesAtSlot { slot: U64.parse("100000")?, accounts: accounts }))
end

from Solana.Read import Pubkey, pubkey_string

pub fn operator_fixture_text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

pub fn operator_fixture_pins(row :: Json) -> CollateralOperatorPins!String do
  Ok(parse_collateral_operator_config(Json.object_get(row, "config")?)?.pins)
end

pub fn operator_fixture_snapshot_for_keys(row :: Json,
  keys :: List<Pubkey>) -> OptionalAccountSlicesAtSlot!String do
  let accounts = Json.object_get(row, "accounts")?
  let values = for key in keys do
    let a = Json.object_get(accounts, pubkey_string(key))?
    case Json.object_get(a, "missing") do
      Ok(_) -> None
      Err(_) -> Some(AccountSlice {
        info: AccountInfo {
          owner: pubkey(operator_fixture_text(a, "owner")?)?,
          executable: Json.as_bool(Json.object_get(a, "executable")?)?,
          lamports: U64.parse(operator_fixture_text(a, "lamports")?)?,
          rent_epoch: U64.parse(operator_fixture_text(a, "rent_epoch")?)?,
          data: Bytes.from_hex(operator_fixture_text(a, "data_hex")?)?
        },
        space: U64.parse(operator_fixture_text(a, "space")?)?
      })
    end
  end
  Ok(OptionalAccountSlicesAtSlot {
    slot: U64.parse(operator_fixture_text(row, "clock_slot")?)?,
    accounts: values
  })
end

pub fn operator_fixture_account(a :: Json) -> AccountSlice!String do
  Ok(AccountSlice {
    info: AccountInfo {
      owner: pubkey(operator_fixture_text(a, "owner")?)?,
      executable: Json.as_bool(Json.object_get(a, "executable")?)?,
      lamports: U64.parse(operator_fixture_text(a, "lamports")?)?,
      rent_epoch: U64.parse(operator_fixture_text(a, "rent_epoch")?)?,
      data: Bytes.from_hex(operator_fixture_text(a, "data_hex")?)?
    },
    space: U64.parse(operator_fixture_text(a, "space")?)?
  })
end
