##! Internal strict account primitives. Callers must supply canonical ordered keys.
from Solana.Read import Pubkey, AccountSlice, OptionalAccountSlicesAtSlot, pubkey, token_account
from Solana.Address import find_program_address

fn pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

pub fn operator_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  size :: Int,
  executable :: Bool) -> AccountSlice!String do
  let value = case List.get(snapshot.accounts, index) do
    None -> return Err("collateral_operator_account_missing")
    Some(value) -> value
  end
  if value.info.owner != owner
    || value.info.executable != executable
    || value.info.lamports == U64.parse("0")?
    || value.space != space
    || Bytes.length(value.info.data) != size do
    return Err("collateral_operator_account_mismatch")
  end
  Ok(value)
end

pub fn operator_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  size :: Int) -> Bytes!String do
  Ok(operator_required(snapshot,
    index,
    owner,
    U64.parse(Int.to_string(size))?,
    size,
    false)?.info.data)
end

pub fn operator_absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(value) -> !value.info.executable
      && U64.to_string(value.space) == "0"
      && Bytes.length(value.info.data) == 0
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
  end
end

pub fn operator_number(bytes :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(bytes, at, 8)?)
end

pub fn operator_code(snapshot :: OptionalAccountSlicesAtSlot,
  program :: Pubkey,
  image_index :: Int,
  data_index :: Int) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = operator_required(snapshot,
    image_index,
    loader,
    U64.parse("36")?,
    36,
    true)?.info.data
  let pd = pda(loader, [program.bytes])?
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != pd.bytes do
    return Err("collateral_operator_executable_mismatch")
  end
  let value = case List.get(snapshot.accounts, data_index) do
    None -> return Err("collateral_operator_program_data_missing")
    Some(value) -> value
  end
  if U64.compare(value.space, U64.parse("45")?) < 0
    || U64.compare(value.space, U64.parse("10485760")?) > 0 do
    return Err("collateral_operator_program_data_mismatch")
  end
  let size = if U64.compare(value.space, U64.parse("9216")?) > 0 do
    9216
  else
    U64.to_int(value.space)?
  end
  let data = operator_required(snapshot, data_index, loader, value.space, size, false)?.info.data
  let slot = operator_number(data, 4)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    return Err("collateral_operator_program_data_mismatch")
  end
  Ok(slot)
end

pub fn vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  mint_key :: Pubkey,
  owner :: Pubkey) -> U64!String do
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let info = operator_required(snapshot, index, token, U64.parse("165")?, 165, false)?.info
  let value = token_account(info)?
  if value.mint != mint_key
    || value.owner != owner
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")? do
    return Err("collateral_operator_vault_mismatch")
  end
  Ok(value.amount)
end

pub fn operator_snapshot_digest(keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot) -> Bytes!String do
  let parts = for index in 0..List.length(keys) do
    let body = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(value) ->
        let prefix = Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex(if value.info.executable do
                "0101"
              else
                "0100"
              end)?,
              value.info.owner.bytes)?,
            Bytes.write_uint_le(U64.to_string(value.space), 8)?)?,
          Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?)?
        Bytes.concat(Bytes.concat(prefix,
            Bytes.write_uint_le(U64.to_string(value.info.rent_epoch), 8)?)?,
          Crypto.sha256(value.info.data))?
    end
    Bytes.concat(List.get(keys, index).bytes, body)?
  end
  let bytes = List.reduce(parts,
    Ok(Bytes.from_utf8("morse-collateral-operator-snapshot-v1")),
    fn(result, part) do Bytes.concat(result?, part) end)?
  Ok(Crypto.sha256(Bytes.concat(Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?, bytes)?))
end

pub fn operator_optional_vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  mint :: Pubkey,
  owner :: Pubkey) -> U64!String do
  if operator_absent(List.get(snapshot.accounts, index)) do
    Ok(U64.parse("0")?)
  else
    vault(snapshot, index, mint, owner)
  end
end
