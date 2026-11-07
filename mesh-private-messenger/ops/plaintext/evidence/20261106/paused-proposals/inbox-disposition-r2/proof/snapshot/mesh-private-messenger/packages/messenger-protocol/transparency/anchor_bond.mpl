from Solana.Read import Pubkey, pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.Config import valid_witness_id

# These codecs do not authenticate RPC ownership or account addresses. Consumers
# must bind both to the configured judge before treating balances as chain state.
pub struct AnchorBondAddresses do
  economics :: Pubkey
  bond :: Pubkey
  vault :: Pubkey
end

pub struct AnchorEconomics do
  log_id :: Bytes
  mint :: Bytes
  directory_owner :: Bytes
  minimum_witness :: U64
  minimum_directory :: U64
  ready_at :: U64
  pending_witness :: U64
  pending_directory :: U64
  pending_ready :: U64
  witness_principal :: U64
  directory_principal :: U64
  directory_status :: Int
  eligibility_revision :: U64
end

pub struct AnchorBond do
  status :: Int
  kind :: Int
  log_id :: Bytes
  witness :: Bytes
  owner :: Bytes
  mint :: Bytes
  vault :: Bytes
  principal :: U64
  bonded_at :: U64
  unbond_at :: U64
  slashed_at :: U64
end

fn zeroes(bytes :: Bytes, offset :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, count)?) == String.repeat("00", count))
end

fn wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Err(_) -> Err("invalid_anchor_custody")
    Ok(value)
  end
end

fn time(bytes :: Bytes, offset :: Int) -> U64!String do
  let value = wide(bytes, offset)?
  if U64.compare(value, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_anchor_custody")
  else
    Ok(value)
  end
end

pub fn decode_anchor_economics(bytes :: Bytes) -> AnchorEconomics!String do
  if Bytes.length(bytes) != 192
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d454301"
    || !zeroes(bytes, 165, 3)?
    || !zeroes(bytes, 176, 16)?
    || zeroes(bytes, 36, 32)?
    || zeroes(bytes, 68, 32)? do
    return Err("invalid_anchor_custody")
  end
  let value = AnchorEconomics {
    log_id: Bytes.slice(bytes, 4, 32)?,
    mint: Bytes.slice(bytes, 36, 32)?,
    directory_owner: Bytes.slice(bytes, 68, 32)?,
    minimum_witness: wide(bytes, 100)?,
    minimum_directory: wide(bytes, 108)?,
    ready_at: time(bytes, 116)?,
    pending_witness: wide(bytes, 124)?,
    pending_directory: wide(bytes, 132)?,
    pending_ready: time(bytes, 140)?,
    witness_principal: wide(bytes, 148)?,
    directory_principal: wide(bytes, 156)?,
    directory_status: Bytes.get(bytes, 164)?,
    eligibility_revision: wide(bytes, 168)?
  }
  let zero = U64.parse("0")?
  if value.minimum_witness == zero
    || U64.compare(value.minimum_directory, value.minimum_witness) < 0
    || value.directory_status > 4 do
    return Err("invalid_anchor_custody")
  end
  if value.pending_ready == zero do
    if value.pending_witness != zero || value.pending_directory != zero do
      return Err("invalid_anchor_custody")
    end
  else if value.pending_witness == zero
    || U64.compare(value.pending_directory, value.pending_witness) < 0
    || U64.compare(value.pending_ready, value.ready_at) < 0 do
    return Err("invalid_anchor_custody")
  end
  if value.directory_status == 1 || value.directory_status == 2 do
    if value.directory_principal == zero
      || U64.compare(value.witness_principal, value.directory_principal) > 0 do
      return Err("invalid_anchor_custody")
    end
  else if value.directory_principal != zero
    || (value.directory_status != 3 && value.witness_principal != zero) do
    return Err("invalid_anchor_custody")
  end
  Ok(value)
end

pub fn decode_anchor_bond(bytes :: Bytes) -> AnchorBond!String do
  if Bytes.length(bytes) != 208
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d424401"
    || !zeroes(bytes, 6, 2)?
    || !zeroes(bytes, 200, 8)?
    || zeroes(bytes, 72, 32)?
    || zeroes(bytes, 104, 32)?
    || zeroes(bytes, 136, 32)? do
    return Err("invalid_anchor_custody")
  end
  let value = AnchorBond {
    status: Bytes.get(bytes, 4)?,
    kind: Bytes.get(bytes, 5)?,
    log_id: Bytes.slice(bytes, 8, 32)?,
    witness: Bytes.slice(bytes, 40, 32)?,
    owner: Bytes.slice(bytes, 72, 32)?,
    mint: Bytes.slice(bytes, 104, 32)?,
    vault: Bytes.slice(bytes, 136, 32)?,
    principal: wide(bytes, 168)?,
    bonded_at: time(bytes, 176)?,
    unbond_at: time(bytes, 184)?,
    slashed_at: time(bytes, 192)?
  }
  let zero = U64.parse("0")?
  if value.status < 1
    || value.status > 4
    || value.kind > 1
    || (value.kind == 0 && !zeroes(bytes, 40, 32)?)
    || (value.kind == 1 && zeroes(bytes, 40, 32)?) do
    return Err("invalid_anchor_custody")
  end
  if value.status == 1 do
    if value.principal == zero || value.unbond_at != zero || value.slashed_at != zero do
      return Err("invalid_anchor_custody")
    end
  else if value.status == 2 || value.status == 4 do
    if (value.status == 2 && value.principal == zero)
      || (value.status == 4 && value.principal != zero)
      || value.unbond_at == zero
      || U64.compare(value.unbond_at, value.bonded_at) < 0
      || value.slashed_at != zero do
      return Err("invalid_anchor_custody")
    end
  else if value.principal != zero
    || value.slashed_at == zero
    || U64.compare(value.slashed_at, value.bonded_at) < 0
    || U64.compare(value.unbond_at, value.slashed_at) > 0
    || (value.unbond_at != zero && U64.compare(value.unbond_at, value.bonded_at) < 0) do
    return Err("invalid_anchor_custody")
  end
  Ok(value)
end

pub fn bond_witness_identity(id :: String, key :: Bytes) -> Bytes!String do
  if !valid_witness_id(id) || Bytes.length(key) != 32 || zeroes(key, 0, 32)? do
    return Err("invalid_anchor_bond_identity")
  end
  let name = Bytes.from_utf8(id)
  let length = case Bytes.from_list([Bytes.length(name)]) do
    Err(_) -> return Err("invalid_anchor_bond_identity")
    Ok(value) -> value
  end
  Ok(Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-witness-record-v1"),
    Bytes.concat(length, Bytes.concat(name, key)?)?)?))
end

fn addresses(program :: Pubkey,
  log_id :: Bytes,
  mint :: Pubkey,
  subject :: Bytes) -> AnchorBondAddresses!String do
  if Bytes.length(log_id) != 32 do
    return Err("invalid_anchor_bond_identity")
  end
  let economics = find_program_address(program, [Bytes.from_utf8("economics"), log_id])?.address
  let bond = find_program_address(program, [Bytes.from_utf8("bond"), log_id, subject])?.address
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let vault = find_program_address(ata, [bond.bytes, token.bytes, mint.bytes])?.address
  Ok(AnchorBondAddresses { economics: economics, bond: bond, vault: vault })
end

pub fn witness_bond_addresses(program :: Pubkey,
  log_id :: Bytes,
  mint :: Pubkey,
  id :: String,
  key :: Bytes) -> AnchorBondAddresses!String do
  addresses(program, log_id, mint, bond_witness_identity(id, key)?)
end

pub fn directory_bond_addresses(program :: Pubkey,
  log_id :: Bytes,
  mint :: Pubkey) -> AnchorBondAddresses!String do
  addresses(program, log_id, mint, Bytes.from_utf8("directory"))
end
