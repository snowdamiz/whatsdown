# Bounded read-only discovery metadata. A raw decoder is not a provider quorum.
from Solana.Read import Pubkey, AccountInfo
from Solana.Address import find_program_address
from Transparency.TokenBurnCarry import decode_token_burn_carry_frame
from Transparency.AnchorBond import bond_witness_identity
from Transparency.Config import valid_witness_id
from Transparency.SlashReceipt import decode_slash_receipt
from CollateralReceipt import decode_public_collateral_receipt

pub struct PublicHistoryScope do
  kind :: Int
  program :: Pubkey
  binding :: Bytes
  usdc :: Bytes
  morse :: Bytes
  treasury :: Bytes
end

pub struct PublicHistoryAccount do
  address :: Pubkey
  account :: AccountInfo
  space :: U64
end

pub struct PublicHistorySnapshot do
  slot :: U64
  accounts :: List<PublicHistoryAccount>
end

pub struct PublicHistoryRecord do
  address :: Pubkey
  version :: Int
  verification :: String
  epoch :: Option<U64>
  witness_id :: String
  public_key :: Bytes
  proof_hash :: Bytes
  registry_status :: Int
end

pub struct PublicHistoryIndex do
  slot :: U64
  records :: List<PublicHistoryRecord>
  digest :: Bytes
  supported_layouts_complete :: Bool
end

fn nonzero(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

fn part(value :: Bytes, at :: Int, count :: Int) -> Bytes!String do
  Bytes.slice(value, at, count)
end

fn zeroes(value :: Bytes, at :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(part(value, at, count)?) == String.repeat("00", count))
end

fn pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

fn record(account :: PublicHistoryAccount,
  version :: Int,
  verification :: String) -> PublicHistoryRecord do
  PublicHistoryRecord {
    address: account.address,
    version: version,
    verification: verification,
    epoch: None,
    witness_id: "",
    public_key: Bytes.empty(),
    proof_hash: Bytes.empty(),
    registry_status: -1
  }
end

fn filter_matches(scope :: PublicHistoryScope, data :: Bytes) -> Bool!String do
  if scope.kind == 0 do
    Ok(Bytes.length(data) >= 36
      && part(data, 0, 2)? == Bytes.from_utf8("MT")
      && part(data, 4, 32)? == scope.binding)
  else if scope.kind == 1 do
    Ok(Bytes.length(data) >= 232
      && part(data, 0, 3)? == Bytes.from_utf8("MWI")
      && part(data, 200, 32)? == scope.binding)
  else
    Ok(Bytes.length(data) >= 40
      && part(data, 0, 3)? == Bytes.from_utf8("MPR")
      && part(data, 8, 32)? == scope.binding)
  end
end

fn burn_record(scope :: PublicHistoryScope,
  account :: PublicHistoryAccount,
  version :: Int) -> PublicHistoryRecord!String do
  let data = account.account.data
  let magic = part(data, 0, 3)?
  if magic != Bytes.from_utf8("MTW") && magic != Bytes.from_utf8("MTC") do
    return Ok(record(account, version, "unsupported-family"))
  end
  if version != 1 && version != 2 do
    return Ok(record(account, version, "unsupported-layout"))
  end
  let frame = decode_token_burn_carry_frame(data)?
  let value = frame.week
  if value.profile.bytes != scope.binding
    || value.usdc.bytes != scope.usdc
    || value.treasury.bytes != scope.treasury
    || account.address != pda(scope.program,
        [Bytes.from_utf8("burn-week"), Bytes.write_uint_le(U64.to_string(value.epoch), 8)?])?
    || (version == 2
      && frame.carry != Some(pda(scope.program, [Bytes.from_utf8("burn-carry")])?)) do
    return Err("public_history_burn_identity")
  end
  Ok(%{record(account, version, "supported") | epoch: Some(value.epoch)})
end

fn witness_record(scope :: PublicHistoryScope,
  account :: PublicHistoryAccount,
  version :: Int) -> PublicHistoryRecord!String do
  if version != 1 do
    return Ok(record(account, version, "unsupported-layout"))
  end
  let data = account.account.data
  if Bytes.length(data) != 320 do
    return Err("public_history_witness_layout")
  end
  let length = Bytes.get(data, 4)?
  let status = Bytes.get(data, 5)?
  if length < 1
    || length > 64
    || status > 4
    || Bytes.get(data, 6)? > 1
    || !zeroes(data, 7, 1)?
    || !zeroes(data, 8 + length, 64 - length)?
    || !zeroes(data, 272, 48)? do
    return Err("public_history_witness_layout")
  end
  let id = Bytes.to_utf8(part(data, 8, length)?)?
  let key = part(data, 72, 32)?
  if !valid_witness_id(id)
    || !nonzero(key)
    || account.address != pda(scope.program,
        [Bytes.from_utf8("witness"), scope.binding, bond_witness_identity(id, key)?])? do
    return Err("public_history_witness_identity")
  end
  Ok(%{record(account, version, "supported") |
    witness_id: id,
    public_key: key,
    registry_status: status
  })
end

fn proof_record(scope :: PublicHistoryScope,
  account :: PublicHistoryAccount,
  version :: Int) -> PublicHistoryRecord!String do
  let data = account.account.data
  let proof = if version == 1 do
    let value = decode_slash_receipt(data)?
    if value.log_id != scope.binding || value.mint != scope.usdc do
      return Err("public_history_proof_identity")
    end
    value.proof_hash
  else if version == 2 do
    let value = decode_public_collateral_receipt(data)?
    if value.log_id != scope.binding
      || value.usdc_mint != scope.usdc
      || value.morse_mint != scope.morse do
      return Err("public_history_proof_identity")
    end
    for row in value.rows do
      if row.witness != pda(scope.program,
          [Bytes.from_utf8("witness"), scope.binding, row.identity])?.bytes do
        return Err("public_history_proof_witness")
      end
    end
    value.proof_hash
  else
    return Ok(record(account, version, "unsupported-layout"))
  end
  if !nonzero(proof)
    || account.address != pda(scope.program, [Bytes.from_utf8("proof"), scope.binding, proof])? do
    return Err("public_history_proof_identity")
  end
  Ok(%{record(account,
    version,
    if version == 1 do
      "legacy"
    else
      "supported"
    end) |
    proof_hash: proof
  })
end

fn account_digest(account :: PublicHistoryAccount) -> Bytes!String do
  let value = account.account
  let parts = [
    account.address.bytes,
    value.owner.bytes,
    Bytes.write_uint_le(U64.to_string(account.space), 8)?,
    Bytes.write_uint_le(U64.to_string(value.lamports), 8)?,
    Bytes.write_uint_le(U64.to_string(value.rent_epoch), 8)?,
    Crypto.sha256(value.data)
  ]
  List.reduce(parts, Ok(Bytes.empty()), fn(result, item) do Bytes.concat(result?, item) end)
end

fn decode_history_context(scope :: PublicHistoryScope,
  snapshot :: PublicHistorySnapshot,
  minimum :: U64,
  maximum :: Int,
  legacy_context :: Bool) -> PublicHistoryIndex!String do
  if scope.kind < 0
    || scope.kind > 2
    || !nonzero(scope.program.bytes)
    || !nonzero(scope.binding)
    || !nonzero(scope.usdc)
    || (legacy_context && (scope.kind == 0 || Bytes.length(scope.morse) != 0))
    || (!legacy_context && (!nonzero(scope.morse) || scope.usdc == scope.morse))
    || maximum < 1
    || maximum > 128
    || U64.compare(snapshot.slot, minimum) < 0
    || snapshot.slot == U64.parse("0")?
    || List.length(snapshot.accounts) > maximum do
    return Err("public_history_scope_or_bound")
  end
  if scope.kind == 0
    && (!nonzero(scope.treasury)
      || scope.binding != pda(scope.program, [Bytes.from_utf8("swap")])?.bytes) do
    return Err("public_history_burn_scope")
  end
  let ordered = List.sort(snapshot.accounts,
    fn(left, right) do
      let a = Bytes.to_hex(left.address.bytes)
      let b = Bytes.to_hex(right.address.bytes)
      if a < b do
        -1
      else if a == b do
        0
      else
        1
      end
    end)
  let rows = for index in 0..List.length(ordered) do
    let account = List.get(ordered, index)
    let info = account.account
    if !nonzero(account.address.bytes)
      || info.owner != scope.program
      || info.executable
      || info.lamports == U64.parse("0")?
      || Bytes.length(info.data) < 4
      || Bytes.length(info.data) > 8416
      || account.space != U64.parse(Int.to_string(Bytes.length(info.data)))?
      || !filter_matches(scope, info.data)? do
      return Err("public_history_account_or_filter")
    end
    if index > 0 && account.address == List.get(ordered, index - 1).address do
      return Err("public_history_duplicate_address")
    end
    let version = Bytes.get(info.data, 3)?
    if scope.kind == 0 do
      burn_record(scope, account, version)?
    else if scope.kind == 1 do
      witness_record(scope, account, version)?
    else if legacy_context && version != 1 do
      # No MORSE pin exists in this explicit single-mint context. A v2/future
      # receipt is only an unvalidated layout observation, never reinterpreted.
      record(account, version, "unsupported-layout")
    else
      proof_record(scope, account, version)?
    end
  end
  let header = List.reduce([
      Bytes.from_utf8(if legacy_context do
        "morse-public-history-legacy-index-v1"
      else
        "morse-public-history-index-v1"
      end),
      Bytes.write_uint_le(Int.to_string(scope.kind), 1)?,
      scope.program.bytes,
      scope.binding,
      Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?,
      Bytes.write_uint_le(Int.to_string(List.length(rows)), 4)?
    ],
    Ok(Bytes.empty()),
    fn(result, item) do Bytes.concat(result?, item) end)?
  let material = List.reduce(ordered,
    Ok(header),
    fn(result, account) do Bytes.concat(result?, account_digest(account)?) end)?
  Ok(PublicHistoryIndex {
    slot: snapshot.slot,
    records: rows,
    digest: Crypto.sha256(material),
    supported_layouts_complete: List.all(rows,
      fn(row) do row.verification == "supported" || row.verification == "legacy" end)
  })
end

pub fn decode_public_history(scope :: PublicHistoryScope,
  snapshot :: PublicHistorySnapshot,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryIndex!String do
  decode_history_context(scope, snapshot, minimum, maximum, false)
end

# Explicit legacy entrypoint; the configured single mint occupies scope.usdc.
# scope.morse must be empty and v2 receipts cannot gain canonical authority here.
pub fn decode_legacy_public_history(scope :: PublicHistoryScope,
  snapshot :: PublicHistorySnapshot,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryIndex!String do
  decode_history_context(scope, snapshot, minimum, maximum, true)
end
