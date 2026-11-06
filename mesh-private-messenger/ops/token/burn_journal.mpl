from Transparency.TokenBurn import TokenBurnProfile, TokenBurnWeek
from Transparency.TokenBurnRead import TokenBurnState
from Transparency.TokenBurnCarry import TokenBurnCarryFrame, TokenBurnCloseReceipt
from Transparency.TokenBurnCarryWrite import (
  token_burn_close_instruction,
  token_burn_fund_v2_instruction,
  token_burn_carry_addresses
)
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenBurnWrite import token_burn_fund_instruction, token_burn_execute_instruction
from Transparency.TokenChain import token_addresses
from Solana.Read import Pubkey, Hash, rpc_send
from Solana.Tx import (
  Instruction,
  AccountMeta,
  compile_legacy_message,
  serialize_legacy_message,
  compute_unit_limit_instruction
)
from Solana.TransactionRead import signed_transaction
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response
from Solana.TransactionWrite import serialize_signed_legacy_transaction
from BurnNetwork import TokenBurnBank

pub struct TokenBurnJournalEntry do
  id :: Bytes
  program :: Pubkey
  payer :: Pubkey
  kind :: Int
  epoch :: U64
  index :: Int
  instruction :: Instruction
  # 0 intent reserved, 1 exact packet committed, 2 RPC acknowledged, 3 receipt finalized.
  status :: Int
  not_before :: U64
  deadline :: U64
  context_slot :: U64
  last_valid_block_height :: U64
  packet :: Bytes
  signature :: Bytes
end

struct TokenBurnJournalSnapshot do
  entry :: TokenBurnJournalEntry
  previous :: Bytes
end

fn journal_cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn journal_wide(value :: U64) -> Bytes!String do
  Bytes.write_uint_le(U64.to_string(value), 8)
end

fn journal_number(data :: Bytes) -> U64!String do
  if Bytes.length(data) != 8 do
    return Err("invalid_token_burn_journal")
  end
  U64.parse(Bytes.read_uint_le(data, 0, 8)?)
end

fn journal_byte(value :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), 1)
end

fn journal_id(program :: Pubkey, kind :: Int, epoch :: U64, index :: Int) -> Bytes!String do
  if Bytes.length(program.bytes) != 32
    || Bytes.to_hex(program.bytes) == String.repeat("00", 32)
    || (kind != 9 && kind != 10 && kind != 13 && kind != 14)
    || (kind != 10 && index != 0)
    || index < 0
    || index >= 24 do
    return Err("invalid_token_burn_operation")
  end
  Ok(Crypto.sha256(journal_cat([
    Bytes.from_utf8("morse-token-burn-operation-v1"),
    program.bytes,
    journal_byte(kind)?,
    journal_wide(epoch)?,
    journal_byte(index)?
  ])?))
end

fn journal_context(program :: Pubkey, id :: Bytes) -> Bytes!String do
  journal_cat([
    Bytes.from_hex("01")?,
    program.bytes,
    Bytes.from_hex(String.repeat("00", 16))?,
    Crypto.sha256(Bytes.from_utf8("morse-token-burn-journal-session-v1")),
    id,
    Bytes.from_hex("000e0000000000000001")?
  ])
end

fn journal_pack(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) > 32 do
    return Err("invalid_token_burn_journal")
  end
  let records = for part in parts do
    if Bytes.length(part) > 4096 do
      return Err("invalid_token_burn_journal")
    end
    journal_cat([Bytes.write_uint_le(Int.to_string(Bytes.length(part)), 2)?, part])?
  end
  journal_cat([journal_byte(List.length(parts))?] ++ records)
end

fn journal_unpack_at(data :: Bytes,
  at :: Int,
  count :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if count == 0 do
    if at != Bytes.length(data) do
      Err("invalid_token_burn_journal")
    else
      Ok(output)
    end
  else
    let size = case String.to_int(Bytes.read_uint_le(data, at, 2)?) do
      None -> return Err("invalid_token_burn_journal")
      Some(value) -> value
    end
    if size > 4096 do
      return Err("invalid_token_burn_journal")
    end
    journal_unpack_at(data,
      at + 2 + size,
      count - 1,
      List.append(output, Bytes.slice(data, at + 2, size)?))
  end
end

fn journal_unpack(data :: Bytes) -> List<Bytes>!String do
  if Bytes.length(data) < 1 || Bytes.length(data) > 8192 || Bytes.get(data, 0)? > 32 do
    return Err("invalid_token_burn_journal")
  end
  journal_unpack_at(data, 1, Bytes.get(data, 0)?, [])
end

fn journal_encode_instruction(value :: Instruction) -> Bytes!String do
  if List.length(value.accounts) < 1
    || List.length(value.accounts) > 32
    || Bytes.length(value.data) > 512 do
    return Err("invalid_token_burn_instruction")
  end
  let metas = for value in value.accounts do
    if Bytes.length(value.pubkey.bytes) != 32 do
      return Err("invalid_token_burn_instruction")
    end
    journal_cat([
      value.pubkey.bytes,
      journal_byte((if value.signer do
        1
      else
        0
      end)
        + (if value.writable do
          2
        else
          0
        end))?
    ])?
  end
  journal_cat([journal_byte(List.length(metas))?] ++ metas ++ [value.data])
end

fn journal_decode_instruction(program :: Pubkey, data :: Bytes) -> Instruction!String do
  let count = Bytes.get(data, 0)?
  if count < 1 || count > 32 || Bytes.length(data) < 1 + count * 33 do
    return Err("invalid_token_burn_instruction")
  end
  let accounts = for index in 0..count do
    let at = 1 + index * 33
    let flags = Bytes.get(data, at + 32)?
    if flags > 3 do
      return Err("invalid_token_burn_instruction")
    end
    AccountMeta {
      pubkey: Pubkey { bytes: Bytes.slice(data, at, 32)? },
      signer: flags % 2 == 1,
      writable: flags / 2 == 1
    }
  end
  Ok(Instruction {
    program_id: program,
    accounts: accounts,
    data: Bytes.slice(data, 1 + count * 33, Bytes.length(data) - 1 - count * 33)?
  })
end

fn journal_packet(entry :: TokenBurnJournalEntry,
  packet :: Bytes,
  signature :: Bytes) -> Result<(), String> do
  let signed = signed_transaction(packet, signature)?
  let instructions = [compute_unit_limit_instruction(1000000)?, entry.instruction]
  let message = compile_legacy_message(entry.payer,
    Hash { bytes: signed.recent_blockhash },
    instructions)?
  if signed.version != -1
    || List.length(signed.accounts) != List.length(message.account_keys)
    || signed.header != message.header
    || List.length(signed.instructions) != 2
    || List.head(signed.accounts).pubkey != entry.payer do
    return Err("token_burn_packet_mismatch")
  end
  # SDKs may order keys differently within the same privilege class. Authenticate
  # the exact signed wire, then require precisely the same keys, global roles,
  # ordered instruction programs/data and ordered account references.
  for index in 0..List.length(message.account_keys) do
    let key = List.get(message.account_keys, index)
    let matches = List.filter(signed.accounts, fn(value) do value.pubkey == key end)
    if List.length(matches) != 1 do
      return Err("token_burn_packet_mismatch")
    end
    let actual = List.head(matches)
    let signer = index < message.header.num_required_signatures
    let writable = if signer do
      index < message.header.num_required_signatures - message.header.num_readonly_signed_accounts
    else
      index < List.length(message.account_keys) - message.header.num_readonly_unsigned_accounts
    end
    if actual.signer != signer || actual.writable != writable do
      return Err("token_burn_packet_mismatch")
    end
  end
  for index in 0..2 do
    let actual = List.get(signed.instructions, index)
    let expected = List.get(instructions, index)
    if actual.program_id != expected.program_id
      || actual.data != expected.data
      || List.length(actual.accounts) != List.length(expected.accounts) do
      return Err("token_burn_packet_mismatch")
    end
    for account in 0..List.length(expected.accounts) do
      if List.get(actual.accounts, account).pubkey != List.get(expected.accounts, account).pubkey do
        return Err("token_burn_packet_mismatch")
      end
    end
  end
  Ok(nil)
end

fn journal_encode(entry :: TokenBurnJournalEntry) -> Bytes!String do
  journal_pack([
    entry.program.bytes,
    entry.payer.bytes,
    journal_byte(entry.kind)?,
    journal_wide(entry.epoch)?,
    journal_byte(entry.index)?,
    journal_encode_instruction(entry.instruction)?,
    journal_byte(entry.status)?,
    journal_wide(entry.not_before)?,
    journal_wide(entry.deadline)?,
    journal_wide(entry.context_slot)?,
    journal_wide(entry.last_valid_block_height)?,
    entry.packet,
    entry.signature
  ])
end

fn journal_decode(program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  data :: Bytes) -> TokenBurnJournalEntry!String do
  let id = journal_id(program, kind, epoch, index)?
  let parts = journal_unpack(data)?
  if List.length(parts) != 13
    || List.get(parts, 0) != program.bytes
    || Bytes.length(List.get(parts, 1)) != 32
    || Bytes.to_hex(List.get(parts, 1)) == String.repeat("00", 32)
    || List.get(parts, 2) != journal_byte(kind)?
    || List.get(parts, 3) != journal_wide(epoch)?
    || List.get(parts, 4) != journal_byte(index)?
    || Bytes.length(List.get(parts, 6)) != 1 do
    return Err("invalid_token_burn_journal")
  end
  let instruction = journal_decode_instruction(program, List.get(parts, 5))?
  let status = Bytes.get(List.get(parts, 6), 0)?
  let not_before = journal_number(List.get(parts, 7))?
  let deadline = journal_number(List.get(parts, 8))?
  let slot = journal_number(List.get(parts, 9))?
  let height = journal_number(List.get(parts, 10))?
  let packet = List.get(parts, 11)
  let signature = List.get(parts, 12)
  let start = U64.multiply(epoch, U64.parse("604800")?)?
  let row_start = U64.add(start,
    U64.parse(Int.to_string((if kind == 10 do
      index
    else
      0
    end)
      * 25200))?)?
  let expected_deadline = if kind == 13 do
    U64.parse("9223372036854775807")?
  else
    U64.add(row_start, U64.parse("25200")?)?
  end
  let count = if kind == 9 do
    17
  else if kind == 10 do
    25
  else if kind == 13 do
    13
  else
    19
  end
  let size = if kind == 9 do
    305
  else if kind == 10 do
    41
  else if kind == 13 do
    9
  else
    313
  end
  let payer = Pubkey { bytes: List.get(parts, 1) }
  if List.length(instruction.accounts) != count || Bytes.length(instruction.data) != size do
    return Err("invalid_token_burn_journal")
  end
  let payer_meta = List.get(instruction.accounts,
    if kind == 9 || kind == 14 do
      1
    else
      0
    end)
  if status > 3
    || Bytes.get(instruction.data, 0)? != kind
    || payer_meta.pubkey != payer
    || !payer_meta.signer
    || !payer_meta.writable
    || deadline != expected_deadline
    || U64.compare(deadline, U64.parse("9223372036854775807")?) > 0
    || ((kind == 9 || kind == 14)
      && (not_before != U64.parse("0")?
        || U64.parse(Bytes.read_uint_le(instruction.data, 1, 8)?)? != epoch))
    || (kind == 13
      && (U64.compare(not_before, deadline) >= 0
        || not_before != U64.add(start, U64.parse("604800")?)?
        || U64.parse(Bytes.read_uint_le(instruction.data, 1, 8)?)? != epoch))
    || (kind == 10
      && (Bytes.get(instruction.data, 1)? != index
        || U64.compare(not_before, row_start) < 0
        || U64.compare(not_before, deadline) >= 0)) do
    return Err("invalid_token_burn_journal")
  end
  if (status == 0
    && (Bytes.length(packet) != 0
      || Bytes.length(signature) != 0
      || slot != U64.parse("0")?
      || height != U64.parse("0")?))
    || (status > 0
      && (Bytes.length(packet) < 1
        || Bytes.length(signature) != 64
        || slot == U64.parse("0")?
        || height == U64.parse("0")?)) do
    return Err("invalid_token_burn_journal")
  end
  let entry = TokenBurnJournalEntry {
    id: id,
    program: program,
    payer: payer,
    kind: kind,
    epoch: epoch,
    index: index,
    instruction: instruction,
    status: status,
    not_before: not_before,
    deadline: deadline,
    context_slot: slot,
    last_valid_block_height: height,
    packet: packet,
    signature: signature
  }
  if status > 0 do
    journal_packet(entry, packet, signature)?
  end
  Ok(entry)
end

fn journal_setup(database :: SqliteConn) -> Result<(), String> do
  Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
  Sqlite.execute(database, "PRAGMA synchronous = FULL", [])?
  Sqlite.execute(database,
    "CREATE TABLE IF NOT EXISTS token_burn_journal (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)",
    [])?
  Sqlite.execute(database,
    "CREATE TABLE IF NOT EXISTS token_burn_retired (id TEXT NOT NULL, signature TEXT NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(id,signature))",
    [])?
  Sqlite.execute(database,
    "CREATE TABLE IF NOT EXISTS token_burn_missed (id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)",
    [])?
  Ok(nil)
end

fn journal_database(path :: String) -> SqliteConn!String do
  if String.length(path) < 1 || String.length(path) > 4096 do
    return Err("invalid_token_burn_journal_path")
  end
  let database = Sqlite.open(path)?
  let result = journal_setup(database)
  if Result.is_err(result) do
    Sqlite.close(database)
    return Err("token_burn_journal_setup_failed")
  end
  Ok(database)
end

fn journal_raw(database :: SqliteConn, id :: Bytes) -> Option<Bytes>!String do
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext FROM token_burn_journal WHERE id = ?",
    [Text(Bytes.to_hex(id))])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  if List.length(rows) != 1 do
    return Err("invalid_token_burn_journal")
  end
  case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> if Bytes.length(value) < 1 || Bytes.length(value) > 8500 do
      Err("invalid_token_burn_journal")
    else
      Ok(Some(value))
    end
    _ -> Err("invalid_token_burn_journal")
  end
end

fn journal_load(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int) -> TokenBurnJournalSnapshot!String do
  let id = journal_id(program, kind, epoch, index)?
  let database = journal_database(path)?
  let raw = journal_raw(database, id)
  Sqlite.close(database)
  let raw = case raw? do
    None -> return Err("token_burn_operation_missing")
    Some(value) -> value
  end
  let opened = case StorageKey.unseal_bytes(raw, wrapping, journal_context(program, id)?) do
    Err(_) -> return Err("token_burn_journal_authentication_failed")
    Ok(value) -> value
  end
  Ok(TokenBurnJournalSnapshot {
    entry: journal_decode(program, kind, epoch, index, opened)?,
    previous: raw
  })
end

fn journal_save(path :: String,
  wrapping :: borrow StorageKey,
  previous :: Bytes,
  entry :: TokenBurnJournalEntry) -> TokenBurnJournalEntry!String do
  let encoded = journal_encode(entry)?
  journal_decode(entry.program, entry.kind, entry.epoch, entry.index, encoded)?
  let sealed = case StorageKey.seal_bytes(encoded,
    wrapping,
    journal_context(entry.program, entry.id)?) do
    Err(_) -> return Err("token_burn_journal_seal_failed")
    Ok(value) -> value
  end
  let database = journal_database(path)?
  let changed = if Bytes.length(previous) == 0 do
    Sqlite.execute_values(database,
      "INSERT INTO token_burn_journal (id,ciphertext) VALUES (?,?) ON CONFLICT(id) DO NOTHING",
      [Text(Bytes.to_hex(entry.id)), Binary(sealed)])
  else
    Sqlite.execute_values(database,
      "UPDATE token_burn_journal SET ciphertext = ? WHERE id = ? AND ciphertext = ?",
      [Binary(sealed), Text(Bytes.to_hex(entry.id)), Binary(previous)])
  end
  Sqlite.close(database)
  if changed? != 1 do
    return Err("token_burn_journal_changed")
  end
  Ok(entry)
end

fn journal_same_intent(first :: TokenBurnJournalEntry, second :: TokenBurnJournalEntry) -> Bool do
  first.id == second.id
    && first.program == second.program
    && first.payer == second.payer
    && first.kind == second.kind
    && first.epoch == second.epoch
    && first.index == second.index
    && first.instruction == second.instruction
    && first.not_before == second.not_before
    && first.deadline == second.deadline
end

fn journal_reserve(path :: String,
  wrapping :: borrow StorageKey,
  entry :: TokenBurnJournalEntry) -> TokenBurnJournalEntry!String do
  let database = journal_database(path)?
  let prior = journal_raw(database, entry.id)
  Sqlite.close(database)
  case prior? do
    None -> case journal_save(path, wrapping, Bytes.empty(), entry) do
      Ok(value) -> return Ok(value)
      Err(error) -> if error != "token_burn_journal_changed" do
        return Err(error)
      end
    end
    Some(_) -> nil
  end
  let current = journal_load(path,
    wrapping,
    entry.program,
    entry.kind,
    entry.epoch,
    entry.index)?.entry
  if !journal_same_intent(entry, current) do
    Err("token_burn_intent_conflict")
  else
    Ok(current)
  end
end

pub fn reserve_token_burn_fund(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  budget :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> TokenBurnJournalEntry!String do
  let instruction = token_burn_fund_instruction(program,
    payer,
    profile,
    epoch,
    budget,
    weights,
    entropy)?
  let deadline = U64.add(U64.multiply(epoch, U64.parse("604800")?)?, U64.parse("25200")?)?
  journal_reserve(path,
    wrapping,
    TokenBurnJournalEntry {
      id: journal_id(program, 9, epoch, 0)?,
      program: program,
      payer: payer,
      kind: 9,
      epoch: epoch,
      index: 0,
      instruction: instruction,
      status: 0,
      not_before: U64.parse("0")?,
      deadline: deadline,
      context_slot: U64.parse("0")?,
      last_valid_block_height: U64.parse("0")?,
      packet: Bytes.empty(),
      signature: Bytes.empty()
    })
end

pub fn reserve_token_burn_chunk(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  week :: TokenBurnWeek,
  index :: Int,
  route :: Bytes,
  spot :: U64) -> TokenBurnJournalEntry!String do
  let instruction = token_burn_execute_instruction(program,
    payer,
    profile,
    week,
    index,
    route,
    spot)?
  let row = List.get(week.rows, index)
  journal_reserve(path,
    wrapping,
    TokenBurnJournalEntry {
      id: journal_id(program, 10, week.epoch, index)?,
      program: program,
      payer: payer,
      kind: 10,
      epoch: week.epoch,
      index: index,
      instruction: instruction,
      status: 0,
      not_before: row.execute_at,
      deadline: row.window_end,
      context_slot: U64.parse("0")?,
      last_valid_block_height: U64.parse("0")?,
      packet: Bytes.empty(),
      signature: Bytes.empty()
    })
end

pub fn load_token_burn_entry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int) -> TokenBurnJournalEntry!String do
  Ok(journal_load(path, wrapping, program, kind, epoch, index)?.entry)
end

pub fn sign_and_commit_token_burn_entry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  payer :: borrow SigningPrivateKey,
  treasury :: borrow SigningPrivateKey,
  blockhash :: Hash,
  slot :: U64,
  height :: U64) -> TokenBurnJournalEntry!String do
  let current = journal_load(path, wrapping, program, kind, epoch, index)?.entry
  if current.status != 0 do
    return Ok(current)
  end
  let message = compile_legacy_message(current.payer,
    blockhash,
    [compute_unit_limit_instruction(1000000)?, current.instruction])?
  let encoded = serialize_legacy_message(message)?
  let signatures = for index in 0..message.header.num_required_signatures do
    let key = List.get(message.account_keys, index)
    if key == current.payer do
      case Crypto.sign(payer, encoded) do
        Err(_) -> return Err("token_burn_signing_failed")
        Ok(value) -> value
      end
    else if (kind == 9 || kind == 14) && key == List.head(current.instruction.accounts).pubkey do
      case Crypto.sign(treasury, encoded) do
        Err(_) -> return Err("token_burn_signing_failed")
        Ok(value) -> value
      end
    else
      return Err("unexpected_token_burn_signer")
    end
  end
  let packet = serialize_signed_legacy_transaction(message, signatures)?
  commit_token_burn_packet(path, wrapping, program, kind, epoch, index, packet, slot, height)
end

pub fn commit_token_burn_packet(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  packet :: Bytes,
  slot :: U64,
  height :: U64) -> TokenBurnJournalEntry!String do
  let current = journal_load(path, wrapping, program, kind, epoch, index)?
  let signature = Bytes.slice(packet, 1, 64)?
  journal_packet(current.entry, packet, signature)?
  if slot == U64.parse("0")? || height == U64.parse("0")? do
    return Err("invalid_token_burn_packet_lifetime")
  end
  if current.entry.status != 0 do
    if current.entry.packet != packet
      || current.entry.context_slot != slot
      || current.entry.last_valid_block_height != height do
      return Err("token_burn_packet_already_committed")
    end
    return Ok(current.entry)
  end
  journal_save(path,
    wrapping,
    current.previous,
    %{current.entry |
      status: 1,
      packet: packet,
      signature: signature,
      context_slot: slot,
      last_valid_block_height: height
    })
end

pub fn submit_token_burn_entry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  client :: Int,
  url :: String,
  now :: U64,
  height :: U64) -> TokenBurnJournalEntry!String do
  let current = journal_load(path, wrapping, program, kind, epoch, index)?
  let entry = current.entry
  if entry.status == 3 do
    return Ok(entry)
  end
  if entry.status == 0 do
    return Err("token_burn_packet_not_committed")
  end
  if U64.compare(now, entry.not_before) < 0
    || U64.compare(now, entry.deadline) >= 0
    || U64.compare(height, entry.last_valid_block_height) > 0 do
    return Err("token_burn_packet_reconcile_only")
  end
  let request = send_transaction_request(2, entry.packet, entry.signature, entry.context_slot)?
  sent_signature_from_response(rpc_send(client, url, request, 5000, 4096)?, entry.signature)?
  let latest = journal_load(path, wrapping, program, kind, epoch, index)?
  if latest.entry.packet != entry.packet do
    return Err("token_burn_journal_changed")
  end
  if latest.entry.status >= 2 do
    return Ok(latest.entry)
  end
  journal_save(path, wrapping, latest.previous, %{latest.entry | status: 2})
end

pub fn confirm_token_burn_entry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  state :: TokenBurnState) -> TokenBurnJournalEntry!String do
  let week = case state.week do
    None -> return Err("token_burn_receipt_missing")
    Some(value) -> value
  end
  journal_confirm_original(path,
    wrapping,
    program,
    kind,
    epoch,
    index,
    state.profile,
    week,
    state.context_slot)
end

fn journal_confirm_original(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  profile :: TokenBurnProfile,
  week :: TokenBurnWeek,
  slot :: U64) -> TokenBurnJournalEntry!String do
  if kind != 9 && kind != 10 do
    return Err("token_burn_receipt_kind")
  end
  let current = journal_load(path, wrapping, program, kind, epoch, index)?
  let entry = current.entry
  let token = token_addresses(program)?
  if profile.config != token.config
    || week.epoch != epoch
    || U64.compare(slot, entry.context_slot) < 0 do
    return Err("token_burn_receipt_mismatch")
  end
  let payload = Bytes.slice(entry.instruction.data, 1, Bytes.length(entry.instruction.data) - 1)?
  let hash = if kind == 9 do
    Crypto.sha256(journal_cat([
      Bytes.from_utf8("morse-burn-week-v1"),
      week.profile.bytes,
      payload
    ])?)
  else
    Crypto.sha256(journal_cat([Bytes.from_utf8("morse-burn-chunk-v1"), payload])?)
  end
  let valid = if kind == 9 do
    week.funding_hash == hash
      && week.profile == List.get(entry.instruction.accounts, 4).pubkey
      && week.usdc == List.get(entry.instruction.accounts, 5).pubkey
      && week.source == List.get(entry.instruction.accounts, 8).pubkey
      && week.budget == U64.parse(Bytes.read_uint_le(entry.instruction.data, 9, 8)?)?
  else
    let row = List.get(week.rows, index)
    row.complete
      && row.execution_hash == hash
      && week.profile == List.get(entry.instruction.accounts, 3).pubkey
      && week.usdc == List.get(entry.instruction.accounts, 4).pubkey
      && week.vault == List.get(entry.instruction.accounts, 6).pubkey
      && row.amount == U64.parse(Bytes.read_uint_le(entry.instruction.data, 10, 8)?)?
  end
  if !valid || entry.status == 0 do
    return Err("token_burn_receipt_mismatch")
  end
  if entry.status == 3 do
    return Ok(entry)
  end
  journal_save(path, wrapping, current.previous, %{entry | status: 3})
end

fn journal_reserve_carry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  payer :: Pubkey,
  kind :: Int,
  epoch :: U64,
  instruction :: Instruction) -> TokenBurnJournalEntry!String do
  let start = U64.multiply(epoch, U64.parse("604800")?)?
  let before = if kind == 13 do
    U64.add(start, U64.parse("604800")?)?
  else
    U64.parse("0")?
  end
  let deadline = if kind == 13 do
    U64.parse("9223372036854775807")?
  else
    U64.add(start, U64.parse("25200")?)?
  end
  journal_reserve(path,
    wrapping,
    TokenBurnJournalEntry {
      id: journal_id(program, kind, epoch, 0)?,
      program: program,
      payer: payer,
      kind: kind,
      epoch: epoch,
      index: 0,
      instruction: instruction,
      status: 0,
      not_before: before,
      deadline: deadline,
      context_slot: U64.parse("0")?,
      last_valid_block_height: U64.parse("0")?,
      packet: Bytes.empty(),
      signature: Bytes.empty()
    })
end

pub fn reserve_token_burn_fund_v2(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  cash :: U64,
  carry :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> TokenBurnJournalEntry!String do
  let instruction = token_burn_fund_v2_instruction(program,
    payer,
    profile,
    epoch,
    cash,
    carry,
    weights,
    entropy)?
  journal_reserve_carry(path, wrapping, program, payer, 14, epoch, instruction)
end

pub fn reserve_token_burn_close(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64) -> TokenBurnJournalEntry!String do
  let instruction = token_burn_close_instruction(program, payer, profile, epoch)?
  journal_reserve_carry(path, wrapping, program, payer, 13, epoch, instruction)
end

# The caller must supply an authenticated finalized bank, never a Boolean "paid" flag.
# The isolated custody-only reader enforces that bank's owners, addresses, code pins and balances.
pub fn confirm_token_burn_carry_entry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  profile :: TokenBurnProfile,
  frame :: TokenBurnCarryFrame,
  receipt :: Option<TokenBurnCloseReceipt>,
  slot :: U64) -> TokenBurnJournalEntry!String do
  if kind != 13 && kind != 14 do
    return Err("token_burn_receipt_kind")
  end
  let current = journal_load(path, wrapping, program, kind, epoch, 0)?
  let entry = current.entry
  let a = token_burn_addresses(program, profile, epoch, 0)?
  let c = token_burn_carry_addresses(program, profile.usdc, epoch)?
  let week = frame.week
  if entry.status == 0
    || U64.compare(slot, entry.context_slot) < 0
    || week.epoch != epoch
    || week.profile != a.profile
    || week.usdc != profile.usdc
    || week.treasury != profile.treasury
    || week.vault != a.week_vault
    || week.source != a.treasury_source
    || (frame.version != 1 && frame.version != 2)
    || U64.add(frame.cash_budget, frame.carry_budget)? != week.budget
    || (frame.version == 2 && frame.carry != Some(c.carry)) do
    return Err("token_burn_receipt_mismatch")
  end
  if frame.closed do
    let r = case receipt do
      None -> return Err("token_burn_close_receipt_missing")
      Some(value) -> value
    end
    if r.profile != a.profile
      || r.week != a.week
      || r.source != a.week_vault
      || r.epoch != epoch
      || r.budget != week.budget
      || r.spent != week.spent
      || r.burned != week.burned
      || r.carried != U64.subtract(week.budget, week.spent)?
      || r.carry != c.carry
      || r.funding_hash != week.funding_hash
      || r.active_frame_hash != frame.active_frame_hash
      || r.version != frame.version do
      return Err("token_burn_close_receipt_mismatch")
    end
  else if receipt != None do
    return Err("token_burn_unexpected_close_receipt")
  end
  let valid = if kind == 13 do
    frame.closed
      && receipt != None
      && entry.instruction == token_burn_close_instruction(program, entry.payer, profile, epoch)?
  else
    let payload = Bytes.slice(entry.instruction.data, 1, 312)?
    let hash = Crypto.sha256(journal_cat([
      Bytes.from_utf8("morse-burn-week-v2"),
      a.profile.bytes,
      payload
    ])?)
    frame.version == 2
      && week.funding_hash == hash
      && frame.cash_budget == U64.parse(Bytes.read_uint_le(payload, 8, 8)?)?
      && frame.carry_budget == U64.parse(Bytes.read_uint_le(payload, 16, 8)?)?
      && a.profile == List.get(entry.instruction.accounts, 4).pubkey
      && a.week == List.get(entry.instruction.accounts, 6).pubkey
      && a.week_vault == List.get(entry.instruction.accounts, 7).pubkey
      && a.treasury_source == List.get(entry.instruction.accounts, 8).pubkey
      && c.carry == List.get(entry.instruction.accounts, 17).pubkey
      && c.carry_vault == List.get(entry.instruction.accounts, 18).pubkey
  end
  if !valid do
    return Err("token_burn_receipt_mismatch")
  end
  if entry.status == 3 do
    return Ok(entry)
  end
  journal_save(path, wrapping, current.previous, %{entry | status: 3})
end

pub fn confirm_token_burn_original_from_carry(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  profile :: TokenBurnProfile,
  frame :: TokenBurnCarryFrame,
  receipt :: Option<TokenBurnCloseReceipt>,
  slot :: U64) -> TokenBurnJournalEntry!String do
  let a = token_burn_addresses(program, profile, epoch, 0)?
  let c = token_burn_carry_addresses(program, profile.usdc, epoch)?
  let week = frame.week
  if week.profile != a.profile
    || week.epoch != epoch
    || week.usdc != profile.usdc
    || week.treasury != profile.treasury
    || week.vault != a.week_vault
    || week.source != a.treasury_source
    || (frame.version == 2 && frame.carry != Some(c.carry)) do
    return Err("token_burn_receipt_mismatch")
  end
  if frame.closed do
    let r = case receipt do
      None -> return Err("token_burn_close_receipt_missing")
      Some(value) -> value
    end
    if r.profile != a.profile
      || r.week != a.week
      || r.source != a.week_vault
      || r.epoch != epoch
      || r.budget != week.budget
      || r.spent != week.spent
      || r.burned != week.burned
      || r.carried != U64.subtract(week.budget, week.spent)?
      || r.carry != c.carry
      || r.funding_hash != week.funding_hash
      || r.active_frame_hash != frame.active_frame_hash
      || r.version != frame.version do
      return Err("token_burn_close_receipt_mismatch")
    end
  else if receipt != None do
    return Err("token_burn_unexpected_close_receipt")
  end
  journal_confirm_original(path, wrapping, program, kind, epoch, index, profile, week, slot)
end

pub struct TokenBurnRetiredPacket do
  entry :: TokenBurnJournalEntry
  replacement_signature :: Bytes
  bank_digest :: Bytes
  observed_slot :: U64
  observed_height :: U64
  observed_time :: U64
end

pub struct TokenBurnMissedWindow do
  epoch :: U64
  index :: Int
  deadline :: U64
  observed_slot :: U64
  observed_height :: U64
  observed_time :: U64
  bank_digest :: Bytes
end

fn journal_evidence_context(program :: Pubkey, id :: Bytes, label :: Bytes) -> Bytes!String do
  journal_context(program,
    Crypto.sha256(journal_cat([Bytes.from_utf8("morse-token-burn-evidence-v1"), id, label])?))
end

fn journal_bank_frame(program :: Pubkey,
  epoch :: U64,
  bank :: TokenBurnBank) -> TokenBurnCarryFrame!String do
  let token = token_addresses(program)?
  let frame = case bank.custody.frame do
    None -> return Err("token_burn_reconcile_bank")
    Some(value) -> value
  end
  if bank.program != program
    || bank.custody.profile.config != token.config
    || frame.week.epoch != epoch
    || !bank.custody.code_current
    || Bytes.length(bank.digest) != 32
    || bank.custody.timestamp <= 0
    || bank.custody.context_slot == U64.parse("0")?
    || bank.height == U64.parse("0")? do
    return Err("token_burn_reconcile_bank")
  end
  Ok(frame)
end

fn journal_replace_intent(entry :: TokenBurnJournalEntry, bank :: TokenBurnBank) -> Bool!String do
  let frame = journal_bank_frame(entry.program, entry.epoch, bank)?
  let original = signed_transaction(entry.packet, entry.signature)?
  if bank.expired_hash != Some(Hash { bytes: original.recent_blockhash }) do
    return Err("token_burn_hash_not_proven_expired")
  end
  let now = U64.parse(Int.to_string(bank.custody.timestamp))?
  if frame.closed
    || entry.status < 1
    || entry.status > 2
    || U64.compare(bank.custody.context_slot, entry.context_slot) < 0
    || U64.compare(bank.height, entry.last_valid_block_height) <= 0
    || U64.compare(bank.height, bank.tip.last_valid_block_height) >= 0
    || U64.compare(bank.tip.context_slot, bank.custody.context_slot) > 0
    || U64.compare(now, entry.not_before) < 0
    || U64.compare(now, entry.deadline) >= 0 do
    return Err("token_burn_reconcile_only")
  end
  let instruction = if entry.kind == 10 do
    let market = case bank.market do
      None -> return Err("token_burn_reconcile_market")
      Some(value) -> value
    end
    if !market.code_current
      || market.profile != bank.custody.profile
      || market.week != Some(frame.week)
      || market.context_slot != bank.custody.context_slot do
      return Err("token_burn_reconcile_market")
    end
    let row = List.get(frame.week.rows, entry.index)
    if row.complete || entry.not_before != row.execute_at || entry.deadline != row.window_end do
      return Err("token_burn_reconcile_only")
    end
    let spot = case market.spot do
      None -> return Err("token_burn_reconcile_price")
      Some(value) -> value
    end
    token_burn_execute_instruction(entry.program,
      entry.payer,
      bank.custody.profile,
      frame.week,
      entry.index,
      Bytes.slice(entry.instruction.data, 2, 39)?,
      spot)?
  else if entry.kind == 13 do
    token_burn_close_instruction(entry.program, entry.payer, bank.custody.profile, entry.epoch)?
  else
    return Err("token_burn_replacement_kind")
  end
  if instruction != entry.instruction do
    return Err("token_burn_intent_conflict")
  end
  Ok(true)
end

fn journal_replace_transaction(database :: SqliteConn,
  id :: Bytes,
  previous :: Bytes,
  sealed :: Bytes,
  signature :: Bytes,
  evidence :: Bytes) -> Bool!String do
  let missed = Sqlite.query_values(database,
    "SELECT id FROM token_burn_missed WHERE id = ?",
    [Text(Bytes.to_hex(id))])?
  if List.length(missed) != 0 do
    return Err("token_burn_reconcile_missed")
  end
  let rows = Sqlite.query_values(database,
    "SELECT signature FROM token_burn_retired WHERE id = ? LIMIT 64",
    [Text(Bytes.to_hex(id))])?
  if List.length(rows) >= 64 do
    return Err("token_burn_replacement_limit")
  end
  let changed = Sqlite.execute_values(database,
    "UPDATE token_burn_journal SET ciphertext = ? WHERE id = ? AND ciphertext = ?",
    [Binary(sealed), Text(Bytes.to_hex(id)), Binary(previous)])?
  if changed != 1 do
    return Err("token_burn_journal_changed")
  end
  let inserted = Sqlite.execute_values(database,
    "INSERT INTO token_burn_retired (id,signature,ciphertext) VALUES (?,?,?)",
    [Text(Bytes.to_hex(id)), Text(Bytes.to_hex(signature)), Binary(evidence)])?
  if inserted != 1 do
    return Err("token_burn_journal_changed")
  end
  Ok(true)
end

# Explicit replacement only. No reserved/status0 interval exists in which a stale old
# signer can resurrect a retired packet. Both archive and current packet change in one CAS.
pub fn replace_token_burn_expired_packet(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  expected_signature :: Bytes,
  bank :: TokenBurnBank,
  payer :: borrow SigningPrivateKey) -> TokenBurnJournalEntry!String do
  let current = journal_load(path, wrapping, program, kind, epoch, index)?
  let entry = current.entry
  if entry.signature != expected_signature do
    return Err("token_burn_journal_changed")
  end
  journal_replace_intent(entry, bank)?
  let message = compile_legacy_message(entry.payer,
    bank.tip.blockhash,
    [compute_unit_limit_instruction(1000000)?, entry.instruction])?
  if message.header.num_required_signatures != 1 do
    return Err("unexpected_token_burn_signer")
  end
  let signed = case Crypto.sign(payer, serialize_legacy_message(message)?) do
    Err(_) -> return Err("token_burn_signing_failed")
    Ok(value) -> value
  end
  let packet = serialize_signed_legacy_transaction(message, [signed])?
  let signature = signed.bytes
  journal_packet(entry, packet, signature)?
  if signature == entry.signature || packet == entry.packet do
    return Err("token_burn_replacement_unchanged")
  end
  let next = %{entry |
    status: 1,
    packet: packet,
    signature: signature,
    context_slot: bank.custody.context_slot,
    last_valid_block_height: bank.tip.last_valid_block_height
  }
  let encoded = journal_encode(next)?
  journal_decode(program, kind, epoch, index, encoded)?
  let sealed = case StorageKey.seal_bytes(encoded, wrapping, journal_context(program, entry.id)?) do
    Err(_) -> return Err("token_burn_journal_seal_failed")
    Ok(value) -> value
  end
  let archive = journal_pack([
    Bytes.from_hex("01")?,
    journal_encode(entry)?,
    current.previous,
    signature,
    bank.digest,
    journal_wide(bank.custody.context_slot)?,
    journal_wide(bank.height)?,
    journal_wide(U64.parse(Int.to_string(bank.custody.timestamp))?)?
  ])?
  let evidence = case StorageKey.seal_bytes(archive,
    wrapping,
    journal_evidence_context(program, entry.id, entry.signature)?) do
    Err(_) -> return Err("token_burn_journal_seal_failed")
    Ok(value) -> value
  end
  let database = journal_database(path)?
  let result = case Sqlite.begin(database) do
    Err(_) -> Err("token_burn_journal_write_failed")
    Ok(_) -> case journal_replace_transaction(database,
      entry.id,
      current.previous,
      sealed,
      entry.signature,
      evidence) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("token_burn_journal_write_failed")
        Ok(_) -> Ok(next)
      end
    end
  end
  if Result.is_err(result) do
    Sqlite.rollback(database)
  else
    Ok(nil)
  end
  Sqlite.close(database)
  result
end

pub fn load_token_burn_retired_packet(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  kind :: Int,
  epoch :: U64,
  index :: Int,
  signature :: Bytes) -> TokenBurnRetiredPacket!String do
  let id = journal_id(program, kind, epoch, index)?
  if Bytes.length(signature) != 64 do
    return Err("invalid_token_burn_retired_signature")
  end
  let database = journal_database(path)?
  let loaded = Sqlite.query_values(database,
    "SELECT ciphertext FROM token_burn_retired WHERE id = ? AND signature = ?",
    [Text(Bytes.to_hex(id)), Text(Bytes.to_hex(signature))])
  Sqlite.close(database)
  let rows = loaded?
  if List.length(rows) != 1 do
    return Err("token_burn_retired_packet_missing")
  end
  let sealed = case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> value
    _ -> return Err("invalid_token_burn_retired_packet")
  end
  let opened = case StorageKey.unseal_bytes(sealed,
    wrapping,
    journal_evidence_context(program, id, signature)?) do
    Err(_) -> return Err("token_burn_retired_authentication_failed")
    Ok(value) -> value
  end
  let parts = journal_unpack(opened)?
  if List.length(parts) != 8
    || List.get(parts, 0) != Bytes.from_hex("01")?
    || Bytes.length(List.get(parts, 3)) != 64
    || Bytes.length(List.get(parts, 4)) != 32 do
    return Err("invalid_token_burn_retired_packet")
  end
  let entry = journal_decode(program, kind, epoch, index, List.get(parts, 1))?
  if entry.signature != signature do
    return Err("invalid_token_burn_retired_packet")
  end
  let original = case StorageKey.unseal_bytes(List.get(parts, 2),
    wrapping,
    journal_context(program, id)?) do
    Err(_) -> return Err("token_burn_retired_authentication_failed")
    Ok(value) -> journal_decode(program, kind, epoch, index, value)?
  end
  if original != entry do
    return Err("invalid_token_burn_retired_packet")
  end
  Ok(TokenBurnRetiredPacket {
    entry: entry,
    replacement_signature: List.get(parts, 3),
    bank_digest: List.get(parts, 4),
    observed_slot: journal_number(List.get(parts, 5))?,
    observed_height: journal_number(List.get(parts, 6))?,
    observed_time: journal_number(List.get(parts, 7))?
  })
end

# A missed window is a durable observation, never a release authorization. The week
# remains funded until the existing canonical close-to-carry instruction succeeds.
pub fn record_token_burn_missed_window(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  epoch :: U64,
  index :: Int,
  bank :: TokenBurnBank) -> TokenBurnMissedWindow!String do
  let frame = journal_bank_frame(program, epoch, bank)?
  let id = journal_id(program, 10, epoch, index)?
  let row = List.get(frame.week.rows, index)
  let now = U64.parse(Int.to_string(bank.custody.timestamp))?
  if frame.closed || row.complete || U64.compare(now, row.window_end) < 0 do
    return Err("token_burn_window_not_missed")
  end
  let prior = load_token_burn_missed_window(path, wrapping, program, epoch, index)?
  case prior do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let plain = journal_pack([
    Bytes.from_hex("01")?,
    journal_wide(epoch)?,
    journal_byte(index)?,
    journal_wide(row.window_end)?,
    journal_wide(bank.custody.context_slot)?,
    journal_wide(bank.height)?,
    journal_wide(now)?,
    bank.digest,
    frame.week.funding_hash
  ])?
  let sealed = case StorageKey.seal_bytes(plain,
    wrapping,
    journal_evidence_context(program, id, Bytes.from_utf8("missed"))?) do
    Err(_) -> return Err("token_burn_journal_seal_failed")
    Ok(value) -> value
  end
  let database = journal_database(path)?
  let result = Sqlite.execute_values(database,
    "INSERT INTO token_burn_missed (id,ciphertext) VALUES (?,?) ON CONFLICT(id) DO NOTHING",
    [Text(Bytes.to_hex(id)), Binary(sealed)])
  Sqlite.close(database)
  result?
  case load_token_burn_missed_window(path, wrapping, program, epoch, index)? do
    None -> Err("token_burn_journal_changed")
    Some(value) -> Ok(value)
  end
end

pub fn load_token_burn_missed_window(path :: String,
  wrapping :: borrow StorageKey,
  program :: Pubkey,
  epoch :: U64,
  index :: Int) -> Option<TokenBurnMissedWindow>!String do
  let id = journal_id(program, 10, epoch, index)?
  let database = journal_database(path)?
  let loaded = Sqlite.query_values(database,
    "SELECT ciphertext FROM token_burn_missed WHERE id = ?",
    [Text(Bytes.to_hex(id))])
  Sqlite.close(database)
  let rows = loaded?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  if List.length(rows) != 1 do
    return Err("invalid_token_burn_missed")
  end
  let sealed = case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> value
    _ -> return Err("invalid_token_burn_missed")
  end
  let plain = case StorageKey.unseal_bytes(sealed,
    wrapping,
    journal_evidence_context(program, id, Bytes.from_utf8("missed"))?) do
    Err(_) -> return Err("token_burn_missed_authentication_failed")
    Ok(value) -> value
  end
  let parts = journal_unpack(plain)?
  if List.length(parts) != 9
    || List.get(parts, 0) != Bytes.from_hex("01")?
    || journal_number(List.get(parts, 1))? != epoch
    || List.get(parts, 2) != journal_byte(index)?
    || Bytes.length(List.get(parts, 7)) != 32
    || Bytes.length(List.get(parts, 8)) != 32 do
    return Err("invalid_token_burn_missed")
  end
  let deadline = journal_number(List.get(parts, 3))?
  let observed = journal_number(List.get(parts, 6))?
  let expected = U64.multiply(U64.add(U64.multiply(epoch, U64.parse("24")?)?,
      U64.parse(Int.to_string(index + 1))?)?,
    U64.parse("25200")?)?
  if deadline != expected || U64.compare(observed, deadline) < 0 do
    return Err("invalid_token_burn_missed")
  end
  Ok(Some(TokenBurnMissedWindow {
    epoch: epoch,
    index: index,
    deadline: deadline,
    observed_slot: journal_number(List.get(parts, 4))?,
    observed_height: journal_number(List.get(parts, 5))?,
    observed_time: observed,
    bank_digest: List.get(parts, 7)
  }))
end
