from Transparency.TokenBurn import decode_token_burn_profile, decode_token_burn_week
from BurnJournal import (
  reserve_token_burn_chunk,
  load_token_burn_entry,
  commit_token_burn_packet,
  submit_token_burn_entry,
  confirm_token_burn_entry
)
from BurnJournal import reserve_token_burn_fund, sign_and_commit_token_burn_entry
from BurnJournal import TokenBurnJournalEntry
from Transparency.TokenBurnRead import TokenBurnReadPins, read_token_burn_quorum
from Transparency.TokenChain import decode_token_config
from Solana.Read import Pubkey, Hash, pubkey
from Solana.TransactionRead import signed_transaction

fn journal_text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn reject_journal_tampering(path :: String,
  wrapping :: borrow StorageKey,
  entry :: TokenBurnJournalEntry) -> Bool!String do
  let database = Sqlite.open(path)?
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext FROM token_burn_journal WHERE id = ?",
    [Text(Bytes.to_hex(entry.id))])?
  let original = case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> value
    _ -> return Err("invalid_tamper_fixture")
  end
  let last = Bytes.length(original) - 1
  let changed = Bytes.concat(Bytes.slice(original, 0, last)?,
    Bytes.write_uint_le(Int.to_string((Bytes.get(original, last)? + 1) % 256), 1)?)?
  Sqlite.execute_values(database,
    "UPDATE token_burn_journal SET ciphertext = ? WHERE id = ?",
    [Binary(changed), Text(Bytes.to_hex(entry.id))])?
  assert(Result.is_err(load_token_burn_entry(path,
    wrapping,
    entry.program,
    entry.kind,
    entry.epoch,
    entry.index)))
  Sqlite.execute_values(database,
    "UPDATE token_burn_journal SET ciphertext = ? WHERE id = ?",
    [Binary(original), Text(Bytes.to_hex(entry.id))])?
  let other_id = Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-token-burn-operation-v1"))
    <> Bytes.to_hex(entry.program.bytes)
    <> "0a"
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(entry.epoch), 8)?)
    <> "16")?)
  Sqlite.execute_values(database,
    "INSERT INTO token_burn_journal (id,ciphertext) VALUES (?,?)",
    [Text(Bytes.to_hex(other_id)), Binary(original)])?
  assert(Result.is_err(load_token_burn_entry(path, wrapping, entry.program, 10, entry.epoch, 22)))
  Sqlite.execute_values(database,
    "DELETE FROM token_burn_journal WHERE id = ?",
    [Text(Bytes.to_hex(other_id))])?
  Sqlite.close(database)
  assert(load_token_burn_entry(path,
    wrapping,
    entry.program,
    entry.kind,
    entry.epoch,
    entry.index)? == entry)
  Ok(true)
end

fn opaque_burn_signers() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", ""))?)?
  let profile = decode_token_burn_profile(Bytes.from_hex(journal_text(root, "profile_hex")?)?)?
  let program = pubkey(journal_text(root, "program")?)?
  let item = Json.array_get(Json.object_get(root, "weeks")?, 3)?
  let week = decode_token_burn_week(Bytes.from_hex(journal_text(item, "initial_data_hex")?)?)?
  let path = Env.get("MORSE_TOKEN_JOURNAL_PATH", "") <> "-opaque"
  let wrapping = case StorageKey.file(Env.get("MORSE_TOKEN_JOURNAL_KEY", "")) do
    Err(_) -> return Err("journal_key_unavailable")
    Ok(value) -> value
  end
  let payer = case Crypto.signing_generate() do
    Err(_) -> return Err("signer_fixture_failed")
    Ok(value) -> value
  end
  let treasury = case Crypto.signing_generate() do
    Err(_) -> return Err("signer_fixture_failed")
    Ok(value) -> value
  end
  let public = Pubkey { bytes: payer.public_key.bytes }
  let profile = %{profile | treasury: Pubkey { bytes: treasury.public_key.bytes }}
  let weights = for row in 0..24 do
    U64.parse("1")?
  end
  let entropy = for row in 0..24 do
    U64.parse(Int.to_string(row))?
  end
  let epoch = U64.add(week.epoch, U64.parse("1")?)?
  reserve_token_burn_fund(path,
    wrapping,
    program,
    public,
    profile,
    epoch,
    U64.parse("240000000")?,
    weights,
    entropy)?
  let hash = Hash { bytes: Bytes.from_hex(String.repeat("a4", 32))? }
  let slot = U64.parse("100")?
  let height = U64.parse("1000")?
  assert(Result.is_err(sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    9,
    epoch,
    0,
    treasury.private_key,
    treasury.private_key,
    hash,
    slot,
    height)))
  assert(load_token_burn_entry(path, wrapping, program, 9, epoch, 0)?.status == 0)
  let committed = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    9,
    epoch,
    0,
    payer.private_key,
    treasury.private_key,
    hash,
    slot,
    height)?
  let parsed = signed_transaction(committed.packet, committed.signature)?
  assert(committed.status == 1
    && List.length(parsed.signatures) == 2
    && parsed.recent_blockhash == hash.bytes)
  let other_hash = Hash { bytes: Bytes.from_hex(String.repeat("b5", 32))? }
  let retry = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    9,
    epoch,
    0,
    payer.private_key,
    treasury.private_key,
    other_hash,
    U64.parse("101")?,
    U64.parse("1001")?)?
  assert(retry == committed)
  Secret.destroy(payer.private_key)
  Secret.destroy(treasury.private_key)
  Secret.destroy(wrapping)
  Ok(true)
end

fn actual_packet_restart() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", ""))?)?
  let profile = decode_token_burn_profile(Bytes.from_hex(journal_text(root, "profile_hex")?)?)?
  let config = decode_token_config(Bytes.from_hex(journal_text(root, "config_hex")?)?)?
  let program = pubkey(journal_text(root, "program")?)?
  let payer = pubkey(journal_text(root, "payer")?)?
  let item = Json.array_get(Json.object_get(root, "weeks")?, 3)?
  let week = decode_token_burn_week(Bytes.from_hex(journal_text(item, "initial_data_hex")?)?)?
  let report = Json.array_get(Json.object_get(Json.object_get(root, "instructions")?, "execute")?,
    95)?
  let route = Bytes.slice(Bytes.from_base64(journal_text(report, "dataBase64")?)?, 2, 39)?
  let tx = Json.array_get(Json.object_get(root, "transactions")?, 95)?
  let packet = Bytes.from_base64(journal_text(tx, "wire_base64")?)?
  let signature = Bytes.from_base58(journal_text(tx, "signature")?)?
  let slot = U64.parse(journal_text(root, "context_slot")?)?
  let height = U64.parse("1000")?
  let now = U64.parse(journal_text(root, "now")?)?
  let stage = Env.get("MORSE_TOKEN_JOURNAL_STAGE", "write")
  let path = Env.get("MORSE_TOKEN_JOURNAL_PATH", "")
    <> (if stage == "concurrent" do
      "-race"
    else
      ""
    end)
  let directory = Env.get("MORSE_TOKEN_JOURNAL_KEY", "")
  let base = Env.get("MORSE_TOKEN_TEST_RPC", "")
  if path == "" || directory == "" || base == "" do
    return Err("run scripts/prove-token.sh for the durable keeper proof")
  end
  let wrapping = case StorageKey.file(directory) do
    Err(_) -> return Err("journal_key_unavailable")
    Ok(value) -> value
  end
  if stage == "concurrent" do
    reserve_token_burn_chunk(path,
      wrapping,
      program,
      payer,
      profile,
      week,
      23,
      route,
      U64.parse("2000000")?)?
    let committed = case commit_token_burn_packet(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      packet,
      slot,
      height) do
      Ok(value) -> value
      Err(error) -> if error == "token_burn_journal_changed" do
        load_token_burn_entry(path, wrapping, program, 10, week.epoch, 23)?
      else
        return Err(error)
      end
    end
    assert(committed.status == 1 && committed.packet == packet && committed.signature == signature)
    println("MORSE_TOKEN_PACKET_CONCURRENT: one immutable intent and packet across competing Mesh processes")
  else if stage == "write" do
    let planned = reserve_token_burn_chunk(path,
      wrapping,
      program,
      payer,
      profile,
      week,
      23,
      route,
      U64.parse("2000000")?)?
    let again = reserve_token_burn_chunk(path,
      wrapping,
      program,
      payer,
      profile,
      week,
      23,
      route,
      U64.parse("2000000")?)?
    assert(planned == again && planned.status == 0 && Bytes.length(planned.packet) == 0)
    let changed_route = Bytes.concat(Bytes.concat(Bytes.slice(route, 0, 16)?,
        Bytes.write_uint_le("5000001", 8)?)?,
      Bytes.slice(route, 24, 15)?)?
    assert(Result.is_err(reserve_token_burn_chunk(path,
      wrapping,
      program,
      payer,
      profile,
      week,
      23,
      changed_route,
      U64.parse("2000000")?)))
    let other = Json.array_get(Json.object_get(root, "transactions")?, 94)?
    assert(Result.is_err(commit_token_burn_packet(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      Bytes.from_base64(journal_text(other, "wire_base64")?)?,
      slot,
      height)))
    let committed = commit_token_burn_packet(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      packet,
      slot,
      height)?
    assert(committed.status == 1 && committed.signature == signature && committed.packet == packet)
    reject_journal_tampering(path, wrapping, committed)?
    assert(commit_token_burn_packet(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      packet,
      slot,
      height)? == committed)
    let client = Http.client()
    assert(Result.is_err(submit_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      client,
      base <> "/send",
      now,
      U64.parse("10")?)))
    let uncertain = load_token_burn_entry(path, wrapping, program, 10, week.epoch, 23)?
    assert(uncertain == committed)
    let acknowledged = submit_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      client,
      base <> "/send",
      now,
      U64.parse("10")?)?
    assert(acknowledged.status == 2
      && acknowledged.packet == packet
      && acknowledged.signature == signature)
    assert(Result.is_err(submit_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      client,
      base <> "/must-not-send",
      List.get(week.rows, 23).window_end,
      U64.parse("10")?)))
    assert(Result.is_err(submit_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      client,
      base <> "/must-not-send",
      now,
      U64.parse("1001")?)))
    Http.client_close(client)
  else
    let recovered = load_token_burn_entry(path, wrapping, program, 10, week.epoch, 23)?
    assert((recovered.status == 2 || recovered.status == 3)
      && recovered.signature == signature
      && recovered.packet == packet)
    let wrong = case StorageKey.file(directory <> "-other") do
      Err(_) -> return Err("wrong_key_fixture_failed")
      Ok(value) -> value
    end
    assert(Result.is_err(load_token_burn_entry(path, wrong, program, 10, week.epoch, 23)))
    Secret.destroy(wrong)
    let client = Http.client()
    let pins = TokenBurnReadPins {
      program: program,
      governance: config.governance,
      program_slot: U64.parse("0")?,
      usdc: profile.usdc,
      treasury: profile.treasury,
      factory: profile.factory
    }
    let state = read_token_burn_quorum(client,
      [base <> "/good-a", base <> "/good-b", base <> "/good-c"],
      true,
      pins,
      week.epoch,
      slot)?
    let finalized = confirm_token_burn_entry(path, wrapping, program, 10, week.epoch, 23, state)?
    assert(finalized.status == 3 && finalized.packet == packet && finalized.signature == signature)
    assert(confirm_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      state)? == finalized)
    let bad_state = %{state |
      week: Some(decode_token_burn_week(Bytes.from_hex(journal_text(item, "initial_data_hex")?)?)?)
    }
    assert(Result.is_err(confirm_token_burn_entry(path,
      wrapping,
      program,
      10,
      week.epoch,
      23,
      bad_state)))
    Http.client_close(client)
  end
  Secret.destroy(wrapping)
  println("MORSE_TOKEN_PACKET_JOURNAL: durable actual SDK packet and immutable intent recovered without resigning")
  Ok(true)
end

test("Durable sealed burn journal preserves the exact executed SDK packet across ambiguous send and process restart") do
  let result = actual_packet_restart()
  case result do
    Err(reason) -> println(reason)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end

test("Opaque keeper signers cannot sign an unreserved role or replace an uncertain two-signer packet") do
  if Env.get("MORSE_TOKEN_JOURNAL_STAGE", "write") == "write" do
    assert(opaque_burn_signers() == Ok(true))
  end
end
