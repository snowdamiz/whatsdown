from BurnCarryFixture import token_burn_carry_fixture
from Transparency.TokenBurnCarryRead import decode_token_burn_carry_snapshot
from BurnJournal import (
  reserve_token_burn_fund,
  reserve_token_burn_chunk,
  confirm_token_burn_original_from_carry,
  reserve_token_burn_fund_v2,
  reserve_token_burn_close,
  sign_and_commit_token_burn_entry,
  load_token_burn_entry,
  confirm_token_burn_carry_entry,
  submit_token_burn_entry
)
from Solana.Read import Pubkey, Hash
from Solana.TransactionRead import signed_transaction

fn actual_journal() -> Bool!String do
  let path = Env.get("MORSE_TOKEN_CARRY_JOURNAL_PATH", "")
  let wrapping = case StorageKey.file(Env.get("MORSE_TOKEN_CARRY_JOURNAL_KEY", "")) do
    Err(_) -> return Err("carry_journal_key_unavailable")
    Ok(value) -> value
  end
  let fixture = token_burn_carry_fixture("mixed-funded")?
  let state = decode_token_burn_carry_snapshot(fixture.pins,
    fixture.epoch,
    fixture.snapshot.slot,
    fixture.snapshot)?
  let frame = case state.frame do
    None -> return Err("missing_frame")
    Some(value) -> value
  end
  let program = fixture.pins.program
  let payer = fixture.pins.governance
  let epoch = fixture.epoch
  let stage = Env.get("MORSE_TOKEN_CARRY_JOURNAL_STAGE", "write")
  if stage == "restart" do
    let restored = load_token_burn_entry(path, wrapping, program, 14, epoch, 0)?
    assert(restored.status == 3
      && Bytes.length(restored.packet) > 0
      && Bytes.length(restored.signature) == 64)
    let closed = load_token_burn_entry(path,
      wrapping,
      program,
      13,
      U64.subtract(epoch, U64.parse("1")?)?,
      0)?
    assert(closed.status == 3 && Bytes.length(closed.packet) > 0)
    Secret.destroy(wrapping)
    IO.eprintln("MORSE_TOKEN_CARRY_JOURNAL_RESTART sealed_exact_packets_two_final_receipts")
    return Ok(true)
  end
  let payer_key = case Crypto.signing_from_seed(Bytes.from_hex(String.repeat("cb", 32))?) do
    Err(_) -> return Err("fixture_signer_failed")
    Ok(value) -> value
  end
  let treasury = case Crypto.signing_from_seed(Bytes.from_hex(String.repeat("19", 32))?) do
    Err(_) -> return Err("fixture_signer_failed")
    Ok(value) -> value
  end
  assert(payer_key.public_key.bytes == payer.bytes)
  assert(treasury.public_key.bytes == state.profile.treasury.bytes)
  let weights = for index in 0..24 do
    U64.parse("1")?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(index * 999999))?
  end
  let reserved = reserve_token_burn_fund_v2(path,
    wrapping,
    program,
    payer,
    state.profile,
    epoch,
    U64.parse("120000000")?,
    U64.parse("120000000")?,
    weights,
    entropy)?
  assert(reserved.status == 0
    && reserved.kind == 14
    && List.length(reserved.instruction.accounts) == 19)
  assert(Result.is_err(reserve_token_burn_fund_v2(path,
    wrapping,
    program,
    payer,
    state.profile,
    epoch,
    U64.parse("119999999")?,
    U64.parse("120000001")?,
    weights,
    entropy)))
  let hash = Hash { bytes: Bytes.from_hex(String.repeat("a4", 32))? }
  assert(Result.is_err(sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    14,
    epoch,
    0,
    treasury.private_key,
    treasury.private_key,
    hash,
    state.context_slot,
    U64.parse("1000")?)))
  let committed = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    14,
    epoch,
    0,
    payer_key.private_key,
    treasury.private_key,
    hash,
    state.context_slot,
    U64.parse("1000")?)?
  assert(committed.status == 1
    && List.length(signed_transaction(committed.packet, committed.signature)?.signatures) == 2)
  let retry = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    14,
    epoch,
    0,
    payer_key.private_key,
    treasury.private_key,
    Hash { bytes: Bytes.from_hex(String.repeat("b5", 32))? },
    state.context_slot,
    U64.parse("2000")?)?
  assert(retry == committed)
  let client = Http.client()
  let base = Env.get("MORSE_TOKEN_CARRY_RPC", "http://127.0.0.1:9")
  assert(Result.is_err(submit_token_burn_entry(path,
    wrapping,
    program,
    14,
    epoch,
    0,
    client,
    base <> "/must-not-send",
    committed.deadline,
    U64.parse("1000")?)))
  assert(load_token_burn_entry(path, wrapping, program, 14, epoch, 0)? == committed)
  assert(Result.is_err(confirm_token_burn_carry_entry(path,
    wrapping,
    program,
    14,
    epoch,
    state.profile,
    %{frame | cash_budget: U64.parse("1")?},
    state.receipt,
    state.context_slot)))
  if Env.get("MORSE_TOKEN_CARRY_RPC", "") != "" do
    let now = U64.multiply(epoch, U64.parse("604800")?)?
    for endpoint in ["send-ambiguous", "send-wrong-id", "send-wrong-signature"] do
      assert(Result.is_err(submit_token_burn_entry(path,
        wrapping,
        program,
        14,
        epoch,
        0,
        client,
        base <> "/" <> endpoint,
        now,
        U64.parse("1000")?)))
      assert(load_token_burn_entry(path, wrapping, program, 14, epoch, 0)? == committed)
    end
    let ack = submit_token_burn_entry(path,
      wrapping,
      program,
      14,
      epoch,
      0,
      client,
      base <> "/send-ok",
      now,
      U64.parse("1000")?)?
    assert(ack.status == 2
      && ack.packet == committed.packet
      && ack.signature == committed.signature)
  end
  let confirmed = confirm_token_burn_carry_entry(path,
    wrapping,
    program,
    14,
    epoch,
    state.profile,
    frame,
    state.receipt,
    state.context_slot)?
  assert(confirmed.status == 3 && confirmed.packet == committed.packet)
  let old_fixture = token_burn_carry_fixture("legacy-closed")?
  let old = decode_token_burn_carry_snapshot(old_fixture.pins,
    old_fixture.epoch,
    old_fixture.snapshot.slot,
    old_fixture.snapshot)?
  let old_frame = case old.frame do
    None -> return Err("missing_closed_frame")
    Some(value) -> value
  end
  let close = reserve_token_burn_close(path,
    wrapping,
    program,
    payer,
    old.profile,
    old_fixture.epoch)?
  assert(close.status == 0
    && close.kind == 13
    && close.not_before == U64.multiply(U64.add(old_fixture.epoch, U64.parse("1")?)?,
        U64.parse("604800")?)?)
  let close_packet = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    13,
    old_fixture.epoch,
    0,
    payer_key.private_key,
    treasury.private_key,
    hash,
    state.context_slot,
    U64.parse("1000")?)?
  assert(List.length(signed_transaction(close_packet.packet,
    close_packet.signature)?.signatures) == 1)
  assert(Result.is_err(confirm_token_burn_carry_entry(path,
    wrapping,
    program,
    13,
    old_fixture.epoch,
    old.profile,
    old_frame,
    None,
    old.context_slot)))
  let final = confirm_token_burn_carry_entry(path,
    wrapping,
    program,
    13,
    old_fixture.epoch,
    old.profile,
    old_frame,
    old.receipt,
    old.context_slot)?
  assert(final.status == 3 && final.packet == close_packet.packet)
  # Historical v1 funding and v2 execution receipts remain recoverable after close.
  let legacy_fund = reserve_token_burn_fund(path,
    wrapping,
    program,
    payer,
    old.profile,
    old_fixture.epoch,
    U64.parse("240000000")?,
    weights,
    entropy)?
  sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    9,
    old_fixture.epoch,
    0,
    payer_key.private_key,
    treasury.private_key,
    hash,
    state.context_slot,
    U64.parse("1000")?)?
  assert(Result.is_err(submit_token_burn_entry(path,
    wrapping,
    program,
    9,
    old_fixture.epoch,
    0,
    client,
    base <> "/must-not-send",
    U64.parse(Int.to_string(old.timestamp))?,
    U64.parse("1000")?)))
  let legacy_final = confirm_token_burn_original_from_carry(path,
    wrapping,
    program,
    9,
    old_fixture.epoch,
    0,
    old.profile,
    old_frame,
    old.receipt,
    old.context_slot)?
  assert(legacy_final.status == 3 && legacy_final.id == legacy_fund.id)
  let raw = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", ""))?)?
  let vectors = Json.object_get(raw, "instructions")?
  let execute_report = Json.object_get(Json.array_get(vectors, 3)?, "instruction")?
  let route = Bytes.slice(Bytes.from_base64(Json.as_string(Json.object_get(execute_report,
      "dataBase64")?)?)?,
    2,
    39)?
  reserve_token_burn_chunk(path,
    wrapping,
    program,
    payer,
    state.profile,
    frame.week,
    0,
    route,
    U64.parse("2000000")?)?
  let execution = sign_and_commit_token_burn_entry(path,
    wrapping,
    program,
    10,
    epoch,
    0,
    payer_key.private_key,
    treasury.private_key,
    hash,
    state.context_slot,
    U64.parse("1000")?)?
  let later_fixture = token_burn_carry_fixture("mixed-closed")?
  let later = decode_token_burn_carry_snapshot(later_fixture.pins,
    later_fixture.epoch,
    later_fixture.snapshot.slot,
    later_fixture.snapshot)?
  let later_frame = case later.frame do
    None -> return Err("missing_later_frame")
    Some(value) -> value
  end
  let execution_final = confirm_token_burn_original_from_carry(path,
    wrapping,
    program,
    10,
    epoch,
    0,
    later.profile,
    later_frame,
    later.receipt,
    later.context_slot)?
  assert(execution_final.status == 3 && execution_final.packet == execution.packet)
  IO.eprintln("MORSE_TOKEN_CARRY_HISTORICAL v1_fund_v2_execution_after_terminal_close_no_rebroadcast")
  Http.client_close(client)
  Secret.destroy(payer_key.private_key)
  Secret.destroy(treasury.private_key)
  Secret.destroy(wrapping)
  IO.eprintln("MORSE_TOKEN_CARRY_JOURNAL immutable_intents_two_signers_exact_packets_reconcile_after_expiry")
  Ok(true)
end

test("sealed carry journal keeps signer roles, conflicting intent and expired packet recovery exact") do
  if Env.get("MORSE_TOKEN_CARRY_JOURNAL_PATH", "") == "" do
    assert(true)
  else
    let result = actual_journal()
    case result do
      Err(error) -> IO.eprintln(error)
      Ok(_) -> nil
    end
    assert(result == Ok(true))
  end
end
