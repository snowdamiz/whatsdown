from Mobile.Profile import device_keys
from Mobile.Attachments import open_attachment_chunk_with_device
from Mobile.BackupAttachmentReader import (
  decode_backup_issuer_frame_result, require_backup_attachment_read_time
)
from Tests.BackupAttachmentFixture import (
  backup_attachment_fixture_material, backup_attachment_fixture_damage,
  backup_attachment_fixture_drop_device
)

fn reader_fixture_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY finite equality and refusal predicates over authored synthetic borrowed attachment fixtures; no real metadata content keys ciphertext errors or prior caller control are disclosed")
end

fn reader_fixture_equals(raw :: Result<Plaintext<Bytes>, String>) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, Bytes.from_utf8("x"))
  end
end

fn borrowed_positive(version :: Int) -> Plaintext<Bool>!String do
  let device = device_keys()?
  let fixture = backup_attachment_fixture_material(device, version, U64.parse("4102444800000")?)?
  let result = reader_fixture_equals(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index, fixture.wire))
  backup_attachment_fixture_drop_device(device)
  Ok(result)
end

fn borrowed_legacy(version :: Int) -> Plaintext<Bool>!String do
  let device = device_keys()?
  let fixture = backup_attachment_fixture_material(device, version, U64.parse("4102444800000")?)?
  let result = reader_fixture_equals(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index, fixture.legacy))
  backup_attachment_fixture_drop_device(device)
  Ok(result)
end

fn borrowed_adversarial(version :: Int) -> Plaintext<Bool>!String do
  let device = device_keys()?
  let wrong = device_keys()?
  let fixture = backup_attachment_fixture_material(device, version, U64.parse("4102444800000")?)?
  let positive = reader_fixture_equals(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index, fixture.wire))
  let replaced = Result.is_err(open_attachment_chunk_with_device(device,
    fixture.replacement, fixture.index, fixture.wire))
  let wrong_device = Result.is_err(open_attachment_chunk_with_device(wrong,
    fixture.reference, fixture.index, fixture.wire))
  let wrong_index = Result.is_err(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index + 1, fixture.wire))
  let damaged = Result.is_err(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index, backup_attachment_fixture_damage(fixture.wire)?))
  let truncated = Result.is_err(open_attachment_chunk_with_device(device,
    fixture.reference, fixture.index, Bytes.slice(fixture.wire, 0, Bytes.length(fixture.wire) - 1)?))
  let outer = if version == 1 do
    reader_fixture_equals(open_attachment_chunk_with_device(device,
      fixture.wrong_outer_id, fixture.index, fixture.wire))
  else
    Result.is_err(open_attachment_chunk_with_device(device,
      fixture.wrong_outer_id, fixture.index, fixture.wire))
  end
  backup_attachment_fixture_drop_device(wrong)
  backup_attachment_fixture_drop_device(device)
  Ok(positive && replaced && wrong_device && wrong_index && damaged && truncated && outer)
end

test("borrowed device opens authored EAM1 ACH3 without a database or platform-key lookup") do
  assert(reader_fixture_observe(Result.unwrap_or(borrowed_positive(1), false)))
end

test("borrowed device opens authored EAM2 final ACH3 and exact padded EAM4 ACH4") do
  assert(reader_fixture_observe(Result.unwrap_or(borrowed_positive(2), false)))
  assert(reader_fixture_observe(Result.unwrap_or(borrowed_positive(4), false)))
end

test("borrowed device retains legacy ACH1 and ACH2 reads") do
  assert(reader_fixture_observe(Result.unwrap_or(borrowed_legacy(1), false)))
  assert(reader_fixture_observe(Result.unwrap_or(borrowed_legacy(2), false)))
end

test("borrowed device rejects exact-EAM substitution wrong owner index tag and modern outer object while preserving legacy route") do
  for version in [1, 2, 4] do
    assert(reader_fixture_observe(Result.unwrap_or(borrowed_adversarial(version), false)))
  end
end

fn issuer_optional_proof() -> Bool!String do
  let origin = "https://issuer.example"
  let empty = Bytes.from_hex("01000000000000")?
  let absent = decode_backup_issuer_frame_result(Err("host_callback_failed:4:2"), origin)
  let system = decode_backup_issuer_frame_result(Ok(empty), origin)
  if absent != Ok(None) || system != Ok(Some(empty)) do return Ok(false) end
  for raw in [
    Err("host_callback_failed:4:1"),
    Err("host_callback_failed:4:3"),
    Err("host_callback_missing"),
    Err("host_callback_not_registered"),
    Ok(Bytes.empty()),
    Ok(Bytes.from_utf8("unreadable resource"))
  ] do
    if !Result.is_err(decode_backup_issuer_frame_result(raw, origin)) do return Ok(false) end
  end
  Ok(true)
end

test("captured issuer selector absence stays distinct from explicit system roots and unreadable input") do
  assert(Result.unwrap_or(issuer_optional_proof(), false))
end

fn reader_time_proof() -> Bool!String do
  let started = U64.parse("100")?
  let fresh = U64.parse("200")?
  let expires = U64.parse("180")?
  Ok(Result.is_ok(require_backup_attachment_read_time(started, fresh, expires, U64.parse("100")?))
    && Result.is_ok(require_backup_attachment_read_time(started, fresh, expires, U64.parse("179")?))
    && Result.is_err(require_backup_attachment_read_time(started, fresh, expires, U64.parse("99")?))
    && Result.is_err(require_backup_attachment_read_time(started, fresh, expires, expires))
    && Result.is_err(require_backup_attachment_read_time(started, fresh, U64.parse("300")?, U64.parse("201")?)))
end

test("pure backup reader guard keeps rollback authority deadline and strict attachment expiry distinct") do
  assert(Result.unwrap_or(reader_time_proof(), false))
end
