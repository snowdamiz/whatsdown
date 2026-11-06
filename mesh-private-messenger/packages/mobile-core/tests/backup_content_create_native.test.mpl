from Mobile.BackupNative import (
  parse_backup_content_create_request,
  parse_backup_create_request,
  parse_backup_list_request,
  parse_backup_pending_state_request
)
from Backups.ContentArchive import BackupAttachmentPolicy
from Mobile.Codec import mobile_byte, mobile_vector, mobile_write_u64

fn native_repeat(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("native_fixture_repeat")
    Ok(bytes)
  end
end

fn native_join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 33554432) do
    Err(_) -> Err("native_fixture_join")
    Ok(bytes)
  end
end

fn native_base() -> Bytes!String do
  native_join([
    mobile_byte(1)?,
    mobile_vector(Bytes.from_utf8("/db"))?,
    mobile_vector(Bytes.from_utf8("profile"))?
  ])
end

fn native_option(value :: Option<U64>) -> Bytes!String do
  case value do
    None -> mobile_byte(0)
    Some(time) -> native_join([mobile_byte(1)?, mobile_write_u64(time)?])
  end
end

fn native_selection(kind :: Int,
  id :: Bytes,
  first :: Option<U64>,
  last :: Option<U64>) -> Bytes!String do
  native_join([mobile_byte(kind)?, mobile_vector(id)?, native_option(first)?, native_option(last)?])
end

fn native_create_frame(rows :: List<Bytes>) -> Bytes!String do
  native_join([
    native_base()?,
    mobile_vector(native_join([mobile_byte(List.length(rows))?] ++ rows)?)?
  ])
end

fn content_create_actual_frame(policy :: Int) -> Bytes!String do
  let encoded = if policy == 2 do
    "02000000142f73796e7468657469632f6261636b75702e64620000001853594e5448455449432d5055424c49432d50524f46494c450000004f020100000010333333333333333333333333333333330001ffffffffffffffff0200000020555555555555555555555555555555555555555555555555555555555555555501000000000000000000"
  else
    "03000000142f73796e7468657469632f6261636b75702e64620000001853594e5448455449432d5055424c49432d50524f46494c450000004f020100000010333333333333333333333333333333330001ffffffffffffffff0200000020555555555555555555555555555555555555555555555555555555555555555501000000000000000000"
  end
  case Bytes.from_hex(encoded) do
    Err(_) -> Err("content_create_fixture_hex")
    Ok(value)
  end
end

fn content_create_tag(input :: Bytes, tag :: Int) -> Bytes!String do
  let rest = case Bytes.slice(input, 1, Bytes.length(input) - 1) do
    Err(_) -> return Err("content_create_fixture_slice")
    Ok(value) -> value
  end
  native_join([mobile_byte(tag)?, rest])
end

test("content create strict parser consumes both actual TS policy frames without changing selectors") do
  let maximum = U64.parse("18446744073709551615")?
  println("CONTENT_CREATE_ACTUAL_TS_READY")
  for tag in [2, 3] do
    let frame = content_create_actual_frame(tag)?
    let raw = parse_backup_content_create_request(frame)
    assert(Result.is_ok(raw))
    let parsed = raw?
    assert(parsed.action.database_path == "/synthetic/backup.db"
      && Bytes.secure_equals(parsed.action.expected_profile,
        Bytes.from_utf8("SYNTHETIC-PUBLIC-PROFILE")))
    assert(case parsed.policy do
      RequireArchiveAttachments -> tag == 2
      AllowArchiveAttachmentOmissions -> tag == 3
    end)
    assert(List.length(parsed.selection) == 2)
    let first = List.head(parsed.selection)
    let second = List.head(List.tail(parsed.selection))
    assert(first.kind == 1 && Bytes.secure_equals(first.scope_id, native_repeat(51, 16)?))
    assert(second.kind == 2 && Bytes.secure_equals(second.scope_id, native_repeat(85, 32)?))
    assert(case (first.from_time, first.through_time, second.from_time, second.through_time) do
      (None, Some(last), Some(start), None) -> U64.compare(last, maximum) == 0
        && U64.compare(start, U64.parse("0")?) == 0
      _ -> false
    end)
    assert(Bytes.secure_equals(frame, content_create_actual_frame(tag)?))
  end
  Ok(nil)
end

test("content create maximum selection still fits exact native request cap for both policies") do
  let maximum = U64.parse("18446744073709551615")?
  let common = native_join([
    mobile_byte(1)?,
    mobile_vector(native_repeat(65, 4096)?)?,
    mobile_vector(native_repeat(66, 36134)?)?
  ])?
  let rows = for index in 0..32 do
    native_selection(2, native_repeat(index, 32)?, Some(maximum), Some(maximum))?
  end
  let legacy = native_join([common, mobile_vector(native_join([mobile_byte(32)?] ++ rows)?)?])?
  assert(Bytes.length(legacy) == 42004 && Result.is_ok(parse_backup_create_request(legacy)))
  println("CONTENT_CREATE_MAXIMUM_READY")
  for tag in [2, 3] do
    let frame = content_create_tag(legacy, tag)?
    let raw = parse_backup_content_create_request(frame)
    assert(Result.is_ok(raw))
    let parsed = raw?
    assert(List.length(parsed.selection) == 32 && Bytes.length(frame) == 42004)
    for row in parsed.selection do
      assert(row.kind == 2 && Bytes.length(row.scope_id) == 32)
      assert(case (row.from_time, row.through_time) do
        (Some(first), Some(last)) -> U64.compare(first, maximum) == 0
          && U64.compare(last, maximum) == 0
        _ -> false
      end)
    end
    assert(Result.is_err(parse_backup_content_create_request(native_join([
      frame,
      mobile_byte(0)?
    ])?)))
  end
  Ok(nil)
end

test("content create tags remain separate from legacy create and every other operation") do
  let frame = content_create_actual_frame(2)?
  println("CONTENT_CREATE_TAGS_READY")
  assert(Result.is_ok(parse_backup_content_create_request(frame)))
  assert(Result.is_ok(parse_backup_create_request(content_create_tag(frame, 1)?)))
  for tag in [0, 1, 4, 5, 255] do
    assert(Result.is_err(parse_backup_content_create_request(content_create_tag(frame, tag)?)))
  end
  for tag in [2, 3] do
    let candidate = content_create_tag(frame, tag)?
    assert(Result.is_err(parse_backup_create_request(candidate)))
    assert(Result.is_err(parse_backup_list_request(content_create_tag(native_base()?, tag)?)))
    assert(Result.is_err(parse_backup_pending_state_request(content_create_tag(native_base()?,
      tag)?)))
  end
  assert(Result.is_err(parse_backup_content_create_request(Bytes.empty())))
  Ok(nil)
end

test("content create normalization preserves strict body rejection and original input bytes") do
  let frame = content_create_actual_frame(3)?
  let maximum = U64.parse("18446744073709551615")?
  let row = native_selection(1, native_repeat(4, 16)?, None, None)?
  println("CONTENT_CREATE_BODY_READY")
  assert(Result.is_ok(parse_backup_content_create_request(frame)))
  for tag in [2, 3] do
    for legacy in [
      native_create_frame([])?,
      native_create_frame([row, row])?,
      native_create_frame([native_selection(1, native_repeat(4, 32)?, None, None)?])?,
      native_create_frame([
        native_selection(1, native_repeat(4, 16)?, Some(maximum), Some(U64.parse("0")?))?
      ])?,
      native_join([
        mobile_byte(1)?,
        mobile_vector(Bytes.from_utf8("/db\0"))?,
        mobile_vector(Bytes.from_utf8("profile"))?,
        mobile_vector(native_join([mobile_byte(1)?, row])?)?
      ])?,
      native_join([
        mobile_byte(1)?,
        mobile_vector(native_repeat(255, 1)?)?,
        mobile_vector(Bytes.from_utf8("profile"))?,
        mobile_vector(native_join([mobile_byte(1)?, row])?)?
      ])?,
      native_join([
        mobile_byte(1)?,
        mobile_vector(Bytes.from_utf8("/db"))?,
        mobile_vector(Bytes.empty())?,
        mobile_vector(native_join([mobile_byte(1)?, row])?)?
      ])?,
      native_join([frame, mobile_byte(0)?])?,
      Bytes.slice(frame, 0, Bytes.length(frame) - 1)?
    ] do
      assert(Result.is_err(parse_backup_content_create_request(content_create_tag(legacy, tag)?)))
    end
  end
  assert(Bytes.secure_equals(frame, content_create_actual_frame(3)?))
  Ok(nil)
end
