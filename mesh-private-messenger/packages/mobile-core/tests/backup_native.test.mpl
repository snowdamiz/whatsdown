from Mobile.BackupNative import (
  BackupNativeSummary,
  parse_backup_list_request,
  parse_backup_create_request,
  parse_backup_preview_request,
  parse_backup_import_request,
  parse_backup_remove_request,
  parse_backup_overview_request,
  parse_backup_page_request,
  encode_backup_create_reply,
  encode_backup_import_reply,
  encode_backup_remove_reply,
  encode_backup_list_reply,
  encode_backup_overview_reply,
  encode_backup_page_reply
)
from Mobile.BackupArchiveView import (
  BackupArchiveConversation,
  BackupArchiveOverview,
  BackupArchivePage
)
from Backups.TextArchive import BackupArchiveRecord
from Mobile.Codec import (
  mobile_byte,
  mobile_vector,
  mobile_write_u16,
  mobile_write_u32,
  mobile_write_u64,
  encode_output_list
)

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

fn native_public_frame_matches(raw :: Result<Bytes, String>, expected :: Bytes) -> Bool do
  case raw do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
end

fn native_synthetic_observation(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY explicitly authored synthetic native backup frame equality length or rejection predicates; no real history recovery code hashes keys or arbitrary errors are disclosed")
end

fn native_synthetic_frame_matches(raw :: Result<Plaintext<Bytes>, String>,
  expected :: Bytes) -> Bool do
  let matches = case raw do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
  native_synthetic_observation(matches)
end

fn native_synthetic_frame_refused(raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  let refused = case raw do
    Err(_) -> true
    Ok(_) -> false
  end
  native_synthetic_observation(refused)
end

fn native_code() -> String!String do
  let bytes = native_join(for index in 0..1024 do
    Bytes.from_utf8("🙂")
  end)?
  case Bytes.to_utf8(bytes) do
    Err(_) -> Err("native_fixture_code")
    Ok(value)
  end
end

fn native_record(index :: Int, size :: Int) -> BackupArchiveRecord!String do
  Ok(BackupArchiveRecord {
    ordinal: index,
    direction: if index == 0 do
      1
    else
      2
    end,
    message_id: native_repeat(index + 1, 32)?,
    sender_account: native_repeat(31, 32)?,
    sender_device: native_repeat(32, 16)?,
    timestamp: U64.parse("18446744073709551615")?,
    attachment_omitted: size == 0,
    text: native_repeat(65, size)?
  })
end

fn native_record_frame(record :: BackupArchiveRecord) -> Bytes!String do
  encode_output_list([
    mobile_write_u16(record.ordinal)?,
    mobile_byte(record.direction)?,
    record.message_id,
    record.sender_account,
    record.sender_device,
    mobile_write_u64(record.timestamp)?,
    mobile_byte(if record.attachment_omitted do
      1
    else
      0
    end)?,
    record.text
  ])
end

fn native_page(entries :: List<BackupArchiveRecord>) -> BackupArchivePage!String do
  Ok(BackupArchivePage {
    backup_id: native_repeat(7, 32)?,
    kind: 2,
    scope_id: native_repeat(8, 32)?,
    offset: 0,
    next_offset: Some(List.length(entries)),
    entries: entries
  })
end

fn native_expected_page(page :: BackupArchivePage) -> Bytes!String do
  let next = case page.next_offset do
    None -> mobile_byte(0)?
    Some(value) -> native_join([mobile_byte(1)?, mobile_write_u32(value)?])?
  end
  native_join([
    mobile_byte(1)?,
    encode_output_list([
      page.backup_id,
      mobile_byte(page.kind)?,
      page.scope_id,
      mobile_write_u32(page.offset)?,
      next,
      encode_output_list(for row in page.entries do
        native_record_frame(row)?
      end)?
    ])?
  ])
end

test("native backup action parser accepts bounded action identity and refuses version arity UTF8 NUL and trailing data") do
  let frame = native_base()?
  println("NATIVE_ACTION_READY")
  let raw = parse_backup_list_request(frame)
  assert(Result.is_ok(raw))
  let action = raw?
  assert(action.database_path == "/db")
  assert(Bytes.secure_equals(action.expected_profile, Bytes.from_utf8("profile")))
  for bad in [
    native_join([
      mobile_byte(0)?,
      mobile_vector(Bytes.from_utf8("/db"))?,
      mobile_vector(Bytes.from_utf8("profile"))?
    ])?,
    native_join([frame, mobile_byte(0)?])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.empty())?,
      mobile_vector(Bytes.from_utf8("profile"))?
    ])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.from_utf8("/db\0other"))?,
      mobile_vector(Bytes.from_utf8("profile"))?
    ])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(native_repeat(255, 1)?)?,
      mobile_vector(Bytes.from_utf8("profile"))?
    ])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(native_repeat(65, 4097)?)?,
      mobile_vector(Bytes.from_utf8("profile"))?
    ])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.from_utf8("/db"))?,
      mobile_vector(Bytes.empty())?
    ])?,
    native_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.from_utf8("/db"))?,
      mobile_vector(native_repeat(65, 36135)?)?
    ])?
  ] do
    assert(Result.is_err(parse_backup_list_request(bad)))
  end
  let maximum = native_join([
    mobile_byte(1)?,
    mobile_vector(native_repeat(65, 4096)?)?,
    mobile_vector(native_repeat(66, 36134)?)?
  ])?
  assert(Bytes.length(maximum) == 40239 && Result.is_ok(parse_backup_list_request(maximum)))
  Ok(nil)
end

test("native backup selection parser preserves full U64 inclusive bounds and rejects duplicates inverted or oversized selection") do
  let maximum = U64.parse("18446744073709551615")?
  let valid = native_create_frame([
    native_selection(1, native_repeat(4, 16)?, Some(maximum), Some(maximum))?
  ])?
  println("NATIVE_SELECTION_READY")
  let raw = parse_backup_create_request(valid)
  assert(Result.is_ok(raw))
  let request = raw?
  let row = List.head(request.selection)
  assert(row.kind == 1 && Bytes.secure_equals(row.scope_id, native_repeat(4, 16)?))
  assert(case (row.from_time, row.through_time) do
    (Some(first), Some(last)) -> U64.compare(first, maximum) == 0 && U64.compare(last, maximum) == 0
    _ -> false
  end)
  let first = native_selection(1, native_repeat(4, 16)?, None, None)?
  for rows in [
    [],
    [first, first],
    [native_selection(3, native_repeat(4, 16)?, None, None)?],
    [native_selection(1, native_repeat(4, 32)?, None, None)?],
    [native_selection(2, native_repeat(4, 16)?, None, None)?],
    [native_selection(1, native_repeat(4, 16)?, Some(maximum), Some(U64.parse("0")?))?],
    for index in 0..33 do
      native_selection(2, native_repeat(index, 32)?, None, None)?
    end
  ] do
    assert(Result.is_err(parse_backup_create_request(native_create_frame(rows)?)))
  end
  let bound = for index in 0..32 do
    native_selection(2, native_repeat(index, 32)?, Some(maximum), Some(maximum))?
  end
  assert(Result.is_ok(parse_backup_create_request(native_create_frame(bound)?)))
  assert(Result.is_err(parse_backup_create_request(native_join([valid, mobile_byte(0)?])?)))
  Ok(nil)
end

test("native portable parsers accept full ciphertext Unicode code bound and fixed confirmation then refuse overrun or trailing fields") do
  let wire = native_repeat(77, 16796864)?
  let code = native_code()?
  let common = native_join([
    mobile_byte(1)?,
    mobile_vector(native_repeat(65, 4096)?)?,
    mobile_vector(native_repeat(66, 36134)?)?
  ])?
  let preview = native_join([common, mobile_vector(wire)?, mobile_vector(Bytes.from_utf8(code))?])?
  let confirmed = native_repeat(9, 32)?
  let imported = native_join([preview, confirmed])?
  assert(Bytes.length(preview) == 16841207 && Bytes.length(imported) == 16841239)
  println("NATIVE_PORTABLE_READY")
  assert(Result.is_ok(parse_backup_preview_request(preview)))
  let raw = parse_backup_import_request(imported)
  assert(Result.is_ok(raw))
  let request = raw?
  assert(Bytes.secure_equals(request.wire, wire) && request.recovery_code == code)
  assert(Bytes.secure_equals(request.confirmed_backup_id, confirmed))
  for bad in [
    native_join([preview, mobile_byte(0)?])?,
    native_join([common, mobile_vector(Bytes.empty())?, mobile_vector(Bytes.from_utf8("code"))?])?,
    native_join([
      native_base()?,
      mobile_vector(native_repeat(77, 16796865)?)?,
      mobile_vector(Bytes.from_utf8("code"))?
    ])?,
    native_join([
      native_base()?,
      mobile_vector(Bytes.from_utf8("wire"))?,
      mobile_vector(Bytes.empty())?
    ])?,
    native_join([
      native_base()?,
      mobile_vector(Bytes.from_utf8("wire"))?,
      mobile_vector(native_repeat(65, 1025)?)?
    ])?
  ] do
    assert(Result.is_err(parse_backup_preview_request(bad)))
  end
  assert(Result.is_err(parse_backup_import_request(preview)))
  assert(Result.is_err(parse_backup_import_request(native_join([imported, mobile_byte(0)?])?)))
  Ok(nil)
end

test("native archive and page requests bind exact IDs and strictly validate scope offsets limits and complete arity") do
  let id = native_repeat(9, 32)?
  let archive = native_join([native_base()?, id])?
  let frame = native_join([
    archive,
    mobile_byte(2)?,
    mobile_vector(native_repeat(10, 32)?)?,
    mobile_write_u32(256)?,
    mobile_byte(16)?
  ])?
  println("NATIVE_PAGE_REQUEST_READY")
  assert(Result.is_ok(parse_backup_overview_request(archive)))
  assert(Result.is_ok(parse_backup_remove_request(archive)))
  let raw = parse_backup_page_request(frame)
  assert(Result.is_ok(raw))
  let request = raw?
  assert(Bytes.secure_equals(request.backup_id, id)
    && request.page.offset == 256
    && request.page.limit == 16)
  for bad in [native_base()?, native_join([archive, mobile_byte(0)?])?] do
    assert(Result.is_err(parse_backup_overview_request(bad)))
    assert(Result.is_err(parse_backup_remove_request(bad)))
  end
  for bad in [
    native_join([frame, mobile_byte(0)?])?,
    native_join([
      archive,
      mobile_byte(2)?,
      mobile_vector(native_repeat(10, 32)?)?,
      mobile_write_u32(257)?,
      mobile_byte(16)?
    ])?,
    native_join([
      archive,
      mobile_byte(2)?,
      mobile_vector(native_repeat(10, 32)?)?,
      mobile_write_u32(0)?,
      mobile_byte(0)?
    ])?,
    native_join([
      archive,
      mobile_byte(2)?,
      mobile_vector(native_repeat(10, 32)?)?,
      mobile_write_u32(0)?,
      mobile_byte(17)?
    ])?,
    native_join([
      archive,
      mobile_byte(1)?,
      mobile_vector(native_repeat(10, 32)?)?,
      mobile_write_u32(0)?,
      mobile_byte(1)?
    ])?
  ] do
    assert(Result.is_err(parse_backup_page_request(bad)))
  end
  Ok(nil)
end

test("native ciphertext code and finite receipts have exact separate framing without clipping") do
  let wire = native_repeat(77, 16796864)?
  let code = native_code()?
  let expected = native_join([
    mobile_byte(1)?,
    mobile_vector(wire)?,
    mobile_vector(Bytes.from_utf8(code))?
  ])?
  assert(Bytes.length(expected) == 16800969)
  println("NATIVE_PUBLIC_REPLY_READY")
  assert(native_public_frame_matches(encode_backup_create_reply(wire, code), expected))
  let id = native_repeat(9, 32)?
  for disposition in [1, 2] do
    assert(native_public_frame_matches(encode_backup_import_reply(id, disposition),
      native_join([mobile_byte(1)?, id, mobile_byte(disposition)?])?))
  end
  assert(native_public_frame_matches(encode_backup_remove_reply(id),
    native_join([mobile_byte(1)?, id, mobile_byte(1)?])?))
  assert(Result.is_err(encode_backup_import_reply(id, 3)))
  assert(Result.is_err(encode_backup_import_reply(Bytes.empty(), 1)))
  assert(Result.is_err(encode_backup_create_reply(native_repeat(77, 16796865)?, code)))
  Ok(nil)
end

test("native archive list frame preserves maximum U64 timestamps and bounded IDs without digest fields") do
  let maximum = U64.parse("18446744073709551615")?
  let values = for index in 0..8 do
    BackupNativeSummary { backup_id: native_repeat(index, 32)?, created_at: maximum }
  end
  let expected = native_join([
    mobile_byte(1)?,
    encode_output_list(for value in values do
      encode_output_list([value.backup_id, native_repeat(255, 8)?])?
    end)?
  ])?
  let protected :: Plaintext<List<BackupNativeSummary>> = values
  assert(Bytes.length(expected) == 489)
  println("NATIVE_LIST_REPLY_READY")
  assert(native_synthetic_frame_matches(encode_backup_list_reply(protected), expected))
  let over :: Plaintext<List<BackupNativeSummary>> = List.append(values, List.head(values))
  assert(native_synthetic_frame_refused(encode_backup_list_reply(over)))
  Ok(nil)
end

test("native overview frame preserves historical labels counts full U64 and excludes owner authorization realm and bodies") do
  let maximum = U64.parse("18446744073709551615")?
  let scopes = for index in 0..32 do
    BackupArchiveConversation {
      kind: 1,
      id: native_repeat(index, 16)?,
      peer: native_repeat(index + 1, 32)?,
      name: case Bytes.to_utf8(native_repeat(65, 96)?) do
        Err(_) -> ""
        Ok(value) -> value
      end,
      message_count: 128
    }
  end
  let overview = BackupArchiveOverview {
    backup_id: native_repeat(9, 32)?,
    created_at: maximum,
    included_count: 4096,
    candidate_count: 8192,
    omitted_timed: 4096,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 4096,
    conversations: scopes
  }
  let expected = native_join([
    mobile_byte(1)?,
    encode_output_list([
      overview.backup_id,
      native_repeat(255, 8)?,
      mobile_write_u32(4096)?,
      mobile_write_u32(8192)?,
      mobile_write_u32(4096)?,
      mobile_write_u32(0)?,
      mobile_write_u32(0)?,
      mobile_write_u32(0)?,
      mobile_write_u32(4096)?,
      encode_output_list(for scope in scopes do
        encode_output_list([
          mobile_byte(1)?,
          scope.id,
          scope.peer,
          Bytes.from_utf8(scope.name),
          mobile_write_u32(128)?
        ])?
      end)?
    ])?
  ])?
  let protected :: Plaintext<BackupArchiveOverview> = overview
  assert(Bytes.length(expected) == 5917 && Bytes.length(expected) <= 8192)
  println("NATIVE_OVERVIEW_REPLY_READY")
  assert(native_synthetic_frame_matches(encode_backup_overview_reply(protected), expected))
  let over :: Plaintext<BackupArchiveOverview> = %{overview |
    conversations: List.append(scopes, List.head(scopes))
  }
  assert(native_synthetic_frame_refused(encode_backup_overview_reply(over)))
  Ok(nil)
end

test("native page frame includes full record metadata beyond text cap and preserves timestamps flags IDs ordinals and cursor") do
  let entries = for index in 0..16 do
    native_record(index,
      if index < 2 do
        65346
      else if index == 2 do
        380
      else
        0
      end)?
  end
  let page = native_page(entries)?
  let expected = native_expected_page(page)?
  let protected :: Plaintext<BackupArchivePage> = page
  assert(Bytes.length(expected) == 133363
    && Bytes.length(expected) > 131072
    && Bytes.length(expected) <= 135168)
  println("NATIVE_PAGE_REPLY_READY")
  assert(native_synthetic_frame_matches(encode_backup_page_reply(protected), expected))
  let original = List.get(entries, 2)
  let extra = %{original | text: native_repeat(65, 381)?}
  let overflow_rows = [List.get(entries, 0), List.get(entries, 1), extra] ++ List.drop(entries, 3)
  let over :: Plaintext<BackupArchivePage> = native_page(overflow_rows)?
  assert(native_synthetic_frame_refused(encode_backup_page_reply(over)))
  let too_many :: Plaintext<BackupArchivePage> = native_page(List.append(entries,
    native_record(16, 0)?))?
  assert(native_synthetic_frame_refused(encode_backup_page_reply(too_many)))
  let empty :: Plaintext<BackupArchivePage> = %{page | offset: 256, next_offset: None, entries: []}
  assert(native_synthetic_frame_matches(encode_backup_page_reply(empty),
    native_expected_page(%{page | offset: 256, next_offset: None, entries: []})?))
  Ok(nil)
end

test("native complete maximum request frames fit exact declared caps and reject time tags truncated fields and extra bytes") do
  let maximum = U64.parse("18446744073709551615")?
  let common = native_join([
    mobile_byte(1)?,
    mobile_vector(native_repeat(65, 4096)?)?,
    mobile_vector(native_repeat(66, 36134)?)?
  ])?
  let rows = for index in 0..32 do
    native_selection(2, native_repeat(index, 32)?, Some(maximum), Some(maximum))?
  end
  let create = native_join([common, mobile_vector(native_join([mobile_byte(32)?] ++ rows)?)?])?
  let archive = native_join([common, native_repeat(9, 32)?])?
  let page = native_join([
    archive,
    mobile_byte(2)?,
    mobile_vector(native_repeat(10, 32)?)?,
    mobile_write_u32(256)?,
    mobile_byte(16)?
  ])?
  assert(Bytes.length(create) == 42004
    && Bytes.length(archive) == 40271
    && Bytes.length(page) == 40313)
  println("NATIVE_COMPLETE_CAPS_READY")
  assert(Result.is_ok(parse_backup_create_request(create)))
  assert(Result.is_ok(parse_backup_overview_request(archive)))
  assert(Result.is_ok(parse_backup_remove_request(archive)))
  assert(Result.is_ok(parse_backup_page_request(page)))
  for input in [
    native_join([create, mobile_byte(0)?])?,
    native_create_frame([
      native_join([
        mobile_byte(1)?,
        mobile_vector(native_repeat(7, 16)?)?,
        mobile_byte(2)?,
        mobile_byte(0)?
      ])?
    ])?,
    native_create_frame([
      native_join([
        mobile_byte(1)?,
        mobile_vector(native_repeat(7, 16)?)?,
        mobile_byte(1)?,
        native_repeat(0, 7)?
      ])?
    ])?
  ] do
    assert(Result.is_err(parse_backup_create_request(input)))
  end
  assert(Result.is_err(parse_backup_list_request(Bytes.slice(common,
    0,
    Bytes.length(common) - 1)?)))
  Ok(nil)
end

from Mobile.BackupNative import (
  BackupNativePendingState,
  parse_backup_pending_state_request,
  parse_backup_pending_repair_request,
  parse_backup_pending_discard_request,
  parse_backup_pending_resume_request,
  encode_backup_pending_create_reply,
  encode_backup_pending_state_reply,
  encode_backup_pending_resume_reply,
  encode_backup_pending_discard_reply,
  encode_backup_pending_repair_reply
)

fn pending_codec_state() -> Result<(), String> do
  let parsed = parse_backup_pending_state_request(native_base()?)
  assert(Result.is_ok(parsed))
  assert(parsed?.database_path == "/db")
  assert(Result.is_err(parse_backup_pending_state_request(native_join([
    native_base()?,
    mobile_byte(0)?
  ])?)))
  Ok(nil)
end

test("pending state request has exact common arity") do
  assert(Result.is_ok(pending_codec_state()))
end

fn pending_codec_repair() -> Result<(), String> do
  let parsed = parse_backup_pending_repair_request(native_base()?)
  assert(Result.is_ok(parsed))
  assert(Bytes.secure_equals(parsed?.expected_profile, Bytes.from_utf8("profile")))
  assert(Result.is_err(parse_backup_pending_repair_request(native_join([
    native_base()?,
    native_repeat(1, 32)?
  ])?)))
  Ok(nil)
end

test("pending repair request accepts no draft or caller storage fields") do
  assert(Result.is_ok(pending_codec_repair()))
end

fn pending_codec_discard() -> Result<(), String> do
  let id = native_repeat(42, 32)?
  let parsed = parse_backup_pending_discard_request(native_join([native_base()?, id])?)
  assert(Result.is_ok(parsed))
  assert(Bytes.secure_equals(parsed?.draft_id, id))
  assert(Result.is_err(parse_backup_pending_discard_request(native_base()?)))
  assert(Result.is_err(parse_backup_pending_discard_request(native_join([
    native_base()?,
    native_repeat(42, 31)?
  ])?)))
  assert(Result.is_err(parse_backup_pending_discard_request(native_join([
    native_base()?,
    native_repeat(42, 33)?
  ])?)))
  Ok(nil)
end

test("pending discard request requires one exact action identifier") do
  assert(Result.is_ok(pending_codec_discard()))
end

fn pending_codec_resume() -> Result<(), String> do
  let id = native_repeat(42, 32)?
  let code = Bytes.from_utf8("SAVEDλ")
  let frame = native_join([native_base()?, id, mobile_vector(code)?])?
  let parsed = parse_backup_pending_resume_request(frame)
  assert(Result.is_ok(parsed))
  assert(parsed?.recovery_code == "SAVEDλ")
  assert(Result.is_err(parse_backup_pending_resume_request(native_join([frame, mobile_byte(0)?])?)))
  assert(Result.is_err(parse_backup_pending_resume_request(native_join([
    native_base()?,
    id,
    mobile_vector(Bytes.empty())?
  ])?)))
  assert(Result.is_err(parse_backup_pending_resume_request(native_join([
    native_base()?,
    id,
    mobile_vector(native_repeat(65, 4097)?)?
  ])?)))
  let wide = String.repeat("λ", 1025)
  assert(Result.is_err(parse_backup_pending_resume_request(native_join([
    native_base()?,
    id,
    mobile_vector(Bytes.from_utf8(wide))?
  ])?)))
  Ok(nil)
end

test("pending resume request carries only exact draft and bounded saved code") do
  assert(Result.is_ok(pending_codec_resume()))
end

fn pending_codec_created() -> Result<(), String> do
  let id = native_repeat(42, 32)?
  let wire = Bytes.from_utf8("opaque ciphertext")
  let code = "SYNTHETIC CODE"
  let expected = native_join([
    mobile_byte(2)?,
    id,
    mobile_vector(wire)?,
    mobile_vector(Bytes.from_utf8(code))?
  ])?
  assert(native_public_frame_matches(encode_backup_pending_create_reply(id, wire, code), expected))
  assert(Result.is_err(encode_backup_pending_create_reply(native_repeat(42, 31)?, wire, code)))
  assert(Result.is_err(encode_backup_pending_create_reply(id, Bytes.empty(), code)))
  assert(Result.is_err(encode_backup_pending_create_reply(id, wire, "")))
  Ok(nil)
end

test("pending create version two binds its exact draft identifier") do
  assert(Result.is_ok(pending_codec_created()))
end

fn pending_codec_state_reply() -> Result<(), String> do
  let id = native_repeat(42, 32)?
  let maximum = U64.parse("18446744073709551615")?
  let zero = U64.parse("0")?
  let value = BackupNativePendingState {
    kind: 1,
    draft_id: id,
    created_at: maximum,
    wire_size: 16796864
  }
  let expected = native_join([
    mobile_byte(1)?,
    mobile_byte(1)?,
    id,
    mobile_write_u64(maximum)?,
    mobile_write_u32(16796864)?
  ])?
  assert(native_synthetic_frame_matches(encode_backup_pending_state_reply(value), expected))
  for kind in [0, 2] do
    assert(native_synthetic_frame_matches(encode_backup_pending_state_reply(BackupNativePendingState {
        kind: kind,
        draft_id: Bytes.empty(),
        created_at: zero,
        wire_size: 0
      }),
      native_join([mobile_byte(1)?, mobile_byte(kind)?])?))
  end
  assert(native_synthetic_observation(Result.is_err(encode_backup_pending_state_reply(%{value |
    kind: 3
  }))))
  assert(native_synthetic_observation(Result.is_err(encode_backup_pending_state_reply(%{value |
    wire_size: 16796865
  }))))
  assert(native_synthetic_observation(Result.is_err(encode_backup_pending_state_reply(%{value |
    wire_size: 0
  }))))
  assert(native_synthetic_observation(Result.is_err(encode_backup_pending_state_reply(%{value |
    kind: 0
  }))))
  Ok(nil)
end

test("pending state has exact finite two or forty six byte lossless time replies") do
  assert(Result.is_ok(pending_codec_state_reply()))
end

fn pending_codec_resume_reply() -> Result<(), String> do
  let wire = Bytes.from_utf8("only original ciphertext")
  let expected = native_join([mobile_byte(1)?, mobile_vector(wire)?])?
  assert(native_public_frame_matches(encode_backup_pending_resume_reply(wire), expected))
  assert(Result.is_err(encode_backup_pending_resume_reply(Bytes.empty())))
  Ok(nil)
end

test("pending resume reply has no code or descriptor fields") do
  assert(Result.is_ok(pending_codec_resume_reply()))
end

fn pending_codec_discard_reply() -> Result<(), String> do
  let id = native_repeat(42, 32)?
  for status in [1, 2] do
    assert(native_public_frame_matches(encode_backup_pending_discard_reply(id, status),
      native_join([mobile_byte(1)?, id, mobile_byte(status)?])?))
  end
  assert(Result.is_err(encode_backup_pending_discard_reply(id, 0)))
  assert(Result.is_err(encode_backup_pending_discard_reply(native_repeat(42, 31)?, 1)))
  Ok(nil)
end

test("pending discard reply echoes exact id and closed receipt only") do
  assert(Result.is_ok(pending_codec_discard_reply()))
end

fn pending_codec_repair_reply() -> Result<(), String> do
  for status in [1, 2] do
    assert(native_public_frame_matches(encode_backup_pending_repair_reply(status),
      native_join([mobile_byte(1)?, mobile_byte(status)?])?))
  end
  assert(Result.is_err(encode_backup_pending_repair_reply(0)))
  assert(Result.is_err(encode_backup_pending_repair_reply(3)))
  Ok(nil)
end

test("pending repair reply has only closed repaired or empty receipt") do
  assert(Result.is_ok(pending_codec_repair_reply()))
end
