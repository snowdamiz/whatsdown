from Mobile.BackupNative import (
  parse_backup_view_request,
  encode_backup_content_overview_reply,
  encode_backup_content_page_reply,
  encode_backup_content_chunk_reply
)
from Mobile.BackupArchiveViewDispatch import (
  BackupReadonlyPageRequest,
  BackupReadonlyOverview,
  BackupReadonlyPage
)
from Mobile.BackupArchiveContentView import (
  BackupContentAttachmentView,
  BackupContentPage,
  BackupContentRecordView,
  BackupContentChunkRequest,
  content_archive_overview,
  content_archive_page,
  content_archive_chunk
)
from Mobile.BackupArchiveView import BackupArchivePageRequest
from Mobile.Codec import (
  mobile_byte,
  mobile_vector,
  mobile_write_u16,
  mobile_write_u32,
  mobile_write_u64,
  encode_output_list
)

fn v_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY exact authored synthetic MCA1 native-view frame equality selector refusal known slot-token binding and fixture row preservation; no user archive content metadata capability key error or private caller control is disclosed")
end

fn v_join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 33554432) do
    Err(_) -> Err("view_fixture_join")
    Ok(bytes) -> Ok(bytes)
  end
end

fn v_repeat(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("view_fixture_repeat")
    Ok(bytes) -> Ok(bytes)
  end
end

fn v_hex(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Err(_) -> Err("view_fixture_hex")
    Ok(bytes) -> Ok(bytes)
  end
end

fn v_literal() -> Result<Plaintext<Bytes>, String> do
  v_hex("014d434101101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000000200000001000000000000000100000000000000000000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff0000000548656c6c6f00000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b711111111111111111111111111111111111111111111111111111111111111114545454545454545454545454545454500000000000000000000000867726f757020cf8000000000d90200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c65676163790001000000a000ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080000000002000000520000000000086e6f74652e62696e000000186170706c69636174696f6e2f6f637465742d73747265616d49fd534fea14753447a1931542d9d58744a75810b88718eadc4ccded926317b50000000400ff4142000000020102")
end

fn v_action() -> Bytes!String do
  v_join([
    mobile_byte(1)?,
    mobile_vector(Bytes.from_utf8("/db"))?,
    mobile_vector(Bytes.from_utf8("profile"))?
  ])
end

fn v_chunk_frame(tag :: Int,
  token :: Bytes,
  ordinal :: Int,
  slot :: Int,
  chunk :: Int) -> Bytes!String do
  v_join([
    v_action()?,
    v_repeat(16, 32)?,
    mobile_byte(tag)?,
    mobile_vector(token)?,
    mobile_byte(ordinal)?,
    mobile_byte(slot)?,
    mobile_byte(chunk)?
  ])
end

pub fn view_request_proof() -> Bool!String do
  let token = v_repeat(91, 32)?
  let parsed = parse_backup_view_request(v_chunk_frame(4, token, 255, 9, 255)?)?
  let correct = case parsed.selection do
    ReadonlyFileChunk(value) -> value.kind == 2
      && value.ordinal == 255
      && value.slot_index == 9
      && value.chunk_index == 255
      && Bytes.secure_equals(value.token, token)
    _ -> false
  end
  if !correct
    || parsed.action.database_path != "/db"
    || !Bytes.secure_equals(parsed.backup_id, v_repeat(16, 32)?) do
    return Ok(false)
  end
  for kind in [1, 2] do
    let frame = v_join([
      v_action()?,
      v_repeat(16, 32)?,
      mobile_byte(kind)?,
      mobile_vector(v_repeat(3,
        if kind == 1 do
          16
        else
          32
        end)?)?,
      mobile_write_u32(256)?,
      mobile_byte(16)?
    ])?
    let accepted = parse_backup_view_request(frame)?
    if !(case accepted.selection do
      ReadonlyMessagePage(value) -> value.kind == kind && value.offset == 256 && value.limit == 16
      _ -> false
    end) do
      return Ok(false)
    end
  end
  let direct = parse_backup_view_request(v_chunk_frame(3, token, 0, 0, 0)?)?
  if !(case direct.selection do
    ReadonlyFileChunk(value) -> value.kind == 1
    _ -> false
  end) do
    return Ok(false)
  end
  let valid = v_chunk_frame(4, token, 255, 9, 255)?
  for bad in [
    v_chunk_frame(5, token, 0, 0, 0)?,
    v_chunk_frame(4, v_repeat(0, 31)?, 0, 0, 0)?,
    v_chunk_frame(4, token, 0, 10, 0)?,
    v_join([valid, mobile_byte(0)?])?,
    Bytes.slice(valid, 0, Bytes.length(valid) - 1)?
  ] do
    if Result.is_ok(parse_backup_view_request(bad)) do
      return Ok(false)
    end
  end
  Ok(true)
end

fn v_matches(raw :: Result<Plaintext<Bytes>, String>, expected :: Bytes) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, expected)
  end
end

fn v_chunk_codec_raw() -> Bool!String do
  let revision = v_repeat(145, 32)?
  let token = v_hex("5d142435427eb850e06b898dc6978a2b3c707128cf22a26b3211087c072a99de")?
  let selected = content_archive_chunk(v_literal()?,
    revision,
    BackupContentChunkRequest {
      kind: 2,
      token: token,
      ordinal: 255,
      slot_index: 0,
      chunk_index: 0
    })?
  let expected = v_join([
    mobile_byte(2)?,
    mobile_byte(1)?,
    encode_output_list([
      v_repeat(16, 32)?,
      mobile_byte(2)?,
      v_repeat(3, 32)?,
      mobile_write_u16(255)?,
      mobile_byte(0)?,
      mobile_byte(0)?,
      mobile_write_u32(4)?,
      token,
      v_hex("00ff4142")?
    ])?
  ])?
  let good = v_matches(encode_backup_content_chunk_reply(selected), expected)
  let bad_size = Result.is_err(encode_backup_content_chunk_reply(%{selected | total_size: 5}))
  let bad_tail = Result.is_err(encode_backup_content_chunk_reply(%{selected |
    bytes: v_hex("00ff41")?
  }))
  let bad_slot = Result.is_err(encode_backup_content_chunk_reply(%{selected | slot_index: 10}))
  Ok(good && bad_size && bad_tail && bad_slot && Bytes.length(expected) == 155)
end

pub fn view_chunk_codec_proof() -> Bool!String do
  Ok(v_observe(Result.unwrap_or(v_chunk_codec_raw(), false)))
end

fn v_page_codec_raw() -> Bool!String do
  let token = v_hex("5d142435427eb850e06b898dc6978a2b3c707128cf22a26b3211087c072a99de")?
  let page = content_archive_page(v_literal()?,
    v_repeat(145, 32)?,
    BackupArchivePageRequest { kind: 2, scope_id: v_repeat(3, 32)?, offset: 0, limit: 16 })?
  let slots = encode_output_list([
    encode_output_list([
      mobile_byte(0)?,
      mobile_byte(0)?,
      Bytes.from_utf8("note.bin"),
      Bytes.from_utf8("application/octet-stream"),
      mobile_write_u32(4)?,
      token
    ])?,
    encode_output_list([mobile_byte(1)?, mobile_byte(2)?])?
  ])?
  let record = encode_output_list([
    mobile_write_u16(255)?,
    mobile_byte(2)?,
    Bytes.empty(),
    v_repeat(85, 32)?,
    v_repeat(70, 16)?,
    mobile_write_u64(U64.parse("72623859790382856")?)?,
    Bytes.empty(),
    slots
  ])?
  let expected = v_join([
    mobile_byte(2)?,
    mobile_byte(0)?,
    encode_output_list([
      v_repeat(16, 32)?,
      mobile_byte(2)?,
      v_repeat(3, 32)?,
      mobile_write_u32(0)?,
      mobile_byte(0)?,
      encode_output_list([record])?
    ])?
  ])?
  let good = v_matches(encode_backup_content_page_reply(page), expected)
  let bad_extent = Result.is_err(encode_backup_content_page_reply(%{page |
    encoded_size: page.encoded_size + 1
  }))
  let bad_cursor = Result.is_err(encode_backup_content_page_reply(%{page | next_offset: Some(0)}))
  let name = v_join([Bytes.from_utf8(String.repeat("é", 127)), Bytes.from_utf8("x")])?
  let mime = v_join([Bytes.from_utf8(String.repeat("µ", 63)), Bytes.from_utf8("a")])?
  let maximum = BackupContentPage {
    backup_id: v_repeat(16, 32)?,
    kind: 2,
    scope_id: v_repeat(3, 32)?,
    offset: 0,
    next_offset: None,
    encoded_size: 70161,
    entries: [
      BackupContentRecordView {
        ordinal: 255,
        direction: 2,
        message_id: v_repeat(7, 32)?,
        sender_account: v_repeat(85, 32)?,
        sender_device: v_repeat(70, 16)?,
        timestamp: U64.parse("18446744073709551615")?,
        text: v_repeat(65, 65346)?,
        attachments: for slot in 0..10 do
          ContentAttachmentIncluded(slot, name, mime, 1, token)
        end
      }
    ]
  }
  let maximum_raw = encode_backup_content_page_reply(maximum)
  let maximum_ok = case maximum_raw do
    Err(_) -> false
    Ok(bytes) -> Bytes.length(bytes) == 70161
  end
  let row = List.head(maximum.entries)
  let invalid_slots = %{maximum |
    entries: [%{row | attachments: [ContentAttachmentIncluded(1, name, mime, 1, token)]}]
  }
  let invalid_utf8 = %{maximum |
    entries: [
      %{row | attachments: [ContentAttachmentIncluded(0, v_repeat(255, 1)?, mime, 1, token)]}
    ]
  }
  let malformed_refused = Result.is_err(encode_backup_content_page_reply(invalid_slots))
    && Result.is_err(encode_backup_content_page_reply(invalid_utf8))
  Ok(good
    && bad_extent
    && bad_cursor
    && maximum_ok
    && malformed_refused
    && Bytes.length(expected) == 351)
end

pub fn view_page_codec_proof() -> Bool!String do
  Ok(v_observe(Result.unwrap_or(v_page_codec_raw(), false)))
end

fn v_overview_codec_raw() -> Bool!String do
  let overview = content_archive_overview(v_literal()?)?
  let scopes = encode_output_list([
    encode_output_list([
      mobile_byte(1)?,
      v_repeat(1, 16)?,
      v_repeat(32, 32)?,
      Bytes.from_utf8("A"),
      mobile_write_u32(1)?
    ])?,
    encode_output_list([
      mobile_byte(2)?,
      v_repeat(2, 32)?,
      Bytes.empty(),
      Bytes.from_utf8("Group"),
      mobile_write_u32(1)?
    ])?,
    encode_output_list([
      mobile_byte(2)?,
      v_repeat(3, 32)?,
      Bytes.empty(),
      Bytes.from_utf8("Legacy"),
      mobile_write_u32(1)?
    ])?
  ])?
  let counts = for value in [3, 8, 2, 1, 1, 1, 1] do
    mobile_write_u32(value)?
  end
  let files = encode_output_list(for value in [2, 1, 0, 1, 0, 0] do
    mobile_write_u32(value)?
  end)?
  let expected = v_join([
    mobile_byte(2)?,
    encode_output_list([v_repeat(16, 32)?, mobile_write_u64(U64.parse("72623859790382856")?)?]
      ++ counts
      ++ [mobile_byte(1)?, files, scopes])?
  ])?
  let good = v_matches(encode_backup_content_overview_reply(overview), expected)
  let bad_counts = Result.is_err(encode_backup_content_overview_reply(%{overview |
    files: %{overview.files | included: 0}
  }))
  let bad_attachment_messages = Result.is_err(encode_backup_content_overview_reply(%{overview |
    attachment_messages: 0
  }))
  Ok(good && bad_counts && bad_attachment_messages)
end

from Mobile.BackupArchive import (
  import_backup_archive,
  read_backup_archive_view_overview,
  read_backup_archive_view_page,
  preview_backup_archive_view_overview
)
from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupArchiveAttachment,
  BackupContentScope,
  BackupContentRecord
)
from Backups.PortableV2 import (
  PortableBackupContentArchive,
  PortableBackupV2Created,
  create_portable_content_backup_v2
)
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_backup_id,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Transport.Packet import decode_client_profile
from Storage.Keys import platform_key, local_context, open_local, seal_local
from Storage.HistoryBlobs import open_history_blob, seal_history_blob
from Storage.Blobs import load_blob
from Storage.Records import with_record_transaction, put_blobs

pub fn view_overview_codec_proof() -> Bool!String do
  Ok(v_observe(Result.unwrap_or(v_overview_codec_raw(), false)))
end

fn v_bundle(f :: D4CoreFixture) -> PortableBackupV2Created!String do
  let profile = decode_client_profile(f.public_profile)?
  let realm = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  let content :: Plaintext<PortableBackupContentArchive> = PortableBackupContentArchive {
    policy: RequireArchiveAttachments,
    owner_account: profile.account_id,
    owner_authorization_key: profile.account.authorization_public_key,
    service_realm: realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 1,
    scopes: [
      BackupContentScope {
        kind: 2,
        id: v_repeat(71, 32)?,
        peer: Bytes.empty(),
        name: "owned view fixture",
        entries: [
          BackupContentRecord {
            ordinal: 255,
            direction: 1,
            message_id: Bytes.empty(),
            sender_account: profile.account_id,
            sender_device: profile.device_id,
            timestamp: f.now,
            text: Bytes.empty(),
            attachments: [
              ArchiveAttachmentIncluded(Bytes.from_utf8("fixture.bin"),
                Bytes.from_utf8("application/octet-stream"),
                v_repeat(165, 65537)?)
            ]
          }
        ]
      }
    ]
  }
  case create_portable_content_backup_v2(content, f.now) do
    Err(_) -> Err("view_fixture_bundle")
    Ok(value) -> Ok(value)
  end
end

fn v_message_request() -> BackupReadonlyPageRequest!String do
  Ok(ReadonlyMessagePage(BackupArchivePageRequest {
    kind: 2,
    scope_id: v_repeat(71, 32)?,
    offset: 0,
    limit: 16
  }))
end

fn v_token_raw(raw :: Result<Plaintext<BackupReadonlyPage>, String>) -> Plaintext<Bytes> do
  case raw do
    Err(_) -> Bytes.empty()
    Ok(page) -> case page do
      ReadonlyContentPage(value) -> if List.length(value.entries) == 1 do
        case List.head(List.head(value.entries).attachments) do
          ContentAttachmentIncluded(_, _, _, _, token) -> token
          _ -> Bytes.empty()
        end
      else
        Bytes.empty()
      end
      _ -> Bytes.empty()
    end
  end
end

fn v_known_fixture_token(raw :: Result<Plaintext<BackupReadonlyPage>, String>) -> Bytes do
  declassify(v_token_raw(raw),
    "TEST ONLY slot equality token for the one known authored synthetic owned view fixture after real guarded import and page projection; no user archive token content digest key error or private caller control is disclosed")
end

fn v_chunk_request(token :: Bytes, index :: Int) -> BackupReadonlyPageRequest do
  ReadonlyFileChunk(BackupContentChunkRequest {
    kind: 2,
    token: token,
    ordinal: 255,
    slot_index: 0,
    chunk_index: index
  })
end

fn v_chunk_matches(raw :: Result<Plaintext<BackupReadonlyPage>, String>,
  index :: Int,
  scope :: Bytes,
  bytes :: Bytes) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(page) -> case page do
      ReadonlyContentChunk(value) -> value.kind == 2
        && Bytes.secure_equals(value.scope_id, scope)
        && value.ordinal == 255
        && value.slot_index == 0
        && value.chunk_index == index
        && value.total_size == 65537
        && Bytes.secure_equals(value.bytes, bytes)
      _ -> false
    end
  end
end

pub fn view_guarded_roundtrip_proof() -> Bool!String do
  let f = d4_core_fixture()?
  let bundle = v_bundle(f)?
  let id = d4_core_backup_id(bundle.wire)?
  let imported = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)
  if Result.is_err(imported) do
    return Err("view_fixture_import")
  end
  let before = d4_core_all_rows(f)?
  println("VIEW_GUARDED_ADMITTED")
  let overview = read_backup_archive_view_overview(f.path, f.public_profile, id)
  let preview = preview_backup_archive_view_overview(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code)
  let page = read_backup_archive_view_page(f.path, f.public_profile, id, v_message_request()?)
  let token = v_known_fixture_token(page)
  let first = read_backup_archive_view_page(f.path, f.public_profile, id, v_chunk_request(token, 0))
  let tail = read_backup_archive_view_page(f.path, f.public_profile, id, v_chunk_request(token, 1))
  let beyond = read_backup_archive_view_page(f.path,
    f.public_profile,
    id,
    v_chunk_request(token, 2))
  let wrong_profile = read_backup_archive_view_page(f.path,
    Bytes.from_utf8("other profile"),
    id,
    v_chunk_request(token, 0))
  let after_rows = d4_core_all_rows(f)?
  d4_core_cleanup(f)?
  let overview_ok = case overview do
    Err(_) -> false
    Ok(value) -> case value do
      ReadonlyContentOverview(meta) -> Bytes.secure_equals(meta.backup_id, id)
        && meta.created_at == f.now
        && meta.files.total == 1
        && meta.files.included == 1
      _ -> false
    end
  end
  let preview_ok = case preview do
    Err(_) -> false
    Ok(value) -> case value do
      ReadonlyContentOverview(meta) -> Bytes.secure_equals(meta.backup_id, id)
        && meta.files.included == 1
      _ -> false
    end
  end
  Ok(Result.is_ok(imported)
    && Bytes.length(token) == 32
    && v_observe(overview_ok
      && preview_ok
      && v_chunk_matches(first, 0, v_repeat(71, 32)?, v_repeat(165, 65536)?)
      && v_chunk_matches(tail, 1, v_repeat(71, 32)?, v_repeat(165, 1)?)
      && Result.is_err(beyond)
      && Result.is_err(wrong_profile))
    && d4_core_rows_preserved(before, after_rows, 0))
end

fn v_reseal(f :: D4CoreFixture, id :: Bytes, index :: Bool) -> Result<(), String> do
  let label = if index do
    "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  else
    "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(id)}"
  end
  let before = load_blob(f.path, label)?
  let value_context = local_context(label)?
  let key = platform_key()?
  let raw = if index do
    open_local(before, key, value_context)
  else
    open_history_blob(before, key, label)
  end
  let sealed = case raw do
    Err(_) -> Err("view_fixture_open")
    Ok(bytes) -> if index do
      seal_local(bytes, key, value_context)
    else
      seal_history_blob(bytes, key, label)
    end
  end
  Secret.destroy(key)
  let after_blob = sealed?
  if Bytes.secure_equals(before, after_blob) do
    return Err("view_fixture_identical_ciphertext")
  end
  with_record_transaction(f.path, fn(database) -> put_blobs(database, [label], [after_blob], 0) end)
end

pub fn view_ciphertext_replacement_proof(index :: Bool) -> Bool!String do
  let f = d4_core_fixture()?
  let bundle = v_bundle(f)?
  let id = d4_core_backup_id(bundle.wire)?
  import_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code, id)?
  d4_core_all_rows(f)?
  if index do
    println("VIEW_INDEX_ADMITTED")
  else
    println("VIEW_ARCHIVE_ADMITTED")
  end
  let original_page = read_backup_archive_view_page(f.path,
    f.public_profile,
    id,
    v_message_request()?)
  let original_token = v_known_fixture_token(original_page)
  let original_chunk = read_backup_archive_view_page(f.path,
    f.public_profile,
    id,
    v_chunk_request(original_token, 1))
  v_reseal(f, id, index)?
  let before = d4_core_all_rows(f)?
  let stale = read_backup_archive_view_page(f.path,
    f.public_profile,
    id,
    v_chunk_request(original_token, 1))
  let fresh_page = read_backup_archive_view_page(f.path, f.public_profile, id, v_message_request()?)
  let fresh_token = v_known_fixture_token(fresh_page)
  let fresh_chunk = read_backup_archive_view_page(f.path,
    f.public_profile,
    id,
    v_chunk_request(fresh_token, 1))
  let after_rows = d4_core_all_rows(f)?
  d4_core_cleanup(f)?
  Ok(Bytes.length(original_token) == 32
    && Bytes.length(fresh_token) == 32
    && !Bytes.secure_equals(original_token, fresh_token)
    && v_observe(v_chunk_matches(original_chunk, 1, v_repeat(71, 32)?, v_repeat(165, 1)?)
      && Result.is_err(stale)
      && v_chunk_matches(fresh_chunk, 1, v_repeat(71, 32)?, v_repeat(165, 1)?))
    && d4_core_rows_preserved(before, after_rows, 0))
end
