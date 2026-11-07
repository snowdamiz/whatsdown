from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  encode_text_archive
)
from Mobile.BackupArchiveView import (
  BackupArchivePageRequest,
  backup_archive_overview,
  backup_archive_page
)

fn bytes(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture_bytes")
    Ok(output)
  end
end

fn fixture_time() -> U64!String do
  U64.parse("18446744073709551615")
end

fn fixture_record(ordinal :: Int,
  group :: Bool,
  attachment :: Bool) -> BackupArchiveRecord!String do
  Ok(BackupArchiveRecord {
    ordinal: ordinal,
    direction: 2,
    message_id: if group do
      Bytes.empty()
    else
      bytes(ordinal, 16)?
    end,
    sender_account: bytes(34, 32)?,
    sender_device: bytes(102, 16)?,
    timestamp: fixture_time()?,
    attachment_omitted: attachment,
    text: if group do
      bytes(65 + ordinal, 65346)?
    else if attachment do
      Bytes.empty()
    else
      Bytes.from_utf8("message #{ordinal}")
    end
  })
end

fn fixture() -> Bytes!String do
  let archive = BackupTextArchive {
    backup_id: bytes(51, 32)?,
    owner_account: bytes(17, 32)?,
    owner_authorization_key: bytes(68, 32)?,
    service_realm: bytes(85, 32)?,
    created_at: fixture_time()?,
    candidate_count: 12,
    omitted_timed: 1,
    omitted_unknown: 1,
    omitted_nontext: 1,
    omitted_empty: 1,
    attachment_messages: 2,
    scopes: [
      BackupArchiveScope {
        kind: 1,
        id: bytes(1, 16)?,
        peer: bytes(34, 32)?,
        name: "Historical contact",
        entries: [
          fixture_record(0, false, false)?,
          fixture_record(3, false, true)?,
          fixture_record(7, false, false)?,
          fixture_record(9, false, true)?,
          fixture_record(255, false, false)?
        ]
      },
      BackupArchiveScope {
        kind: 2,
        id: bytes(2, 32)?,
        peer: Bytes.empty(),
        name: "Historical group",
        entries: [
          fixture_record(0, true, false)?,
          fixture_record(1, true, false)?,
          fixture_record(2, true, false)?
        ]
      }
    ]
  }
  case encode_text_archive(archive) do
    Err(_) -> Err("fixture_archive")
    Ok(output)
  end
end

fn observed(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY exact generated archive overview paging bounds and refusal predicates; no user archive or arbitrary payload is disclosed")
end

fn request(kind :: Int,
  scope_id :: Bytes,
  offset :: Int,
  limit :: Int) -> BackupArchivePageRequest do
  BackupArchivePageRequest { kind: kind, scope_id: scope_id, offset: offset, limit: limit }
end

test("archive overview preserves original counts time and historical labels without message bodies") do
  let wire = fixture()?
  let id = bytes(51, 32)?
  let time = fixture_time()?
  let result = backup_archive_overview(wire)
  assert(observed(case result do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value.backup_id, id)
      && U64.compare(value.created_at, time) == 0
      && value.included_count == 8
      && value.candidate_count == 12
      && value.omitted_timed == 1
      && value.omitted_unknown == 1
      && value.omitted_nontext == 1
      && value.omitted_empty == 1
      && value.attachment_messages == 2
      && List.length(value.conversations) == 2
      && List.get(value.conversations, 0).name == "Historical contact"
      && List.get(value.conversations, 0).message_count == 5
      && List.get(value.conversations, 1).name == "Historical group"
      && List.get(value.conversations, 1).message_count == 3
  end))
  Ok(nil)
end

test("archive pages use record offsets preserve sparse ordinals and include attachment placeholders") do
  let wire = fixture()?
  let scope = bytes(1, 16)?
  let first = backup_archive_page(wire, request(1, scope, 0, 2))
  let middle = backup_archive_page(wire, request(1, scope, 2, 2))
  let last = backup_archive_page(wire, request(1, scope, 4, 2))
  let finished = backup_archive_page(wire, request(1, scope, 5, 2))
  assert(observed(case (first, middle, last, finished) do
    (Ok(a), Ok(b), Ok(c), Ok(d)) -> List.length(a.entries) == 2
      && a.next_offset == Some(2)
      && List.get(a.entries, 0).ordinal == 0
      && List.get(a.entries, 1).ordinal == 3
      && List.get(a.entries, 1).attachment_omitted
      && Bytes.length(List.get(a.entries, 1).text) == 0
      && List.get(b.entries, 0).ordinal == 7
      && List.get(b.entries, 1).ordinal == 9
      && b.next_offset == Some(4)
      && List.length(c.entries) == 1
      && List.head(c.entries).ordinal == 255
      && c.next_offset == None
      && List.length(d.entries) == 0
      && d.next_offset == None
    _ -> false
  end))
  Ok(nil)
end

test("archive pages stop before the text budget and preserve whole large legacy group records") do
  let wire = fixture()?
  let scope = bytes(2, 32)?
  let expected = bytes(67, 65346)?
  let first = backup_archive_page(wire, request(2, scope, 0, 16))
  let last = backup_archive_page(wire, request(2, scope, 2, 16))
  assert(observed(case (first, last) do
    (Ok(a), Ok(b)) -> List.length(a.entries) == 2
      && a.next_offset == Some(2)
      && Bytes.length(List.get(a.entries, 0).text) == 65346
      && Bytes.length(List.get(a.entries, 1).text) == 65346
      && Bytes.length(List.get(a.entries, 0).message_id) == 0
      && Bytes.length(List.get(a.entries, 1).message_id) == 0
      && List.length(b.entries) == 1
      && b.next_offset == None
      && Bytes.secure_equals(List.head(b.entries).text, expected)
    _ -> false
  end))
  Ok(nil)
end

test("archive views reject malformed payloads unknown scopes and invalid paging requests") do
  let wire = fixture()?
  let scope = bytes(1, 16)?
  let unknown = bytes(3, 16)?
  assert(observed(Result.is_err(backup_archive_overview(Bytes.empty()))))
  assert(observed(Result.is_err(backup_archive_page(Bytes.from_utf8("bad"),
    request(1, scope, 0, 1)))))
  for page in [
    request(1, scope, -1, 1),
    request(1, scope, 257, 1),
    request(1, scope, 0, 0),
    request(1, scope, 0, 17),
    request(1, scope, 6, 1),
    request(1, unknown, 0, 1),
    request(2, scope, 0, 1),
    request(3, scope, 0, 1)
  ] do
    assert(observed(Result.is_err(backup_archive_page(wire, page))))
  end
  Ok(nil)
end
