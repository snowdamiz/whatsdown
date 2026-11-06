from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupAttachmentOmission,
  BackupArchiveAttachment,
  BackupContentArchive,
  BackupContentScope,
  BackupContentRecord,
  encode_content_archive,
  decode_content_archive
)
from Mobile.BackupArchiveContentView import (
  BackupContentAttachmentView,
  BackupContentChunkRequest,
  content_archive_overview,
  content_archive_page,
  content_archive_chunk
)
from Mobile.BackupArchiveView import BackupArchivePageRequest

fn cv_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY exact authored synthetic MCA1 view metadata slot-token bytes page budget chunk equality and finite refusal predicates; no user archive file content digest key or arbitrary error is disclosed")
end

fn cv_repeat(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("cv_fixture_repeat")
    Ok(bytes) -> Ok(bytes)
  end
end

fn cv_hex(value :: String) -> Bytes!String do
  case Bytes.from_hex(value) do
    Err(_) -> Err("cv_fixture_hex")
    Ok(bytes) -> Ok(bytes)
  end
end

fn cv_revision() -> Bytes!String do
  cv_repeat(145, 32)
end

fn cv_literal() -> Result<Plaintext<Bytes>, String> do
  cv_hex("014d434101101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000000200000001000000000000000100000000000000000000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff0000000548656c6c6f00000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b711111111111111111111111111111111111111111111111111111111111111114545454545454545454545454545454500000000000000000000000867726f757020cf8000000000d90200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c65676163790001000000a000ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080000000002000000520000000000086e6f74652e62696e000000186170706c69636174696f6e2f6f637465742d73747265616d49fd534fea14753447a1931542d9d58744a75810b88718eadc4ccded926317b50000000400ff4142000000020102")
end

fn cv_literal_token() -> Bytes!String do
  cv_hex("5d142435427eb850e06b898dc6978a2b3c707128cf22a26b3211087c072a99de")
end

fn cv_page(kind :: Int, id :: Bytes, offset :: Int, limit :: Int) -> BackupArchivePageRequest do
  BackupArchivePageRequest { kind: kind, scope_id: id, offset: offset, limit: limit }
end

fn cv_chunk(kind :: Int,
  token :: Bytes,
  ordinal :: Int,
  slot :: Int,
  index :: Int) -> BackupContentChunkRequest do
  BackupContentChunkRequest {
    kind: kind,
    token: token,
    ordinal: ordinal,
    slot_index: slot,
    chunk_index: index
  }
end

fn cv_encode(value :: BackupContentArchive) -> Result<Plaintext<Bytes>, String> do
  case encode_content_archive(value) do
    Err(_) -> Err("cv_fixture_encode")
    Ok(bytes) -> Ok(bytes)
  end
end

fn cv_overview_raw() -> Bool!String do
  let result = content_archive_overview(cv_literal()?)
  let id = cv_repeat(16, 32)?
  let time = U64.parse("72623859790382856")?
  case result do
    Err(_) -> Ok(false)
    Ok(value) -> do
      let allowed = case value.policy do
        AllowArchiveAttachmentOmissions -> true
        _ -> false
      end
      Ok(Bytes.secure_equals(value.backup_id, id)
        && value.created_at == time
        && allowed
        && value.included_count == 3
        && value.candidate_count == 8
        && value.omitted_timed == 2
        && value.omitted_unknown == 1
        && value.omitted_nontext == 1
        && value.omitted_empty == 1
        && value.attachment_messages == 1
        && value.files.total == 2
        && value.files.included == 1
        && value.files.expired == 1
        && value.files.unavailable == 0
        && value.files.unsupported == 0
        && value.files.above_profile == 0
        && List.length(value.conversations) == 3
        && List.get(value.conversations, 0).name == "A"
        && List.get(value.conversations, 1).name == "Group"
        && List.get(value.conversations, 2).name == "Legacy")
    end
  end
end

pub fn content_view_overview_proof() -> Bool do
  cv_observe(Result.unwrap_or(cv_overview_raw(), false))
end

fn cv_literal_page_raw() -> Bool!String do
  let payload = cv_literal()?
  let revision = cv_revision()?
  let expected_token = cv_literal_token()?
  let result = content_archive_page(payload, revision, cv_page(2, cv_repeat(3, 32)?, 0, 16))
  case result do
    Err(_) -> Ok(false)
    Ok(page) -> do
      let record = List.head(page.entries)
      let descriptors = case (List.get(record.attachments, 0), List.get(record.attachments, 1)) do
        (ContentAttachmentIncluded(slot, name, mime, size, token), ContentAttachmentOmitted(omitted_slot, ArchiveAttachmentExpired)) ->
          slot == 0
            && omitted_slot == 1
            && size == 4
            && Bytes.secure_equals(name, Bytes.from_utf8("note.bin"))
            && Bytes.secure_equals(mime, Bytes.from_utf8("application/octet-stream"))
            && Bytes.secure_equals(token, expected_token)
        _ -> false
      end
      let selected = content_archive_chunk(payload,
        revision,
        cv_chunk(2, expected_token, 255, 0, 0))
      let exact_file = case selected do
        Err(_) -> false
        Ok(file) -> file.ordinal == 255
          && file.slot_index == 0
          && file.chunk_index == 0
          && file.kind == 2
          && Bytes.secure_equals(file.scope_id, cv_repeat(3, 32)?)
          && file.total_size == 4
          && Bytes.secure_equals(file.bytes, cv_hex("00ff4142")?)
          && Bytes.secure_equals(file.token, expected_token)
      end
      Ok(page.offset == 0
        && page.next_offset == None
        && List.length(page.entries) == 1
        && page.encoded_size == 351
        && record.ordinal == 255
        && Bytes.length(record.message_id) == 0
        && Bytes.length(record.text) == 0
        && descriptors
        && exact_file)
    end
  end
end

pub fn content_view_literal_proof() -> Bool do
  cv_observe(Result.unwrap_or(cv_literal_page_raw(), false)
    && Result.unwrap_or(cv_two_scopes_raw(), false))
end

fn cv_payload(direct :: Bool,
  count :: Int,
  large :: Bool,
  mixed :: Bool) -> Result<Plaintext<Bytes>, String> do
  let owner = cv_repeat(17, 32)?
  let name = Bytes.from_utf8("éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééx")
  let mime = Bytes.from_utf8("µµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµµa")
  let entries = for index in 0..count do
    let attachments = for slot in 0..10 do
      if mixed && slot >= 4 do
        ArchiveAttachmentOmitted(ArchiveAttachmentExpired)
      else
        ArchiveAttachmentIncluded(name, mime, Bytes.from_utf8("x"))
      end
    end
    BackupContentRecord {
      ordinal: index,
      direction: 1,
      message_id: cv_repeat(index,
        if direct do
          16
        else
          32
        end)?,
      sender_account: owner,
      sender_device: cv_repeat(102, 16)?,
      timestamp: U64.parse("18446744073709551615")?,
      text: if large do
        cv_repeat(65,
          if direct do
            32768
          else
            65346
          end)?
      else
        Bytes.from_utf8("t")
      end,
      attachments: attachments
    }
  end
  cv_encode(BackupContentArchive {
    policy: if mixed do
      AllowArchiveAttachmentOmissions
    else
      RequireArchiveAttachments
    end,
    backup_id: cv_repeat(68, 32)?,
    owner_account: owner,
    owner_authorization_key: cv_repeat(34, 32)?,
    service_realm: cv_repeat(51, 32)?,
    created_at: U64.parse("18446744073709551615")?,
    candidate_count: count,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: count,
    scopes: [
      BackupContentScope {
        kind: if direct do
          1
        else
          2
        end,
        id: cv_repeat(3,
          if direct do
            16
          else
            32
          end)?,
        peer: if direct do
          cv_repeat(34, 32)?
        else
          Bytes.empty()
        end,
        name: "Historical",
        entries: entries
      }
    ]
  })
end

fn cv_budget_raw() -> Bool!String do
  let revision = cv_revision()?
  let group = cv_payload(false, 16, true, false)?
  let direct = cv_payload(true, 16, true, false)?
  let mixed = cv_payload(false, 16, true, true)?
  let small = cv_payload(false, 16, false, false)?
  let a = content_archive_page(group, revision, cv_page(2, cv_repeat(3, 32)?, 0, 16))
  let last = content_archive_page(group, revision, cv_page(2, cv_repeat(3, 32)?, 15, 16))
  let b = content_archive_page(direct, revision, cv_page(1, cv_repeat(3, 16)?, 0, 16))
  let c = content_archive_page(mixed, revision, cv_page(2, cv_repeat(3, 32)?, 0, 16))
  let d = content_archive_page(small, revision, cv_page(2, cv_repeat(3, 32)?, 0, 16))
  case (a, last, b, c, d) do
    (Ok(one), Ok(final), Ok(three), Ok(two), Ok(sixteen)) -> do
      let names = case List.head(List.head(one.entries).attachments) do
        ContentAttachmentIncluded(_, filename, mime, _, _) ->
          Bytes.length(filename) == 255 && Bytes.length(mime) == 127
        _ -> false
      end
      Ok(names
        && List.length(one.entries) == 1
        && one.next_offset == Some(1)
        && one.encoded_size == 70165
        && List.head(one.entries).ordinal == 0
        && List.length(final.entries) == 1
        && final.next_offset == None
        && final.encoded_size == 70161
        && List.head(final.entries).ordinal == 15
        && List.length(three.entries) == 3
        && three.next_offset == Some(3)
        && three.encoded_size == 112465
        && List.length(two.entries) == 2
        && two.next_offset == Some(2)
        && two.encoded_size == 135006
        && List.length(sixteen.entries) == 16
        && sixteen.next_offset == None
        && sixteen.encoded_size == 75376)
    end
    _ -> Ok(false)
  end
end

pub fn content_view_budget_proof() -> Bool do
  cv_observe(Result.unwrap_or(cv_budget_raw(), false))
end

fn cv_file_payload() -> Result<Plaintext<Bytes>, String> do
  let raw = cv_payload(false, 1, false, false)?
  let archive = case decode_content_archive(raw) do
    Err(_) -> return Err("cv_fixture_decode")
    Ok(value) -> value
  end
  let scope = List.head(archive.scopes)
  let record = List.head(scope.entries)
  cv_encode(%{archive |
    scopes: [
      %{scope |
        entries: [
          %{record |
            ordinal: 255,
            message_id: Bytes.empty(),
            text: Bytes.empty(),
            attachments: [
              ArchiveAttachmentIncluded(Bytes.empty(), Bytes.from_utf8("a"), cv_repeat(165, 65537)?)
            ]
          }
        ]
      }
    ]
  })
end

fn cv_token_from_page(payload :: Plaintext<Bytes>,
  revision :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let page = content_archive_page(payload, revision, cv_page(2, cv_repeat(3, 32)?, 0, 1))?
  case List.head(List.head(page.entries).attachments) do
    ContentAttachmentIncluded(_, _, _, _, token) -> Ok(token)
    _ -> Err("cv_fixture_token")
  end
end

fn cv_chunk_raw() -> Bool!String do
  let payload = cv_file_payload()?
  let revision = cv_revision()?
  let token = cv_token_from_page(payload, revision)?
  let first = content_archive_chunk(payload, revision, cv_chunk(2, token, 255, 0, 0))
  let last = content_archive_chunk(payload, revision, cv_chunk(2, token, 255, 0, 1))
  let requests = [
    cv_chunk(2, token, 0, 0, 0),
    cv_chunk(2, token, 255, 1, 0),
    cv_chunk(2, token, 255, 0, 2),
    cv_chunk(2, token, 255, 0, 256),
    cv_chunk(3, token, 255, 0, 0),
    cv_chunk(1, token, 255, 0, 0),
    cv_chunk(2, token, -1, 0, 0),
    cv_chunk(2, token, 255, 10, 0)
  ]
  let all_refused = List.all(requests,
    fn(request) -> Result.is_err(content_archive_chunk(payload, revision, request)) end)
  let archive = case decode_content_archive(payload) do
    Err(_) -> return Err("cv_fixture_decode")
    Ok(value) -> value
  end
  let changed = cv_encode(%{archive | created_at: U64.parse("9")?})?
  let revision_changed = Result.is_err(content_archive_chunk(payload,
    cv_repeat(146, 32)?,
    cv_chunk(2, token, 255, 0, 0)))
  let payload_changed = Result.is_err(content_archive_chunk(changed,
    revision,
    cv_chunk(2, token, 255, 0, 0)))
  let fresh_revision = cv_repeat(146, 32)?
  let fresh_token = cv_token_from_page(payload, fresh_revision)?
  let fresh_revision_result = content_archive_chunk(payload,
    fresh_revision,
    cv_chunk(2, fresh_token, 255, 0, 1))
  let changed_token = cv_token_from_page(changed, revision)?
  let fresh_payload_result = content_archive_chunk(changed,
    revision,
    cv_chunk(2, changed_token, 255, 0, 1))
  let fresh_acceptance = case (fresh_revision_result, fresh_payload_result) do
    (Ok(a), Ok(b)) -> !Bytes.secure_equals(token, fresh_token)
      && !Bytes.secure_equals(token, changed_token)
      && Bytes.secure_equals(a.bytes, cv_repeat(165, 1)?)
      && Bytes.secure_equals(b.bytes, cv_repeat(165, 1)?)
    _ -> false
  end
  let bad_token = Result.is_err(content_archive_chunk(payload,
    revision,
    cv_chunk(2, cv_repeat(0, 32)?, 255, 0, 0)))
    && Result.is_err(content_archive_chunk(payload,
      revision,
      cv_chunk(2, cv_repeat(0, 31)?, 255, 0, 0)))
  case (first, last) do
    (Ok(a), Ok(b)) -> Ok(a.ordinal == 255
      && a.slot_index == 0
      && a.chunk_index == 0
      && b.chunk_index == 1
      && a.total_size == 65537
      && b.total_size == 65537
      && Bytes.length(a.bytes) == 65536
      && Bytes.length(b.bytes) == 1
      && Bytes.secure_equals(a.bytes, cv_repeat(165, 65536)?)
      && Bytes.secure_equals(b.bytes, cv_repeat(165, 1)?)
      && Bytes.secure_equals(a.token, token)
      && Bytes.secure_equals(b.token, token)
      && all_refused
      && revision_changed
      && payload_changed
      && fresh_acceptance
      && bad_token)
    _ -> Ok(false)
  end
end

pub fn content_view_chunk_proof() -> Bool do
  cv_observe(Result.unwrap_or(cv_chunk_raw(), false))
end

fn cv_refusal_raw() -> Bool!String do
  let payload = cv_literal()?
  let revision = cv_revision()?
  let id = cv_repeat(3, 32)?
  let finished = content_archive_page(payload, revision, cv_page(2, id, 1, 16))
  let invalid = [
    cv_page(2, id, -1, 1),
    cv_page(2, id, 257, 1),
    cv_page(2, id, 0, 0),
    cv_page(2, id, 0, 17),
    cv_page(2, id, 2, 1),
    cv_page(1, id, 0, 1),
    cv_page(3, id, 0, 1),
    cv_page(2, cv_repeat(4, 32)?, 0, 1)
  ]
  let pages = List.all(invalid,
    fn(request) -> Result.is_err(content_archive_page(payload, revision, request)) end)
  let legacy = Result.is_err(content_archive_overview(cv_legacy_payload()?))
  let truncated = case Bytes.slice(payload, 0, Bytes.length(payload) - 1) do
    Err(_) -> return Err("cv_fixture_slice")
    Ok(value) -> value
  end
  let trailing = case Bytes.concat(payload, Bytes.from_utf8("x")) do
    Err(_) -> return Err("cv_fixture_concat")
    Ok(value) -> value
  end
  let invalid_payloads = Result.is_err(content_archive_overview(Bytes.empty()))
    && Result.is_err(content_archive_overview(truncated))
    && Result.is_err(content_archive_overview(trailing))
    && Result.is_err(content_archive_page(payload, Bytes.empty(), cv_page(2, id, 0, 1)))
  let omitted = Result.is_err(content_archive_chunk(payload,
    revision,
    cv_chunk(2, cv_literal_token()?, 255, 1, 0)))
  case finished do
    Err(_) -> Ok(false)
    Ok(page) -> Ok(List.length(page.entries) == 0
      && page.next_offset == None
      && page.encoded_size == 112
      && legacy
      && pages
      && invalid_payloads
      && omitted)
  end
end

pub fn content_view_refusal_proof() -> Bool do
  cv_observe(Result.unwrap_or(cv_refusal_raw(), false))
end

fn cv_two_scopes_raw() -> Bool!String do
  let raw = cv_file_payload()?
  let archive = case decode_content_archive(raw) do
    Err(_) -> return Err("cv_fixture_decode")
    Ok(value) -> value
  end
  let first = List.head(archive.scopes)
  let record = List.head(first.entries)
  let second = %{first |
    id: cv_repeat(4, 32)?,
    entries: [
      %{record |
        attachments: [
          ArchiveAttachmentIncluded(Bytes.empty(), Bytes.from_utf8("a"), Bytes.from_utf8("Y"))
        ]
      }
    ]
  }
  let payload = cv_encode(%{archive |
    candidate_count: 2,
    attachment_messages: 2,
    scopes: [first, second]
  })?
  let revision = cv_revision()?
  let left = content_archive_page(payload, revision, cv_page(2, cv_repeat(3, 32)?, 0, 1))
  let right = content_archive_page(payload, revision, cv_page(2, cv_repeat(4, 32)?, 0, 1))
  case (left, right) do
    (Ok(a), Ok(b)) -> do
      case (List.head(List.head(a.entries).attachments),
        List.head(List.head(b.entries).attachments)) do
        (ContentAttachmentIncluded(_, _, _, _, ta), ContentAttachmentIncluded(_, _, _, _, tb)) -> do
          let one = content_archive_chunk(payload, revision, cv_chunk(2, ta, 255, 0, 1))
          let two = content_archive_chunk(payload, revision, cv_chunk(2, tb, 255, 0, 0))
          case (one, two) do
            (Ok(x), Ok(y)) -> Ok(!Bytes.secure_equals(ta, tb)
              && Bytes.secure_equals(x.scope_id, cv_repeat(3, 32)?)
              && Bytes.secure_equals(y.scope_id, cv_repeat(4, 32)?)
              && Bytes.secure_equals(x.bytes, cv_repeat(165, 1)?)
              && Bytes.secure_equals(y.bytes, Bytes.from_utf8("Y")))
            _ -> Ok(false)
          end
        end
        _ -> Ok(false)
      end
    end
    _ -> Ok(false)
  end
end

fn cv_legacy_payload() -> Bytes!String do
  cv_hex("014d5441101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff000000000548656c6c6f000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b71111111111111111111111111111111111111111111111111111111111111111454545454545454545454545454545450000000000000000000000000867726f757020cf800000007d0200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c656761637900010000004400ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080100000000")
end
