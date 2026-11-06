from Mobile.Attachments import (
  BackupAttachmentReferenceSlot,
  backup_attachment_reference_slots,
  encode_reference,
  decode_reference,
  group_attachment_reference
)
from Mobile.Types import MobileAttachmentReference
from Mobile.Codec import mobile_byte, mobile_write_u32, mobile_join, mobile_vector
from Tests.Support import repeated

# These are canonical syntax fixtures with explicitly opaque EAM/wrap bytes.
# Neither this parser nor these fixtures claim manifest/source authentication.
struct ParserRecipient do
  account_id :: Bytes
  device_id :: Bytes
  wrapped :: Bytes
end

fn parser_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY finite equality count and refusal predicates over authored opaque positional syntax fixtures; no real history references metadata keys content errors or caller control are disclosed")
end

fn parser_reference(tag :: Int) -> Bytes!String do
  encode_reference(MobileAttachmentReference {
    object_id: repeated(tag, 32)?,
    download_capability: repeated(tag + 1, 32)?,
    encrypted_manifest: Bytes.from_utf8("opaque syntax EAM"),
    wrapped_key: repeated(tag + 2, 80)?
  })
end

fn parser_recipient(reference :: Bytes, here :: Bool) -> ParserRecipient!String do
  let value = decode_reference(reference)?
  Ok(ParserRecipient {
    account_id: repeated(if here do
        201
      else
        203
      end,
      32)?,
    device_id: repeated(if here do
        202
      else
        204
      end,
      16)?,
    wrapped: value.wrapped_key
  })
end

fn parser_group(reference :: Bytes, recipients :: List<ParserRecipient>) -> Bytes!String do
  let value = decode_reference(reference)?
  let entries = for entry in recipients do
    mobile_join([entry.account_id, entry.device_id, mobile_vector(entry.wrapped)?],
      0,
      Bytes.empty())?
  end
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("ATG"),
      value.object_id,
      value.download_capability,
      mobile_vector(value.encrypted_manifest)?,
      mobile_write_u32(List.length(recipients))?,
      mobile_join(entries, 0, Bytes.empty())?
    ],
    0,
    Bytes.empty())
end

fn parser_batch(parts :: List<Bytes>) -> Bytes!String do
  let values = for part in parts do
    mobile_vector(part)?
  end
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("ATB"),
      mobile_write_u32(List.length(parts))?,
      mobile_join(values, 0, Bytes.empty())?
    ],
    0,
    Bytes.empty())
end

fn parser_parse(input :: Bytes,
  scope_kind :: Int) -> Result<Plaintext<List<BackupAttachmentReferenceSlot>>, String> do
  backup_attachment_reference_slots(input, scope_kind, repeated(201, 32)?, repeated(202, 16)?)
end

fn parser_same_slots(actual :: List<BackupAttachmentReferenceSlot>,
  expected :: List<Option<Bytes>>,
  index :: Int) -> Plaintext<Bool> do
  if index >= List.length(expected) do
    return true
  end
  let same = case List.get(expected, index) do
    None -> case List.get(actual, index) do
      BackupAttachmentNoRecipient -> true
      _ -> false
    end
    Some(reference) -> case List.get(actual, index) do
      BackupAttachmentReference(value) -> Bytes.secure_equals(value, reference)
      _ -> false
    end
  end
  same && parser_same_slots(actual, expected, index + 1)
end

fn parser_matches(raw :: Result<Plaintext<List<BackupAttachmentReferenceSlot>>, String>,
  expected :: List<Option<Bytes>>) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(actual) -> List.length(actual) == List.length(expected)
      && parser_same_slots(actual, expected, 0)
  end
end

fn parser_direct_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let two = parser_reference(21)?
  let three = parser_reference(31)?
  let batch = parser_batch([one, two, three])?
  println("POSITIONAL_DIRECT_SYNTAX_READY")
  let empty = parser_matches(parser_parse(Bytes.empty(), 1), [])
  let single = parser_matches(parser_parse(one, 1), [Some(one)])
  let ordered = parser_matches(parser_parse(batch, 1), [Some(one), Some(two), Some(three)])
  Ok(empty && single && ordered)
end

test("positional backup parser preserves empty single and ordered direct slots") do
  assert(parser_observe(Result.unwrap_or(parser_direct_proof(), false)))
end

fn parser_group_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let two = parser_reference(21)?
  let three = parser_reference(31)?
  let first = parser_group(one, [parser_recipient(one, true)?])?
  let missing = parser_group(two, [parser_recipient(two, false)?])?
  let last = parser_group(three, [parser_recipient(three, true)?])?
  let batch = parser_batch([first, missing, last])?
  println("POSITIONAL_GROUP_SYNTAX_READY")
  let single = parser_matches(parser_parse(first, 2), [Some(one)])
  let absent = parser_matches(parser_parse(missing, 2), [None])
  let ordered = parser_matches(parser_parse(batch, 2), [Some(one), None, Some(three)])
  let mixed = parser_matches(parser_parse(parser_batch([one, missing, three])?, 2),
    [Some(one), None, Some(three)])
  Ok(single && absent && ordered && mixed)
end

test("positional backup parser preserves unaddressed group slots and original batch positions") do
  assert(parser_observe(Result.unwrap_or(parser_group_proof(), false)))
end

fn parser_duplicate_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let two = parser_reference(21)?
  let here = parser_recipient(one, true)?
  let valid = parser_group(one, [here])?
  let identical = parser_group(one, [here, here])?
  let conflicting = parser_group(one, [here, parser_recipient(two, true)?])?
  println("POSITIONAL_DUPLICATE_SYNTAX_READY")
  let positive = parser_matches(parser_parse(valid, 2), [Some(one)])
  Ok(positive
    && Result.is_err(parser_parse(identical, 2))
    && Result.is_err(parser_parse(conflicting, 2)))
end

test("positional backup parser refuses ambiguous current-recipient duplicates") do
  assert(parser_observe(Result.unwrap_or(parser_duplicate_proof(), false)))
end

fn parser_malformed_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let here = parser_recipient(one, true)?
  let group = parser_group(one, [here])?
  let empty_wrapped = %{here | wrapped: Bytes.empty()}
  let empty_group = parser_group(one, [empty_wrapped])?
  let valid_batch = parser_batch([one, one])?
  let malformed = [
    Bytes.slice(one, 0, Bytes.length(one) - 1)?,
    Bytes.concat(one, mobile_byte(0)?)?,
    parser_batch([valid_batch, one])?,
    parser_batch([one])?,
    parser_batch([one, Bytes.empty()])?,
    Bytes.from_utf8("unrecognized stored summary")
  ]
  println("POSITIONAL_MALFORMED_SYNTAX_READY")
  let positive = parser_matches(parser_parse(valid_batch, 1), [Some(one), Some(one)])
  let bad_direct = for value in malformed do
    Result.is_err(parser_parse(value, 1))
  end
  Ok(positive
    && List.all(bad_direct, fn(value) -> value end)
    && Result.is_err(parser_parse(Bytes.slice(group, 0, Bytes.length(group) - 1)?, 2))
    && Result.is_err(parser_parse(Bytes.concat(group, mobile_byte(0)?)?, 2))
    && Result.is_err(parser_parse(empty_group, 2)))
end

test("positional backup parser refuses malformed truncated trailing nested and empty slot framing") do
  assert(parser_observe(Result.unwrap_or(parser_malformed_proof(), false)))
end

fn parser_limits_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let here = parser_recipient(one, true)?
  let away = parser_recipient(one, false)?
  let ten = parser_batch(for _ in 0..10 do
    one
  end)?
  let eleven = parser_batch(for _ in 0..11 do
    one
  end)?
  let maximum = parser_group(one,
    [here]
      ++ (for _ in 0..255 do
        away
      end))?
  let over = parser_group(one,
    [here]
      ++ (for _ in 0..256 do
        away
      end))?
  let zero = parser_group(one, [])?
  println("POSITIONAL_LIMIT_SYNTAX_READY")
  let positive_parts = parser_matches(parser_parse(ten, 1),
    for _ in 0..10 do
      Some(one)
    end)
  let positive_recipients = parser_matches(parser_parse(maximum, 2), [Some(one)])
  Ok(positive_parts
    && positive_recipients
    && Result.is_err(parser_parse(eleven, 1))
    && Result.is_err(parser_parse(over, 2))
    && Result.is_err(parser_parse(zero, 2)))
end

test("positional backup parser enforces ten slots and bounded nonempty group recipient lists") do
  assert(parser_observe(Result.unwrap_or(parser_limits_proof(), false)))
end

fn parser_scope_proof() -> Plaintext<Bool>!String do
  let one = parser_reference(11)?
  let group = parser_group(one, [parser_recipient(one, true)?])?
  let batch = parser_batch([one, group])?
  println("POSITIONAL_SCOPE_SYNTAX_READY")
  let positive_direct = parser_matches(parser_parse(one, 1), [Some(one)])
  let positive_group = parser_matches(parser_parse(batch, 2), [Some(one), Some(one)])
  let bad_account = backup_attachment_reference_slots(one,
    1,
    repeated(201, 31)?,
    repeated(202, 16)?)
  let bad_device = backup_attachment_reference_slots(one, 2, repeated(201, 32)?, repeated(202, 15)?)
  Ok(positive_direct
    && positive_group
    && Result.is_err(parser_parse(group, 1))
    && Result.is_err(parser_parse(batch, 1))
    && Result.is_err(parser_parse(one, 0))
    && Result.is_err(parser_parse(one, 3))
    && Result.is_err(bad_account)
    && Result.is_err(bad_device))
end

test("positional backup parser keeps direct and group grammar and owner-shape boundaries") do
  assert(parser_observe(Result.unwrap_or(parser_scope_proof(), false)))
end

fn parser_ordinary_proof() -> Bool!String do
  let one = parser_reference(11)?
  let two = parser_reference(21)?
  let here = parser_recipient(one, true)?
  let duplicate = parser_group(one, [here, parser_recipient(two, true)?])?
  let addressed = parser_group(one, [here])?
  let missing = parser_group(two, [parser_recipient(two, false)?])?
  let batch = parser_batch([missing, addressed])?
  println("POSITIONAL_ORDINARY_SYNTAX_READY")
  Ok(Bytes.secure_equals(group_attachment_reference(duplicate,
      repeated(201, 32)?,
      repeated(202, 16)?)?,
    one)
    && Bytes.secure_equals(group_attachment_reference(batch,
        repeated(201, 32)?,
        repeated(202, 16)?)?,
      one))
end

test("ordinary group attachment reader retains existing first-match and missing-recipient filtering") do
  case parser_ordinary_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
