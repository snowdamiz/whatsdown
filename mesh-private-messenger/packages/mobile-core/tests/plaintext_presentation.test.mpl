import File
from Mobile.Presentation import (
  encode_presented_message_with_attachment,
  presented_message_writes,
  load_presentation_record,
  record_change_allowed,
  store_group_anchor
)
from Mobile.Codec import mobile_join, mobile_vector, mobile_write_u64, mobile_wide
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs, store_updated_session
from Tests.Support import repeated, database_path

fn record(name :: String, revision :: Int) -> Bytes!String do
  mobile_join([
      mobile_vector(Bytes.from_utf8(name))?,
      mobile_vector(Bytes.empty())?,
      mobile_vector(mobile_write_u64(mobile_wide(Int.to_string(revision))?)?)?
    ],
    0,
    Bytes.empty())
end

fn community(name :: String,
  revision :: Int,
  owner :: Bytes,
  admins :: List<Bytes>) -> Bytes!String do
  let roles = mobile_join([owner] ++ admins, 0, Bytes.empty())?
  mobile_join([
      record(name, revision)?,
      mobile_vector(Bytes.from_utf8("Private community details"))?,
      mobile_vector(roles)?
    ],
    0,
    Bytes.empty())
end

fn known_fixture(value :: Bool) -> Bool do
  declassify(value,
    "test-only comparison of known synthetic presentation fixtures; no application disclosure")
end

fn receive_plan(path :: String,
  wrapping :: borrow StorageKey,
  sender :: Bytes,
  group :: Bytes,
  creator :: Bytes,
  input :: Bytes) -> Result<(Bytes, Bytes, List<String>, List<Bytes>), String> do
  # The fixed public fixture drives the real SQLite/reseal path. The identical
  # labeled fixture is independently checked without exposing its payload/branch.
  let expected = presented_message_writes(path, wrapping, sender, group, creator, input)
  let private_input :: Plaintext<Bytes> = input
  let actual = presented_message_writes(path, wrapping, sender, group, creator, private_input)
  assert(known_fixture(case expected do
    Err(expected_error) -> case actual do
      Err(actual_error) -> actual_error == expected_error
      Ok(_) -> false
    end
    Ok((body, attachment, labels, blobs)) -> case actual do
      Err(_) -> false
      Ok((actual_body, actual_attachment, actual_labels, actual_blobs)) ->
        Bytes.secure_equals(actual_body, body)
          && Bytes.secure_equals(actual_attachment, attachment)
          && actual_labels == labels
          && List.length(actual_blobs) == List.length(blobs)
          && List.all(List.zip(actual_blobs, blobs),
            fn(pair) do
              let (actual_blob, blob) = pair
              Bytes.length(actual_blob) == Bytes.length(blob)
            end)
    end
  end))
  expected
end

fn commit(path :: String,
  plan :: (Bytes, Bytes, List<String>, List<Bytes>)) -> Result<(), String> do
  let (body, attachment, labels, blobs) = plan
  store_updated_blobs(path, labels, blobs)
end

fn exercise_direct() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("private_presentation_direct")?
  ensure_schema(path)?
  let sender = repeated(1, 32)?
  let key = Bytes.from_utf8("user/" <> Bytes.to_hex(sender))
  let fresh = record("Synthetic private name", 3)?
  let body = Bytes.from_utf8("Synthetic private message")
  let attachment = Bytes.from_utf8("Synthetic private attachment")
  let framed = encode_presented_message_with_attachment(body, fresh, Bytes.empty(), attachment)?
  let first = receive_plan(path, wrapping, sender, Bytes.empty(), Bytes.empty(), framed)?
  let (first_body, first_attachment, first_labels, first_blobs) = first
  assert(known_fixture(Bytes.secure_equals(first_body, body)
    && Bytes.secure_equals(first_attachment, attachment)))
  assert(List.length(first_labels) == 1 && List.length(first_blobs) == 1)
  commit(path, first)?
  let second = receive_plan(path, wrapping, sender, Bytes.empty(), Bytes.empty(), framed)?
  let (_, _, second_labels, second_blobs) = second
  assert(List.length(second_labels) == 1 && List.length(second_blobs) == 1)
  assert(!Bytes.secure_equals(List.head(first_blobs), List.head(second_blobs)))
  commit(path, second)?
  assert(known_fixture(Bytes.secure_equals(load_presentation_record(path, wrapping, key)?, fresh)))
  let older = record("Older private name", 2)?
  let old_frame = encode_presented_message_with_attachment(body,
    older,
    Bytes.empty(),
    Bytes.empty())?
  let old_plan = receive_plan(path, wrapping, sender, Bytes.empty(), Bytes.empty(), old_frame)?
  let (_, _, old_labels, old_blobs) = old_plan
  assert(List.length(old_labels) == 1 && List.length(old_blobs) == 1)
  commit(path, old_plan)?
  assert(known_fixture(Bytes.secure_equals(load_presentation_record(path, wrapping, key)?, fresh)))
  let malformed = Bytes.from_utf8("MORSE-PRESENTATION/1\nnot a valid frame")
  let (fallback, fallback_attachment, fallback_labels, fallback_blobs) = receive_plan(path,
    wrapping,
    sender,
    Bytes.empty(),
    Bytes.empty(),
    malformed)?
  assert(known_fixture(Bytes.secure_equals(fallback, malformed)
    && Bytes.length(fallback_attachment) == 0))
  assert(List.length(fallback_labels) == 0 && List.length(fallback_blobs) == 0)
  File.delete(path)?
  Ok(true)
end

fn exercise_roles() -> Bool!String do
  let owner = repeated(1, 32)?
  let admin = repeated(2, 32)?
  let other = repeated(3, 32)?
  let plain = record("Plain group", 1)?
  let base :: Plaintext<Bytes> = community("Private group", 1, owner, [admin])?
  let edited = community("Edited group", 2, owner, [admin])?
  let changed_roles = community("Changed roles", 3, owner, [other])?
  assert(known_fixture(record_change_allowed(Bytes.empty(), base, owner, owner, Bytes.empty())?))
  assert(known_fixture(!record_change_allowed(Bytes.empty(), base, admin, owner, Bytes.empty())?))
  assert(known_fixture(record_change_allowed(Bytes.empty(), base, admin, owner, admin)?))
  assert(known_fixture(!record_change_allowed(Bytes.empty(), base, other, owner, other)?))
  assert(known_fixture(record_change_allowed(base, edited, admin, owner, Bytes.empty())?))
  assert(known_fixture(!record_change_allowed(base, changed_roles, admin, owner, Bytes.empty())?))
  assert(known_fixture(record_change_allowed(base, changed_roles, owner, owner, Bytes.empty())?))
  assert(known_fixture(!record_change_allowed(base, edited, other, owner, Bytes.empty())?))
  assert(known_fixture(!record_change_allowed(base, plain, owner, owner, Bytes.empty())?))
  assert(known_fixture(record_change_allowed(plain, base, owner, owner, Bytes.empty())?))
  assert(known_fixture(!record_change_allowed(plain, base, admin, owner, Bytes.empty())?))
  Ok(true)
end

fn exercise_group() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("private_presentation_group")?
  ensure_schema(path)?
  let owner = repeated(1, 32)?
  let attacker = repeated(3, 32)?
  let group = repeated(4, 32)?
  let group_key = Bytes.from_utf8("group/" <> Bytes.to_hex(group))
  let profile = record("Sender", 1)?
  let established = community("Owner group", 1, owner, [])?
  let first_frame = encode_presented_message_with_attachment(Bytes.from_utf8("first"),
    profile,
    established,
    Bytes.empty())?
  let first = receive_plan(path, wrapping, owner, group, owner, first_frame)?
  let (_, _, first_labels, first_blobs) = first
  assert(List.length(first_labels) == 2 && List.length(first_blobs) == 2)
  commit(path, first)?
  let forged = community("Unauthorized replacement", 2, attacker, [])?
  let bad_frame = encode_presented_message_with_attachment(Bytes.from_utf8("body survives"),
    profile,
    forged,
    Bytes.empty())?
  let rejected = receive_plan(path, wrapping, attacker, group, owner, bad_frame)?
  let (body, _, rejected_labels, rejected_blobs) = rejected
  assert(known_fixture(Bytes.secure_equals(body, Bytes.from_utf8("body survives"))))
  assert(List.length(rejected_labels) == 2 && List.length(rejected_blobs) == 2)
  commit(path, rejected)?
  assert(known_fixture(Bytes.secure_equals(load_presentation_record(path, wrapping, group_key)?,
    established)))
  # A corrupt unused anchor must not prevent delivery without group metadata.
  store_updated_session(path,
    "group-anchor/v1/" <> Bytes.to_hex(group),
    Bytes.from_utf8("corrupt"))?
  let no_group = encode_presented_message_with_attachment(Bytes.from_utf8("no group metadata"),
    profile,
    Bytes.empty(),
    Bytes.empty())?
  let (_, _, only_user, _) = receive_plan(path, wrapping, owner, group, owner, no_group)?
  assert(List.length(only_user) == 1)
  let corrupt_result = receive_plan(path, wrapping, owner, group, owner, first_frame)
  assert(Result.is_err(corrupt_result))
  store_group_anchor(path, wrapping, group, owner)?
  let valid_again = receive_plan(path, wrapping, owner, group, owner, first_frame)?
  let (_, _, restored_labels, _) = valid_again
  assert(List.length(restored_labels) == 2)
  File.delete(path)?
  Ok(true)
end

test("private presentation plans reseal unchanged metadata and preserve exact revision and fallback semantics") do
  assert(known_fixture(case exercise_direct() do
    Ok(value) -> value
    Err(_) -> false
  end))
end

test("private community roles preserve creator anchor owner and admin authorization") do
  assert(known_fixture(case exercise_roles() do
    Ok(value) -> value
    Err(_) -> false
  end))
end

test("unauthorized group metadata keeps prior encrypted record and unused corrupt anchor stays untouched") do
  assert(known_fixture(case exercise_group() do
    Ok(value) -> value
    Err(_) -> false
  end))
end
