from Mobile.Codec import mobile_reader, take_fixed, take_vector_error, mobile_vector, mobile_join
from Storage.JournalBlobs import seal_journal_blob, open_journal_blob
from Storage.Keys import platform_key, seal_local, local_context
from Tests.Support import repeated

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let label = "journal/v1/read-state/index"
  let value = repeated(91, 131073)?
  let first = seal_journal_blob(value, key, label)?
  let other = seal_journal_blob(value, key, label)?
  assert(!Bytes.secure_equals(first, other))
  assert(Bytes.secure_equals(open_journal_blob(first, key, label)?, value))
  assert(Result.is_err(open_journal_blob(first, key, "journal/v1/receipt-marks/index")))
  assert(Result.is_err(open_journal_blob(Bytes.slice(first, 0, Bytes.length(first) - 1)?,
    key,
    label)))
  assert(Result.is_err(open_journal_blob(Bytes.concat(first, Bytes.from_hex("00")?)?, key, label)))
  let first_header = take_fixed(mobile_reader(first, 265000, "bad_fixture")?, 36)?
  let root = take_vector_error(first_header.state, 66000, "bad_fixture")?
  let first_part = take_vector_error(root.state, 66000, "bad_fixture")?
  let second_part = take_vector_error(first_part.state, 66000, "bad_fixture")?
  let third_part = take_vector_error(second_part.state, 66000, "bad_fixture")?
  let other_header = take_fixed(mobile_reader(other, 265000, "bad_fixture")?, 36)?
  let other_root = take_vector_error(other_header.state, 66000, "bad_fixture")?
  let other_part = take_vector_error(other_root.state, 66000, "bad_fixture")?
  # Another independently sealed generation, even with identical content, cannot
  # donate a part or manifest to this record. Nor can equal-sized parts swap.
  for parts in [
    [root.value, other_part.value, second_part.value, third_part.value],
    [other_root.value, first_part.value, second_part.value, third_part.value],
    [root.value, second_part.value, first_part.value, third_part.value]
  ] do
    let replaced = mobile_join([first_header.value]
        ++ for part in parts do
          mobile_vector(part)?
        end,
      0,
      Bytes.empty())?
    assert(Result.is_err(open_journal_blob(replaced, key, label)))
  end
  let small = Bytes.from_utf8("legacy record")
  let legacy = seal_local(small, key, local_context(label)?)?
  assert(Bytes.secure_equals(open_journal_blob(legacy, key, label)?, small))
  assert(Result.is_err(seal_journal_blob(repeated(91, 262145)?, key, label)))
  Ok(nil)
end

test("chunked journals reject generation mixing, reordered chunks, cross-label replay and broken framing while reading legacy ciphertext") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
