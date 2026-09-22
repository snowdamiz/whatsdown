from Groups.KeySchedule import group_mix_epoch, group_confirmation
from Groups.Mls import GroupError

fn oracle() -> Bool ! GroupError do
  let root = case Env.get_secret_hex("MORSE_TEST_GROUP_ROOT") do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  let previous = case Env.get_secret_hex("MORSE_TEST_GROUP_PRIOR") do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  let context = Bytes.from_utf8("group schedule oracle")
  let epoch = group_mix_epoch(root, previous, context) ?
  let tag = group_confirmation(epoch, context) ?
  Ok(Bytes.to_hex(tag) == Env.get("MORSE_TEST_GROUP_CONFIRMATION", ""))
end

test("C3 group epoch mix matches independent OpenSSL HKDF and AEAD derivation") do
  case oracle() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
