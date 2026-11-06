from MobileCore import (
  bounty_status_export,
  bounty_set_enabled_export,
  bounty_commit_export,
  bounty_unavailable_export,
  transparency_fork_export
)
from Mobile.TransparencySafety import retain_fork
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.Codec import mobile_byte
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated, append
from Tests.ForkFilingSupport import filing_fixture
from Transparency.Config import encode_security_config
from Transparency.Fork import encode_fork, decode_fork

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let (sample, config) = filing_fixture()?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let path = database_path("bounty-native")?
  let db = Bytes.from_utf8(path)
  let initial = unpack_credit_parts(bounty_status_export(db)?, 6, 32)?
  assert(List.length(initial) == 6 && Bytes.to_hex(List.head(initial)) == "01424650")
  assert(Bytes.to_hex(List.get(initial, 1)) == "00" && Bytes.to_hex(List.get(initial, 2)) == "00")
  assert(Bytes.length(List.get(initial, 3)) == 0 && Bytes.length(List.get(initial, 4)) == 0)
  assert(Bytes.to_hex(List.get(initial, 5)) == "0000000000000000")
  assert(Result.is_err(bounty_status_export(Bytes.empty())))
  assert(Result.is_err(bounty_status_export(repeated(65, 4097)?)))
  assert(Result.is_err(bounty_set_enabled_export(pack_credit_parts([db])?)))
  assert(Result.is_err(bounty_set_enabled_export(pack_credit_parts([db, mobile_byte(2)?])?)))
  assert(Result.is_err(bounty_set_enabled_export(pack_credit_parts([db, repeated(1, 2)?])?)))
  assert(Result.is_err(bounty_set_enabled_export(pack_credit_parts([db, mobile_byte(1)?, db])?)))
  let enabled = unpack_credit_parts(bounty_set_enabled_export(pack_credit_parts([
      db,
      mobile_byte(1)?
    ])?)?,
    6,
    32)?
  assert(Bytes.to_hex(List.get(enabled, 1)) == "01")
  let key = platform_key()?
  let fork = %{sample | finder: repeated(0, 32)?}
  retain_fork(path, key, fork)?
  let pending = unpack_credit_parts(bounty_status_export(db)?, 6, 32)?
  let identity = List.get(pending, 3)
  assert(Bytes.to_hex(List.get(pending, 2)) == "01")
  assert(Bytes.secure_equals(identity, Crypto.sha256(encode_fork(fork)?)))
  assert(Result.is_err(bounty_commit_export(pack_credit_parts([db, identity])?)))
  assert(Result.is_err(bounty_unavailable_export(pack_credit_parts([db, repeated(0, 32)?])?)))
  let sdk = append(Bytes.from_hex("ffffff7f00000000")?, repeated(90, 32)?)?
  let selected = unpack_credit_parts(bounty_commit_export(pack_credit_parts([db, identity, sdk])?)?,
    6,
    32)?
  assert(Bytes.to_hex(List.get(selected, 2)) == "03")
  assert(Bytes.to_hex(List.get(selected, 5)) == "000000007fffffff")
  assert(Bytes.secure_equals(List.get(selected, 4), repeated(90, 32)?))
  assert(Bytes.secure_equals(decode_fork(transparency_fork_export(db)?)?.finder,
    List.get(selected, 4)))
  assert(Result.is_err(bounty_unavailable_export(pack_credit_parts([db, identity])?)))
  let disabled = unpack_credit_parts(bounty_set_enabled_export(pack_credit_parts([
      db,
      mobile_byte(0)?
    ])?)?,
    6,
    32)?
  assert(Bytes.to_hex(List.get(disabled, 1)) == "00")
  assert(Bytes.secure_equals(List.get(disabled, 4), List.get(selected, 4)))
  File.delete(path)?
  Ok(true)
end

test("bounty native byte ABI binds the exact proof and preserves the SDK derivation index") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
