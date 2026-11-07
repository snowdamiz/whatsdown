import File
from Mobile.CreditState import CreditWallet
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Storage.Credits import (
  CreditWalletIdentity,
  CreditCacheWrite,
  load_credit_wallet,
  commit_credit_wallet_with_cache
)
from Tests.Support import database_path, repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let who = CreditWalletIdentity {
    account_id: repeated(11, 32)?,
    device_id: repeated(12, 16)?,
    service_key: repeated(13, 32)?,
    purpose: 1
  }
  let path = database_path("credits_cache_cas")?
  let first = load_credit_wallet(path, key, who)?
  let one = repeated(21, 20)?
  let two = repeated(22, 20)?
  commit_credit_wallet_with_cache(path,
    key,
    who,
    first,
    CreditWallet { revision: U64.parse("1")?, records: [] },
    [
      CreditCacheWrite { label: "transparency-checkpoint/v1", previous: Bytes.empty(), value: one }
    ])?
  let second = load_credit_wallet(path, key, who)?
  # A validated existing cursor is replaced, rather than reinserted under its
  # unique key. Both the wallet and cursor must advance or neither may advance.
  commit_credit_wallet_with_cache(path,
    key,
    who,
    second,
    CreditWallet { revision: U64.parse("2")?, records: [] },
    [CreditCacheWrite { label: "transparency-checkpoint/v1", previous: one, value: two }])?
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, two))
  let third = load_credit_wallet(path, key, who)?
  assert(Result.is_err(commit_credit_wallet_with_cache(path,
    key,
    who,
    third,
    CreditWallet { revision: U64.parse("3")?, records: [] },
    [
      CreditCacheWrite {
        label: "transparency-checkpoint/v1",
        previous: one,
        value: repeated(23, 20)?
      }
    ])))
  assert(load_credit_wallet(path, key, who)?.wallet.revision == U64.parse("2")?)
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, two))
  let own = "transparency-device-set/v1/#{Bytes.to_hex(who.account_id)}"
  assert(Result.is_err(commit_credit_wallet_with_cache(path,
    key,
    who,
    third,
    CreditWallet { revision: U64.parse("3")?, records: [] },
    [
      CreditCacheWrite {
        label: "transparency-device-set/v1/#{Bytes.to_hex(repeated(99, 32)?)}",
        previous: Bytes.empty(),
        value: one
      }
    ])))
  commit_credit_wallet_with_cache(path,
    key,
    who,
    third,
    CreditWallet { revision: U64.parse("3")?, records: [] },
    [CreditCacheWrite { label: own, previous: Bytes.empty(), value: one }])?
  assert(Bytes.secure_equals(load_blob(path, own)?, one))
  File.delete(path)?
  Ok(true)
end

test("credit cache CAS replaces an existing cursor and rejects stale or foreign guards") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
