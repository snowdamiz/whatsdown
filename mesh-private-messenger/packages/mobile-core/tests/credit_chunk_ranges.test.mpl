import File
from Mobile.CreditState import CreditRecord, CreditWallet, encode_credit_wallet
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  credit_wallet_label,
  credit_context
)
from Storage.Keys import platform_key, seal_local
from Storage.Blobs import put_blob
from Tests.Support import database_path, repeated

fn identity() -> CreditWalletIdentity!String do
  Ok(CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: repeated(42, 16)?,
    service_key: repeated(43, 32)?,
    purpose: 1
  })
end

fn wallet(length :: Int) -> CreditWallet!String do
  Ok(CreditWallet {
    revision: U64.parse("1")?,
    records: [
      CreditRecord {
        kind: 2,
        id: repeated(44, 32)?,
        metadata: Bytes.empty(),
        payload: repeated(45, length)?
      }
    ]
  })
end

fn chunk_label(who :: CreditWalletIdentity, generation :: Bytes, index :: Int) -> String do
  credit_wallet_label(who) <> "/#{Bytes.to_hex(generation)}/#{index}"
end

fn boundary_roundtrips() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let who = identity()?
  # Wallet framing is 61 bytes. Exercise exact 60000-byte boundaries, both
  # adjacent lengths, and odd chunk counts without depending on a join tree.
  for length in [0, 59938, 59939, 59940, 119938, 119939, 119940, 179940, 299940, 539940] do
    let path = database_path("credit_chunk_boundary")?
    let initial = load_credit_wallet(path, key, who)?
    let expected = wallet(length)?
    let wire = encode_credit_wallet(expected)?
    assert(Bytes.length(wire) == length + 61)
    commit_credit_wallet(path, key, who, initial, expected)?
    let reopened = load_credit_wallet(path, key, who)?
    assert(reopened.chunk_count == (length + 61 + 59999) / 60000)
    assert(Bytes.secure_equals(encode_credit_wallet(reopened.wallet)?, wire))
    assert(Bytes.secure_equals(load_credit_wallet(path, key, who)?.previous, reopened.previous))
    File.delete(path)?
  end
  Ok(true)
end

test("wallet chunks preserve exact boundaries and odd-count ordering") do
  case boundary_roundtrips() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn authenticated_chunk_failures() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let who = identity()?
  let path = database_path("credit_chunk_failures")?
  let initial = load_credit_wallet(path, key, who)?
  let expected = wallet(299940)?
  let wire = encode_credit_wallet(expected)?
  commit_credit_wallet(path, key, who, initial, expected)?
  let saved = load_credit_wallet(path, key, who)?
  assert(saved.chunk_count == 6)
  # Check the first, interior and short final chunk. Authenticated wrong-size
  # chunks fail before decoding, and restoring each exact chunk recovers root.
  for index in [0, 2, 5] do
    let label = chunk_label(who, saved.generation, index)
    let size = if index == 5 do
      1
    else
      60000
    end
    let original = Bytes.slice(wire, index * 60000, size)?
    let malformed = seal_local(Bytes.slice(original, 0, size - 1)?,
      key,
      credit_context(who, label)?)?
    let database = Sqlite.open(path)?
    put_blob(database, label, malformed)?
    Sqlite.close(database)
    assert(load_credit_wallet(path, key, who) == Err("invalid_credit_wallet_chunk"))
    let repaired = seal_local(original, key, credit_context(who, label)?)?
    let database = Sqlite.open(path)?
    put_blob(database, label, repaired)?
    Sqlite.close(database)
    assert(Bytes.secure_equals(load_credit_wallet(path, key, who)?.previous, saved.previous))
  end
  # A later malformed ciphertext must not hide an earlier authenticated length
  # failure; this fixes the observable left-to-right error order.
  let first = chunk_label(who, saved.generation, 0)
  let last = chunk_label(who, saved.generation, 5)
  let shorter = seal_local(Bytes.slice(wire, 0, 59999)?, key, credit_context(who, first)?)?
  let database = Sqlite.open(path)?
  put_blob(database, first, shorter)?
  put_blob(database, last, Bytes.from_hex("000102")?)?
  Sqlite.close(database)
  assert(load_credit_wallet(path, key, who) == Err("invalid_credit_wallet_chunk"))
  let repaired = seal_local(Bytes.slice(wire, 0, 60000)?, key, credit_context(who, first)?)?
  let database = Sqlite.open(path)?
  put_blob(database, first, repaired)?
  Sqlite.close(database)
  assert(load_credit_wallet(path, key, who) == Err("local_state_open_failed"))
  File.delete(path)?
  Ok(true)
end

test("wallet chunks authenticate lengths in order without replacing the root") do
  case authenticated_chunk_failures() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
