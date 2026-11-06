from Storage.Blobs import blob_record_hash
import File
from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  empty_credit_wallet,
  encode_credit_wallet,
  decode_credit_wallet
)
from Storage.Credits import (
  CreditWalletIdentity,
  CreditWalletSnapshot,
  CreditCacheWrite,
  load_credit_wallet,
  commit_credit_wallet,
  commit_credit_wallet_with_cache,
  seal_credit_payload,
  open_credit_payload
)
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn identity() -> CreditWalletIdentity!String do
  Ok(CreditWalletIdentity {
    account_id: repeated(11, 32)?,
    device_id: repeated(12, 16)?,
    service_key: repeated(13, 32)?,
    purpose: 1
  })
end

fn record(id :: Int, length :: Int) -> CreditRecord!String do
  Ok(CreditRecord {
    kind: 2,
    id: repeated(id, 32)?,
    metadata: Bytes.from_utf8("sealed-test-metadata"),
    payload: repeated(17, length)?
  })
end

fn storage() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let who = identity()?
  let path = database_path("credits_wallet")?
  let first = load_credit_wallet(path, key, who)?
  assert(List.length(first.wallet.records) == 0)
  let one = CreditWallet {
    revision: U64.parse("1")?,
    records: [record(21, 70000)?, record(22, 100)?]
  }
  commit_credit_wallet(path, key, who, first, one)?
  let reopened = load_credit_wallet(path, key, who)?
  assert(Bytes.secure_equals(encode_credit_wallet(reopened.wallet)?, encode_credit_wallet(one)?))
  assert(reopened.chunk_count > 1)
  let forged = CreditWalletSnapshot {
    wallet: CreditWallet { revision: reopened.wallet.revision, records: [] },
    previous: reopened.previous,
    generation: reopened.generation,
    chunk_count: reopened.chunk_count
  }
  let candidate = CreditWallet { revision: U64.parse("2")?, records: [record(23, 101)?] }
  assert(Result.is_err(commit_credit_wallet(path, key, who, forged, candidate)))
  let forged_chunks = CreditWalletSnapshot {
    wallet: reopened.wallet,
    previous: reopened.previous,
    generation: repeated(98, 32)?,
    chunk_count: 0
  }
  assert(Result.is_err(commit_credit_wallet(path, key, who, forged_chunks, candidate)))
  assert(Bytes.secure_equals(encode_credit_wallet(load_credit_wallet(path, key, who)?.wallet)?,
    encode_credit_wallet(one)?))
  let other = CreditWalletIdentity {
    account_id: repeated(99, 32)?,
    device_id: who.device_id,
    service_key: who.service_key,
    purpose: who.purpose
  }
  assert(Result.is_err(load_credit_wallet(path, key, other)))
  let two = CreditWallet { revision: U64.parse("2")?, records: [record(23, 101)?] }
  commit_credit_wallet(path, key, who, reopened, two)?
  assert(Result.is_err(commit_credit_wallet(path, key, who, reopened, two)))
  let winner = load_credit_wallet(path, key, who)?
  assert(Bytes.secure_equals(encode_credit_wallet(winner.wallet)?, encode_credit_wallet(two)?))
  # Admission must share the global checkpoint cursor's CAS, not only the wallet's.
  let guarded = CreditCacheWrite {
    label: "transparency-checkpoint/v1",
    previous: Bytes.empty(),
    value: repeated(81, 20)?
  }
  let database = Sqlite.open(path)?
  Sqlite.execute_values(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(blob_record_hash(database, guarded.label)?), Binary(repeated(82, 20)?)])?
  Sqlite.close(database)
  let three = CreditWallet { revision: U64.parse("3")?, records: [record(24, 80000)?] }
  assert(Result.is_err(commit_credit_wallet_with_cache(path, key, who, winner, three, [guarded])))
  assert(load_credit_wallet(path, key, who)?.wallet.revision == two.revision)
  # A failed chunk insert must roll back the manifest update and every new chunk.
  let database = Sqlite.open(path)?
  Sqlite.execute(database,
    "CREATE TRIGGER credit_fail BEFORE INSERT ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'credit injected failure'); END",
    [])?
  Sqlite.close(database)
  let three = CreditWallet { revision: U64.parse("3")?, records: [record(24, 80000)?] }
  assert(Result.is_err(commit_credit_wallet(path, key, who, winner, three)))
  let rolled_back = load_credit_wallet(path, key, who)?
  assert(Bytes.secure_equals(encode_credit_wallet(rolled_back.wallet)?, encode_credit_wallet(two)?))
  let database = Sqlite.open(path)?
  Sqlite.execute(database, "DROP TRIGGER credit_fail", [])?
  # Tampering with any persisted snapshot must fail closed, never look empty.
  Sqlite.execute_values(database,
    "UPDATE encrypted_blobs SET ciphertext = ?",
    [Binary(Bytes.from_hex("000102")?)])?
  Sqlite.close(database)
  assert(Result.is_err(load_credit_wallet(path, key, who)))
  File.delete(path)?
  Ok(true)
end

test("credit wallet snapshots recover chunks and reject stale, torn and foreign writes") do
  case storage() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn codec() -> Bool!String do
  let value = record(31, 8)?
  let wallet = CreditWallet { revision: U64.parse("1")?, records: [value] }
  let encoded = encode_credit_wallet(wallet)?
  assert(Result.is_ok(decode_credit_wallet(encoded)))
  assert(Result.is_err(decode_credit_wallet(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  assert(Result.is_err(encode_credit_wallet(CreditWallet {
    revision: wallet.revision,
    records: [value, value]
  })))
  assert(Result.is_err(encode_credit_wallet(CreditWallet {
    revision: wallet.revision,
    records: [
      CreditRecord { kind: 9, id: value.id, metadata: value.metadata, payload: value.payload }
    ]
  })))
  Ok(true)
end

test("credit wallet codec rejects duplicates, trailing input and unsupported record types") do
  case codec() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn payload() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let who = identity()?
  let bytes = repeated(71, 130000)?
  let encrypted = seal_credit_payload(bytes, key, who, "test-purchase/first")?
  assert(Bytes.secure_equals(open_credit_payload(encrypted, key, who, "test-purchase/first")?,
    bytes))
  assert(Result.is_err(open_credit_payload(encrypted, key, who, "test-purchase/other")))
  assert(Result.is_err(open_credit_payload(Bytes.slice(encrypted, 0, Bytes.length(encrypted) - 1)?,
    key,
    who,
    "test-purchase/first")))
  Ok(true)
end

test("large credit payloads bind every chunk and the complete sequence to one local record") do
  case payload() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
