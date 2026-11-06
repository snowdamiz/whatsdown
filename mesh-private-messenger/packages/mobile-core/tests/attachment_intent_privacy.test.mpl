from Storage.Blobs import blob_record_hash
import File
from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  encode_credit_wallet,
  decode_credit_wallet,
  pack_credit_parts,
  credit_attachment_cursor
)
from Mobile.CreditAttachmentJournal import (
  attachment_binding,
  attachment_journal_parts,
  open_attachment_binding,
  seal_attachment_binding,
  attachment_intent_matches
)
from Mobile.CreditAttachmentNative import parse_credit_attachment_prepare_request
from Mobile.Requests import parse_attachment_prepare_request
from Mobile.Codec import mobile_write_u32, mobile_join, mobile_vector
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  seal_credit_payload,
  credit_context,
  credit_attachment_intent_context,
  credit_wallet_label,
  test_competing_attachment_loaders
)
from Storage.Keys import platform_key
from Tests.Support import repeated, database_path

fn exact_fixture(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic attachment privacy fixture assertion only; no application disclosure")
end

fn generic_refusal() -> Bool!String do
  let record = CreditRecord {
    kind: 6,
    id: repeated(71, 32)?,
    metadata: repeated(17, 36)?,
    payload: Bytes.from_utf8("legacy-synthetic-ciphertext")
  }
  let encoded = encode_credit_wallet(CreditWallet { revision: U64.parse("1")?, records: [record] })?
  assert(decode_credit_wallet(encoded) == Err("legacy_credit_attachment_requires_private_load"))
  Ok(true)
end

test("generic wallet decoder cannot expose a legacy attachment binding") do
  assert(generic_refusal() == Ok(true))
end

fn identity() -> CreditWalletIdentity!String do
  Ok(CreditWalletIdentity {
    account_id: repeated(21, 32)?,
    device_id: repeated(22, 16)?,
    service_key: repeated(23, 32)?,
    purpose: 1
  })
end

fn legacy(wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Int,
  with_action :: Bool) -> CreditRecord!String do
  let nonce = repeated(id, 32)?
  let metadata = Bytes.concat(repeated(17, 32)?, mobile_write_u32(128)?)?
  Ok(CreditRecord {
    kind: 6,
    id: nonce,
    metadata: if with_action do
      Bytes.concat(metadata, repeated(45, 32)?)?
    else
      metadata
    end,
    payload: seal_credit_payload(pack_credit_parts([
        Bytes.from_utf8("fixture grant"),
        Bytes.from_utf8("fixture encrypted reference")
      ])?,
      wrapping,
      who,
      "attachment/#{Bytes.to_hex(nonce)}")?
  })
end

fn raw_root(path :: String, who :: CreditWalletIdentity) -> Bytes!String do
  let database = Sqlite.open(path)?
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(blob_record_hash(database, credit_wallet_label(who))?)])?
  Sqlite.close(database)
  case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> Ok(value)
    Text(_) -> Err("fixture root is not binary")
    Null -> Err("fixture root missing")
  end
end

fn migration(with_action :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let path = database_path(if with_action do
    "attachment_private_68"
  else
    "attachment_private_36"
  end)?
  let initial = load_credit_wallet(path, wrapping, who)?
  let old = legacy(wrapping, who, 71, with_action)?
  commit_credit_wallet(path,
    wrapping,
    who,
    initial,
    CreditWallet { revision: U64.parse("1")?, records: [old] })?
  let original_root = raw_root(path, who)?
  assert(Result.is_err(load_credit_wallet(path, wrapping, %{who | account_id: repeated(99, 32)?})))
  assert(Bytes.secure_equals(raw_root(path, who)?, original_root))
  # A failed migration commit keeps the old generation and can be retried after restart.
  let database = Sqlite.open(path)?
  Sqlite.execute(database,
    "CREATE TRIGGER fail_private_migration BEFORE INSERT ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'fixture migration failure'); END",
    [])?
  Sqlite.close(database)
  assert(Result.is_err(load_credit_wallet(path, wrapping, who)))
  assert(Bytes.secure_equals(raw_root(path, who)?, original_root))
  let database = Sqlite.open(path)?
  Sqlite.execute(database, "DROP TRIGGER fail_private_migration", [])?
  Sqlite.close(database)
  let snapshot = load_credit_wallet(path, wrapping, who)?
  assert(snapshot.wallet.revision == U64.parse("2")?)
  let normalized = List.head(snapshot.wallet.records)
  assert(credit_attachment_cursor(normalized.metadata)? == 128)
  assert(Bytes.length(normalized.metadata) == if with_action do
      40
    else
      8
    end)
  if with_action do
    assert(Bytes.secure_equals(Bytes.slice(normalized.metadata, 8, 32)?, repeated(45, 32)?))
  else
    nil
  end
  let parts = attachment_journal_parts(normalized.payload)?
  assert(Bytes.secure_equals(List.get(parts, 1), old.payload))
  assert(!Bytes.secure_equals(snapshot.previous, original_root))
  let aad = credit_attachment_intent_context(who, old.id)?
  let binding = case declassify_discriminant(open_attachment_binding(normalized.payload,
      wrapping,
      aad),
    "synthetic private binding fixture authentication tag only") do
    Err(_) -> return Err("fixture binding failed")
    Ok(value) -> value
  end
  assert(attachment_intent_matches(binding.digest, repeated(17, 32)?))
  assert(exact_fixture(Result.is_err(open_attachment_binding(normalized.payload,
    wrapping,
    credit_attachment_intent_context(%{who | purpose: 0}, old.id)?))))
  assert(exact_fixture(Result.is_err(open_attachment_binding(normalized.payload,
    wrapping,
    credit_attachment_intent_context(who, repeated(72, 32)?)?))))
  let foreign_wallets = [
    %{who | account_id: repeated(99, 32)?},
    %{who | device_id: repeated(99, 16)?},
    %{who | service_key: repeated(99, 32)?}
  ]
  for foreign in foreign_wallets do
    assert(exact_fixture(Result.is_err(open_attachment_binding(normalized.payload,
      wrapping,
      credit_attachment_intent_context(foreign, old.id)?))))
  end
  let restarted = load_credit_wallet(path, wrapping, who)?
  assert(restarted.wallet.revision == snapshot.wallet.revision)
  assert(Bytes.secure_equals(restarted.previous, snapshot.previous))
  # Returned normalized snapshots have valid new-root authority for the next CAS.
  commit_credit_wallet(path,
    wrapping,
    who,
    snapshot,
    %{snapshot.wallet | revision: U64.parse("3")?})?
  assert(Result.is_err(commit_credit_wallet(path,
    wrapping,
    who,
    restarted,
    %{restarted.wallet | revision: U64.parse("3")?})))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("3")?)
  File.delete(path)?
  Ok(true)
end

test("legacy36 migrates atomically before exposure and preserves ciphertext and cursor across restart") do
  case migration(false) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("legacy68 preserves action identity and refuses foreign wallet and nonce AAD") do
  case migration(true) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn corrupted_old_record() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let path = database_path("attachment_private_corrupt")?
  let initial = load_credit_wallet(path, wrapping, who)?
  let first = legacy(wrapping, who, 71, false)?
  let second = legacy(wrapping, who, 72, true)?
  let corrupt = %{second | payload: Bytes.from_utf8("corrupted sealed old record")}
  commit_credit_wallet(path,
    wrapping,
    who,
    initial,
    CreditWallet { revision: U64.parse("1")?, records: [first, corrupt] })?
  let original = raw_root(path, who)?
  assert(Result.is_err(load_credit_wallet(path, wrapping, who)))
  assert(Bytes.secure_equals(raw_root(path, who)?, original))
  File.delete(path)?
  Ok(true)
end

test("a corrupt later legacy record refuses the complete migration without changing the original root") do
  case corrupted_old_record() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn request() -> Bytes!String do
  pack_credit_parts([
    Bytes.from_utf8("fixture.sqlite"),
    repeated(71, 32)?,
    Bytes.from_utf8("private.bin"),
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(17)?,
    Bytes.from_utf8("opaque recipient ticket")
  ])
end

fn ingress() -> Bool!String do
  let parsed = case declassify_discriminant(parse_credit_attachment_prepare_request(request()?),
    "synthetic private paid request fixture result tag only") do
    Err(_) -> return Err("fixture parser failed")
    Ok(value) -> value
  end
  assert(exact_fixture(Bytes.secure_equals(parsed.filename, Bytes.from_utf8("private.bin"))))
  assert(exact_fixture(Bytes.secure_equals(parsed.mime_type,
    Bytes.from_utf8("application/octet-stream"))))
  assert(parsed.plaintext_size == 17)
  let free = mobile_join([
      mobile_vector(Bytes.from_utf8("fixture.sqlite"))?,
      mobile_vector(Bytes.from_utf8("private.bin"))?,
      mobile_vector(Bytes.from_utf8("application/octet-stream"))?,
      mobile_vector(mobile_write_u32(17)?)?,
      mobile_vector(mobile_write_u32(1)?)?
    ],
    0,
    Bytes.empty())?
  let parsed_free = case declassify_discriminant(parse_attachment_prepare_request(free),
    "synthetic private free request fixture result tag only") do
    Err(_) -> return Err("fixture free parser failed")
    Ok(value) -> value
  end
  assert(exact_fixture(Bytes.secure_equals(parsed_free.filename, Bytes.from_utf8("private.bin"))))
  assert(exact_fixture(Bytes.secure_equals(parsed_free.mime_type,
    Bytes.from_utf8("application/octet-stream"))))
  let invalid_utf8 = mobile_join([
      mobile_vector(Bytes.from_utf8("fixture.sqlite"))?,
      mobile_vector(Bytes.from_hex("ff")?)?,
      mobile_vector(Bytes.from_utf8("application/octet-stream"))?,
      mobile_vector(mobile_write_u32(17)?)?,
      mobile_vector(mobile_write_u32(1)?)?
    ],
    0,
    Bytes.empty())?
  assert(exact_fixture(parse_attachment_prepare_request(invalid_utf8) == Err("invalid_attachment_request")))
  # The paid binary API historically admitted non-UTF8 metadata; preserve that.
  let paid_binary = pack_credit_parts([
    Bytes.from_utf8("fixture.sqlite"),
    repeated(71, 32)?,
    Bytes.from_hex("ff")?,
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(17)?,
    Bytes.empty()
  ])?
  assert(exact_fixture(Result.is_ok(parse_credit_attachment_prepare_request(paid_binary))))
  let invalid = pack_credit_parts([
    Bytes.from_utf8("fixture.sqlite"),
    repeated(71, 32)?,
    repeated(65, 256)?,
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(17)?,
    Bytes.empty()
  ])?
  assert(exact_fixture(parse_credit_attachment_prepare_request(invalid) == Err("invalid_credit_attachment_request")))
  Ok(true)
end

test("paid native preparation classifies the actual filename MIME fields and preserves precise admission error") do
  case ingress() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn competing() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let path = database_path("attachment_private_competing")?
  let initial = load_credit_wallet(path, wrapping, who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    initial,
    CreditWallet { revision: U64.parse("1")?, records: [legacy(wrapping, who, 71, true)?] })?
  assert(test_competing_attachment_loaders(path, wrapping, who)?)
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("3")?)
  File.delete(path)?
  Ok(true)
end

test("competing migration loaders cannot expose or commit an uncommitted normalized snapshot") do
  case competing() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn binding_compatibility() -> Bool!String do
  let names = [Bytes.empty(), Bytes.from_utf8("private.bin"), repeated(65, 255)?]
  let mimes = [
    Bytes.from_utf8("x"),
    Bytes.from_utf8("application/octet-stream"),
    repeated(66, 127)?
  ]
  for index in 0..3 do
    let name = List.get(names, index)
    let mime = List.get(mimes, index)
    let binding = attachment_binding(name, mime, 16777217)?
    let old = Crypto.sha256(pack_credit_parts([name, mime, mobile_write_u32(16777217)?])?)
    assert(exact_fixture(Bytes.secure_equals(binding.digest, old)))
  end
  Ok(true)
end

test("private primitive framing preserves the exact legacy attachment binding including metadata length edges") do
  case binding_compatibility() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
