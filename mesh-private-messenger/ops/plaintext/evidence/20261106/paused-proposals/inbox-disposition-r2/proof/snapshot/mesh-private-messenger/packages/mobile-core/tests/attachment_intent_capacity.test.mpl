import File
from Mobile.CreditState import CreditRecord, CreditWallet, pack_credit_parts, encode_credit_wallet, decode_credit_wallet, find_credit_record, put_credit_record, test_credit_wallet_logical_size
from Mobile.Codec import mobile_write_u32, mobile_write_u16, mobile_write_u64, mobile_join
from Mobile.CreditAttachmentJournal import attachment_journal_payload, attachment_journal_parts, seal_attachment_binding, open_attachment_binding
from Storage.Credits import CreditWalletIdentity, credit_attachment_intent_context, load_credit_wallet, commit_credit_wallet, seal_credit_payload, test_credit_wallet_manifest_bound
from Storage.Keys import platform_key
from Tests.Support import repeated, database_path

fn identity() -> CreditWalletIdentity!String do
  Ok(CreditWalletIdentity { account_id: repeated(21, 32)?, device_id: repeated(22, 16)?, service_key: repeated(23, 32)?, purpose: 1 })
end

fn nonce(index :: Int) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("full attachment fixture/#{index}"))
end

fn maximum_legacy() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let path = database_path("attachment_private_full_capacity")?
  let initial = load_credit_wallet(path, wrapping, who)?
  let id = nonce(0)
  let attachment = CreditRecord { kind: 6, id: id,
    metadata: Bytes.concat(repeated(17, 32)?, mobile_write_u32(128)?)?,
    payload: seal_credit_payload(pack_credit_parts([Bytes.from_utf8("fixture grant"), Bytes.from_utf8("fixture encrypted reference")])?, wrapping, who, "attachment/#{Bytes.to_hex(id)}")?
  }
  let empty = for index in 0..4 do
    CreditRecord { kind: 2, id: nonce(index +1), metadata: Bytes.empty(), payload: Bytes.empty() }
  end
  let framing = Bytes.length(encode_credit_wallet(CreditWallet { revision: U64.parse("1")?, records: [attachment] ++ empty })?)
  let padding = 15360000 - framing
  let fillers = for index in 0..4 do
    let size = if index < 3 do 4000000 else padding -12000000 end
    %{List.get(empty, index) | payload: repeated(65, size)?}
  end
  let records = [attachment] ++ fillers
  let legacy = CreditWallet { revision: U64.parse("1")?, records: records }
  assert(Bytes.length(encode_credit_wallet(legacy)?) == 15360000)
  commit_credit_wallet(path, wrapping, who, initial, legacy)?
  let migrated = load_credit_wallet(path, wrapping, who)?
  assert(migrated.wallet.revision == U64.parse("2")?)
  assert(List.length(migrated.wallet.records) == 5)
  assert(Bytes.length(encode_credit_wallet(migrated.wallet)?) == 15360091)
  assert(migrated.chunk_count == 257)
  let original = case find_credit_record(legacy, 6, nonce(0)) do None -> return Err("fixture original missing") Some(value) -> value end
  let normalized = case find_credit_record(migrated.wallet, 6, nonce(0)) do None -> return Err("fixture normalized missing") Some(value) -> value end
  assert(Bytes.secure_equals(List.get(attachment_journal_parts(normalized.payload)?, 1), original.payload))
  let filler = case find_credit_record(migrated.wallet, 2, nonce(1)) do None -> return Err("fixture filler missing") Some(value) -> value end
  let expanded = %{filler | payload: Bytes.concat(filler.payload, Bytes.from_hex("00")?)?}
  assert(encode_credit_wallet(put_credit_record(migrated.wallet, expanded)) == Err("credit_wallet_capacity"))
  let mixed = %{normalized | metadata: repeated(17, 36)?}
  assert(encode_credit_wallet(put_credit_record(migrated.wallet, mixed)) == Err("credit_wallet_capacity"))
  let restarted = load_credit_wallet(path, wrapping, who)?
  assert(restarted.wallet.revision == migrated.wallet.revision)
  assert(Bytes.secure_equals(restarted.previous, migrated.previous))
  let next = %{migrated.wallet | revision: U64.parse("3")?}
  commit_credit_wallet(path, wrapping, who, migrated, next)?
  assert(commit_credit_wallet(path, wrapping, who, restarted, next) == Err("credit_wallet_changed"))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("3")?)
  File.delete(path)?
  Ok(true)
end

test("a full legacy wallet migrates beyond256 chunks without expanding logical capacity then restarts and enforces CAS") do
  case maximum_legacy() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn wrapper_refusals() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let id = nonce(0)
  let aad = credit_attachment_intent_context(who, id)?
  let binding = seal_attachment_binding(repeated(17, 32)?, wrapping, aad)?
  assert(Bytes.length(binding) == 99)
  let metadata = Bytes.concat(Bytes.from_hex("0241494a")?, mobile_write_u32(0)?)?
  let material = seal_credit_payload(pack_credit_parts([Bytes.from_utf8("fixture grant"), Bytes.from_utf8("fixture reference")])?, wrapping, who, "attachment/#{Bytes.to_hex(id)}")?
  let good = CreditRecord { kind: 6, id: id, metadata: metadata, payload: attachment_journal_payload(material, binding)? }
  let wallet = CreditWallet { revision: U64.parse("1")?, records: [good] }
  assert(Result.is_ok(decode_credit_wallet(encode_credit_wallet(wallet)?)))
  let wrong_length = Bytes.concat(Bytes.concat(Bytes.slice(binding, 0, 47)?, mobile_write_u32(31)?)?, Bytes.slice(binding, 51, 48)?)?
  let wrong_version = Bytes.concat(Bytes.from_hex("02")?, Bytes.slice(binding, 1, 98)?)?
  let malformed = [
    pack_credit_parts([Bytes.from_hex("02414950")?, material, Bytes.slice(binding, 0, 98)?])?,
    pack_credit_parts([Bytes.from_hex("02414950")?, material, Bytes.concat(binding, Bytes.from_hex("00")?)?])?,
    pack_credit_parts([Bytes.from_hex("02414950")?, material, wrong_length])?,
    pack_credit_parts([Bytes.from_hex("02414950")?, material, wrong_version])?,
    pack_credit_parts([Bytes.from_hex("01414950")?, material, binding])?,
    pack_credit_parts([Bytes.from_hex("02414950")?, material, binding, Bytes.empty()])?,
    material
  ]
  for payload in malformed do
    let invalid = %{good | payload: payload}
    assert(Result.is_err(encode_credit_wallet(%{wallet | records: [invalid]})))
  end
  # Structural envelope admission is deliberately distinct from AEAD authentication.
  let flipped = Bytes.concat(Bytes.slice(binding, 0, 98)?, repeated((Bytes.get(binding, 98)? +1) %256, 1)?)?
  let forged = %{good | payload: attachment_journal_payload(material, flipped)?}
  assert(Result.is_ok(decode_credit_wallet(encode_credit_wallet(%{wallet | records: [forged]})?)))
  assert(Result.is_err(open_attachment_binding(forged.payload, wrapping, aad)))
  Ok(true)
end

test("only canonical attachment wrappers receive headroom and structural checks do not claim AEAD authentication") do
  case wrapper_refusals() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn manifest(size :: Int, count :: Int) -> Bytes!String do
  mobile_join([Bytes.from_hex("0143574d")?, mobile_write_u64(U64.parse("1")?)?, repeated(19, 32)?, mobile_write_u32(size)?, mobile_write_u16(count)?, repeated(20, 32)?], 0, Bytes.empty())
end

fn maximum_structural() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let who = identity()?
  let aad = credit_attachment_intent_context(who, nonce(0))?
  let binding = seal_attachment_binding(repeated(17, 32)?, wrapping, aad)?
  let material = seal_credit_payload(pack_credit_parts([Bytes.from_utf8("fixture grant"), Bytes.from_utf8("fixture reference")])?, wrapping, who, "attachment/#{Bytes.to_hex(nonce(0))}")?
  let record = CreditRecord { kind: 6, id: nonce(0), metadata: Bytes.concat(Bytes.from_hex("0241494a")?, mobile_write_u32(0)?)?, payload: attachment_journal_payload(material, binding)? }
  # Structural accounting only, without serializing an8192-record full wallet.
  # The real authenticated15,360,000-byte migration is the separate test above.
  let records = for index in 0..8192 do %{record | id: nonce(index)} end
  assert(test_credit_wallet_logical_size(records, 16105472) == Ok(15360000))
  assert(test_credit_wallet_logical_size(records, 16105473) == Err("credit_wallet_capacity"))
  assert(test_credit_wallet_logical_size(records ++ [%{record | id: nonce(8192)}], 16105472) == Err("credit_wallet_capacity"))
  let malformed = %{record | payload: material}
  assert(Result.is_err(test_credit_wallet_logical_size([malformed] ++ List.tail(records), 16105472)))
  let mixed = %{record | metadata: repeated(17, 36)?}
  assert(test_credit_wallet_logical_size([mixed] ++ List.tail(records), 16105472) == Err("credit_wallet_capacity"))
  assert(test_credit_wallet_manifest_bound(manifest(15360000, 256)?) == Ok(256))
  assert(test_credit_wallet_manifest_bound(manifest(16105472, 269)?) == Ok(269))
  assert(Result.is_err(test_credit_wallet_manifest_bound(manifest(15360000, 257)?)))
  assert(Result.is_err(test_credit_wallet_manifest_bound(manifest(16105472, 270)?)))
  assert(Result.is_err(test_credit_wallet_manifest_bound(manifest(16105473, 269)?)))
  Ok(true)
end

test("8192-record structural accounting and canonical269-chunk manifest limits are exact without claiming full max-record migration") do
  case maximum_structural() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
