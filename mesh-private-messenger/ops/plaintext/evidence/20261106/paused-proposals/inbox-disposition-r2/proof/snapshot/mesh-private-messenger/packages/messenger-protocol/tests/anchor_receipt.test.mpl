from Transparency.AnchorReceipt import (
  AnchorReceipt,
  encode_anchor_receipt,
  decode_anchor_receipt,
  anchor_receipt_json
)

fn rejected(value :: AnchorReceipt) -> Bool do
  case encode_anchor_receipt(value) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn proof() -> Bool!String do
  let hash = Crypto.sha256(Bytes.from_utf8("checkpoint"))
  let signature = Bytes.concat(hash, hash)?
  let value = AnchorReceipt {
    log_version: 2,
    sequence: U64.parse("9007199254740993")?,
    tree_size: U64.parse("4294967295")?,
    checkpoint_hash: hash,
    ring_index: 4095,
    transaction_signature: signature,
    slot: U64.parse("18446744073709551615")?
  }
  let bytes = encode_anchor_receipt(value)?
  assert(Bytes.length(bytes) == 128)
  assert(Bytes.to_hex(Bytes.slice(bytes, 0, 6)?) == "014b54410002")
  # Independent field positions and widths, not only an encoder/decoder roundtrip.
  assert(Bytes.to_hex(bytes) == "014b54410002002000000000000100000000ffffffff"
      <> Bytes.to_hex(hash)
      <> "0fff"
      <> Bytes.to_hex(signature)
      <> "ffffffffffffffff")
  let decoded = decode_anchor_receipt(bytes)?
  assert(Bytes.secure_equals(encode_anchor_receipt(decoded)?, bytes))
  let document = anchor_receipt_json(decoded)?
  assert(String.contains(document, "\"checkpoint_sequence\":\"9007199254740993\""))
  assert(String.contains(document, "\"slot\":\"18446744073709551615\""))
  assert(String.contains(document, "\"tx_signature\":\"" <> Bytes.to_base58(signature) <> "\""))
  assert(!rejected(%{value | log_version: 1, ring_index: 0, slot: U64.parse("0")?}))
  for invalid in [
    %{value | log_version: 0},
    %{value | log_version: 3},
    %{value | sequence: U64.parse("0")?},
    %{value | tree_size: U64.parse("0")?},
    %{value | tree_size: U64.parse("4294967296")?},
    %{value | ring_index: -1},
    %{value | ring_index: 4096},
    %{value | checkpoint_hash: Bytes.empty()},
    %{value | transaction_signature: hash}
  ] do
    assert(rejected(invalid))
  end
  for malformed in [
    Bytes.empty(),
    Bytes.slice(bytes, 0, 127)?,
    Bytes.concat(bytes, Bytes.from_hex("00")?)?,
    Bytes.concat(Bytes.from_hex("024b5441")?, Bytes.slice(bytes, 4, 124)?)?
  ] do
    assert(case decode_anchor_receipt(malformed) do
      Err(_) -> true
      Ok(_) -> false
    end)
  end
  Ok(true)
end

test("anchor receipts bind the log and preserve full-width public coordinates without granting chain trust") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
