from Credits.IssuerKey import (
  IssuerKeyRevocation,
  credits_decode_issuer_key,
  credits_decode_issuer_keys,
  credits_decode_revocation,
  credits_encode_issuer_key,
  credits_encode_issuer_keys,
  credits_encode_revocation,
  credits_epoch_at,
  credits_issuer_key,
  credits_key_valid_at,
  credits_leaf_kind
)

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn refused<T>(value :: Result<T, String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

# Epoch 690 runs from 690 × 30 days; its key is accepted through the next
# epoch, as the current key and then the previous one.

fn epochs() -> Bool!String do
  let key = credits_issuer_key(1, "credits.morseapp.io", 690, repeated(7, 342))?
  let start = 690 * 2592000000
  Ok(key.not_before == start
    && key.not_after == start + 2 * 2592000000
    && credits_epoch_at(start) == 690
    && credits_epoch_at(start - 1) == 689
    && credits_key_valid_at(key, start)
    && credits_key_valid_at(key, start + 2 * 2592000000 - 1)
    && !credits_key_valid_at(key, start + 2 * 2592000000)
    && !credits_key_valid_at(key, start - 1))
end

test("an epoch key is accepted during its epoch and the next one") do
  assert(epochs() == Ok(true))
end

fn leaves() -> Bool!String do
  let key = credits_issuer_key(2, "credits.morseapp.io", 690, repeated(7, 342))?
  let encoded = credits_encode_issuer_key(key)?
  let revocation = IssuerKeyRevocation {
    purpose: 2,
    issuer_name: "credits.morseapp.io",
    epoch: 690,
    token_key_id: Crypto.sha256(repeated(7, 342)),
    revoked_at: 1788500000000
  }
  let revoked = credits_encode_revocation(revocation)?
  let shifted = %{key | not_after: key.not_after + 1}
  Ok(credits_decode_issuer_key(encoded)? == key
    && Bytes.length(encoded) == 4 + 1 + 4 + 19 + 4 + 8 + 8 + 342
    && credits_decode_revocation(revoked)? == revocation
    && credits_leaf_kind(encoded) == 2
    && credits_leaf_kind(revoked) == 3
    && credits_leaf_kind(Bytes.from_hex("01445653")?) == 1
    && credits_leaf_kind(Bytes.from_utf8("xx")) == 0
    && refused(credits_encode_issuer_key(shifted))
    && refused(credits_issuer_key(3, "credits.morseapp.io", 690, repeated(7, 342)))
    && refused(credits_issuer_key(1, "credits.morseapp.io", 690, repeated(7, 341)))
    && refused(credits_decode_issuer_key(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
end

test("issuer-key and revocation leaves have one canonical encoding each") do
  case leaves() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn listing() -> Bool!String do
  let evidence = [Bytes.from_utf8("first"), Bytes.from_utf8("second")]
  let decoded = credits_decode_issuer_keys(credits_encode_issuer_keys(evidence)?)?
  Ok(List.length(decoded) == 2
    && Bytes.secure_equals(List.get(decoded, 1), Bytes.from_utf8("second"))
    && credits_decode_issuer_keys(credits_encode_issuer_keys([])?)? == [])
end

test("the issuer-key listing carries one evidence frame per key") do
  assert(listing() == Ok(true))
end
