from Credits.Attachment import (
  CreditAttachmentGrant,
  encode_credit_attachment_grant,
  decode_credit_attachment_grant,
  credit_attachment_action,
  credit_attachment_result,
  encode_credit_attachment_result,
  decode_credit_attachment_result
)
from Credits.Policy import attachment_credits

fn bytes(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture_bytes_failed")
    Ok(value)
  end
end

fn changed(input :: Bytes, offset :: Int, value :: Int) -> Bytes!String do
  let byte = case Bytes.from_list([value]) do
    Err(_) -> return Err("fixture_byte_failed")
    Ok(value) -> value
  end
  Bytes.concat(Bytes.concat(Bytes.slice(input, 0, offset)?, byte)?,
    Bytes.slice(input, offset + 1, Bytes.length(input) - offset - 1)?)
end

fn fixture(size :: Int) -> CreditAttachmentGrant!String do
  Ok(CreditAttachmentGrant {
    layout_version: 1,
    operation_nonce: bytes(1, 32)?,
    object_id: bytes(2, 32)?,
    upload_capability: bytes(3, 32)?,
    download_capability: bytes(4, 32)?,
    size_bytes: size,
    manifest_size: 514,
    manifest_sha256: bytes(5, 32)?,
    expires_at_ms: U64.parse("4102444800000")?,
    action_expires_at: U64.parse("4102444800")?
  })
end

fn proof() -> Bool!String do
  for capacity in [16842752, 33554432, 536870912] do
    let old = encode_credit_attachment_grant(fixture(capacity)?)?
    assert(Bytes.length(old) == 186 && Bytes.get(old, 0) == Ok(1))
    let wire = changed(old, 0, 2)?
    let grant = decode_credit_attachment_grant(wire)?
    assert(Bytes.secure_equals(encode_credit_attachment_grant(grant)?, wire))
    assert(credit_attachment_action(grant)?.quantity == U64.parse(Int.to_string(capacity))?)
    let result = encode_credit_attachment_result(credit_attachment_result(grant)?)?
    assert(Bytes.length(result) == 84 && Bytes.get(result, 0) == Ok(2))
    assert(Bytes.secure_equals(encode_credit_attachment_result(decode_credit_attachment_result(result)?)?,
      result))
    # The public capacity must be aligned and the manifest envelope fixed.
    assert(Result.is_err(decode_credit_attachment_grant(changed(wire, 135, 1)?)))
    assert(Result.is_err(decode_credit_attachment_grant(changed(wire, 137, 1)?)))
    assert(Result.is_err(decode_credit_attachment_grant(changed(wire, 0, 4)?)))
  end
  Ok(true)
end

test("LAG2 and LAR2 bind rounded capacity with exact versioned replay and refuse mixed or malformed profiles") do
  case proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

test("every64KiB interval preserves the current16MiB credit tier including maximum512MiB") do
  for count in 1..8193 do
    let capacity = count * 65536
    for size in [capacity - 65535, capacity] do
      assert(attachment_credits(size) == attachment_credits(capacity))
    end
  end
end
