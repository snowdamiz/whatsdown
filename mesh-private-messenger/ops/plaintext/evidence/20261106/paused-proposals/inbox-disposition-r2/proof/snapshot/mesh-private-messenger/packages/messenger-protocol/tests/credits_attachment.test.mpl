from Attachments.Layout import (
  large_attachment_chunks,
  large_attachment_part_bytes,
  large_attachment_total_bytes
)
from Credits.Attachment import (
  CreditAttachmentGrant,
  encode_credit_attachment_grant,
  decode_credit_attachment_grant,
  credit_attachment_action,
  credit_attachment_result,
  encode_credit_attachment_result,
  decode_credit_attachment_result,
  validate_credit_attachment_grant,
  credit_attachment_effect_id,
  verify_credit_attachment_receipt
)
from Credits.Action import credit_action_price
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Wire import CreditFrame, CreditToken, CreditTokenInput

fn bytes(value :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, 32))
end

fn proof() -> Bool!String do
  let grant = CreditAttachmentGrant {
    layout_version: 1,
    operation_nonce: bytes("11")?,
    object_id: bytes("22")?,
    upload_capability: bytes("33")?,
    download_capability: bytes("44")?,
    size_bytes: 16777217,
    manifest_size: 150,
    manifest_sha256: bytes("55")?,
    expires_at_ms: U64.parse("2000000")?,
    action_expires_at: U64.parse("1600")?
  }
  let encoded = encode_credit_attachment_grant(grant)?
  assert(Bytes.length(encoded) == 186)
  assert(Bytes.secure_equals(encode_credit_attachment_grant(decode_credit_attachment_grant(encoded)?)?,
    encoded))
  assert(large_attachment_chunks(16777217)? == 257)
  assert(large_attachment_part_bytes(16777217, 257)? == 41)
  assert(large_attachment_part_bytes(16777217, 256)? == 65576)
  assert(large_attachment_total_bytes(536870912, 514)? == 537199106)
  assert(large_attachment_chunks(536870912)? == 8192)
  let action = credit_attachment_action(grant)?
  assert(credit_action_price(action, 0, 16, 16)? == 1)
  assert(credit_action_price(credit_attachment_action(%{grant | size_bytes: 536870912})?,
    0,
    16,
    16)? == 31)
  for size in [0, 16777216, 536870913] do
    assert(Result.is_err(encode_credit_attachment_grant(%{grant | size_bytes: size})))
  end
  assert(Result.is_err(encode_credit_attachment_grant(%{grant | manifest_size: 515})))
  assert(Result.is_err(encode_credit_attachment_grant(%{grant |
    upload_capability: grant.download_capability
  })))
  assert(Result.is_err(decode_credit_attachment_grant(Bytes.concat(encoded,
    Bytes.from_hex("00")?)?)))
  assert(Result.is_err(validate_credit_attachment_grant(grant, U64.parse("2000")?)))
  let result = credit_attachment_result(grant)?
  let result_wire = encode_credit_attachment_result(result)?
  assert(Bytes.length(result_wire) == 84)
  assert(Bytes.secure_equals(encode_credit_attachment_result(decode_credit_attachment_result(result_wire)?)?,
    result_wire))
  let token = CreditToken {
    input: CreditTokenInput {
      nonce: bytes("66")?,
      challenge_digest: bytes("77")?,
      token_key_id: bytes("88")?
    },
    authenticator: Bytes.from_hex(String.repeat("99", 256))?
  }
  let submission = CreditActionSubmission {
    action: action,
    request_body: encoded,
    frame: CreditFrame { binding: Crypto.sha256(encoded), tokens: [token] }
  }
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let receipt = sign_credit_action_receipt(signer.private_key,
    submission,
    credit_attachment_effect_id(action)?,
    U64.parse("1000")?,
    result_wire)?
  let receipt_wire = encode_credit_action_receipt(receipt)?
  assert(Bytes.length(receipt_wire) == 290)
  assert(verify_credit_attachment_receipt(submission,
    signer.public_key,
    receipt_wire)?.size_bytes == 16777217)
  let changed_result = sign_credit_action_receipt(signer.private_key,
    submission,
    credit_attachment_effect_id(action)?,
    U64.parse("1000")?,
    encode_credit_attachment_result(%{result | total_bytes: result.total_bytes + 1})?)?
  assert(Result.is_err(verify_credit_attachment_receipt(submission,
    signer.public_key,
    encode_credit_action_receipt(changed_result)?)))
  assert(Result.is_err(verify_credit_attachment_receipt(submission,
    signer.public_key,
    encode_credit_action_receipt(%{receipt |
      signature: Bytes.from_hex(String.repeat("00", 64))?
    })?)))
  Ok(true)
end

test("large attachment grants bind exact size, capabilities, deadlines and trusted completion") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
