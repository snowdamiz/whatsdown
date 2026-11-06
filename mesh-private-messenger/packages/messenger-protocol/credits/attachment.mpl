from Attachments.Layout import (
  large_attachment_chunks,
  large_attachment_total_bytes,
  bucketed_large_attachment_chunks,
  bucketed_large_attachment_total_bytes
)
from Credits.Action import CreditAction, credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)

# Anonymous upload authorization. Size, capabilities, manifest and deadlines
# are immutable; filenames, MIME types and attachment keys never enter it.
pub struct CreditAttachmentGrant do
  layout_version :: Int
  operation_nonce :: Bytes
  object_id :: Bytes
  upload_capability :: Bytes
  download_capability :: Bytes
  # v1 exact size; v2 rounded capacity. Never use this as the original v2 file size.
  size_bytes :: Int
  manifest_size :: Int
  manifest_sha256 :: Bytes
  expires_at_ms :: U64
  action_expires_at :: U64
end

pub struct CreditAttachmentResult do
  layout_version :: Int
  object_id :: Bytes
  grant_sha256 :: Bytes
  total_bytes :: Int
  part_count :: Int
  expires_at_ms :: U64
end

fn nonzero(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_attachment_grant")
    Ok(output)
  end
end

fn narrow(value :: Int, width :: Int) -> Bytes!String do
  let parsed = U64.parse(Int.to_string(value))?
  let encoded = case Bytes.write_u32_be(parsed) do
    Err(_) -> return Err("invalid_credit_attachment_grant")
    Ok(output) -> output
  end
  if width == 4 do
    Ok(encoded)
  else if value >= 0 && value <= 65535 do
    Bytes.slice(encoded, 2, 2)
  else
    Err("invalid_credit_attachment_grant")
  end
end

fn number(input :: Bytes, offset :: Int, width :: Int) -> Int!String do
  if width == 2 do
    Ok(Bytes.get(input, offset)? * 256 + Bytes.get(input, offset + 1)?)
  else
    let value = case Bytes.read_u32_be(input, offset) do
      Err(_) -> return Err("invalid_credit_attachment_grant")
      Ok(output) -> output
    end
    U64.to_int(value)
  end
end

fn timestamp(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_attachment_grant")
    Ok(output)
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  let builder = case BytesBuilder.new(256) do
    Err(_) -> return Err("invalid_credit_attachment_grant")
    Ok(output) -> output
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_credit_attachment_grant")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_credit_attachment_grant")
    Ok(output)
  end
end

pub fn encode_credit_attachment_grant(value :: CreditAttachmentGrant) -> Bytes!String do
  if value.layout_version == 1 do
    large_attachment_total_bytes(value.size_bytes, value.manifest_size)?
  else if value.layout_version == 2 do
    bucketed_large_attachment_total_bytes(value.size_bytes, value.manifest_size)?
  else
    return Err("invalid_credit_attachment_grant")
  end
  if !nonzero(value.operation_nonce)
    || !nonzero(value.object_id)
    || !nonzero(value.upload_capability)
    || !nonzero(value.download_capability)
    || !nonzero(value.manifest_sha256)
    || Bytes.secure_equals(value.upload_capability, value.download_capability)
    || value.expires_at_ms == U64.parse("0")?
    || value.action_expires_at == U64.parse("0")? do
    return Err("invalid_credit_attachment_grant")
  end
  join([
    Bytes.from_hex(if value.layout_version == 1 do
      "014c4147"
    else
      "024c4147"
    end)?,
    value.operation_nonce,
    value.object_id,
    value.upload_capability,
    value.download_capability,
    narrow(value.size_bytes, 4)?,
    narrow(value.manifest_size, 2)?,
    value.manifest_sha256,
    wide(value.expires_at_ms)?,
    wide(value.action_expires_at)?
  ])
end

pub fn decode_credit_attachment_grant(input :: Bytes) -> CreditAttachmentGrant!String do
  if Bytes.length(input) != 186
    || !List.contains(["014c4147", "024c4147"], Bytes.to_hex(Bytes.slice(input, 0, 4)?)) do
    return Err("invalid_credit_attachment_grant")
  end
  let value = CreditAttachmentGrant {
    layout_version: Bytes.get(input, 0)?,
    operation_nonce: Bytes.slice(input, 4, 32)?,
    object_id: Bytes.slice(input, 36, 32)?,
    upload_capability: Bytes.slice(input, 68, 32)?,
    download_capability: Bytes.slice(input, 100, 32)?,
    size_bytes: number(input, 132, 4)?,
    manifest_size: number(input, 136, 2)?,
    manifest_sha256: Bytes.slice(input, 138, 32)?,
    expires_at_ms: timestamp(input, 170)?,
    action_expires_at: timestamp(input, 178)?
  }
  encode_credit_attachment_grant(value)?
  Ok(value)
end

pub fn credit_attachment_action(value :: CreditAttachmentGrant) -> CreditAction!String do
  let body = encode_credit_attachment_grant(value)?
  Ok(CreditAction {
    kind: 1,
    operation_nonce: value.operation_nonce,
    target: value.object_id,
    expires_at: value.action_expires_at,
    quantity: U64.parse(Int.to_string(value.size_bytes))?,
    request_sha256: Crypto.sha256(body)
  })
end

pub fn validate_credit_attachment_grant(value :: CreditAttachmentGrant,
  now_seconds :: U64) -> Result<(), String> do
  encode_credit_attachment_grant(value)?
  let now_ms = U64.multiply(now_seconds, U64.parse("1000")?)?
  if U64.compare(value.expires_at_ms, now_ms) <= 0
    || U64.compare(value.expires_at_ms, U64.add(now_ms, U64.parse("604800000")?)?) > 0 do
    return Err("invalid_credit_attachment_expiry")
  end
  Ok(nil)
end

pub fn credit_attachment_effect_id(action :: CreditAction) -> Bytes!String do
  if action.kind != 1 do
    return Err("invalid_credit_attachment_grant")
  end
  Ok(Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-large-attachment-effect-v1"),
    credit_action_id(action)?)?))
end

pub fn credit_attachment_result(value :: CreditAttachmentGrant) -> CreditAttachmentResult!String do
  Ok(CreditAttachmentResult {
    layout_version: value.layout_version,
    object_id: value.object_id,
    grant_sha256: Crypto.sha256(encode_credit_attachment_grant(value)?),
    total_bytes: if value.layout_version == 1 do
      large_attachment_total_bytes(value.size_bytes, value.manifest_size)?
    else if value.layout_version == 2 do
      bucketed_large_attachment_total_bytes(value.size_bytes, value.manifest_size)?
    else
      return Err("invalid_credit_attachment_grant")
    end,
    part_count: if value.layout_version == 1 do
      large_attachment_chunks(value.size_bytes)? + 1
    else
      bucketed_large_attachment_chunks(value.size_bytes)? + 1
    end,
    expires_at_ms: value.expires_at_ms
  })
end

pub fn encode_credit_attachment_result(value :: CreditAttachmentResult) -> Bytes!String do
  if (value.layout_version != 1 && value.layout_version != 2)
    || !nonzero(value.object_id)
    || !nonzero(value.grant_sha256)
    || value.total_bytes <= 16777216
    || value.total_bytes > 537199106
    || value.part_count < 258
    || value.part_count > 8193
    || (value.layout_version == 2 && value.total_bytes != 514 + (value.part_count - 1) * 65576)
    || value.expires_at_ms == U64.parse("0")? do
    return Err("invalid_credit_attachment_result")
  end
  join([
    Bytes.from_hex(if value.layout_version == 1 do
      "014c4152"
    else
      "024c4152"
    end)?,
    value.object_id,
    value.grant_sha256,
    narrow(value.total_bytes, 4)?,
    narrow(value.part_count, 4)?,
    wide(value.expires_at_ms)?
  ])
end

pub fn decode_credit_attachment_result(input :: Bytes) -> CreditAttachmentResult!String do
  if Bytes.length(input) != 84
    || !List.contains(["014c4152", "024c4152"], Bytes.to_hex(Bytes.slice(input, 0, 4)?)) do
    return Err("invalid_credit_attachment_result")
  end
  let value = CreditAttachmentResult {
    layout_version: Bytes.get(input, 0)?,
    object_id: Bytes.slice(input, 4, 32)?,
    grant_sha256: Bytes.slice(input, 36, 32)?,
    total_bytes: number(input, 68, 4)?,
    part_count: number(input, 72, 4)?,
    expires_at_ms: timestamp(input, 76)?
  }
  encode_credit_attachment_result(value)?
  Ok(value)
end

# Raw receipts do not authenticate RPC/HTTP. Caller must supply its pinned core
# key and the exact durably reserved CAP, never a key selected by that response.
pub fn verify_credit_attachment_receipt(submission :: CreditActionSubmission,
  pinned_core :: SigningPublicKey,
  response :: Bytes) -> CreditAttachmentGrant!String do
  let grant = decode_credit_attachment_grant(submission.request_body)?
  if !Bytes.secure_equals(encode_credit_action(submission.action)?,
    encode_credit_action(credit_attachment_action(grant)?)?) do
    return Err("credit_action_request_mismatch")
  end
  let receipt = decode_credit_action_receipt(response)?
  let earliest = if U64.compare(submission.action.expires_at, U64.parse("900")?) < 0 do
    U64.parse("0")?
  else
    U64.subtract(submission.action.expires_at, U64.parse("900")?)?
  end
  if !verify_credit_action_receipt(receipt, pinned_core, submission)?
    || !Bytes.secure_equals(receipt.effect_id, credit_attachment_effect_id(submission.action)?)
    || !Bytes.secure_equals(receipt.result,
      encode_credit_attachment_result(credit_attachment_result(grant)?)?)
    || U64.compare(receipt.applied_at, earliest) < 0
    || U64.compare(receipt.applied_at, submission.action.expires_at) >= 0 do
    return Err("unverified_credit_attachment_receipt")
  end
  validate_credit_attachment_grant(grant, receipt.applied_at)?
  Ok(grant)
end
