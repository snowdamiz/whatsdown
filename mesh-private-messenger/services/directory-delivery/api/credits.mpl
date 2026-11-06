from Api.Binary import BinaryResult
from Credits.Action import decode_credit_action
from Credits.Wire import decode_credit_frame
from Storage.Credits import redeem_credits, prune_credit_ledger
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Transparency.Wire import decode_transparency_evidence, encode_checkpoint

fn response(status :: Int, document :: String) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.from_utf8(document) }
end

fn failure(error :: String) -> BinaryResult do
  let conflict = List.contains([
      "credit_already_spent",
      "credit_operation_conflict",
      "credit_effect_conflict",
      "credit_issuer_changed",
      "credit_issuer_key_reused"
    ],
    error)
  let invalid = List.contains([
      "invalid_credit_request",
      "invalid_credit_action",
      "invalid_credit_action_quantity",
      "invalid_credit_attachment_size",
      "invalid_credit_retention",
      "credit_action_request_mismatch",
      "expired_credit_action",
      "credit_not_required",
      "unknown_credit_mailbox",
      "unknown_credit_issuer",
      "invalid_credit_token",
      "invalid_credit_frame",
      "duplicate_credit_token",
      "credit_amount_mismatch",
      "credit_binding_mismatch",
      "inactive_credit_issuer",
      "unverified_credit_issuer",
      "unannounced_credit_issuer",
      "invalid_credit_issuer_key",
      "invalid_credit_issuer_leaf",
      "invalid_credit_issuer_purpose",
      "invalid_credit_prune_limit",
      "credit_request_too_large"
    ],
    error)
  if conflict do
    response(409, "{\"error\":" <> Json.encode_string(error) <> "}")
  else if invalid do
    response(400, "{\"error\":" <> Json.encode_string(error) <> "}")
  else
    response(503, "{\"error\":\"credit_ledger_unavailable\"}")
  end
end

fn document(body :: Bytes, maximum :: Int) -> Json!String do
  if Bytes.length(body) > maximum do
    return Err("invalid_credit_request")
  end
  case Bytes.to_utf8(body) do
    Err(_) -> Err("invalid_credit_request")
    Ok(value) -> case Json.parse(value) do
      Err(_) -> Err("invalid_credit_request")
      Ok(parsed)
    end
  end
end

fn field(value :: Json, name :: String) -> Json!String do
  case Json.object_get(value, name) do
    Err(_) -> Err("invalid_credit_request")
    Ok(output)
  end
end

fn integer(value :: Json, name :: String) -> Int!String do
  case Json.as_int(field(value, name)?) do
    Err(_) -> Err("invalid_credit_request")
    Ok(output)
  end
end

fn hex(value :: Json, name :: String, maximum :: Int) -> Bytes!String do
  let encoded = case Json.as_string(field(value, name)?) do
    Err(_) -> return Err("invalid_credit_request")
    Ok(output) -> output
  end
  if String.length(encoded) > maximum * 2 do
    return Err("invalid_credit_request")
  end
  let bytes = case Bytes.from_hex(encoded) do
    Err(_) -> return Err("invalid_credit_request")
    Ok(output) -> output
  end
  if Bytes.to_hex(bytes) != encoded do
    return Err("invalid_credit_request")
  end
  Ok(bytes)
end

fn redemption(pool :: PoolHandle, body :: Bytes) -> BinaryResult!String do
  let input = document(body, 180000)?
  if integer(input, "schema_version")? != 1 do
    return Err("invalid_credit_request")
  end
  let action = decode_credit_action(hex(input, "action", 117)?)?
  let request_body = hex(input, "request_body", 65536)?
  let frame = decode_credit_frame(hex(input, "frame", 22694)?)?
  let result = redeem_credits(pool, action, request_body, frame)?
  let hold = result.hold
  Ok(response(if result.created do
      201
    else
      200
    end,
    "{\"schema_version\":1,\"hold_id\":"
      <> Json.encode_string(Bytes.to_hex(hold.id))
      <> ",\"state\":"
      <> Json.encode_string(hold.state)
      <> ",\"action_sha256\":"
      <> Json.encode_string(Bytes.to_hex(Crypto.sha256(hold.action)))
      <> ",\"request_sha256\":"
      <> Json.encode_string(Bytes.to_hex(action.request_sha256))
      <> ",\"credits\":#{hold.credits},\"expires_at\":"
      <> Json.encode_string(U64.to_string(hold.expires_at))
      <> ",\"retain_until\":"
      <> Json.encode_string(U64.to_string(hold.retain_until))
      <> "}"))
end

pub fn credit_redeem_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case redemption(pool, body) do
    Err(error) -> failure(error)
    Ok(value) -> value
  end
end

fn announcement(pool :: PoolHandle, body :: Bytes) -> BinaryResult!String do
  let leaf = hex(document(body, 2048)?, "leaf", 387)?
  let result = announce_credit_issuer(pool, leaf)?
  Ok(response(if result.created do
      201
    else
      200
    end,
    "{\"schema_version\":1,\"entry_sequence\":"
      <> Json.encode_string(Int.to_string(result.entry_sequence))
      <> ",\"checkpoint\":"
      <> Json.encode_string(Bytes.to_hex(encode_checkpoint(result.checkpoint)?))
      <> "}"))
end

pub fn credit_issuer_announce_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case announcement(pool, body) do
    Err(error) -> failure(error)
    Ok(value) -> value
  end
end

fn admission(pool :: PoolHandle, body :: Bytes) -> BinaryResult!String do
  let evidence = case decode_transparency_evidence(hex(document(body, 70000)?,
    "evidence",
    32768)?) do
    Err(_) -> return Err("invalid_credit_request")
    Ok(output) -> output
  end
  let created = admit_credit_issuer(pool, evidence)?
  Ok(response(if created do
      201
    else
      200
    end,
    "{\"schema_version\":1,\"admitted\":true}"))
end

pub fn credit_issuer_admit_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case admission(pool, body) do
    Err(error) -> failure(error)
    Ok(value) -> value
  end
end

fn prune(pool :: PoolHandle, body :: Bytes) -> BinaryResult!String do
  let limit = integer(document(body, 128)?, "limit")?
  let result = prune_credit_ledger(pool, limit)?
  Ok(response(200, "{\"spent\":#{result.spent},\"holds\":#{result.holds}}"))
end

pub fn credit_prune_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case prune(pool, body) do
    Err(error) -> failure(error)
    Ok(value) -> value
  end
end
