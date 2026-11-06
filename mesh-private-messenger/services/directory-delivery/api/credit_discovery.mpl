from Api.Binary import BinaryResult
from Credits.Discovery import decode_credit_issuer_query
from Storage.CreditDiscovery import (
  current_credit_issuer_evidence,
  announced_credit_issuer_evidence,
  credit_issuer_cursor
)
from Storage.CreditIssuers import configured_credit_purpose
from Transparency.Wire import encode_transparency_evidence

fn evidence_request(pool :: PoolHandle, body :: Bytes, admitted :: Bool) -> BinaryResult do
  let query = case decode_credit_issuer_query(body) do
    Err(_) -> return BinaryResult { status: 400, body: Bytes.empty() }
    Ok(value) -> value
  end
  let purpose = case configured_credit_purpose() do
    Err(_) -> return BinaryResult { status: 503, body: Bytes.empty() }
    Ok(value) -> value
  end
  if query.purpose != purpose do
    return BinaryResult { status: 400, body: Bytes.empty() }
  end
  let result = if admitted do
    current_credit_issuer_evidence(pool, query)
  else
    announced_credit_issuer_evidence(pool, query)
  end
  case result do
    Err("credit_issuer_previous_ahead") -> BinaryResult { status: 409, body: Bytes.empty() }
    Err(_) -> BinaryResult { status: 503, body: Bytes.empty() }
    Ok(evidence) -> case encode_transparency_evidence(evidence) do
      Err(_) -> BinaryResult { status: 503, body: Bytes.empty() }
      Ok(value) -> BinaryResult { status: 200, body: value }
    end
  end
end

pub fn credit_issuer_discovery_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  evidence_request(pool, body, true)
end

pub fn credit_issuer_candidate_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  evidence_request(pool, body, false)
end

pub fn credit_issuer_cursor_request(pool :: PoolHandle) -> BinaryResult do
  case credit_issuer_cursor(pool) do
    Err(_) -> BinaryResult { status: 503, body: Bytes.empty() }
    Ok(value) -> BinaryResult { status: 200, body: value }
  end
end
