from Credits.Discovery import CreditIssuerQuery, encode_credit_issuer_query
from Credits.Issuer import encode_issuer_key, decode_issuer_key, issuer_key_id, verify_issuer_key
from Credits.Policy import issuer_epoch
from Privacy.Edge import internal_delivery_authorization
from Runtime.Config import IssuerServerConfig, open_storage_key, issuer_admin_url
from Storage.Keys import ensure_current_key, issuer_cursor
from Storage.Issuance import admit_issuer_key
from Transparency.Config import pinned_witness_keys
from Transparency.Wire import (
  TransparencyEvidence,
  decode_transparency_evidence,
  encode_transparency_evidence,
  decode_checkpoint
)

pub fn issuer_now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) / 1000))
end

fn post(config :: IssuerServerConfig,
  operation :: String,
  body :: Bytes,
  content_type :: String) -> Bytes!String do
  let response = Http.build(:post, issuer_admin_url(config, operation)?)
    |> Http.header("Authorization", internal_delivery_authorization(config.issuer_admin_token)?)
    |> Http.header("Content-Type", content_type)
    |> Http.body_bytes(body)
    |> Http.timeout(10000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(70000)
    |> Http.send()?
  if response.status != 200 && response.status != 201 do
    return Err("issuer_key_sync_pending")
  end
  Ok(response.body_bytes)
end

fn evidence(config :: IssuerServerConfig, size :: U64) -> TransparencyEvidence!String do
  let body = post(config,
    "evidence",
    encode_credit_issuer_query(CreditIssuerQuery {
      purpose: config.policy.purpose,
      previous_size: size
    })?,
    "application/octet-stream")?
  case decode_transparency_evidence(body) do
    Ok(value)
    Err(_) -> Err("invalid_issuer_admission_evidence")
  end
end

fn core_cursor(config :: IssuerServerConfig) -> Bytes!String do
  let response = Http.build(:get, issuer_admin_url(config, "cursor")?)
    |> Http.header("Authorization", internal_delivery_authorization(config.issuer_admin_token)?)
    |> Http.timeout(10000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(512)
    |> Http.send()?
  if response.status != 200 do
    return Err("issuer_key_sync_pending")
  end
  Ok(response.body_bytes)
end

# Durable local generation precedes announcement. Each admission checks its
# own persisted cursor; an interrupted two-service update is retried safely.
pub fn synchronize_current_key(pool :: PoolHandle,
  config :: IssuerServerConfig,
  now :: U64) -> U64!String do
  let managed = ensure_current_key(pool,
    config.policy.purpose,
    now,
    fn() do open_storage_key(config.key_directory) end,
    config.policy.service_key)?
  let id = issuer_key_id(managed.key)?
  post(config,
    "announce",
    Bytes.from_utf8("{\"leaf\":"
      <> Json.encode_string(Bytes.to_hex(encode_issuer_key(managed.key)?))
      <> "}"),
    "application/json")?
  let previous = issuer_cursor(pool)?
  let previous_size = if Bytes.length(previous) == 0 do
    U64.parse("0")?
  else
    decode_checkpoint(previous)?.tree_size
  end
  let candidate = evidence(config, previous_size)?
  if !Bytes.secure_equals(issuer_key_id(decode_issuer_key(candidate.entry_bytes)?)?, id) do
    return Err("issuer_admission_key_mismatch")
  end
  let pins = pinned_witness_keys(config.trust)
  let service_key = SigningPublicKey { bytes: config.policy.service_key }
  verify_issuer_key(candidate,
    service_key,
    pins,
    config.trust.threshold,
    previous,
    now,
    config.policy.purpose)?
  let cursor = core_cursor(config)?
  let size = if Bytes.length(cursor) == 0 do
    U64.parse("0")?
  else
    decode_checkpoint(cursor)?.tree_size
  end
  let for_core = evidence(config, size)?
  let verified = verify_issuer_key(for_core,
    service_key,
    pins,
    config.trust.threshold,
    cursor,
    now,
    config.policy.purpose)?
  if !Bytes.secure_equals(issuer_key_id(verified)?, id) do
    return Err("issuer_admission_key_mismatch")
  end
  post(config,
    "admit",
    Bytes.from_utf8("{\"evidence\":"
      <> Json.encode_string(Bytes.to_hex(encode_transparency_evidence(for_core)?))
      <> "}"),
    "application/json")?
  # Activate local quote issuance only after the core has admitted the same
  # key. A crash between those commits leaves issuance disabled until retry.
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do admit_issuer_key(conn,
      candidate,
      service_key,
      pins,
      config.trust.threshold,
      now,
      config.policy.purpose) end)?
  U64.multiply(U64.add(issuer_epoch(now)?, U64.parse("1")?)?, U64.parse("2592000")?)
end

fn run(pool :: PoolHandle, config :: IssuerServerConfig, due :: U64) -> Result<(), String> do
  if Process.shutdown_requested() do
    return Ok(nil)
  end
  let now = issuer_now()?
  let next = if U64.compare(now, due) >= 0 do
    case synchronize_current_key(pool, config, now) do
      Ok(value) -> value
      Err(_) -> do
        io_eprintln("credit issuer is waiting for key synchronization")
        U64.add(now, U64.parse("30")?)?
      end
    end
  else
    due
  end
  let current = issuer_now()?
  let delay = if U64.compare(next, current) <= 0 do
    1000
  else
    let seconds = U64.to_int(U64.subtract(next, current)?)?
    if seconds > 60 do
      60000
    else
      seconds * 1000
    end
  end
  Timer.sleep(delay)
  run(pool, config, next)
end

actor key_synchronizer(pool :: PoolHandle, config :: IssuerServerConfig) do
  case issuer_now() do
    Ok(now) -> case run(pool, config, now) do
      Ok(_) -> nil
      Err(_) -> io_eprintln("credit issuer key worker stopped")
    end
    Err(_) -> io_eprintln("credit issuer clock unavailable")
  end
end

pub fn start_key_synchronizer(pool :: PoolHandle, config :: IssuerServerConfig) do
  if config.policy.enabled do
    spawn(key_synchronizer, pool, config)
  end
end
