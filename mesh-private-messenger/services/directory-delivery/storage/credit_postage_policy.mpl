from Credits.PostagePolicy import PostagePolicy, encode_postage_policy, verify_postage_policy
from Storage.RateLimit import allow_request_on_connection
from Protocol.IdentityWire import decode_account_identity
from Protocol.MailboxWire import mailbox_request_is_fresh
from Storage.PostagePolicyState import (
  latest_postage_policy_on_connection,
  mirror_postage_policy_on_connection
)
from Storage.Devices import record_postage_device_set_on_connection

pub struct PostagePolicyWrite do
  created :: Bool
  device_set_revision :: U64
end

fn policy_text(value :: DbValue) -> String!String do
  case value do
    Text(value) -> Ok(value)
    _ -> Err("invalid_stored_postage_policy")
  end
end

fn policy_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_stored_postage_policy")
  end
end

fn publish(conn :: borrow PgConn,
  policy :: PostagePolicy,
  encoded :: Bytes) -> PostagePolicyWrite!String do
  # Verify the account signature before acquiring its exclusive lock. Arbitrary
  # anonymous bytes cannot hold a victim's account lock during signature work.
  let owners = Pg.query_values(conn,
    "SELECT account_identity FROM messenger_accounts WHERE account_id = $1",
    [Binary(policy.account_id)])?
  if List.length(owners) != 1 do
    return Err("invalid_postage_policy_authority")
  end
  let identity = case decode_account_identity(policy_binary(Map.get(List.head(owners),
    "account_identity"))?) do
    Err(_) -> return Err("invalid_stored_postage_policy")
    Ok(value) -> value
  end
  if !verify_postage_policy(policy, identity)? do
    return Err("invalid_postage_policy_authority")
  end
  let accounts = Pg.query_values(conn,
    "SELECT username, account_identity, sequence::text FROM messenger_accounts WHERE account_id = $1 FOR UPDATE",
    [Binary(policy.account_id)])?
  if List.length(accounts) != 1
    || !Bytes.secure_equals(policy_binary(Map.get(List.head(accounts), "account_identity"))?,
      policy_binary(Map.get(List.head(owners), "account_identity"))?) do
    return Err("invalid_postage_policy_authority")
  end
  let previous = Pg.query_values(conn,
    "SELECT statement, device_set_sequence::text FROM credit_postage_policies WHERE account_id = $1 AND revision = $2::numeric",
    [Binary(policy.account_id), Text(U64.to_string(policy.revision))])?
  if List.length(previous) == 1 do
    let row = List.head(previous)
    if !Bytes.secure_equals(policy_binary(Map.get(row, "statement"))?, encoded) do
      return Err("postage_policy_conflict")
    end
    return Ok(PostagePolicyWrite {
      created: false,
      device_set_revision: U64.parse(policy_text(Map.get(row, "device_set_sequence"))?)?
    })
  end
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  if !mailbox_request_is_fresh(policy.issued_at_ms, now) do
    return Err("expired_postage_policy")
  end
  let row = List.head(accounts)
  let sequence = U64.parse(policy_text(Map.get(row, "sequence"))?)?
  let expected_revision = case latest_postage_policy_on_connection(conn, policy.account_id)? do
    None -> U64.parse("1")?
    Some(value) -> U64.add(value.revision, U64.parse("1")?)?
  end
  if policy.revision != expected_revision || policy.expected_device_set_revision != sequence do
    return Err("postage_policy_conflict")
  end
  if List.length(Pg.query_values(conn,
    "SELECT device_id FROM messenger_devices WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    [Binary(policy.account_id), Binary(policy.publisher_device_id)])?) != 1 do
    return Err("invalid_postage_policy_authority")
  end
  let bucket = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-postage-policy-rate-v1"),
    policy.account_id)?)
  if !allow_request_on_connection(conn, bucket, 8, 3600)? do
    return Err("postage_policy_rate_limited")
  end
  let next = U64.add(sequence, U64.parse("1")?)?
  mirror_postage_policy_on_connection(conn, policy.account_id, policy)?
  Pg.execute_values(conn,
    "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1",
    [Binary(policy.account_id), Text(U64.to_string(next))])?
  record_postage_device_set_on_connection(conn,
    policy.account_id,
    policy_text(Map.get(row, "username"))?)?
  Pg.execute_values(conn,
    "INSERT INTO credit_postage_policies (account_id, revision, statement, credits, device_set_sequence, issued_at_ms) VALUES ($1, $2::numeric, $3, $4::smallint, $5::bigint, $6::numeric)",
    [
      Binary(policy.account_id),
      Text(U64.to_string(policy.revision)),
      Binary(encoded),
      Text(Int.to_string(policy.credits)),
      Text(U64.to_string(next)),
      Text(U64.to_string(policy.issued_at_ms))
    ])?
  Ok(PostagePolicyWrite { created: true, device_set_revision: next })
end

pub fn publish_postage_policy(pool :: PoolHandle,
  policy :: PostagePolicy) -> PostagePolicyWrite!String do
  let encoded = encode_postage_policy(policy)?
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> publish(conn, policy, encoded) end)
end
