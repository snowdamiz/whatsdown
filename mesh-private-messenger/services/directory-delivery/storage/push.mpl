from Storage.MailboxAuth import bundle_signing_public_key
from Push.Binding import PushBindRequest, PushUnbindRequest, encode_push_bind, encode_push_unbind, push_bind_signing_bytes, push_unbind_signing_bytes

pub type PushWrite do
  PushAccepted

  PushUnauthorized

  PushStale
end deriving(Eq, Debug)

pub struct ProviderPushBinding do
  wake_token_hash :: Bytes
  provider :: Int
  provider_token_ciphertext :: Bytes
end

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid push row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid push row")
  end
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid push provider")
    Some(output) -> Ok(output)
  end
end

fn active_signing_key(conn :: borrow PgConn, mailbox_token_hash :: Bytes) -> Option < Bytes > ! String do
  let rows = Pg.query_values(conn,
  "SELECT device.prekey_bundle FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.mailbox_token_hash = $1 AND device.revoked_at IS NULL AND mailbox.active FOR SHARE OF device, mailbox",
  [Binary(mailbox_token_hash)]) ?
  case rows do
    [] -> Ok(None)
    [row] -> Ok(Some(bundle_signing_public_key(binary(Map.get(row, "prekey_bundle")) ?) ?))
    _ -> Err("duplicate active mailbox device")
  end
end

fn authorized(conn :: borrow PgConn,
mailbox_token_hash :: Bytes,
signing_bytes :: Bytes,
signature :: Bytes) -> Bool ! String do
  case active_signing_key(conn, mailbox_token_hash) ? do
    None -> Ok(false)
    Some(key) -> case Crypto.verify(SigningPublicKey { bytes : key },
    signing_bytes,
    Signature { bytes : signature }) do
      Err(_) -> Ok(false)
      Ok(valid) -> Ok(valid)
    end
  end
end

fn disabled_placeholder(label :: String, mailbox_token_hash :: Bytes) -> Bytes ! String do
  let material = case Bytes.concat(Bytes.from_utf8(label), mailbox_token_hash) do
    Err(_) -> Err("push placeholder allocation failed")
    Ok(output) -> Ok(output)
  end ?
  Ok(Crypto.sha256(material))
end

fn bind_on_connection(conn :: borrow PgConn, request :: PushBindRequest) -> PushWrite ! String do
  if !(authorized(conn,
  request.mailbox_token_hash,
  push_bind_signing_bytes(request) ?,
  request.signature) ?) do
    Ok(PushUnauthorized)
  else
    let changed = Pg.execute_values(conn,
    "INSERT INTO messenger_push_bindings (mailbox_token_hash, wake_token_hash, revision, provider, provider_token_ciphertext) VALUES ($1, $2, $3::bigint, $4::smallint, $5) ON CONFLICT (mailbox_token_hash) DO UPDATE SET wake_token_hash = EXCLUDED.wake_token_hash, revision = EXCLUDED.revision, provider = EXCLUDED.provider, provider_token_ciphertext = EXCLUDED.provider_token_ciphertext, disabled_at = NULL WHERE messenger_push_bindings.revision < EXCLUDED.revision OR (messenger_push_bindings.revision = EXCLUDED.revision AND messenger_push_bindings.disabled_at IS NULL AND messenger_push_bindings.wake_token_hash = EXCLUDED.wake_token_hash AND messenger_push_bindings.provider = EXCLUDED.provider AND messenger_push_bindings.provider_token_ciphertext = EXCLUDED.provider_token_ciphertext)",
    [Binary(request.mailbox_token_hash), Binary(request.wake_token_hash), Text(U64.to_string(request.revision)), Text(Int.to_string(request.provider)), Binary(request.provider_token_ciphertext)]) ?
    if changed == 1 do
      Ok(PushAccepted)
    else
      Ok(PushStale)
    end
  end
end

pub fn bind_push(pool :: PoolHandle, request :: PushBindRequest) -> PushWrite ! String do
  let _ = encode_push_bind(request) ?
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> bind_on_connection(conn, request) end)
end

fn unbind_on_connection(conn :: borrow PgConn, request :: PushUnbindRequest) -> PushWrite ! String do
  if !(authorized(conn,
  request.mailbox_token_hash,
  push_unbind_signing_bytes(request) ?,
  request.signature) ?) do
    Ok(PushUnauthorized)
  else
    let wake_placeholder = disabled_placeholder("mesh-msg/v1/disabled-push-wake",
    request.mailbox_token_hash) ?
    let token_placeholder = disabled_placeholder("mesh-msg/v1/disabled-push-token",
    request.mailbox_token_hash) ?
    let changed = Pg.execute_values(conn,
    "INSERT INTO messenger_push_bindings (mailbox_token_hash, wake_token_hash, revision, provider, provider_token_ciphertext, disabled_at) VALUES ($1, $2, $3::bigint, 1, $4, now()) ON CONFLICT (mailbox_token_hash) DO UPDATE SET wake_token_hash = EXCLUDED.wake_token_hash, revision = EXCLUDED.revision, provider = EXCLUDED.provider, provider_token_ciphertext = EXCLUDED.provider_token_ciphertext, disabled_at = coalesce(messenger_push_bindings.disabled_at, EXCLUDED.disabled_at) WHERE messenger_push_bindings.revision < EXCLUDED.revision OR (messenger_push_bindings.revision = EXCLUDED.revision AND messenger_push_bindings.disabled_at IS NOT NULL)",
    [Binary(request.mailbox_token_hash), Binary(wake_placeholder), Text(U64.to_string(request.revision)), Binary(token_placeholder)]) ?
    if changed == 1 do
      Ok(PushAccepted)
    else
      Ok(PushStale)
    end
  end
end

pub fn unbind_push(pool :: PoolHandle, request :: PushUnbindRequest) -> PushWrite ! String do
  let _ = encode_push_unbind(request) ?
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> unbind_on_connection(conn, request) end)
end

fn find_on_connection(conn :: borrow PgConn, mailbox_token_hash :: Bytes) -> Option < ProviderPushBinding > ! String do
  let rows = Pg.query_values(conn,
  "SELECT binding.wake_token_hash, binding.provider::text, binding.provider_token_ciphertext FROM messenger_push_bindings AS binding JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = binding.mailbox_token_hash AND mailbox.active WHERE binding.mailbox_token_hash = $1 AND binding.disabled_at IS NULL",
  [Binary(mailbox_token_hash)]) ?
  case rows do
    [] -> Ok(None)
    [row] -> Ok(Some(ProviderPushBinding {
      wake_token_hash : binary(Map.get(row, "wake_token_hash")) ?,
      provider : integer(Map.get(row, "provider")) ?,
      provider_token_ciphertext : binary(Map.get(row, "provider_token_ciphertext")) ?
    }))
    _ -> Err("duplicate push binding")
  end
end

pub fn find_push_binding_for_mailbox(pool :: PoolHandle, mailbox_token_hash :: Bytes) -> Option < ProviderPushBinding > ! String do
  if Bytes.length(mailbox_token_hash) != 32 do
    Err("invalid mailbox token hash")
  else
    Repo.transaction(pool,
    fn (conn :: borrow PgConn) -> find_on_connection(conn, mailbox_token_hash) end)
  end
end
