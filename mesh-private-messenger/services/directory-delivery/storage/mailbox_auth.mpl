##! Device-signature authorization for mailbox reads and acknowledgements.
##!
##! The mailbox address is public: the directory publishes it so that anyone can
##! deposit an envelope. Reading or acknowledging a mailbox instead requires a
##! fresh statement signed by the one active, unrevoked device registered for it.

from Protocol.IdentityWire import decode_device_credential
from Protocol.MailboxWire import mailbox_ack_signing_bytes, mailbox_fetch_signing_bytes, mailbox_request_is_fresh
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import MailboxAck, MailboxFetch

pub struct MailboxOwner do
  mailbox_token :: Bytes
  signing_public_key :: Bytes
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid mailbox owner row")
  end
end

## The Ed25519 key in the account-signed credential of a stored prekey bundle.

pub fn bundle_signing_public_key(bundle_bytes :: Bytes) -> Bytes!String do
  let bundle = case decode_prekey_bundle(bundle_bytes) do
    Err(_) -> Err("invalid stored prekey bundle")
    Ok(output)
  end?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("invalid stored device credential")
    Ok(output)
  end?
  Ok(credential.signing_public_key)
end

pub fn mailbox_owner(pool :: PoolHandle, mailbox_token_hash :: Bytes) -> Option<MailboxOwner>!String do
  let rows = Pool.query_values(pool,
    "SELECT device.prekey_bundle, device.mailbox_token FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.mailbox_token_hash = $1 AND device.revoked_at IS NULL AND mailbox.active",
    [Binary(mailbox_token_hash)])?
  case rows do
    [] -> Ok(None)
    [row] -> Ok(Some(MailboxOwner {
      mailbox_token: binary(Map.get(row, "mailbox_token"))?,
      signing_public_key: bundle_signing_public_key(binary(Map.get(row, "prekey_bundle"))?)?
    }))
    _ -> Err("duplicate active mailbox device")
  end
end

fn current_time() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn signed_by(owner :: MailboxOwner, signing_bytes :: Bytes, signature :: Bytes) -> Bool do
  case Crypto.verify(SigningPublicKey { bytes: owner.signing_public_key },
    signing_bytes,
    Signature { bytes: signature }) do
    Err(_) -> false
    Ok(valid) -> valid
  end
end

# Freshness is checked before the database so a stale or replayed frame costs
# no query. Every rejection is the same `None`: callers answer 403 without
# revealing whether the mailbox exists.

fn authorize(pool :: PoolHandle,
  mailbox_token_hash :: Bytes,
  issued_at :: U64,
  signing_bytes :: Bytes,
  signature :: Bytes) -> Option<MailboxOwner>!String do
  if !mailbox_request_is_fresh(issued_at, current_time()?) do
    Ok(None)
  else
    case mailbox_owner(pool, mailbox_token_hash)? do
      None -> Ok(None)
      Some(owner) -> if signed_by(owner, signing_bytes, signature) do
        Ok(Some(owner))
      else
        Ok(None)
      end
    end
  end
end

pub fn authorize_mailbox_fetch(pool :: PoolHandle, request :: MailboxFetch) -> Option<MailboxOwner>!String do
  let signing_bytes = case mailbox_fetch_signing_bytes(request) do
    Err(_) -> Err("invalid mailbox fetch")
    Ok(output)
  end?
  authorize(pool, request.mailbox_token_hash, request.issued_at, signing_bytes, request.signature)
end

pub fn authorize_mailbox_ack(pool :: PoolHandle, request :: MailboxAck) -> Option<MailboxOwner>!String do
  let signing_bytes = case mailbox_ack_signing_bytes(request) do
    Err(_) -> Err("invalid mailbox acknowledgement")
    Ok(output)
  end?
  authorize(pool, request.mailbox_token_hash, request.issued_at, signing_bytes, request.signature)
end
