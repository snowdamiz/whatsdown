from Mobile.History import update_conversation
from Mobile.Profile import load_profile, peer_account_id
from Mobile.Sessions import find_peer_session, load_session_ids
from Mobile.Types import MobilePeerRequest, MobilePolicyRequest, MobileTriplePayloadRequest
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Transport.Packet import decode_client_profile

##! The safety number as a code to scan or paste (`protocol/safety-number-qr-v1.md`):
##! `morse-verify:1:<shower's account ID>:<the account it is shown to>:<safety number>`,
##! each 64 lowercase hex digits. The comparison is made here, never in the app.

fn code_prefix() -> String do
  "morse-verify:1:"
end

fn chat_safety(database_path :: String, peer :: Bytes) -> Bytes!String do
  let wrapping_key = platform_key()?
  let loaded = find_peer_session(database_path,
    wrapping_key,
    peer,
    load_session_ids(database_path, wrapping_key)?,
    0)?
  if Bytes.length(loaded.record.safety_number) != 64 do
    Err("safety_number_unavailable")
  else
    Ok(loaded.record.safety_number)
  end
end

fn local_account(database_path :: String) -> Bytes!String do
  Ok(decode_client_profile(load_profile(database_path)?)?.account_id)
end

## This device's code for the chat with the peer, to show as a QR code.

pub fn safety_code(request :: MobilePeerRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let peer = peer_account_id(request.peer_profile)?
  let safety = chat_safety(request.database_path, peer)?
  let number = case Bytes.to_utf8(safety) do
    Err(_) -> Err("safety_number_unavailable")
    Ok(value)
  end?
  Ok(Bytes.from_utf8(code_prefix()
    <> Bytes.to_hex(local_account(request.database_path)?)
    <> ":"
    <> Bytes.to_hex(peer)
    <> ":"
    <> number))
end

fn set_verified(database_path :: String, peer :: Bytes, verified :: Bool) -> Result<(), String> do
  update_conversation(MobilePolicyRequest {
    database_path: database_path,
    peer_profile: peer,
    action: if verified do
      4
    else
      6
    end,
    value: 0
  })?
  Ok(nil)
end

## Checks a code scanned or pasted in the chat with `first` (a peer profile or
## account ID). `verified`: it is that contact's code for this account and the
## numbers match, and the chat is marked verified. `mismatch`: it is theirs but
## the numbers differ, so the chat is no longer marked verified. `wrong_contact`:
## it was made for another chat. `invalid`: it is not a code at all.

pub fn safety_code_check(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let text = case Bytes.to_utf8(request.second) do
    Err(_) -> ""
    Ok(value) -> String.trim(value)
  end
  if !Regex.is_match(~r/^morse-verify:1:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$/, text) do
    return Ok(Bytes.from_utf8("invalid"))
  end
  let parts = String.split(text, ":")
  let peer = peer_account_id(request.first)?
  let local = local_account(request.database_path)?
  if List.get(parts, 2) != Bytes.to_hex(peer) || List.get(parts, 3) != Bytes.to_hex(local) do
    return Ok(Bytes.from_utf8("wrong_contact"))
  end
  let safety = chat_safety(request.database_path, peer)?
  let matches = Bytes.secure_equals(Bytes.from_utf8(List.get(parts, 4)), safety)
  set_verified(request.database_path, peer, matches)?
  if matches do
    Ok(Bytes.from_utf8("verified"))
  else
    Ok(Bytes.from_utf8("mismatch"))
  end
end
