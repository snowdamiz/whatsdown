from Mobile.Account import create_account
from Mobile.Messages import start_conversation
from Mobile.History import load_visible_history
from Mobile.HistoryWire import encode_history
from Mobile.Requests import parse_peer_request
from Mobile.Sessions import find_peer_session, load_session_ids
from Mobile.Types import MobileAccountRequest, MobileStartRequest, MobileHistoryEntry
from Protocol.V1 import InnerEnvelope
from Storage.HistoryBlobs import seal_history_blob
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Transport.Packet import decode_client_profile

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture_repeat_failed")
    Ok(output)
  end
end

@export("mesh_history_fixture_seed")
pub fn seed(input :: Bytes) -> Bytes!String do
  let path = case Bytes.to_utf8(input) do
    Err(_) -> return Err("fixture_invalid_path")
    Ok(value) -> value
  end
  let local_wire = create_account(MobileAccountRequest {
    database_path: input,
    username: Bytes.from_utf8("history_fixture_local")
  })?
  let peer_wire = create_account(MobileAccountRequest {
    database_path: Bytes.from_utf8(path <> "-peer"),
    username: Bytes.from_utf8("history_fixture_peer")
  })?
  start_conversation(MobileStartRequest {
    database_path: path,
    peer_profile: peer_wire,
    body: Bytes.from_utf8("fixture session"),
    attachment: Bytes.empty()
  })?
  let local = decode_client_profile(local_wire)?
  let peer = decode_client_profile(peer_wire)?
  let wrapping = platform_key()?
  let loaded = find_peer_session(path,
    wrapping,
    peer.account_id,
    load_session_ids(path, wrapping)?,
    0)?
  let body = repeated(120, 32768)?
  let entries = for index in 0..256 do
    MobileHistoryEntry {
      direction: 1,
      inner: InnerEnvelope {
        version: 1,
        sender_account_id: local.account_id,
        sender_device_id: local.device_id,
        recipient_device_id: peer.device_id,
        conversation_id: loaded.record.conversation_id,
        client_message_id: repeated(index, 16)?,
        client_timestamp: U64.parse("1")?,
        message_type: 1,
        body: body,
        reply_reference: Bytes.empty(),
        attachment_manifest: Bytes.empty(),
        receipt_policy: 0,
        disappearing_seconds: 0,
        extensions: []
      }
    }
  end
  let label = "history/v1/" <> Bytes.to_hex(loaded.record.conversation_id)
  store_updated_blobs(path,
    [label],
    [seal_history_blob(encode_history(entries)?, wrapping, label)?])?
  Ok(peer_wire)
end

@export("mesh_history_fixture_load", max_output: 16_794_632)
pub fn load(input :: Bytes) -> Bytes!String do
  load_visible_history(parse_peer_request(input)?)
end

@export("mesh_history_fixture_default_load")
pub fn default_load(input :: Bytes) -> Bytes!String do
  load_visible_history(parse_peer_request(input)?)
end
