##! Mobile.Healing: what this device tells its peers about its sessions, and how
##! it finds the session of a message whose header is encrypted. The session
##! reset that heals a session which lost more messages than it can skip is in
##! `Mobile.SessionReset`.

from Mobile.Sessions import load_session_record, restore_session
from Mobile.Types import MobileLoadedSession
from Protocol.V1 import ProtocolExtension
from Session.Handshake import RatchetState
from Session.Header import (
  ratchet_feature_deniable_groups,
  ratchet_feature_header_encryption,
  ratchet_feature_post_quantum,
  ratchet_feature_session_reset,
  ratchet_session_features_extension
)
from Session.Ratchet import RatchetMessage, ratchet_header_matches

## Header encryption, the post-quantum ratchet, session reset, and deniable
## group messages: every message this build sends says so in inner-envelope
## extension 3, and a peer that reads it upgrades its sessions with this device
## (and signs its group messages deniably, `Mobile.GroupSigning`).

pub fn session_features() -> Int do
  ratchet_feature_header_encryption()
    + ratchet_feature_post_quantum()
    + ratchet_feature_session_reset()
    + ratchet_feature_deniable_groups()
end

fn features_value() -> Bytes!String do
  case Bytes.from_list([session_features()]) do
    Err(_) -> Err("session_features_failed")
    Ok(value)
  end
end

fn inserted(extensions :: List<ProtocolExtension>,
  feature :: ProtocolExtension,
  index :: Int,
  output :: List<ProtocolExtension>,
  placed :: Bool) -> List<ProtocolExtension> do
  if index >= List.length(extensions) do
    if placed do
      output
    else
      List.append(output, feature)
    end
  else
    let extension = List.get(extensions, index)
    if extension.id == feature.id do
      inserted(extensions, feature, index + 1, output, placed)
    else if extension.id > feature.id && !placed do
      inserted(extensions,
        feature,
        index + 1,
        List.append(List.append(output, feature), extension),
        true)
    else
      inserted(extensions, feature, index + 1, List.append(output, extension), placed)
    end
  end
end

## The extensions of an outgoing inner envelope with this build's features in
## their place (extensions are in increasing identifier order).

pub fn with_session_features(extensions :: List<ProtocolExtension>) -> List<ProtocolExtension>!String do
  let feature = ProtocolExtension {
    id: ratchet_session_features_extension(),
    mandatory: false,
    value: features_value()?
  }
  Ok(inserted(extensions, feature, 0, List.new(), false))
end

## What an authenticated inner envelope says its sender supports: 0 from a
## build that predates the extension, or from a malformed one.

pub fn peer_session_features(extensions :: List<ProtocolExtension>) -> Int do
  case List.find(extensions, fn value -> value.id == ratchet_session_features_extension() end) do
    None -> 0
    Some(extension) -> if Bytes.length(extension.value) != 1 do
      0
    else
      case Bytes.get(extension.value, 0) do
        Err(_) -> 0
        Ok(value) -> value
      end
    end
  end
end

fn drop_candidate(state :: consume RatchetState) do
  nil
end

# ponytail: restores every session until one opens the header, O(sessions)
# unseals a message; keep an index of expected header keys if that shows.

## The session whose header keys open a version 4 message, which names none in
## the clear. `local_state_not_found` when none does, as for an unknown ID.

pub fn locate_header_session(database_path :: String,
  wrapping_key :: borrow StorageKey,
  message :: RatchetMessage,
  session_ids :: List<Bytes>,
  index :: Int) -> Result<(MobileLoadedSession, RatchetState), String> do
  if index >= List.length(session_ids) do
    Err("local_state_not_found")
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    if Bytes.length(loaded.record.snapshot) == 0 do
      locate_header_session(database_path, wrapping_key, message, session_ids, index + 1)
    else
      let state = restore_session(loaded, wrapping_key)?
      if ratchet_header_matches(state, message) do
        Ok((loaded, state))
      else
        drop_candidate(state)
        locate_header_session(database_path, wrapping_key, message, session_ids, index + 1)
      end
    end
  end
end
