from Mobile.Codec import mobile_utf8
from Mobile.Types import MobilePayloadRequest, MobileTriplePayloadRequest
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_record_changes

##! The app's own notes on which messages were read, announced and acknowledged.
##!
##! They hold no message text, but they name chats and say when each was used, so
##! the app hands them to the core to seal instead of keeping them in the clear.
##! The core does not interpret them. It does fix where they may be kept: one of
##! three journals, and in it a chat, a group, or the list of those that have a
##! record, so that nothing else the device stores can be read or written this way.

fn journal_label(key :: Bytes) -> String ! String do
  let text = mobile_utf8(key, "invalid_journal_key") ?
  if Regex.is_match(~r/^(read-state|notification-state|receipt-marks)\/(index|chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/,
  text) do
    Ok("journal/v1/" <> text)
  else
    Err("invalid_journal_key")
  end
end

# Empty when there is no such record.

pub fn load_journal(request :: MobilePayloadRequest) -> Bytes ! String do
  let label = journal_label(request.payload) ?
  let wrapping_key = platform_key() ?
  case load_blob(request.database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok( blob) -> open_local(blob, wrapping_key, local_context(label) ?)
  end
end

# A request cannot carry an empty value, so a single zero byte, which no record
# is, removes the record.

pub fn save_journal(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  let label = journal_label(request.first) ?
  let wrapping_key = platform_key() ?
  if Bytes.length(request.second) > 262144 do
    Err("journal_record_too_large")
  else if Bytes.secure_equals(request.second, Bytes.from_hex("00") ?) do
    store_record_changes(request.database_path, List.new(), List.new(), [label]) ?
    Ok(Bytes.empty())
  else
    let sealed = seal_local(request.second, wrapping_key, local_context(label) ?) ?
    store_record_changes(request.database_path, [label], [sealed], List.new()) ?
    Ok(Bytes.empty())
  end
end
