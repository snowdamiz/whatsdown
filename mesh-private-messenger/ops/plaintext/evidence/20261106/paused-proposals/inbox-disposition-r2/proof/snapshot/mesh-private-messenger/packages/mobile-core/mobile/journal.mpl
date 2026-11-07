from Mobile.Codec import mobile_utf8
from Mobile.Types import MobilePayloadRequest, MobileTriplePayloadRequest
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Storage.JournalBlobs import open_journal_blob, seal_journal_blob
from Storage.Records import store_record_changes

##! The app's own notes on which messages were read, announced and acknowledged.
##!
##! They hold no message text, but they name chats and say when each was used, so
##! the app hands them to the core to seal instead of keeping them in the clear.
##! The core does not interpret them. It does fix where they may be kept: one of
##! three journals, and in it a chat, a group, or the list of those that have a
##! record; or the requests to join a community an admin declined, by chat. Nothing
##! else the device stores can be read or written this way.

pub fn journal_label(key :: Bytes) -> String!String do
  let text = mobile_utf8(key, "invalid_journal_key")?
  if Regex.is_match(~r/^(read-state|notification-state|receipt-marks)\/(index|chat\/[a-f0-9]{32}|group\/[a-f0-9]{64})$/,
    text)
    || Regex.is_match(~r/^preferences\/(read-receipts|notification-preview|desktop-notifications)$/,
      text)
    || Regex.is_match(~r/^community-requests\/(index|chat\/[a-f0-9]{32})$/, text) do
    Ok("journal/v1/" <> text)
  else
    Err("invalid_journal_key")
  end
end

# Empty when there is no such record.

pub fn load_journal(request :: MobilePayloadRequest) -> Bytes!String do
  let label = journal_label(request.payload)?
  let wrapping_key = platform_key()?
  case load_blob(request.database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_journal_blob(blob, wrapping_key, label)
  end
end

# A request cannot carry an empty value, so a single zero byte, which no record
# is, removes the record.

pub fn save_journal(request :: MobileTriplePayloadRequest) -> Bytes!String do
  let label = journal_label(request.first)?
  validate_journal_value(label, request.second)?
  let wrapping_key = platform_key()?
  if Bytes.length(request.second) > 262144 do
    Err("journal_record_too_large")
  else if Bytes.secure_equals(request.second, Bytes.from_hex("00")?) do
    store_record_changes(request.database_path, List.new(), List.new(), [label])?
    Ok(Bytes.empty())
  else
    let sealed = seal_journal_blob(request.second, wrapping_key, label)?
    store_record_changes(request.database_path, [label], [sealed], List.new())?
    Ok(Bytes.empty())
  end
end

pub fn validate_journal_value(label :: String, value :: Bytes) -> Result<(), String> do
  if Bytes.secure_equals(value, Bytes.from_hex("00")?) do
    return Ok(nil)
  end
  let allowed = if label == "journal/v1/preferences/read-receipts"
    || label == "journal/v1/preferences/desktop-notifications" do
    ["on", "off"]
  else if label == "journal/v1/preferences/notification-preview" do
    ["full", "sender", "none"]
  else
    return Ok(nil)
  end
  if List.any(allowed, fn(choice) -> Bytes.secure_equals(value, Bytes.from_utf8(choice)) end) do
    Ok(nil)
  else
    Err("invalid_journal_preference")
  end
end
