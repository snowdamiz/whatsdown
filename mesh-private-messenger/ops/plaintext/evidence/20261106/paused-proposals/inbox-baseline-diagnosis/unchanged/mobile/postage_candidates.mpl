from Mobile.Codec import canonical_outer
from Mobile.CreditState import pack_credit_parts
from Mobile.Delivery import load_delivery
from Mobile.History import postage_message_recipient
from Mobile.Outbox import load_outbox_ids, load_postage_outbox_entries
from Mobile.PostageQueue import postage_owned_ids
from Mobile.Types import MobileVerifiedDeviceSet

pub struct PostageCandidate do
  message_id :: Bytes
  trigger_id :: Bytes
  ids :: List<Bytes>
end

pub fn postage_message_id(path :: String,
  wrapping :: borrow StorageKey,
  trigger :: Bytes) -> Bytes!String do
  if Bytes.length(trigger) != 16 || !List.contains(load_outbox_ids(path, wrapping)?, trigger) do
    return Err("invalid_postage_candidate")
  end
  let found = List.filter(load_delivery(path, wrapping)?,
    fn(row) -> row.kind == 1 && Bytes.secure_equals(row.envelope_id, trigger) end)
  if List.length(found) != 1 || Bytes.length(List.head(found).message_id) != 16 do
    return Err("unsupported_postage_message")
  end
  Ok(List.head(found).message_id)
end

# One trigger comes from the exact envelope refused402. The native delivery
# links select its logical message; JS cannot combine different messages into a
# cheap batch or cause one prompt/payment for every linked device.
pub fn postage_candidate(path :: String,
  wrapping :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet,
  trigger :: Bytes) -> PostageCandidate!String do
  let message = postage_message_id(path, wrapping, trigger)?
  let queued = load_outbox_ids(path, wrapping)?
  let owned = postage_owned_ids(path, wrapping)?
  let linked = List.filter(load_delivery(path, wrapping)?,
    fn(row) -> row.kind == 1
      && Bytes.secure_equals(row.message_id, message)
      && List.contains(queued, row.envelope_id) end)
  let ids = for row in linked do
    row.envelope_id
  end
  if List.length(ids) != List.length(devices.value.devices)
    || List.length(ids) < 1
    || List.length(ids) > 8
    || List.any(ids, fn(id) -> List.contains(owned, id) end) do
    return Err("incomplete_postage_fanout")
  end
  let outers = load_postage_outbox_entries(path, wrapping, ids)?
  let ordered = for entry in devices.value.devices do
    let matches = List.filter(outers,
      fn(raw) do
        case canonical_outer(raw) do
          Err(_) -> false
          Ok(value) -> Bytes.secure_equals(value.mailbox_token, entry.mailbox_token)
        end
      end)
    if List.length(matches) != 1 do
      return Err("invalid_credit_postage_outbox")
    end
    canonical_outer(List.head(matches))?.envelope_id
  end
  if !List.contains(ordered, trigger) || List.length(devices.expired) > 0 do
    return Err("invalid_postage_candidate")
  end
  Ok(PostageCandidate { message_id: message, trigger_id: trigger, ids: ordered })
end

pub fn require_postage_fanout(path :: String,
  wrapping :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet,
  ids :: List<Bytes>) -> PostageCandidate!String do
  if List.length(ids) < 1 do
    return Err("invalid_postage_candidate")
  end
  let candidate = postage_candidate(path, wrapping, devices, List.head(ids))?
  if !Bytes.secure_equals(pack_credit_parts(candidate.ids)?, pack_credit_parts(ids)?) do
    return Err("invalid_postage_fanout_order")
  end
  Ok(candidate)
end
