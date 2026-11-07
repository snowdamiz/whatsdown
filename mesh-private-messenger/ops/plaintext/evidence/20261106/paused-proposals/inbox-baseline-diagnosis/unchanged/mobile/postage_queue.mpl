from Mobile.CreditState import credit_record_id, pack_credit_parts, unpack_credit_parts
from Storage.Blobs import load_blob
from Storage.Credits import CreditCacheWrite
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import compare_and_swap_blobs

pub struct PostageQueueRow do
  nonce :: Bytes
  ids :: List<Bytes>
end

pub struct PostageQueueSnapshot do
  rows :: List<PostageQueueRow>
  previous :: Bytes
end

fn postage_queue_label() -> String do
  "postage-queue/v1"
end

fn queue_bytes(rows :: List<PostageQueueRow>) -> Bytes!String do
  if List.length(rows) > 16 do
    return Err("credit_postage_capacity")
  end
  let flat = List.flat_map(rows, fn(row) -> row.ids end)
  for index in 0..List.length(flat) do
    if Bytes.length(List.get(flat, index)) != 16 do
      return Err("invalid_postage_queue")
    end
    for prior in 0..index do
      if Bytes.secure_equals(List.get(flat, prior), List.get(flat, index)) do
        return Err("credit_postage_message_already_reserved")
      end
    end
  end
  let encoded = for index in 0..List.length(rows) do
    let row = List.get(rows, index)
    if !credit_record_id(row.nonce) || List.length(row.ids) < 1 || List.length(row.ids) > 8 do
      return Err("invalid_postage_queue")
    end
    for prior in 0..index do
      if Bytes.secure_equals(List.get(rows, prior).nonce, row.nonce) do
        return Err("invalid_postage_queue")
      end
    end
    pack_credit_parts([row.nonce] ++ row.ids)?
  end
  pack_credit_parts(encoded)
end

pub fn load_postage_queue(path :: String,
  wrapping :: borrow StorageKey) -> PostageQueueSnapshot!String do
  let previous = case load_blob(path, postage_queue_label()) do
    Err(error) -> if error == "local_state_not_found" do
      Bytes.empty()
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  if Bytes.length(previous) == 0 do
    return Ok(PostageQueueSnapshot { rows: [], previous: previous })
  end
  let encoded = open_local(previous, wrapping, local_context(postage_queue_label())?)?
  let rows = for item in unpack_credit_parts(encoded, 16, 256)? do
    let parts = unpack_credit_parts(item, 9, 32)?
    if List.length(parts) < 2 do
      return Err("invalid_postage_queue")
    end
    PostageQueueRow { nonce: List.head(parts), ids: List.drop(parts, 1) }
  end
  if !Bytes.secure_equals(queue_bytes(rows)?, encoded) do
    return Err("invalid_postage_queue")
  end
  Ok(PostageQueueSnapshot { rows: rows, previous: previous })
end

# This cache update MUST share the wallet's kind8-creation CAS transaction.
# Ordinary outbox reads need no credit configuration to honor ownership.
pub fn postage_queue_cache(snapshot :: PostageQueueSnapshot,
  nonce :: Bytes,
  ids :: List<Bytes>,
  wrapping :: borrow StorageKey) -> CreditCacheWrite!String do
  let rows = snapshot.rows ++ [PostageQueueRow { nonce: nonce, ids: ids }]
  Ok(CreditCacheWrite {
    label: postage_queue_label(),
    previous: snapshot.previous,
    value: seal_local(queue_bytes(rows)?, wrapping, local_context(postage_queue_label())?)?
  })
end

pub fn postage_owned_ids(path :: String, wrapping :: borrow StorageKey) -> List<Bytes>!String do
  Ok(List.flat_map(load_postage_queue(path, wrapping)?.rows, fn(row) -> row.ids end))
end

# Safe after a verified CAR has acknowledged every original envelope, or after
# a signed cancellation. A crash before this conservative cleanup is recoverable.
pub fn forget_postage_queue(path :: String,
  wrapping :: borrow StorageKey,
  nonce :: Bytes) -> Result<(), String> do
  let before = load_postage_queue(path, wrapping)?
  let rows = List.filter(before.rows, fn(row) -> !Bytes.secure_equals(row.nonce, nonce) end)
  if List.length(rows) == List.length(before.rows) do
    return Ok(nil)
  end
  let sealed = seal_local(queue_bytes(rows)?, wrapping, local_context(postage_queue_label())?)?
  compare_and_swap_blobs(path, [postage_queue_label()], [sealed], before.previous)
end

# Capture before reading the exact fanout/outer frames. These are read-only
# guards in the same wallet + queue-ownership commit, never replacement writes.
pub fn postage_outbox_guards(path :: String) -> List<CreditCacheWrite>!String do
  let rows = for label in ["profile/v1", "outbox/v1", "delivery/v1"] do
    let previous = case load_blob(path, label) do
      Ok(value) -> value
      Err("local_state_not_found") -> Bytes.empty()
      Err(error) -> return Err(error)
    end
    if label != "delivery/v1" && Bytes.length(previous) == 0 do
      return Err("credit_postage_outbox_changed")
    end
    CreditCacheWrite { label: label, previous: previous, value: Bytes.empty() }
  end
  Ok(rows)
end
