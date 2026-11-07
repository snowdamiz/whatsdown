from Identity.Device import DeviceKeys
from Credits.Action import credit_action_id
from Credits.Attachment import credit_attachment_action
from Mobile.Attachments import decode_reference, seal_large_attachment_chunk
from Mobile.CreditAttachment import credit_attachment_reference, saved_credit_attachment_grant
from Mobile.CreditState import (
  CreditRecord,
  valid_credit_attachment_metadata,
  credit_attachment_cursor,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.Codec import mobile_read_u32, mobile_write_u32
from Storage.Blobs import load_blob
from Storage.CreditAttachment import insert_credit_attachment_part
from Mobile.CreditWallet import recover_credit_reservation
from Storage.Credits import (
  CreditWalletIdentity,
  credit_wallet_label,
  seal_credit_payload,
  open_credit_payload,
  load_credit_wallet,
  commit_credit_wallet,
  commit_credit_attachment_cleanup
)

fn part_label(who :: CreditWalletIdentity, nonce :: Bytes, index :: Int) -> String do
  "#{credit_wallet_label(who)}/attachment-part/#{Bytes.to_hex(nonce)}/#{index}"
end

fn opened_part(sealed :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  label :: String,
  index :: Int) -> List<Bytes>!String do
  if Bytes.length(sealed) > 70000 do
    return Err("invalid_credit_attachment_part")
  end
  let parts = unpack_credit_parts(open_credit_payload(sealed, wrapping, who, label)?, 2, 65576)?
  if List.length(parts) != 2 || Bytes.length(List.get(parts, 0)) != 32 do
    return Err("invalid_credit_attachment_part")
  end
  let wire = List.get(parts, 1)
  if Bytes.length(wire) < 41
    || Bytes.length(wire) > 65576
    || !List.contains(["02414348", "03414348", "04414348"],
      Bytes.to_hex(Bytes.slice(wire, 0, 4)?)) do
    return Err("invalid_credit_attachment_part")
  end
  let encoded_index = case Bytes.read_u32_be(wire, 4) do
    Err(_) -> return Err("invalid_credit_attachment_part")
    Ok(value) -> value
  end
  if encoded_index != U64.parse(Int.to_string(index))? do
    return Err("invalid_credit_attachment_part")
  end
  Ok(parts)
end

fn read_saved(path :: String, label :: String) -> Option<Bytes>!String do
  case load_blob(path, label) do
    Ok(value) -> Ok(Some(value))
    Err(error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
  end
end

fn same_plaintext(sealed :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  label :: String,
  index :: Int,
  plaintext :: Bytes) -> Bytes!String do
  let parts = opened_part(sealed, wrapping, who, label, index)?
  if !Bytes.secure_equals(List.get(parts, 0), Crypto.sha256(plaintext)) do
    return Err("credit_attachment_part_changed")
  end
  Ok(List.get(parts, 1))
end

# An exact staged ciphertext survives a lost PUT response and process restart.
# A changed plaintext for the same index cannot replace it. The SQLite CAS
# chooses one committed ciphertext before any caller may transmit the result.
pub fn seal_credit_attachment_part(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  device :: borrow DeviceKeys,
  nonce :: Bytes,
  index :: Int,
  plaintext :: Bytes,
  now_ms :: U64) -> Bytes!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let grant = saved_credit_attachment_grant(path, wrapping, who, nonce)?
  let operation_id = credit_action_id(credit_attachment_action(grant)?)?
  case find_credit_record(before.wallet, 4, operation_id) do
    None -> nil
    Some(_) -> if recover_credit_reservation(path, wrapping, who, operation_id)?.status == 2 do
      return Err("credit_reservation_cancelled")
    else
      nil
    end
  end
  if U64.compare(now_ms, grant.expires_at_ms) >= 0 do
    return Err("credit_attachment_expired")
  end
  if !Bytes.secure_equals(who.device_id, device.device_id)
    || index < 0
    || index >= 8192
    || Bytes.length(plaintext) < 1
    || Bytes.length(plaintext) > 65536 do
    return Err("invalid_credit_attachment_part")
  end
  let reference = credit_attachment_reference(path, wrapping, who, nonce)?
  let label = part_label(who, nonce, index)
  case read_saved(path, label)? do
    Some(sealed) -> return same_plaintext(sealed, wrapping, who, label, index, plaintext)
    None -> nil
  end
  let wire = seal_large_attachment_chunk(device, reference, index, plaintext)?
  let sealed = seal_credit_payload(pack_credit_parts([Crypto.sha256(plaintext), wire])?,
    wrapping,
    who,
    label)?
  case insert_credit_attachment_part(path, who, before, nonce, index, sealed) do
    Ok(_) -> Ok(wire)
    Err(error) -> if error == "local_state_changed" do
      same_plaintext(load_blob(path, label)?, wrapping, who, label, index, plaintext)
    else
      Err(error)
    end
  end
end

pub fn recover_credit_attachment_part(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  index :: Int) -> Bytes!String do
  if index < 0 || index >= 8192 do
    return Err("invalid_credit_attachment_part")
  end
  decode_reference(credit_attachment_reference(path, wrapping, who, nonce)?)?
  let label = part_label(who, nonce, index)
  Ok(List.get(opened_part(load_blob(path, label)?, wrapping, who, label, index)?, 1))
end

# At most128 sealed part records are removed per call. Early cleanup requires
# a verified non-consumption receipt. Pending/completed grants retain their
# recovery window because a dropped upload response may still need the parts.
pub fn prune_credit_attachment_parts(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  start :: Int,
  now_ms :: U64) -> Int!String do
  let grant = saved_credit_attachment_grant(path, wrapping, who, nonce)?
  if U64.compare(now_ms, U64.add(grant.expires_at_ms, U64.parse("604800000")?)?) < 0 do
    let id = credit_action_id(credit_attachment_action(grant)?)?
    let spend = case recover_credit_reservation(path, wrapping, who, id) do
      Err(_) -> return Err("credit_attachment_recovery_active")
      Ok(value) -> value
    end
    if spend.status != 2 do
      return Err("credit_attachment_recovery_active")
    end
  end
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 6, nonce) do
    None -> return Err("credit_attachment_not_found")
    Some(value) -> value
  end
  if !valid_credit_attachment_metadata(record.metadata)
    || credit_attachment_cursor(record.metadata)? != start do
    return Err("invalid_credit_attachment_cleanup")
  end
  let count = (grant.size_bytes + 65535) / 65536
  if start < 0 || start >= count || start % 128 != 0 do
    return Err("invalid_credit_attachment_cleanup")
  end
  let stop = if start + 128 < count do
    start + 128
  else
    count
  end
  let wallet = if stop == count do
    %{before.wallet |
      records: List.filter(before.wallet.records,
        fn(value) do value.kind != 6 || !Bytes.secure_equals(value.id, nonce) end)
    }
  else
    put_credit_record(before.wallet,
      CreditRecord {
        kind: record.kind,
        id: record.id,
        payload: record.payload,
        metadata: Bytes.concat(Bytes.concat(Bytes.slice(record.metadata, 0, 4)?,
            mobile_write_u32(stop)?)?,
          Bytes.slice(record.metadata, 8, Bytes.length(record.metadata) - 8)?)?
      })
  end
  commit_credit_attachment_cleanup(path,
    wrapping,
    who,
    before,
    %{wallet | revision: U64.add(wallet.revision, U64.parse("1")?)?},
    nonce,
    start,
    stop)?
  Ok(stop)
end
