from Mobile.CreditState import valid_credit_attachment_metadata, credit_attachment_cursor
from Credits.Action import credit_action_id
from Credits.Attachment import credit_attachment_action
from Mobile.Codec import mobile_read_u32
from Mobile.CreditAttachment import saved_credit_attachment_grant
from Mobile.CreditAttachmentParts import prune_credit_attachment_parts
from Mobile.CreditWallet import (
  CreditHistoryPrune,
  credit_reservation_status,
  prune_credit_history_after_attachment
)
from Storage.CreditMaintenance import load_credit_maintenance
from Storage.Credits import CreditWalletIdentity, load_credit_wallet

# One material cursor (at most128 original part labels), then at most64 shared
# token/reservation records per explicit refresh. Never perform network work.
pub fn maintain_credit_storage(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  now :: U64) -> CreditHistoryPrune!String do
  let clock = load_credit_maintenance(path, wrapping, who)?
  let timestamp = if U64.compare(now, clock.watermark) < 0 do
    clock.watermark
  else
    now
  end
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let records = List.sort(List.filter(wallet.records, fn(record) -> record.kind == 6 end),
    fn(left, right) do
      if Bytes.to_hex(left.id) < Bytes.to_hex(right.id) do
        -1
      else if Bytes.to_hex(left.id) > Bytes.to_hex(right.id) do
        1
      else
        0
      end
    end)
  let following = List.filter(records,
    fn(record) -> Bytes.to_hex(record.id) > Bytes.to_hex(clock.attachment_cursor) end)
  let candidates = if List.length(following) == 0 do
    records
  else
    following
  end
  let next_cursor = if List.length(candidates) == 0 do
    clock.attachment_cursor
  else
    let record = List.head(candidates)
    let grant = saved_credit_attachment_grant(path, wrapping, who, record.id)?
    let operation = credit_action_id(credit_attachment_action(grant)?)?
    let expired = U64.compare(U64.multiply(timestamp, U64.parse("1000")?)?,
      U64.add(grant.expires_at_ms, U64.parse("604800000")?)?) >= 0
    let eligible = case credit_reservation_status(wallet, operation)? do
      None -> expired
      Some(0) -> false
      Some(1) -> expired
      Some(2) -> true
      Some(_) -> return Err("invalid_credit_reservation")
    end
    if eligible do
      if !valid_credit_attachment_metadata(record.metadata) do
        return Err("invalid_credit_attachment_material")
      end
      let start = credit_attachment_cursor(record.metadata)?
      let stop = prune_credit_attachment_parts(path,
        wrapping,
        who,
        record.id,
        start,
        U64.multiply(timestamp, U64.parse("1000")?)?)?
      if stop == (grant.size_bytes + 65535) / 65536 do
        record.id
      else
        clock.attachment_cursor
      end
    else
      record.id
    end
  end
  prune_credit_history_after_attachment(path, wrapping, who, timestamp, Some(next_cursor))
end
