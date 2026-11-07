from Storage.Blobs import load_blob
from Storage.Credits import (
  CreditWalletIdentity,
  CreditCacheWrite,
  credit_wallet_label,
  credit_context
)
from Storage.Keys import open_local, seal_local
from Mobile.Codec import mobile_read_u64, mobile_write_u64

pub struct CreditMaintenanceSnapshot do
  cursor :: Bytes
  watermark :: U64
  attachment_cursor :: Bytes
  previous :: Bytes
end

pub fn credit_maintenance_label(who :: CreditWalletIdentity) -> String do
  credit_wallet_label(who) <> "/maintenance"
end

pub fn load_credit_maintenance(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditMaintenanceSnapshot!String do
  let previous = case load_blob(path, credit_maintenance_label(who)) do
    Err("local_state_not_found") -> Bytes.empty()
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  if Bytes.length(previous) == 0 do
    return Ok(CreditMaintenanceSnapshot {
      cursor: Bytes.from_hex(String.repeat("00", 33))?,
      attachment_cursor: Bytes.from_hex(String.repeat("00", 32))?,
      watermark: U64.parse("0")?,
      previous: previous
    })
  end
  let value = open_local(previous, wrapping, credit_context(who, "maintenance")?)?
  if (Bytes.length(value) != 45 && Bytes.length(value) != 77)
    || Bytes.to_hex(Bytes.slice(value, 0, 4)?) != "01434d41" do
    return Err("invalid_credit_maintenance")
  end
  Ok(CreditMaintenanceSnapshot {
    cursor: Bytes.slice(value, 4, 33)?,
    attachment_cursor: if Bytes.length(value) == 77 do
      Bytes.slice(value, 45, 32)?
    else
      Bytes.from_hex(String.repeat("00", 32))?
    end,
    watermark: mobile_read_u64(Bytes.slice(value, 37, 8)?)?,
    previous: previous
  })
end

pub fn credit_maintenance_write(before :: CreditMaintenanceSnapshot,
  cursor :: Bytes,
  watermark :: U64,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditCacheWrite!String do
  if Bytes.length(cursor) != 33
    || Bytes.length(before.attachment_cursor) != 32
    || U64.compare(watermark, before.watermark) < 0 do
    return Err("invalid_credit_maintenance")
  end
  let value = Bytes.concat(Bytes.concat(Bytes.from_hex("01434d41")?, cursor)?,
    Bytes.concat(mobile_write_u64(watermark)?, before.attachment_cursor)?)?
  Ok(CreditCacheWrite {
    label: credit_maintenance_label(who),
    previous: before.previous,
    value: seal_local(value, wrapping, credit_context(who, "maintenance")?)?
  })
end
