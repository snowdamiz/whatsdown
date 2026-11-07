from Mobile.CreditState import find_credit_record
from Mobile.CreditWallet import credit_operation_nonce_seen
from Mobile.Codec import mobile_write_u64, mobile_read_u64, random_bytes
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.CreditMaintenance import load_credit_maintenance

# Public opaque32-byte operation nonce: timestamp8BE plus192 CSPRNG bits.
# It is not a secret or an authorization. The timestamp makes retired native
# intents rejectable without an unbounded permanent tombstone collection.
pub fn issued_credit_intent_nonce(now_ms :: U64) -> Bytes!String do
  if now_ms == U64.parse("0")? do
    return Err("credit_preview_expired")
  end
  Bytes.concat(mobile_write_u64(now_ms)?, random_bytes(24)?)
end

pub fn require_fresh_credit_intent_nonce(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  kind :: Int,
  nonce :: Bytes,
  now_ms :: U64) -> Result<(), String> do
  if Bytes.length(nonce) != 32 || (kind != 1 && kind != 3) do
    return Err("invalid_credit_intent_nonce")
  end
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let material_kind = if kind == 1 do
    6
  else
    8
  end
  # The exact material parser/binding check still runs in the real builder.
  # This exemption preserves every previously persisted legacy nonce/retry.
  if Option.is_some(find_credit_record(wallet, material_kind, nonce)) do
    return Ok(nil)
  end
  if credit_operation_nonce_seen(wallet, kind, nonce)? do
    return Err("credit_intent_retired")
  end
  let clock = load_credit_maintenance(path, wrapping, who)?
  let watermark = U64.multiply(clock.watermark, U64.parse("1000")?)?
  let timestamp = if U64.compare(now_ms, watermark) >= 0 do
    now_ms
  else
    watermark
  end
  let issued = mobile_read_u64(Bytes.slice(nonce, 0, 8)?)?
  if issued == U64.parse("0")? || U64.compare(issued, timestamp) > 0 do
    return Err("credit_preview_expired")
  end
  if U64.compare(U64.subtract(timestamp, issued)?, U64.parse("900000")?) > 0 do
    return Err("credit_preview_expired")
  end
  Ok(nil)
end
