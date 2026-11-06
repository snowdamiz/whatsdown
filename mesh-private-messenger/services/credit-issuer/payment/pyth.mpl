from Solana.Read import AccountAtSlot, pubkey, pubkey_equal

pub struct PythPrice do
  usd_micros :: U64
  observed_at :: U64
  slot :: U64
end

fn number(data :: Bytes, offset :: Int, width :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, offset, width)?)
end

fn power10(exponent :: Int, value :: U128) -> U128!String do
  if exponent == 0 do
    Ok(value)
  else
    power10(exponent - 1, U128.multiply(value, U128.parse("10")?)?)
  end
end

# PriceUpdateV2 Borsh layout, full guardian verification only. The final byte
# is unused allocation space for the larger Partial enum variant; it is not a
# field and may retain old data. The receiver program and feed are pins.
pub fn pyth_price_from_account(value :: AccountAtSlot,
  feed :: Bytes,
  now :: U64) -> PythPrice!String do
  let account = value.account
  let data = account.data
  if account.executable
    || !pubkey_equal(account.owner, pubkey("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp")?)
    || Bytes.length(data) != 134
    || Bytes.to_hex(Bytes.slice(data, 0, 8)?) != "22f123639d7ef4cd"
    || Bytes.to_hex(Bytes.slice(data, 40, 1)?) != "01"
    || Bytes.length(feed) != 32
    || !Bytes.secure_equals(Bytes.slice(data, 41, 32)?, feed) do
    return Err("unverified_pyth_price")
  end
  let price = number(data, 73, 8)?
  let confidence = number(data, 81, 8)?
  let encoded_exponent = U64.to_int(number(data, 89, 4)?)?
  let exponent = if encoded_exponent >= 2147483648 do
    encoded_exponent - 4294967296
  else
    encoded_exponent
  end
  let published = number(data, 93, 8)?
  let previous = number(data, 101, 8)?
  let posted_slot = number(data, 125, 8)?
  if price == U64.parse("0")?
    || U64.compare(price, U64.parse("9223372036854775807")?) > 0
    || exponent < -12
    || exponent > 0
    || U64.compare(published, now) > 0
    || U64.compare(U64.subtract(now, published)?, U64.parse("60")?) > 0
    || U64.compare(previous, published) > 0
    || posted_slot == U64.parse("0")?
    || U64.compare(posted_slot, value.slot) > 0 do
    return Err("invalid_or_stale_pyth_price")
  end
  let wide_price = U128.parse(U64.to_string(price))?
  if U128.compare(U128.multiply(U128.parse(U64.to_string(confidence))?, U128.parse("100")?)?,
    wide_price) > 0 do
    return Err("uncertain_pyth_price")
  end
  # Floor the USD value, then each payment policy rounds the payment up. This avoids
  # binary floating point and never rounds a customer's payment down.
  let micros = U128.divide(U128.multiply(wide_price, U128.parse("1000000")?)?,
    power10(-exponent, U128.parse("1")?)?)?
  let converted = U64.parse(U128.to_string(micros))?
  if converted == U64.parse("0")? do
    return Err("invalid_pyth_price")
  end
  Ok(PythPrice { usd_micros: converted, observed_at: published, slot: value.slot })
end
