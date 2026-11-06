from Solana.Read import (
  AccountAtSlot,
  RpcResponse,
  Pubkey,
  get_account_info_request,
  account_from_response,
  rpc_send
)
from Payment.Pyth import pyth_price_from_account

pub struct BtcPrice do
  usd_micros :: U64
  observed_at :: U64
  slot :: U64
end

pub fn btc_price_from_account(value :: AccountAtSlot, now :: U64) -> BtcPrice!String do
  let price = pyth_price_from_account(value,
    Bytes.from_hex("e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43")?,
    now)?
  Ok(BtcPrice { usd_micros: price.usd_micros, observed_at: price.observed_at, slot: price.slot })
end

pub fn btc_price_from_response(response :: RpcResponse, id :: Int, now :: U64) -> BtcPrice!String do
  if response.id != id do
    return Err("mismatched_btc_price_response")
  end
  btc_price_from_account(account_from_response(response)?, now)
end

# The address is operator-pinned configuration, never a quote request field.
# Trust in the finalized RPC view is the same as the payment verifier's.
pub fn read_btc_price(client :: Int,
  url :: String,
  address :: Pubkey,
  id :: Int,
  now :: U64) -> BtcPrice!String do
  let request = get_account_info_request(id, address, "finalized")?
  btc_price_from_response(rpc_send(client, url, request, 5000, 4096)?, id, now)
end
