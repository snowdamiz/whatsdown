from Solana.Read import (
  AccountAtSlot,
  RpcResponse,
  Pubkey,
  get_account_info_request,
  account_from_response,
  rpc_send
)
from Payment.Pyth import pyth_price_from_account

pub struct SolPrice do
  usd_micros :: U64
  observed_at :: U64
  slot :: U64
end

pub fn sol_price_from_account(value :: AccountAtSlot, now :: U64) -> SolPrice!String do
  let price = pyth_price_from_account(value,
    Bytes.from_hex("ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d")?,
    now)?
  Ok(SolPrice { usd_micros: price.usd_micros, observed_at: price.observed_at, slot: price.slot })
end

pub fn sol_price_from_response(response :: RpcResponse, id :: Int, now :: U64) -> SolPrice!String do
  if response.id != id do
    return Err("mismatched_sol_price_response")
  end
  sol_price_from_account(account_from_response(response)?, now)
end

# The address is operator-pinned configuration, never a quote request field.
# Trust in the finalized RPC view is the same as the payment verifier's.
pub fn read_sol_price(client :: Int,
  url :: String,
  address :: Pubkey,
  id :: Int,
  now :: U64) -> SolPrice!String do
  let request = get_account_info_request(id, address, "finalized")?
  sol_price_from_response(rpc_send(client, url, request, 5000, 4096)?, id, now)
end
