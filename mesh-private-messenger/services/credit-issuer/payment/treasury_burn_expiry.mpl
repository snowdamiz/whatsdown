from Runtime.Treasury import TreasuryWorkerConfig
from Payment.TreasuryBurn import treasury_burn_check_sources, treasury_burn_check_genesis
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnExpiryRead import (
  TokenBurnExpiryBank,
  token_burn_expiry_read_keys,
  decode_token_burn_expiry_snapshot
)
from Solana.Read import (
  rpc_send,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response
)

fn one_expiry(client :: Int,
  url :: String,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  id :: Int) -> TokenBurnExpiryBank!String do
  treasury_burn_check_genesis(client, url, worker, id)?
  let request = get_multiple_accounts_slice_request(id + 1,
    token_burn_expiry_read_keys(pins, epoch)?,
    "finalized",
    0,
    320,
    None)?
  let response = rpc_send(client, url, request, 5000, 65536)?
  decode_token_burn_expiry_snapshot(pins,
    epoch,
    U64.parse("0")?,
    optional_accounts_slice_from_response(response)?)
end

fn expiry_quorum(client :: Int,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64) -> TokenBurnExpiryBank!String do
  treasury_burn_check_sources(worker, pins)?
  let first = one_expiry(client, List.get(worker.providers, 0), worker, pins, epoch, 350)?
  let second = one_expiry(client, List.get(worker.providers, 1), worker, pins, epoch, 360)?
  # Both complete banks authenticate independently. Heads, clock and donated
  # rent can progress, while immutable context and the exact pair must agree.
  if first.footprint != second.footprint do
    return Err("treasury_burn_expiry_quorum_mismatch")
  end
  Ok(first)
end

# An absent pair permits preparation only. Runtime must require the permanent
# authenticated pair before releasing any reservation; no caller Boolean exists.
pub fn read_treasury_burn_expiry_bank(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64) -> TokenBurnExpiryBank!String do
  let client = Http.client()
  let result = expiry_quorum(client, worker, pins, epoch)
  Http.client_close(client)
  result
end
