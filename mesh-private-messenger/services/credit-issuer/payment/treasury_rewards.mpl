from Payment.Treasury import TreasuryChainConfig
from Runtime.Treasury import TreasuryWorkerConfig, treasury_provider_hash
from Solana.Read import (
  Pubkey,
  clock_sysvar_address,
  clock_sysvar,
  get_multiple_accounts_context_request,
  optional_accounts_from_response,
  rpc_request,
  rpc_send
)
from Transparency.RewardsChain import (
  RewardFundingReceipt,
  decode_reward_funding_receipt,
  reward_funding_address,
  reward_pool_address
)

pub struct TreasuryFundingProof do
  current_epoch :: U64
  receipt_bytes :: Bytes
  receipt :: Option<RewardFundingReceipt>
end

fn one_funding_proof(client :: Int,
  url :: String,
  config :: TreasuryChainConfig,
  operation_id :: Bytes,
  id :: Int) -> TreasuryFundingProof!String do
  let genesis = rpc_send(client, url, rpc_request(id + 10, "getGenesisHash", "[]")?, 3000, 4096)?
  if !genesis.ok
    || !Bytes.secure_equals(Bytes.from_base58(Json.as_string(Json.parse(genesis.result_json)?)?)?,
      config.cluster) do
    return Err("treasury_cluster_mismatch")
  end
  let receipt_address = reward_funding_address(Pubkey { bytes: config.rewards_program },
    Pubkey { bytes: config.treasury_owner },
    operation_id)?
  if !Bytes.secure_equals(reward_pool_address(Pubkey { bytes: config.rewards_program })?.bytes,
    config.rewards_pool) do
    return Err("treasury_rewards_pool_mismatch")
  end
  let request = get_multiple_accounts_context_request(id,
    [receipt_address, clock_sysvar_address()?],
    "finalized",
    None)?
  let response = rpc_send(client, url, request, 3000, 8192)?
  let batch = optional_accounts_from_response(response)?
  if List.length(batch.accounts) != 2 do
    return Err("treasury_funding_account_count")
  end
  let clock_account = case List.get(batch.accounts, 1) do
    Some(value) -> value
    None -> return Err("missing_treasury_chain_clock")
  end
  let clock = clock_sysvar(clock_account)?
  if clock.slot != batch.slot || clock.unix_timestamp <= 0 do
    return Err("treasury_funding_clock_mismatch")
  end
  let epoch = U64.divide(U64.parse(Int.to_string(clock.unix_timestamp))?, U64.parse("604800")?)?
  case List.get(batch.accounts, 0) do
    None -> Ok(TreasuryFundingProof {
      current_epoch: epoch,
      receipt_bytes: Bytes.empty(),
      receipt: None
    })
    Some(account) -> do
      if account.executable
        || account.lamports == U64.parse("0")?
        || !Bytes.secure_equals(account.owner.bytes, config.rewards_program) do
        return Err("invalid_treasury_funding_owner")
      end
      let receipt = decode_reward_funding_receipt(account.data)?
      if !Bytes.secure_equals(receipt.funder, config.treasury_owner)
        || !Bytes.secure_equals(receipt.operation_id, operation_id)
        || U64.compare(receipt.funded_at, U64.parse(Int.to_string(clock.unix_timestamp))?) > 0 do
        return Err("treasury_funding_receipt_mismatch")
      end
      Ok(TreasuryFundingProof {
        current_epoch: epoch,
        receipt_bytes: account.data,
        receipt: Some(receipt)
      })
    end
  end
end

fn read_funding(client :: Int,
  config :: TreasuryWorkerConfig,
  operation_id :: Bytes) -> TreasuryFundingProof!String do
  if !Bytes.secure_equals(treasury_provider_hash(config.providers)?, config.chain.providers_hash) do
    return Err("treasury_provider_pin_mismatch")
  end
  for url in config.providers do
    let loopback = String.starts_with(url, "http://127.0.0.1:")
      || String.starts_with(url, "http://localhost:")
    if !String.starts_with(url, "https://") && !(config.test_mode && loopback) do
      return Err("treasury_provider_requires_tls")
    end
  end
  let first = one_funding_proof(client,
    List.get(config.providers, 0),
    config.chain,
    operation_id,
    260)?
  let second = one_funding_proof(client,
    List.get(config.providers, 1),
    config.chain,
    operation_id,
    261)?
  if first.current_epoch != second.current_epoch
    || !Bytes.secure_equals(first.receipt_bytes, second.receipt_bytes) do
    return Err("treasury_funding_quorum_mismatch")
  end
  Ok(first)
end

# Receipt and Clock are read from the same finalized bank on each pinned provider.
# Permanent receipt absence plus a later chain epoch can close only an unfunded
# old intent; nonce changes and HTTP acknowledgments cannot discharge liability.
pub fn read_treasury_funding(config :: TreasuryWorkerConfig,
  operation_id :: Bytes) -> TreasuryFundingProof!String do
  let client = Http.client()
  let result = read_funding(client, config, operation_id)
  Http.client_close(client)
  result
end
