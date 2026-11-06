from Payment.SolConversionPacket import SolConversionProfile
from Solana.Read import Pubkey, pubkey

pub fn conversion_fixture_text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn key(root :: Json, name :: String) -> Pubkey!String do
  pubkey(conversion_fixture_text(root, name)?)
end

pub fn conversion_fixture_profile(root :: Json) -> SolConversionProfile!String do
  Ok(SolConversionProfile {
    treasury_config: Bytes.from_hex(conversion_fixture_text(root, "treasury_config")?)?,
    owner: key(root, "owner")?,
    payer: key(root, "payer")?,
    usdc: key(root, "usdc")?,
    pool: key(root, "pool")?,
    amm_config: key(root, "amm_config")?,
    authority: key(root, "authority")?,
    input_vault: key(root, "input_vault")?,
    output_vault: key(root, "output_vault")?,
    observation: key(root, "observation")?,
    oracle: key(root, "oracle")?,
    raydium_code: Bytes.from_hex(conversion_fixture_text(root, "raydium_code")?)?,
    token_code: Bytes.from_hex(conversion_fixture_text(root, "token_code")?)?,
    amm_hash: Bytes.from_hex(conversion_fixture_text(root, "amm_hash")?)?,
    rent: U64.parse(conversion_fixture_text(root, "rent")?)?,
    maximum_fee: U64.parse("100000")?
  })
end

from Payment.SolConversionBank import (
  admit_sol_conversion_bank,
  sol_conversion_bank_keys,
  SolConversionBank
)
from Solana.Read import OptionalAccountsAtSlot, account_info, rpc_response
from Solana.TransactionRead import (
  FinalizedTransactionOutcome,
  finalized_transaction_outcome_from_response
)

pub fn conversion_fixture_raw_bank(root :: Json,
  profile :: SolConversionProfile,
  id :: Bytes) -> OptionalAccountsAtSlot!String do
  let raw = Json.object_get(root, "accounts")?
  let rows = for index in 0..Json.array_length(raw)? do
    Json.array_get(raw, index)?
  end
  let accounts = for address in sol_conversion_bank_keys(profile, id)? do
    let matches = List.filter(rows,
      fn(row) do conversion_fixture_text(row, "address") == Ok(Bytes.to_base58(address.bytes)) end)
    if List.length(matches) != 1 do
      return Err("fixture_snapshot_key_missing")
    end
    let row = Json.object_get(List.head(matches), "account")?
    if Json.encode(row) == "null" do
      None
    else
      Some(account_info(Json.encode(row))?)
    end
  end
  Ok(OptionalAccountsAtSlot {
    slot: U64.parse(conversion_fixture_text(root, "slot")?)?,
    accounts: accounts
  })
end

pub fn conversion_fixture_bank(root :: Json,
  profile :: SolConversionProfile,
  id :: Bytes) -> SolConversionBank!String do
  admit_sol_conversion_bank(profile, id, conversion_fixture_raw_bank(root, profile, id)?)
end

pub fn conversion_fixture_outcome(executed :: Json,
  wire :: Bytes,
  signature :: Bytes) -> FinalizedTransactionOutcome!String do
  let execution_error = case Json.object_get(executed, "execution_error") do
    Ok(value) -> Json.encode(value)
    Err(_) -> "null"
  end
  let raw = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"slot\":"
    <> Json.encode(Json.object_get(executed, "slot")?)
    <> ",\"blockTime\":"
    <> Json.encode(Json.object_get(executed, "block_time")?)
    <> ",\"transaction\":["
    <> Json.encode_string(Bytes.to_base64(wire))
    <> ",\"base64\"],\"version\":\"legacy\",\"meta\":{\"err\":"
    <> execution_error
    <> ",\"fee\":"
    <> Json.encode(Json.object_get(executed, "fee")?)
    <> ",\"preBalances\":"
    <> Json.encode(Json.object_get(executed, "pre_balances")?)
    <> ",\"postBalances\":"
    <> Json.encode(Json.object_get(executed, "post_balances")?)
    <> ",\"preTokenBalances\":"
    <> Json.encode(Json.object_get(executed, "pre_tokens")?)
    <> ",\"postTokenBalances\":"
    <> Json.encode(Json.object_get(executed, "post_tokens")?)
    <> ",\"loadedAddresses\":{\"writable\":[],\"readonly\":[]},\"innerInstructions\":null}}}"
  case finalized_transaction_outcome_from_response(rpc_response(raw)?, signature, 1)? do
    None -> return Err("fixture_transaction_missing")
    Some(value) -> Ok(value)
  end
end

from Runtime.SolConversionNetwork import SolConversionConfig
from Payment.Treasury import TreasuryChainConfig

pub fn conversion_fixture_config(root :: Json) -> SolConversionConfig!String do
  Ok(SolConversionConfig {
    profile: conversion_fixture_profile(root)?,
    providers: ["http://127.0.0.1:24494", "http://127.0.0.1:24495"],
    test_mode: true,
    chain: TreasuryChainConfig {
      cluster: Bytes.from_hex(conversion_fixture_text(root, "cluster")?)?,
      providers_hash: Bytes.from_hex(conversion_fixture_text(root, "providers_hash")?)?,
      mint: pubkey(conversion_fixture_text(root, "usdc")?)?.bytes,
      treasury_owner: pubkey(conversion_fixture_text(root, "owner")?)?.bytes,
      fee_payer: pubkey(conversion_fixture_text(root, "payer")?)?.bytes,
      nonce_authority: Bytes.from_hex(conversion_fixture_text(root, "nonce_authority")?)?,
      nonce_address: Bytes.from_hex(conversion_fixture_text(root, "nonce_address")?)?,
      rewards_program: Bytes.from_hex(conversion_fixture_text(root, "rewards_program")?)?,
      rewards_pool: Bytes.from_hex(conversion_fixture_text(root, "rewards_pool")?)?
    }
  })
end
