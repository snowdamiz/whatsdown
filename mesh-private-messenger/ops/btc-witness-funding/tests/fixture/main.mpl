from FixtureConfig import funding_config
from Runtime.BtcConversionFunding import prepare_btc_witness_output, reconcile_btc_witness_output
from Storage.BtcConversionFunding import (
  reserve_btc_witness_funding,
  load_btc_witness_funding,
  reconcile_btc_witness_funding,
  btc_witness_funding_instruction
)
from Storage.TreasuryFunding import TreasuryFundingIntent
from Payment.TreasuryRewards import TreasuryFundingProof
from Transparency.RewardsChain import decode_reward_funding_receipt
from Transparency.RewardsWrite import RewardWriteContext
from Solana.Read import Pubkey
from Solana.Tx import instruction_report_json

fn intent_json(value :: TreasuryFundingIntent) -> String do
  "{\"id\":\""
    <> Bytes.to_hex(value.intent_id)
    <> "\",\"epoch\":\""
    <> U64.to_string(value.epoch)
    <> "\",\"amount\":\""
    <> U64.to_string(value.amount)
    <> "\",\"batch\":\""
    <> U64.to_string(value.batch_id)
    <> "\",\"state\":"
    <> Int.to_string(value.state)
    <> "}"
end

fn run() -> String!String do
  let config = funding_config()?
  let pool = Pool.open(Env.get("BTC_FIXTURE_DATABASE", ""), 1, 4, 5000)?
  let args = Env.args()
  let operation = List.get(args, 1)
  let id = Bytes.from_hex(List.get(args, 2))?
  let result = if operation == "prepare" do
    prepare_btc_witness_output(pool, config, id)
  else if operation == "reconcile" do
    reconcile_btc_witness_output(pool, config, id)
  else
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        if operation == "reserve" do
          return reserve_btc_witness_funding(conn,
            config.conversion,
            config.treasury.chain,
            id,
            U64.parse(List.get(args, 3))?)
        end
        if operation == "absent" do
          return reconcile_btc_witness_funding(conn,
            config.conversion,
            config.treasury.chain,
            id,
            TreasuryFundingProof {
              current_epoch: U64.parse(List.get(args, 3))?,
              receipt_bytes: Bytes.empty(),
              receipt: None
            })
        end
        if operation == "receipt" do
          let raw = Bytes.from_hex(Bytes.to_utf8(File.read_bytes(List.get(args, 4), 0, 1024)?)?)?
          return reconcile_btc_witness_funding(conn,
            config.conversion,
            config.treasury.chain,
            id,
            TreasuryFundingProof {
              current_epoch: U64.parse(List.get(args, 3))?,
              receipt_bytes: raw,
              receipt: Some(decode_reward_funding_receipt(raw)?)
            })
        end
        load_btc_witness_funding(conn, config.conversion, config.treasury.chain, id)
      end)
  end
  Pool.close(pool)
  let value = result?
  if operation == "instruction" do
    let context = RewardWriteContext {
      program: Pubkey { bytes: config.treasury.chain.rewards_program },
      judge: Pubkey {
        bytes: Bytes.from_hex(Env.get("BTC_FIXTURE_JUDGE", String.repeat("33", 32)))?
      },
      log_name: Env.get("BTC_FIXTURE_LOG", "sol-conversion"),
      mint: Pubkey { bytes: config.conversion.mint }
    }
    return Ok(instruction_report_json(btc_witness_funding_instruction(value,
      context,
      config.conversion,
      config.treasury.chain)?))
  end
  Ok(intent_json(value))
end

fn main() do
  case run() do
    Ok(value) -> println(value)
    Err(error) -> do
      IO.eprintln(error)
      Process.exit(1)
    end
  end
end
