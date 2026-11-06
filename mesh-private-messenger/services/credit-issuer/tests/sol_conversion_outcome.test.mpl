from Tests.SolConversionFixture import (
  conversion_fixture_profile,
  conversion_fixture_text,
  conversion_fixture_outcome
)
from Payment.SolConversionPacket import (
  SolConversionPacket,
  sol_conversion_profile_hash,
  sol_conversion_message
)
from Payment.SolConversionOutcome import sol_conversion_outcome
from Solana.Read import Hash, rpc_response
from Solana.Tx import serialize_legacy_message
from Solana.TransactionRead import finalized_transaction_outcome_from_response

fn cases() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let executed = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_EXECUTION", ""))?)?
  let profile = conversion_fixture_profile(root)?
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  let lamports = U64.parse(conversion_fixture_text(root, "principal")?)?
  let minimum = U64.parse(conversion_fixture_text(root, "minimum")?)?
  let blockhash = Hash { bytes: Bytes.from_base58(conversion_fixture_text(root, "blockhash")?)? }
  let message = serialize_legacy_message(sol_conversion_message(profile,
    id,
    lamports,
    minimum,
    blockhash)?)?
  assert(message == Bytes.from_base64(conversion_fixture_text(executed, "message")?)?)
  let plan = SolConversionPacket {
    intent_id: id,
    profile_hash: sol_conversion_profile_hash(profile)?,
    lamports: lamports,
    minimum: minimum,
    blockhash: blockhash,
    message: message
  }
  let wire = Bytes.from_base64(conversion_fixture_text(executed, "wire")?)?
  let signature = Bytes.from_base58(conversion_fixture_text(executed, "signature")?)?
  let value = conversion_fixture_outcome(executed, wire, signature)?
  let prepared = U64.parse(conversion_fixture_text(root, "slot")?)?
  let result = sol_conversion_outcome(profile, plan, wire, prepared, value)?
  assert(result.successful)
  assert(result.received == U64.parse(conversion_fixture_text(executed, "received_usdc")?)?)
  assert(result.received != minimum)
  assert(result.receipt == sol_conversion_outcome(profile, plan, wire, prepared, value)?.receipt)
  assert(Result.is_err(sol_conversion_outcome(profile,
    plan,
    wire,
    U64.add(prepared, U64.parse("1")?)?,
    value)))
  assert(Result.is_err(sol_conversion_outcome(profile,
    plan,
    wire,
    prepared,
    %{value |
      transaction: %{value.transaction | fee: U64.add(value.transaction.fee, U64.parse("1")?)?}
    })))
  assert(Result.is_err(sol_conversion_outcome(profile,
    plan,
    wire,
    prepared,
    %{value | execution_error: Some("{\"InstructionError\":[5,{\"Custom\":6000}]}")})))
  let rows = value.transaction.post_token_balances
  let wrong_owner = for row in rows do
    %{row | owner: Some(profile.payer)}
  end
  assert(Result.is_err(sol_conversion_outcome(profile,
    plan,
    wire,
    prepared,
    %{value | transaction: %{value.transaction | post_token_balances: wrong_owner}})))
  Ok(true)
end

test("actual native swap bytes and deltas produce actual output receipt, never oracle-valued USDC") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
