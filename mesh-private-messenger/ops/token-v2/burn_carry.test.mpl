from Transparency.TokenBurn import decode_token_burn_week
from Transparency.TokenBurnCarry import (
  decode_token_burn_carry_frame,
  decode_token_burn_carry_account,
  decode_token_burn_close_receipt
)

fn item_text(item :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(item, key)?)
end

fn item_data(accounts :: Json, index :: Int) -> Bytes!String do
  Bytes.from_hex(item_text(Json.array_get(accounts, index)?, "data_hex")?)
end

fn changed(data :: Bytes, index :: Int, value :: Int) -> Bytes!String do
  let left = Bytes.slice(data, 0, index)?
  let byte = Bytes.write_uint_le(Int.to_string(value), 1)?
  Bytes.concat(Bytes.concat(left, byte)?,
    Bytes.slice(data, index + 1, Bytes.length(data) - index - 1)?)
end

fn actual_carry() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", ""))?)?
  let snapshots = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(snapshots)? do
    let item = Json.array_get(snapshots, index)?
    let name = item_text(item, "name")?
    let accounts = Json.object_get(item, "accounts")?
    let data = item_data(accounts, 5)?
    let frame = decode_token_burn_carry_frame(data)?
    assert((frame.week.budget) == (U64.parse("240000000")?))
    assert((frame.week.epoch) == (U64.parse(item_text(item, "epoch")?)?))
    assert((frame.closed) == (String.ends_with(name, "closed")))
    assert((frame.version) == (if String.starts_with(name, "legacy")
        || name == "all-missed-closed" do
        1
      else
        2
      end))
    if frame.version == 1 do
      assert((frame.cash_budget) == (frame.week.budget))
      assert((frame.carry_budget) == (U64.parse("0")?))
    else if name == "carry-only-funded" do
      assert((frame.cash_budget) == (U64.parse("0")?))
      assert((frame.carry_budget) == (U64.parse("240000000")?))
    else
      assert((frame.cash_budget) == (U64.parse("120000000")?))
      assert((frame.carry_budget) == (U64.parse("120000000")?))
    end
    assert(Result.is_err(decode_token_burn_carry_frame(changed(data, 248, 1)?)))
    assert(Result.is_err(decode_token_burn_carry_frame(changed(data, 52, 0)?)))
    assert(Result.is_err(decode_token_burn_carry_frame(changed(data, 232, 255)?)))
    if frame.version == 2 || frame.closed do
      assert(Result.is_err(decode_token_burn_week(data)))
    end
    if frame.version == 2 do
      assert(Result.is_err(decode_token_burn_carry_frame(changed(data, 304, 1)?)))
      assert(Result.is_err(decode_token_burn_carry_frame(changed(data, 264, 1)?)))
    end
    if name != "legacy-partial" do
      let carry_data = item_data(accounts, 7)?
      let carry = decode_token_burn_carry_account(carry_data)?
      assert((U128.subtract(carry.closed_total,
        carry.reserved_total)?) == (U128.parse(U64.to_string(carry.accounted))?))
      assert(Result.is_err(decode_token_burn_carry_account(changed(carry_data, 100, 255)?)))
      assert(Result.is_err(decode_token_burn_carry_account(changed(carry_data, 156, 1)?)))
    end
    if frame.closed do
      let receipt_data = item_data(accounts, 9)?
      let receipt = decode_token_burn_close_receipt(receipt_data)?
      assert((receipt.budget) == (frame.week.budget))
      assert((receipt.spent) == (frame.week.spent))
      assert((receipt.burned) == (frame.week.burned))
      assert((receipt.version) == (frame.version))
      assert((receipt.carried) == (U64.subtract(frame.week.budget, frame.week.spent)?))
      assert((receipt.active_frame_hash) == (frame.active_frame_hash))
      assert(Result.is_err(decode_token_burn_close_receipt(changed(receipt_data, 245, 1)?)))
      assert(Result.is_err(decode_token_burn_close_receipt(changed(receipt_data, 132, 255)?)))
    end
  end
  IO.eprintln("MORSE_TOKEN_BURN_CARRY_CODEC exact_actual_v1_v2_terminal_frames_units_conservation")
  Ok(true)
end

test("actual closed and funded SBF frames retain exact carry units without legacy reinterpretation") do
  if Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", "") == "" do
    assert(true)
  else
    assert((actual_carry()) == (Ok(true)))
  end
end
