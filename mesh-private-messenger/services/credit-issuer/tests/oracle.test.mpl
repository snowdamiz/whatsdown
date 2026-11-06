from Payment.Oracle import sol_price_from_account, sol_price_from_response
from Solana.Read import AccountInfo, AccountAtSlot, pubkey, rpc_response

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

# Independently packed with Python struct from the upstream Borsh field order.
fn fixture() -> AccountAtSlot!String do
  Ok(AccountAtSlot {
    slot: wide(101)?,
    account: AccountInfo {
      data: Bytes.from_hex("22f123639d7ef4cd111111111111111111111111111111111111111111111111111111111111111101ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d4e29d4a80400000040420f0000000000f8ffffff00f1536500000000fff053650000000000c817a80400000040420f0000000000640000000000000000")?,
      owner: pubkey("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp")?,
      executable: false,
      lamports: wide(2000000)?,
      rent_epoch: wide(0)?
    }
  })
end

fn replace(value :: AccountAtSlot, offset :: Int, bytes :: Bytes) -> AccountAtSlot!String do
  let data = value.account.data
  Ok(%{value |
    account: %{value.account |
      data: Bytes.concat(Bytes.concat(Bytes.slice(data, 0, offset)?, bytes)?,
        Bytes.slice(data,
          offset + Bytes.length(bytes),
          Bytes.length(data) - offset - Bytes.length(bytes))?)?
    }
  })
end

fn oracle_cases() -> Bool!String do
  let value = fixture()?
  let now = wide(1700000060)?
  let price = sol_price_from_account(value, now)?
  assert(price.usd_micros == wide(200123456)?)
  assert(price.observed_at == wide(1700000000)?)
  assert(price.slot == wide(101)?)
  assert(Result.is_err(sol_price_from_account(value, wide(1700000061)?)))
  assert(Result.is_err(sol_price_from_account(value, wide(1699999999)?)))
  assert(Result.is_err(sol_price_from_account(%{value | slot: wide(99)?}, now)))
  assert(Result.is_err(sol_price_from_account(%{value |
      account: %{value.account | executable: true}
    },
    now)))
  assert(Result.is_err(sol_price_from_account(%{value |
      account: %{value.account | owner: pubkey("11111111111111111111111111111111")?}
    },
    now)))
  for offset in [0, 40, 41] do
    assert(Result.is_err(sol_price_from_account(replace(value, offset, Bytes.from_hex("00")?)?,
      now)))
  end
  for price_bytes in ["0000000000000000", "ffffffffffffffff", "0000000000000080"] do
    assert(Result.is_err(sol_price_from_account(replace(value, 73, Bytes.from_hex(price_bytes)?)?,
      now)))
  end
  # Confidence is bounded to 1%; compare integer products without rounding.
  let exact = replace(replace(value, 73, Bytes.write_uint_le("20000000000", 8)?)?,
    81,
    Bytes.write_uint_le("200000000", 8)?)?
  assert(Result.is_ok(sol_price_from_account(exact, now)))
  assert(Result.is_err(sol_price_from_account(replace(exact,
      81,
      Bytes.write_uint_le("200000001", 8)?)?,
    now)))
  for exponent in ["f3ffffff", "01000000", "ffffff7f", "00000080"] do
    assert(Result.is_err(sol_price_from_account(replace(value, 89, Bytes.from_hex(exponent)?)?,
      now)))
  end
  assert(Result.is_err(sol_price_from_account(replace(value,
      101,
      Bytes.write_uint_le("1700000001", 8)?)?,
    now)))
  assert(Result.is_err(sol_price_from_account(replace(value, 125, Bytes.write_uint_le("0", 8)?)?,
    now)))
  assert(Result.is_err(sol_price_from_account(%{value |
      account: %{value.account | data: Bytes.slice(value.account.data, 0, 133)?}
    },
    now)))
  let response = rpc_response("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"context\":{\"slot\":101},\"value\":{\"data\":["
    <> Json.encode_string(Bytes.to_base64(value.account.data))
    <> ",\"base64\"],\"executable\":false,\"lamports\":2000000,\"owner\":\"rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp\",\"rentEpoch\":0}}}")?
  assert(sol_price_from_response(response, 7, now)?.usd_micros == price.usd_micros)
  assert(Result.is_err(sol_price_from_response(response, 8, now)))
  Ok(true)
end

test("SOL quotes require a fresh fully verified pinned Pyth feed and exact integer price") do
  assert(oracle_cases() == Ok(true))
end
