from Solana.Read import Pubkey, pubkey_string
from Transparency.RewardsChain import (
  RewardAddresses,
  RewardPoolAccount,
  RewardMemberAccount,
  RewardEpochAccount,
  RewardClaimRow,
  reward_addresses,
  reward_pool_address,
  reward_member_address,
  reward_epoch_address,
  reward_pool_vault,
  decode_reward_pool,
  decode_reward_member,
  decode_reward_epoch,
  RewardFundingReceipt,
  reward_funding_address,
  decode_reward_funding_receipt
)

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn funding_receipt_cases() -> Bool!String do
  let bytes = cat([
    Bytes.from_hex("4d524601")?,
    key("aa")?,
    key("bb")?,
    key("cc")?,
    wide("2813")?,
    Bytes.from_hex("01000000")?,
    wide("18446744073709551615")?,
    key("dd")?,
    key("ee")?,
    wide("1701302401")?
  ])?
  let receipt = decode_reward_funding_receipt(bytes)?
  assert(U64.to_string(receipt.amount) == "18446744073709551615")
  assert(receipt.epoch == U64.parse("2813")? && receipt.kind == 1)
  assert(Bytes.secure_equals(receipt.operation_id, key("cc")?))
  let address = reward_funding_address(Pubkey { bytes: key("66")? },
    Pubkey { bytes: key("88")? },
    key("99")?)?
  assert(pubkey_string(address) == "NeSNbrQasxwPFQ4DCRVvWKvrTsM4DTUNo9keQrspbEH")
  for invalid in [
    Bytes.slice(bytes, 0, 191)?,
    cat([bytes, zeroes(1)?])?,
    patch(bytes, 3, Bytes.from_hex("02")?)?,
    patch(bytes, 108, Bytes.from_hex("02")?)?,
    patch(bytes, 109, Bytes.from_hex("01")?)?,
    patch(bytes, 68, zeroes(32)?)?,
    patch(bytes, 4, zeroes(32)?)?,
    patch(bytes, 36, zeroes(32)?)?,
    patch(bytes, 120, zeroes(32)?)?,
    patch(bytes, 152, zeroes(32)?)?,
    patch(bytes, 112, wide("0")?)?,
    patch(bytes, 184, wide("0")?)?,
    patch(bytes, 184, wide("18446744073709551615")?)?,
    patch(bytes, 100, wide("2814")?)?
  ] do
    case decode_reward_funding_receipt(invalid) do
      Ok(_) -> return Err("accepted malformed reward funding receipt")
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn zeroes(length :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", length))
end

fn key(value :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, 32))
end

fn wide(value :: String) -> Bytes!String do
  Bytes.write_uint_le(value, 8)
end

fn wide128(low :: String, high :: String) -> Bytes!String do
  cat([wide(low)?, wide(high)?])
end

fn byte_list(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Ok(value)
    Err(_) -> Err("invalid_test_byte_list")
  end
end

fn patch(bytes :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  cat([
    Bytes.slice(bytes, 0, offset)?,
    replacement,
    Bytes.slice(bytes,
      offset + Bytes.length(replacement),
      Bytes.length(bytes) - offset - Bytes.length(replacement))?
  ])
end

fn pool_wire() -> Bytes!String do
  cat([
    Bytes.from_hex("4d525001")?,
    key("11")?,
    key("22")?,
    key("33")?,
    key("44")?,
    key("55")?,
    wide("6048010")?,
    wide("11")?,
    wide("12")?,
    wide("9")?,
    wide("1")?,
    wide("18446744073709551605")?,
    wide("18446744073709551615")?,
    wide("0")?,
    zeroes(32)?,
    wide("0")?,
    key("66")?,
    zeroes(4)?
  ])
end

fn member_wire() -> Bytes!String do
  cat([
    Bytes.from_hex("4d524d01")?,
    key("01")?,
    Bytes.from_hex("01000000")?,
    wide("0")?,
    wide("6500000")?,
    zeroes(8)?
  ])
end

fn row(witness :: String, payout :: String, bond :: String, amount :: String) -> Bytes!String do
  cat([
    key(witness)?,
    key(payout)?,
    key(bond)?,
    wide128("18446744073709551613", "2")?,
    wide("0")?,
    wide(amount)?
  ])
end

fn epoch_wire(status :: Int, count :: Int) -> Bytes!String do
  let final = status == 2
  let total = if count == 2 do
    wide128("18446744073709551610", "5")?
  else
    wide128("18446744073709551613", "2")?
  end
  cat([
    Bytes.from_hex("4d524501")?,
    key("aa")?,
    wide("11")?,
    wide("18446744073709551615")?,
    byte_list([status, count, 2, 0])?,
    key("09")?,
    wide("18446744073709551615")?,
    total,
    wide("0")?,
    wide("0")?,
    wide("18446744073709551615")?,
    wide("0")?,
    wide(if final do
      "18446744073709551614"
    else
      "0"
    end)?,
    wide(if final do
      "1"
    else
      "0"
    end)?,
    wide("0")?,
    wide("7257600")?,
    wide("18446744073709551615")?,
    zeroes(40)?,
    row("01",
      "11",
      "21",
      if final do
        "9223372036854775807"
      else
        "0"
      end)?,
    if count == 2 do
      row("02",
        "12",
        "22",
        if final do
          "9223372036854775807"
        else
          "0"
        end)?
    else
      zeroes(128)?
    end,
    zeroes(62 * 128)?
  ])
end

fn full_claims_wire() -> Bytes!String do
  let rows = for index in 0..64 do
    cat([
      Bytes.from_hex(String.repeat(Bytes.to_hex(byte_list([index + 1])?), 32))?,
      key("11")?,
      Bytes.from_hex(String.repeat(Bytes.to_hex(byte_list([index + 65])?), 32))?,
      wide128("3", "0")?,
      wide("0")?,
      wide("1")?
    ])?
  end
  cat([
    Bytes.from_hex("4d524501")?,
    key("aa")?,
    wide("11")?,
    wide("64")?,
    Bytes.from_hex("02404000")?,
    key("09")?,
    wide("1")?,
    wide128("192", "0")?,
    wide("0")?,
    wide("0")?,
    wide("64")?,
    wide("0")?,
    wide("64")?,
    wide("0")?,
    wide("18446744073709551615")?,
    wide("7257600")?,
    wide("1")?,
    zeroes(40)?,
    cat(rows)?
  ])
end

fn pool_cases() -> Bool!String do
  let bytes = pool_wire()?
  let value = decode_reward_pool(bytes)?
  assert(U64.to_string(value.accounted) == "18446744073709551615")
  assert(U64.to_string(value.liabilities) == "18446744073709551605")
  assert(value.active_epoch == None && value.governance_ready == U64.parse("0")?)
  let active = patch(patch(bytes, 180, wide("11")?)?, 220, wide("12")?)?
  assert(decode_reward_pool(active)?.active_epoch == Some(U64.parse("11")?))
  let pending = patch(patch(bytes, 228, key("99")?)?, 260, wide("7257600")?)?
  assert(decode_reward_pool(pending)?.governance_ready == U64.parse("7257600")?)
  for invalid in [
    Bytes.slice(bytes, 0, 303)?,
    cat([bytes, zeroes(1)?])?,
    patch(bytes, 3, Bytes.from_hex("02")?)?,
    patch(bytes, 300, Bytes.from_hex("01")?)?,
    patch(bytes, 4, zeroes(32)?)?,
    patch(bytes, 100, zeroes(32)?)?,
    patch(bytes, 164, wide("18446744073709551615")?)?,
    patch(bytes, 172, wide("10")?)?,
    patch(bytes, 180, wide("10")?)?,
    patch(bytes, 220, wide("12")?)?,
    patch(bytes, 188, wide("10")?)?,
    patch(bytes, 228, key("99")?)?,
    patch(bytes, 260, wide("7257600")?)?
  ] do
    case decode_reward_pool(invalid) do
      Ok(_) -> return Err("accepted malformed reward pool")
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn member_cases() -> Bool!String do
  let bytes = member_wire()?
  assert(decode_reward_member(bytes)?.status == 1)
  let pending = patch(patch(bytes, 37, Bytes.from_hex("02")?)?, 40, wide("7257600")?)?
  assert(decode_reward_member(pending)?.pending == 2)
  for invalid in [
    Bytes.slice(bytes, 0, 63)?,
    patch(bytes, 3, Bytes.from_hex("02")?)?,
    patch(bytes, 4, zeroes(32)?)?,
    patch(bytes, 36, Bytes.from_hex("03")?)?,
    patch(bytes, 37, Bytes.from_hex("01")?)?,
    patch(bytes, 38, Bytes.from_hex("01")?)?,
    patch(bytes, 56, Bytes.from_hex("01")?)?,
    patch(bytes, 48, wide("0")?)?,
    patch(bytes, 40, wide("18446744073709551615")?)?
  ] do
    case decode_reward_member(invalid) do
      Ok(_) -> return Err("accepted malformed reward member")
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn epoch_cases() -> Bool!String do
  let bytes = epoch_wire(2, 2)?
  let value = decode_reward_epoch(bytes)?
  assert(U128.to_string(value.total_weight) == "110680464442257309690")
  assert(U128.to_string(List.head(value.rows).weight) == "55340232221128654845")
  assert(U64.to_string(value.posts) == "18446744073709551615")
  assert(U64.to_string(value.eligibility_revision) == "18446744073709551615")
  assert(List.length(value.rows) == 2 && !List.head(value.rows).claimed)
  let claimed = decode_reward_epoch(patch(bytes, 160, wide("3")?)?)?
  assert(List.head(claimed.rows).claimed && List.get(claimed.rows, 1).claimed)
  let collecting = decode_reward_epoch(epoch_wire(1, 1)?)?
  assert(collecting.status == 1 && List.length(collecting.rows) == 1 && collecting.expected == 2)
  let full = decode_reward_epoch(full_claims_wire()?)?
  assert(U64.to_string(full.claimed_mask) == "18446744073709551615")
  assert(List.length(List.filter(full.rows, fn(value) -> value.claimed end)) == 64)
  let open = cat([
    Bytes.from_hex("4d524501")?,
    key("aa")?,
    wide("18446744073709551615")?,
    wide("18446744073709551615")?,
    zeroes(8364)?
  ])?
  assert(U64.to_string(decode_reward_epoch(open)?.epoch) == "18446744073709551615")
  for invalid in [
    Bytes.slice(bytes, 0, 8415)?,
    patch(bytes, 3, Bytes.from_hex("02")?)?,
    patch(bytes, 52, Bytes.from_hex("03")?)?,
    patch(bytes, 53, Bytes.from_hex("01")?)?,
    patch(bytes, 54, Bytes.from_hex("41")?)?,
    patch(bytes, 55, Bytes.from_hex("01")?)?,
    patch(bytes, 184, Bytes.from_hex("01")?)?,
    patch(bytes, 56, zeroes(32)?)?,
    patch(bytes, 96, wide128("0", "0")?)?,
    patch(bytes, 112, wide("1")?)?,
    patch(bytes, 144, wide("18446744073709551613")?)?,
    patch(bytes, 152, wide("0")?)?,
    patch(bytes, 160, wide("4")?)?,
    patch(bytes, 168, wide("6048000")?)?,
    patch(bytes, 160, wide("9223372036854775808")?)?,
    patch(bytes, 224 + 96, wide128("18446744073709551615", "18446744073709551615")?)?,
    patch(bytes, 224 + 128, key("01")?)?,
    patch(bytes, 224 + 32, zeroes(32)?)?,
    patch(bytes, 224 + 256, Bytes.from_hex("01")?)?,
    patch(epoch_wire(1, 1)?, 160, wide("1")?)?,
    patch(epoch_wire(1, 1)?, 224 + 120, wide("1")?)?,
    patch(open, 88, wide("1")?)?
  ] do
    case decode_reward_epoch(invalid) do
      Ok(_) -> return Err("accepted malformed reward epoch")
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn addresses_case() -> Bool!String do
  # Independently derived by solana-address 2.7 in the Rust rewards program.
  let program = Pubkey { bytes: key("66")? }
  let witness = Pubkey { bytes: key("01")? }
  let mint = Pubkey { bytes: key("77")? }
  let maximum = U64.parse("18446744073709551615")?
  let addresses = reward_addresses(program, witness, maximum, mint)?
  assert(pubkey_string(addresses.pool) == "AYEAZnLGHzjV95vMtRu4StknBBRtmZUGLwK297Na1jqK")
  assert(pubkey_string(addresses.member) == "5ve21kaazCkupZwgYTuD9phMcJYEy5Uojrz4jJdpXCTW")
  assert(pubkey_string(addresses.epoch) == "Da7kLkGX3ykmYgJ5Q1TGKQm3EM1hLw5beynx8QgMSUqH")
  assert(pubkey_string(addresses.vault) == "EmXsPprSeSwqUmzD8sfTZdhxZxeeat74NwAAma9eZpPW")
  assert(reward_pool_address(program)? == addresses.pool)
  assert(reward_member_address(program, witness)? == addresses.member)
  assert(reward_epoch_address(program, maximum)? == addresses.epoch)
  assert(reward_pool_vault(program, mint)? == addresses.vault)
  case reward_member_address(program, Pubkey { bytes: zeroes(32)? }) do
    Ok(_) -> return Err("accepted zero reward member witness")
    Err(_) -> nil
  end
  case reward_pool_address(Pubkey { bytes: zeroes(31)? }) do
    Ok(_) -> return Err("accepted malformed reward program key")
    Err(_) -> nil
  end
  Ok(true)
end

test("reward chain codecs preserve wide values and reject inconsistent pool state") do
  case pool_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("reward member codecs reject invalid proposals and padding") do
  case member_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("reward epochs validate staged rows, full-width claims and accounting conservation") do
  case epoch_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("reward PDAs and the pool ATA match independent Rust vectors at maximum u64 epoch") do
  case addresses_case() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("durable funding receipts preserve intent precision and reject malformed cross-fields") do
  case funding_receipt_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
