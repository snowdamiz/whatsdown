from Transparency.AnchorBond import (
  AnchorBond,
  AnchorEconomics,
  AnchorBondAddresses,
  decode_anchor_bond,
  decode_anchor_economics,
  witness_bond_addresses,
  directory_bond_addresses
)
from Solana.Read import pubkey

fn join(parts :: List<Bytes>, output :: Bytes) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(output)
  else
    join(List.tail(parts), Bytes.concat(output, List.head(parts))?)
  end
end

fn wide(value :: String) -> Bytes!String do
  case Bytes.write_uint_le(value, 8) do
    Err(_) -> Err("fixture_integer")
    Ok(bytes)
  end
end

fn replace(bytes :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  join([
      Bytes.slice(bytes, 0, offset)?,
      replacement,
      Bytes.slice(bytes,
        offset + Bytes.length(replacement),
        Bytes.length(bytes) - offset - Bytes.length(replacement))?
    ],
    Bytes.empty())
end

fn bond() -> Bytes!String do
  join([
      Bytes.from_hex("4d42440101010000"
        <> String.repeat("11", 32)
        <> String.repeat("22", 32)
        <> String.repeat("33", 32)
        <> String.repeat("44", 32)
        <> String.repeat("55", 32))?,
      wide("18446744073709551615")?,
      wide("1210600")?,
      wide("0")?,
      wide("0")?,
      wide("0")?
    ],
    Bytes.empty())
end

fn economics() -> Bytes!String do
  join([
      Bytes.from_hex("4d454301"
        <> String.repeat("11", 32)
        <> String.repeat("44", 32)
        <> String.repeat("33", 32))?,
      wide("100000000")?,
      wide("500000000")?,
      wide("1210600")?,
      wide("0")?,
      wide("0")?,
      wide("0")?,
      wide("18446744073709551615")?,
      wide("18446744073709551615")?,
      Bytes.from_hex("01" <> String.repeat("00", 27))?
    ],
    Bytes.empty())
end

fn invalid_bond(bytes :: Bytes) do
  case decode_anchor_bond(bytes) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
end

fn invalid_economics(bytes :: Bytes) do
  case decode_anchor_economics(bytes) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
end

fn proof() -> Bool!String do
  let wire = bond()?
  assert(U64.to_string(decode_anchor_bond(wire)?.principal) == "18446744073709551615")
  for length in 0..208 do
    invalid_bond(Bytes.slice(wire, 0, length)?)
  end
  invalid_bond(Bytes.concat(wire, Bytes.from_hex("00")?)?)
  for offset in [0, 4, 5, 6, 7, 200, 207] do
    invalid_bond(replace(wire, offset, Bytes.from_hex("ff")?)?)
  end
  for offset in [40, 72, 104, 136] do
    invalid_bond(replace(wire, offset, Bytes.from_hex(String.repeat("00", 32))?)?)
  end
  for offset in [176, 184, 192] do
    invalid_bond(replace(wire, offset, wide("9223372036854775808")?)?)
  end
  invalid_bond(replace(wire, 168, wide("0")?)?)
  invalid_bond(replace(wire, 184, wide("1210600")?)?)
  let unbonding = replace(replace(wire, 4, Bytes.from_hex("02")?)?, 184, wide("1210600")?)?
  assert(decode_anchor_bond(unbonding)?.status == 2)
  invalid_bond(replace(unbonding, 184, wide("1210599")?)?)
  let withdrawn = replace(replace(unbonding, 4, Bytes.from_hex("04")?)?, 168, wide("0")?)?
  assert(decode_anchor_bond(withdrawn)?.status == 4)
  invalid_bond(replace(withdrawn, 168, wide("1")?)?)
  let slashed = replace(replace(withdrawn, 4, Bytes.from_hex("03")?)?, 192, wide("1210601")?)?
  assert(decode_anchor_bond(slashed)?.status == 3)
  invalid_bond(replace(slashed, 184, wide("1210602")?)?)
  # A slash may follow an active or unbonding bond, but never an unbond request
  # that predates that bond. Do not show malformed state as a real slash.
  invalid_bond(replace(slashed, 184, wide("1210599")?)?)
  assert(decode_anchor_bond(replace(slashed, 184, wide("0")?)?)?.status == 3)
  let policy = economics()?
  assert(U64.to_string(decode_anchor_economics(policy)?.directory_principal) == "18446744073709551615")
  assert(U64.to_string(decode_anchor_economics(policy)?.eligibility_revision) == "0")
  let revised = replace(policy, 168, wide("18446744073709551615")?)?
  assert(U64.to_string(decode_anchor_economics(revised)?.eligibility_revision) == "18446744073709551615")
  for length in 0..192 do
    invalid_economics(Bytes.slice(policy, 0, length)?)
  end
  invalid_economics(Bytes.concat(policy, Bytes.from_hex("00")?)?)
  for offset in [0, 164, 165, 167, 176, 191] do
    invalid_economics(replace(policy, offset, Bytes.from_hex("ff")?)?)
  end
  for offset in [36, 68] do
    invalid_economics(replace(policy, offset, Bytes.from_hex(String.repeat("00", 32))?)?)
  end
  invalid_economics(replace(policy, 100, wide("0")?)?)
  invalid_economics(replace(policy, 108, wide("99999999")?)?)
  invalid_economics(replace(policy, 156, wide("18446744073709551614")?)?)
  invalid_economics(replace(policy, 124, wide("200000000")?)?)
  let pending = replace(replace(replace(policy, 124, wide("200000000")?)?,
      132,
      wide("600000000")?)?,
    140,
    wide("2420200")?)?
  assert(U64.to_string(decode_anchor_economics(pending)?.pending_ready) == "2420200")
  invalid_economics(replace(pending, 140, wide("1210599")?)?)
  for status in [0, 3, 4] do
    let changed = replace(policy,
      164,
      case Bytes.from_list([status]) do
        Err(_) -> return Err("fixture")
        Ok(value) -> value
      end)?
    invalid_economics(changed)
  end
  let program = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let mint = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let log_id = Crypto.sha256(Bytes.from_utf8("morse-main"))
  let key = Bytes.from_hex(String.repeat("12", 32))?
  let long = witness_bond_addresses(program, log_id, mint, String.repeat("a", 64), key)?
  let rotated = witness_bond_addresses(program,
    log_id,
    mint,
    String.repeat("a", 64),
    Bytes.from_hex(String.repeat("13", 32))?)?
  assert(!Bytes.secure_equals(long.bond.bytes, rotated.bond.bytes))
  assert(!Bytes.secure_equals(long.vault.bytes, rotated.vault.bytes))
  assert(Bytes.secure_equals(long.economics.bytes, rotated.economics.bytes))
  let directory = directory_bond_addresses(program, log_id, mint)?
  let named_directory = witness_bond_addresses(program, log_id, mint, "directory", key)?
  assert(!Bytes.secure_equals(directory.bond.bytes, named_directory.bond.bytes))
  for id in ["", String.repeat("a", 65), "outside/witness", "Outside"] do
    case witness_bond_addresses(program, log_id, mint, id, key) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("custody codecs reject malformed balances and impossible lifecycle states without losing u64 precision") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
