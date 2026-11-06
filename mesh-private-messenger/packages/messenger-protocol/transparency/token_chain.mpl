from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Solana.Tx import Instruction, AccountMeta
from Transparency.TokenPolicy import token_initial_allocations

pub struct TokenAddresses do
  config :: Pubkey
  mint :: Pubkey
  oracle :: Pubkey
  program_data :: Pubkey
  allocations :: List<Pubkey>
  vaults :: List<Pubkey>
end

pub struct TokenConfig do
  governance :: Pubkey
  mint :: Pubkey
  started :: U64
  beneficiaries :: List<Pubkey>
end

pub struct TokenAllocation do
  kind :: Int
  config :: Pubkey
  beneficiary :: Pubkey
  started :: U64
  total :: U64
  claimed :: U64
  mint :: Pubkey
end

pub struct TokenOracle do
  config :: Pubkey
  mint :: Pubkey
  receiver :: Pubkey
  source :: Pubkey
  feed :: Bytes
  last_time :: U64
  last_price :: U64
  last_slot :: U64
  pending_receiver :: Option<Pubkey>
  pending_source :: Option<Pubkey>
  pending_feed :: Option<Bytes>
  ready_at :: U64
  revision :: U64
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn byte(value :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), 1)
end

fn part(data :: Bytes, at :: Int, size :: Int) -> Bytes!String do
  Bytes.slice(data, at, size)
end

fn number(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

fn wide_number(data :: Bytes, at :: Int) -> U128!String do
  let low = U128.parse(U64.to_string(number(data, at)?))?
  let high = U128.parse(U64.to_string(number(data, at + 8)?))?
  U128.add(low, U128.multiply(high, U128.parse("18446744073709551616")?)?)
end

fn nonzero(data :: Bytes) -> Bool do
  Bytes.to_hex(data) != String.repeat("00", Bytes.length(data))
end

fn wallet(value :: Pubkey) -> Pubkey!String do
  if Bytes.length(value.bytes) != 32 || !nonzero(value.bytes) do
    Err("invalid_token_chain")
  else
    Ok(value)
  end
end

fn key(data :: Bytes, at :: Int) -> Pubkey!String do
  wallet(Pubkey { bytes: part(data, at, 32)? })
end

fn meta(value :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: value, signer: signer, writable: writable }
end

fn token_program() -> Pubkey!String do
  pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
end

fn ata_program() -> Pubkey!String do
  pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
end

fn system_program() -> Pubkey!String do
  pubkey("11111111111111111111111111111111")
end

fn receiver(value :: Pubkey) -> Pubkey!String do
  if value != pubkey("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ")?
    && value != pubkey("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp")? do
    Err("invalid_token_receiver")
  else
    Ok(value)
  end
end

pub fn token_payout_address(owner :: Pubkey, mint :: Pubkey) -> Pubkey!String do
  wallet(owner)?
  wallet(mint)?
  let result = find_program_address(ata_program()?,
    [owner.bytes, token_program()?.bytes, mint.bytes])?
  Ok(result.address)
end

pub fn token_addresses(program :: Pubkey) -> TokenAddresses!String do
  wallet(program)?
  let config = find_program_address(program, [Bytes.from_utf8("token")])?
  let mint = find_program_address(program, [Bytes.from_utf8("mint")])?
  let oracle = find_program_address(program, [Bytes.from_utf8("oracle")])?
  let program_data = find_program_address(pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?,
    [program.bytes])?
  let allocations = for kind in 0..7 do
    let value = find_program_address(program, [Bytes.from_utf8("allocation"), byte(kind)?])?
    value.address
  end
  let vaults = for allocation in allocations do
    token_payout_address(allocation, mint.address)?
  end
  Ok(TokenAddresses {
    config: config.address,
    mint: mint.address,
    oracle: oracle.address,
    program_data: program_data.address,
    allocations: allocations,
    vaults: vaults
  })
end

fn instruction(program :: Pubkey,
  tag :: Int,
  payload :: Bytes,
  accounts :: List<AccountMeta>) -> Instruction!String do
  wallet(program)?
  for value in accounts do
    if Bytes.length(value.pubkey.bytes) != 32 do
      return Err("invalid_token_chain")
    end
  end
  Ok(Instruction { program_id: program, accounts: accounts, data: cat([byte(tag)?, payload])? })
end

pub fn token_prepare_instruction(program :: Pubkey, payer :: Pubkey) -> Instruction!String do
  wallet(payer)?
  let addresses = token_addresses(program)?
  let states = for value in addresses.allocations do
    meta(value, false, true)
  end
  instruction(program,
    2,
    Bytes.empty(),
    [
      meta(payer, true, true),
      meta(addresses.config, false, true),
      meta(system_program()?, false, false)
    ]
      ++ states)
end

pub fn token_initialize_instruction(program :: Pubkey,
  authority :: Pubkey,
  payer :: Pubkey,
  governance :: Pubkey,
  beneficiaries :: List<Pubkey>) -> Instruction!String do
  wallet(authority)?
  wallet(payer)?
  wallet(governance)?
  if List.length(beneficiaries) != 7 do
    return Err("invalid_token_chain")
  end
  let a = token_addresses(program)?
  let payloads = for value in beneficiaries do
    wallet(value)?
    if value == a.config || value == a.mint || List.contains(a.allocations, value) do
      return Err("invalid_token_chain")
    end
    value.bytes
  end
  let pairs = for kind in 0..7 do
    [meta(List.get(a.allocations, kind), false, true), meta(List.get(a.vaults, kind), false, true)]
  end
  instruction(program,
    0,
    cat([governance.bytes] ++ payloads)?,
    [
      meta(authority, true, false),
      meta(payer, true, true),
      meta(a.config, false, true),
      meta(a.mint, false, true),
      meta(program, false, false),
      meta(a.program_data, false, false),
      meta(token_program()?, false, false),
      meta(ata_program()?, false, false),
      meta(system_program()?, false, false)
    ]
      ++ List.flatten(pairs))
end

pub fn token_claim_instruction(program :: Pubkey,
  payer :: Pubkey,
  beneficiary :: Pubkey,
  kind :: Int) -> Instruction!String do
  if kind < 0 || kind > 6 || kind == 4 do
    return Err("invalid_token_chain")
  end
  wallet(payer)?
  wallet(beneficiary)?
  let a = token_addresses(program)?
  instruction(program,
    1,
    byte(kind)?,
    [
      meta(payer, true, true),
      meta(a.config, false, false),
      meta(List.get(a.allocations, kind), false, true),
      meta(List.get(a.vaults, kind), false, true),
      meta(token_payout_address(beneficiary, a.mint)?, false, true),
      meta(beneficiary, false, false),
      meta(a.mint, false, false),
      meta(token_program()?, false, false),
      meta(ata_program()?, false, false),
      meta(system_program()?, false, false)
    ])
end

pub fn token_oracle_initialize_instruction(program :: Pubkey,
  governance :: Pubkey,
  payer :: Pubkey,
  source_program :: Pubkey,
  source :: Pubkey,
  feed :: Bytes) -> Instruction!String do
  wallet(governance)?
  wallet(payer)?
  wallet(source)?
  receiver(source_program)?
  if Bytes.length(feed) != 32 || !nonzero(feed) do
    return Err("invalid_token_chain")
  end
  let a = token_addresses(program)?
  instruction(program,
    3,
    cat([source.bytes, feed])?,
    [
      meta(governance, true, false),
      meta(payer, true, true),
      meta(a.config, false, false),
      meta(a.mint, false, false),
      meta(a.oracle, false, true),
      meta(source_program, false, false),
      meta(source, false, false),
      meta(system_program()?, false, false)
    ])
end

pub fn token_oracle_observe_instruction(program :: Pubkey,
  source_program :: Pubkey,
  source :: Pubkey) -> Instruction!String do
  receiver(source_program)?
  wallet(source)?
  let a = token_addresses(program)?
  instruction(program,
    4,
    Bytes.empty(),
    [
      meta(a.config, false, false),
      meta(a.mint, false, false),
      meta(a.oracle, false, true),
      meta(source_program, false, false),
      meta(source, false, false)
    ])
end

pub fn decode_token_config(data :: Bytes) -> TokenConfig!String do
  if Bytes.length(data) != 320
    || Bytes.to_hex(part(data, 0, 4)?) != "4d544b01"
    || nonzero(part(data, 76, 4)?)
    || nonzero(part(data, 304, 16)?) do
    return Err("invalid_token_config")
  end
  let started = number(data, 68)?
  if U64.compare(started, U64.parse("0")?) <= 0
    || U64.compare(started, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_token_config")
  end
  let beneficiaries = for kind in 0..7 do
    key(data, 80 + kind * 32)?
  end
  Ok(TokenConfig {
    governance: key(data, 4)?,
    mint: key(data, 36)?,
    started: started,
    beneficiaries: beneficiaries
  })
end

pub fn decode_token_allocation(data :: Bytes) -> TokenAllocation!String do
  if Bytes.length(data) != 128
    || Bytes.to_hex(part(data, 0, 4)?) != "4d544101"
    || nonzero(part(data, 5, 3)?) do
    return Err("invalid_token_allocation")
  end
  let kind = Bytes.get(data, 4)?
  if kind > 6 do
    return Err("invalid_token_allocation")
  end
  let total = number(data, 80)?
  let claimed = number(data, 88)?
  let started = number(data, 72)?
  if total != List.get(token_initial_allocations()?, kind)
    || U64.compare(claimed, total) > 0
    || started == U64.parse("0")?
    || U64.compare(started, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_token_allocation")
  end
  Ok(TokenAllocation {
    kind: kind,
    config: key(data, 8)?,
    beneficiary: key(data, 40)?,
    started: started,
    total: total,
    claimed: claimed,
    mint: key(data, 96)?
  })
end

pub fn decode_token_oracle(data :: Bytes) -> TokenOracle!String do
  if Bytes.length(data) != 5728
    || Bytes.to_hex(part(data, 0, 4)?) != "4d544f01"
    || nonzero(part(data, 300, 20)?) do
    return Err("invalid_token_oracle")
  end
  let ready = number(data, 284)?
  let pending = ready != U64.parse("0")?
  if !pending && nonzero(part(data, 188, 96)?) do
    return Err("invalid_token_oracle")
  end
  let revision = number(data, 292)?
  let time = number(data, 164)?
  let price = number(data, 172)?
  let slot = number(data, 180)?
  if revision == U64.parse("0")?
    || price == U64.parse("0")?
    || slot == U64.parse("0")?
    || U64.compare(time, U64.parse("3600")?) < 0
    || U64.compare(time, U64.parse("9223372036854775807")?) > 0
    || U64.compare(ready, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_token_oracle")
  end
  Ok(TokenOracle {
    config: key(data, 4)?,
    mint: key(data, 36)?,
    receiver: receiver(key(data, 68)?)?,
    source: key(data, 100)?,
    feed: key(data, 132)?.bytes,
    last_time: time,
    last_price: price,
    last_slot: slot,
    pending_receiver: if pending do
      Some(receiver(key(data, 188)?)?)
    else
      None
    end,
    pending_source: if pending do
      Some(key(data, 220)?)
    else
      None
    end,
    pending_feed: if pending do
      Some(key(data, 252)?.bytes)
    else
      None
    end,
    ready_at: ready,
    revision: revision
  })
end

pub fn token_oracle_twap(data :: Bytes, now :: U64) -> U64!String do
  let oracle = decode_token_oracle(data)?
  if U64.compare(now, oracle.last_time) < 0
    || U64.compare(U64.subtract(now, oracle.last_time)?, U64.parse("60")?) > 0
    || U64.divide(now, U64.parse("3600")?)? != U64.divide(oracle.last_time, U64.parse("3600")?)? do
    return Err("unavailable_token_twap")
  end
  let end_hour = case String.to_int(U64.to_string(U64.divide(oracle.last_time,
    U64.parse("3600")?)?)) do
    Some(value) -> value
    None -> return Err("unavailable_token_twap")
  end
  if end_hour < 168 do
    return Err("unavailable_token_twap")
  end
  let integrals = for hour in (end_hour - 168)..end_hour do
    let at = 320 + (hour % 169) * 32
    let integral = wide_number(data, at + 8)?
    if number(data, at)? != U64.parse(Int.to_string(hour))?
      || number(data, at + 24)? != U64.parse("3600")?
      || U128.compare(integral, U128.parse("3600")?) < 0
      || U128.compare(integral,
        U128.multiply(U128.parse("18446744073709551615")?, U128.parse("3600")?)?) > 0 do
      return Err("unavailable_token_twap")
    end
    integral
  end
  let sum = List.reduce(integrals,
    Ok(U128.parse("0")?),
    fn(result, value) do U128.add(result?, value) end)?
  U64.parse(U128.to_string(U128.divide(sum, U128.parse("604800")?)?))
end

pub fn token_oracle_validate_instruction(program :: Pubkey) -> Instruction!String do
  let a = token_addresses(program)?
  instruction(program,
    5,
    Bytes.empty(),
    [meta(a.config, false, false), meta(a.mint, false, false), meta(a.oracle, false, false)])
end

pub fn token_oracle_propose_source_instruction(program :: Pubkey,
  governance :: Pubkey,
  source_program :: Pubkey,
  source :: Pubkey,
  feed :: Bytes) -> Instruction!String do
  wallet(governance)?
  wallet(source)?
  receiver(source_program)?
  if Bytes.length(feed) != 32 || !nonzero(feed) do
    return Err("invalid_token_chain")
  end
  let a = token_addresses(program)?
  instruction(program,
    6,
    cat([source.bytes, feed])?,
    [
      meta(governance, true, false),
      meta(a.config, false, false),
      meta(a.mint, false, false),
      meta(a.oracle, false, true),
      meta(source_program, false, false),
      meta(source, false, false)
    ])
end

pub fn token_oracle_execute_source_instruction(program :: Pubkey,
  source_program :: Pubkey,
  source :: Pubkey) -> Instruction!String do
  receiver(source_program)?
  wallet(source)?
  let a = token_addresses(program)?
  instruction(program,
    7,
    Bytes.empty(),
    [
      meta(a.config, false, false),
      meta(a.mint, false, false),
      meta(a.oracle, false, true),
      meta(source_program, false, false),
      meta(source, false, false)
    ])
end

pub fn token_oracle_spot(data :: Bytes, now :: U64) -> U64!String do
  let oracle = decode_token_oracle(data)?
  if U64.compare(now, oracle.last_time) < 0
    || U64.compare(U64.subtract(now, oracle.last_time)?, U64.parse("60")?) > 0 do
    Err("unavailable_token_spot")
  else
    Ok(oracle.last_price)
  end
end
