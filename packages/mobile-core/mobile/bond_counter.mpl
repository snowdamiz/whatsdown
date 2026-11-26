from Mobile.Types import MobileSecurityConfig, MobileTransparencyView
from Security.Config import SecurityConfig
from Mobile.AnchorSteps import (
  AnchorContext,
  AnchorExchange,
  AnchorStop,
  anchor_asks,
  anchor_rpc,
  anchor_soft,
  anchor_waiting
)
from Mobile.Chain import (
  ChainAccount,
  ChainLog,
  ChainTokenAmount,
  ChainWitness,
  ChainWitnessState,
  chain_account,
  chain_account_request,
  chain_accounts,
  chain_accounts_request,
  chain_address_at,
  chain_decode_token,
  chain_decode_witness,
  chain_log_id,
  chain_program_account,
  chain_program_request,
  chain_project_account,
  chain_project_accounts,
  chain_project_program,
  chain_spl_token_program,
  chain_u32_at
)
from Transparency.Codec import tcodec_join, tcodec_u64, tcodec_u8, tcodec_vector

##! Mobile.BondCounter: the bonds and slashes of the pinned log, read from the
##! chain through the pinned RPC providers like the anchor check (plan §6.17).
##! Only the `morse-main` log counts: a test build pinning the canary log reads
##! it for the anchor check but shows no bond counter. Every number is a read
##! two providers agreed on; when they do not agree the counter is unavailable,
##! never a guess. Token bonds carry a USD value only when the rewards
##! program's price feed is fresh.
##!
##! Body (network status section 3): u8 available || u8 counted ||
##! u8 service_slashed || u8 slashed_witnesses || bond(directory) || u8 n ||
##! n x (vector32(witness_id) || u8 status || bond), one row per pinned witness
##! (status as the judge keeps it, 255 when the log does not list it);
##! bond = u8 asset (0 none, 1 USDC, 2 Morse token, 3 other) || u64 amount ||
##! u8 usd_known || u64 usd_micros. Amounts are base units (6 decimals).

struct BondValue do
  asset :: Int
  amount :: Int
  usd :: Int
end

struct BondMints do
  usdc :: String
  token :: String
  rewards :: String
end

struct BondPrice do
  price :: Int
  exponent :: Int
end

fn zero_address() -> String do
  "11111111111111111111111111111111"
end

fn none() -> BondValue do
  BondValue { asset: 0, amount: 0, usd: -1 }
end

fn encode_bond(value :: BondValue) -> Bytes!String do
  tcodec_join([
    tcodec_u8(value.asset)?,
    tcodec_u64(value.amount)?,
    tcodec_u8(if value.usd >= 0 do
      1
    else
      0
    end)?,
    tcodec_u64(if value.usd >= 0 do
      value.usd
    else
      0
    end)?
  ])
end

fn flag(value :: Bool) -> Bytes!String do
  tcodec_u8(if value do
    1
  else
    0
  end)
end

fn encode(available :: Bool,
  counted :: Bool,
  log :: ChainLog,
  slashed :: Int,
  directory :: BondValue,
  rows :: List<(String, Int, BondValue)>) -> Bytes!String do
  let encoded = for (id, status, bond) in rows do
    tcodec_join([tcodec_vector(Bytes.from_utf8(id))?, tcodec_u8(status)?, encode_bond(bond)?])?
  end
  tcodec_join([
    flag(available)?,
    flag(counted)?,
    flag(log.service_slashed)?,
    tcodec_u8(slashed)?,
    encode_bond(directory)?,
    tcodec_u8(List.length(rows))?
  ]
    ++ encoded)
end

fn unavailable(counted :: Bool, log :: ChainLog) -> Bytes!String do
  encode(false, counted, log, 0, none(), List.new())
end

fn witness_state(account :: Option<ChainAccount>, judge :: String) -> Option<ChainWitnessState> do
  case account do
    None
    Some(value) -> if value.owner != judge do
      None
    else
      case chain_decode_witness(value.data) do
        Err(_) -> None
        Ok(state) -> Some(state)
      end
    end
  end
end

# Every listed witness's account, or None when any is missing or malformed.

fn all_states(accounts :: List<Option<ChainAccount>>,
  judge :: String,
  output :: List<ChainWitnessState>) -> Option<List<ChainWitnessState>> do
  case accounts do
    [] -> Some(output)
    account :: rest -> case witness_state(account, judge) do
      None
      Some(state) -> all_states(rest, judge, List.append(output, state))
    end
  end
end

fn witness_states(projection :: Bytes,
  count :: Int,
  judge :: String) -> Option<List<ChainWitnessState>> do
  case chain_accounts(projection, count) do
    Err(_) -> None
    Ok(accounts) -> all_states(accounts, judge, List.new())
  end
end

fn all_amounts(accounts :: List<Option<ChainAccount>>,
  output :: List<Option<ChainTokenAmount>>) -> Option<List<Option<ChainTokenAmount>>> do
  case accounts do
    [] -> Some(output)
    account :: rest -> case token_amount(account) do
      None
      Some(amount) -> all_amounts(rest, List.append(output, amount))
    end
  end
end

# A vault that does not exist holds no bond; one not owned by the SPL Token
# program is not a vault at all.

fn token_amount(account :: Option<ChainAccount>) -> Option<Option<ChainTokenAmount>> do
  case account do
    None -> Some(None)
    Some(value) -> if value.owner != chain_spl_token_program() do
      None
    else
      case chain_decode_token(value.data) do
        Err(_) -> None
        Ok(amount) -> Some(Some(amount))
      end
    end
  end
end

fn mint_fields(account :: ChainAccount) -> BondMints!String do
  Ok(BondMints {
    usdc: chain_address_at(account.data, 40)?,
    token: chain_address_at(account.data, 72)?,
    rewards: chain_address_at(account.data, 104)?
  })
end

fn mints(found :: Option<(String, ChainAccount)>, judge :: String) -> Option<BondMints> do
  case found do
    None
    Some((_, account)) -> if account.owner != judge do
      None
    else
      case mint_fields(account) do
        Err(_) -> None
        Ok(value) -> Some(value)
      end
    end
  end
end

fn pow10(exponent :: Int) -> U128!String do
  U128.parse("1" <> String.repeat("0", exponent))
end

# USD micro-dollars = amount x price x 10^exponent (both mints have 6
# decimals, morse-judge-v1.md §10.4).

fn usd_micros(amount :: Int, price :: BondPrice) -> Int!String do
  let product = U128.multiply(U128.parse(Int.to_string(amount))?,
    U128.parse(Int.to_string(price.price))?)?
  let scaled = if price.exponent >= 0 do
    U128.multiply(product, pow10(price.exponent)?)?
  else
    U128.divide(product, pow10(0 - price.exponent)?)?
  end
  case String.to_int(U128.to_string(scaled)) do
    Some(value) -> Ok(value)
    None -> Err("bond_value_too_large")
  end
end

fn usd_value(amount :: Int, price :: BondPrice) -> Int do
  case usd_micros(amount, price) do
    Ok(value) -> value
    Err(_) -> -1
  end
end

fn value_of(amount :: Option<ChainTokenAmount>,
  mints :: BondMints,
  price :: Option<BondPrice>) -> BondValue do
  case amount do
    None -> none()
    Some(value) -> if value.amount == 0 do
      none()
    else if value.mint == mints.usdc do
      BondValue { asset: 1, amount: value.amount, usd: value.amount }
    else if value.mint == mints.token && mints.token != zero_address() do
      BondValue {
        asset: 2,
        amount: value.amount,
        usd: case price do
          None -> -1
          Some(known) -> usd_value(value.amount, known)
        end
      }
    else
      BondValue { asset: 3, amount: value.amount, usd: -1 }
    end
  end
end

fn signed32(value :: Int) -> Int do
  if value >= 2147483648 do
    value - 4294967296
  else
    value
  end
end

fn feed_price(projection :: Option<Bytes>, oracle :: String, now_ms :: Int) -> Option<BondPrice> do
  case projection do
    None
    Some(bytes) -> case chain_account(bytes) do
      Ok(Some(account)) -> if account.owner != oracle do
        None
      else
        read_price(account.data, now_ms)
      end
      _ -> None
    end
  end
end

fn price_fields(data :: Bytes, now_ms :: Int) -> BondPrice!String do
  let price = case Bytes.read_u64_le(data, 0) do
    Err(_) -> Err("invalid")
    Ok(value) -> U64.to_int(value)
  end?
  let exponent = signed32(chain_u32_at(data, 8)?)
  let published = case Bytes.read_u64_le(data, 12) do
    Err(_) -> Err("invalid")
    Ok(value) -> U64.to_int(value)
  end?
  let now = now_ms / 1000
  if price <= 0
    || exponent < -18
    || exponent > 18
    || published > now + 60
    || now - published > 86400 do
    Err("stale")
  else
    Ok(BondPrice { price: price, exponent: exponent })
  end
end

fn read_price(data :: Bytes, now_ms :: Int) -> Option<BondPrice> do
  case price_fields(data, now_ms) do
    Ok(value) -> Some(value)
    Err(_) -> None
  end
end

fn price_needed(amounts :: List<Option<ChainTokenAmount>>, mints :: BondMints) -> Bool do
  mints.token != zero_address()
    && mints.rewards != zero_address()
    && List.any(amounts,
      fn amount -> case amount do
        Some(value) -> value.mint == mints.token && value.amount > 0
        None -> false
      end end)
end

# The rewards program's price feed and the oracle program that must own it.

fn feed_fields(projection :: Bytes, rewards :: String) -> (String, String)!String do
  case chain_program_account(projection)? do
    None -> Err("no_rewards_config")
    Some((_, account)) -> if account.owner != rewards do
      Err("no_rewards_config")
    else
      Ok((chain_address_at(account.data, 200)?, chain_address_at(account.data, 168)?))
    end
  end
end

fn price_of(ctx :: AnchorContext,
  mints :: BondMints,
  log_bytes :: Bytes,
  judge_bytes :: Bytes) -> Result<Option<BondPrice>, AnchorStop> do
  let found = anchor_soft(anchor_rpc(ctx,
    "bond-rewards",
    chain_program_request(mints.rewards, 904, [(0, pair(1)), (40, judge_bytes), (72, log_bytes)]),
    fn body -> chain_project_program(body) end))?
  let feed = case found do
    None
    Some(projection) -> case feed_fields(projection, mints.rewards) do
      Ok(value) -> Some(value)
      Err(_) -> None
    end
  end
  case feed do
    None -> Ok(None)
    Some((address, oracle)) -> do
      let read = anchor_soft(anchor_rpc(ctx,
        "bond-feed",
        chain_account_request(address, 0, 20),
        fn body -> chain_project_account(body, 20) end))?
      Ok(feed_price(read, oracle, ctx.now))
    end
  end
end

# Tag byte then layout version 1: how every judge and rewards account starts.

fn pair(tag :: Int) -> Bytes do
  case Bytes.from_list([tag, 1]) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
end

fn base58_bytes(address :: String) -> Bytes do
  case Bytes.from_base58(address) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
end

pub fn bond_counter_read(ctx :: AnchorContext, log :: ChainLog) -> Result<Bytes, AnchorStop> do
  let counted = case chain_log_id("morse-main") do
    Ok(id) -> Bytes.secure_equals(id, log.log_id)
    Err(_) -> false
  end
  let judge = ctx.config.config.judge_program_id
  if !counted do
    return lift(unavailable(false, log))
  end
  let accounts = List.map(log.witnesses, fn witness -> witness.account end)
  let count = List.length(accounts)
  let witnesses_read = if count == 0 do
    Ok(Some(Bytes.empty()))
  else
    anchor_soft(anchor_rpc(ctx,
      "bond-witnesses",
      chain_accounts_request(accounts, 264),
      fn body -> chain_project_accounts(body, count, 264) end))
  end
  let directory_read = anchor_soft(anchor_rpc(ctx,
    "bond-directory",
    chain_account_request(log.directory_vault, 0, 72),
    fn body -> chain_project_account(body, 72) end))
  let config_read = anchor_soft(anchor_rpc(ctx,
    "bond-config",
    chain_program_request(judge, 192, [(0, pair(1))]),
    fn body -> chain_project_program(body) end))
  anchor_waiting(anchor_asks(witnesses_read)
    ++ anchor_asks(directory_read)
    ++ anchor_asks(config_read))?
  let states = case witnesses_read? do
    None
    Some(projection) -> if count == 0 do
      Some(List.new())
    else
      witness_states(projection, count, judge)
    end
  end
  let directory = case directory_read? do
    None
    Some(projection) -> case chain_account(projection) do
      Err(_) -> None
      Ok(account) -> token_amount(account)
    end
  end
  let found_mints = case config_read? do
    None
    Some(projection) -> case chain_program_account(projection) do
      Err(_) -> None
      Ok(found) -> mints(found, judge)
    end
  end
  case (states, directory, found_mints) do
    (Some(listed), Some(directory_amount), Some(known)) -> with_vaults(ctx,
      log,
      listed,
      directory_amount,
      known)
    _ -> lift(unavailable(true, log))
  end
end

fn lift(value :: Bytes!String) -> Result<Bytes, AnchorStop> do
  case value do
    Ok(bytes)
    Err(error) -> Err(AnchorStop { asks: List.new(), outcome: error })
  end
end

fn with_vaults(ctx :: AnchorContext,
  log :: ChainLog,
  states :: List<ChainWitnessState>,
  directory :: Option<ChainTokenAmount>,
  known :: BondMints) -> Result<Bytes, AnchorStop> do
  let count = List.length(states)
  let vaults = List.map(states, fn state -> state.vault end)
  let vaults_read = if count == 0 do
    Ok(Some(Bytes.empty()))
  else
    anchor_soft(anchor_rpc(ctx,
      "bond-vaults",
      chain_accounts_request(vaults, 72),
      fn body -> chain_project_accounts(body, count, 72) end))
  end
  let amounts = case vaults_read? do
    None
    Some(projection) -> if count == 0 do
      Some(List.new())
    else
      case chain_accounts(projection, count) do
        Err(_) -> None
        Ok(accounts) -> all_amounts(accounts, List.new())
      end
    end
  end
  case amounts do
    None -> lift(unavailable(true, log))
    Some(witness_amounts) -> do
      let price = if price_needed([directory] ++ witness_amounts, known) do
        price_of(ctx,
          known,
          base58_bytes(ctx.config.config.log_account),
          base58_bytes(ctx.config.config.judge_program_id))?
      else
        None
      end
      let slashed = List.length(List.filter(states, fn state -> state.status == 3 end))
      let rows = for witness in ctx.config.config.witnesses do
        row(log, states, witness_amounts, known, price, witness.witness_id)
      end
      lift(encode(true, true, log, slashed, value_of(directory, known, price), rows))
    end
  end
end

fn row(log :: ChainLog,
  states :: List<ChainWitnessState>,
  amounts :: List<Option<ChainTokenAmount>>,
  known :: BondMints,
  price :: Option<BondPrice>,
  id :: String) -> (String, Int, BondValue) do
  let indexes = for index in 0..List.length(log.witnesses) when List.get(log.witnesses,
    index).witness_id == id do
    index
  end
  case indexes do
    [] -> (id, 255, none())
    index :: _ -> (id,
      List.get(states, index).status,
      value_of(List.get(amounts, index), known, price))
  end
end
