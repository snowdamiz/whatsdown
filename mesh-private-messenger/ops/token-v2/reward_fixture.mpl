from RewardRead import TokenRewardReadPins, token_reward_read_keys
from Transparency.TokenWrite import TokenRewardWriteContext
from Transparency.TokenChain import decode_token_oracle
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

pub struct TokenRewardFixture do
  pins :: TokenRewardReadPins
  epoch :: U64
  snapshot :: OptionalAccountSlicesAtSlot
end

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn account(root :: Json, name :: String) -> AccountSlice!String do
  let value = Json.object_get(root, name)?
  Ok(AccountSlice {
    space: U64.parse(text(value, "space")?)?,
    info: AccountInfo {
      owner: pubkey(text(value, "owner")?)?,
      data: Bytes.from_hex(text(value, "data_hex")?)?,
      lamports: U64.parse(text(value, "lamports")?)?,
      rent_epoch: U64.parse("0")?,
      executable: Json.as_bool(Json.object_get(value, "executable")?)?
    }
  })
end

fn address(root :: Json, name :: String) -> Pubkey!String do
  pubkey(text(Json.object_get(root, name)?, "address")?)
end

fn optional_account(root :: Json, name :: String) -> Option<AccountSlice>!String do
  let value = Json.object_get(root, name)?
  case Json.object_get(value, "missing") do
    Ok(flag) -> if Json.as_bool(flag)? do
      return Ok(None)
    end
    Err(_) -> nil
  end
  Ok(Some(account(root, name)?))
end

pub fn token_reward_fixture(label :: String) -> TokenRewardFixture!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let entries = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(entries)? do
    let item = Json.array_get(entries, index)?
    if text(item, "name")? == label do
      let accounts = Json.object_get(item, "accounts")?
      let log = account(accounts, "log")?.info.data
      let pool = account(accounts, "pool")?.info.data
      let config = account(accounts, "token_config")?.info.data
      let oracle = decode_token_oracle(account(accounts, "oracle")?.info.data)?
      let pins = TokenRewardReadPins {
        context: TokenRewardWriteContext {
          program: pubkey(text(item, "rewards_program")?)?,
          judge: pubkey(text(item, "program")?)?,
          token: pubkey(text(item, "token_program")?)?,
          log_name: text(item, "log_name")?,
          usdc_mint: address(accounts, "usdc")?
        },
        governance: Pubkey { bytes: Bytes.slice(pool, 4, 32)? },
        token_governance: Pubkey { bytes: Bytes.slice(config, 4, 32)? },
        service_key: Bytes.slice(log, 72, 32)?,
        log_version: Bytes.get(log, 4)?,
        network_started: U64.parse(Bytes.read_uint_le(pool, 164, 8)?)?,
        token_slot: U64.parse("0")?,
        judge_slot: U64.parse("0")?,
        rewards_slot: U64.parse("0")?,
        source_program: oracle.receiver,
        source: oracle.source,
        feed: oracle.feed,
        source_revision: oracle.revision
      }
      let epoch = U64.parse(text(item, "epoch")?)?
      let keys = token_reward_read_keys(pins, epoch)?
      let names = [
        "pool",
        "token_pool",
        "epoch",
        "token_epoch",
        "pool_usdc_vault",
        "pool_morse_vault",
        "usdc",
        "morse",
        "log",
        "economics",
        "binding",
        "token_config",
        "oracle",
        "reserve_profile",
        "clock",
        "attendance_clock",
        "attendance_epoch",
        "token",
        "token_data",
        "judge",
        "judge_data",
        "rewards",
        "rewards_data",
        "reserve_receipt",
        "reserve_allocation",
        "reserve_vault"
      ]
      if List.length(keys) != 26 do
        return Err("invalid_reward_fixture_keys")
      end
      let snapshot = OptionalAccountSlicesAtSlot {
        slot: U64.parse(text(item, "context_slot")?)?,
        accounts: for position in 0..26 do
          let role = List.get(names, position)
          if List.get(keys, position) != address(accounts, role)? do
            return Err("invalid_reward_fixture_key")
          end
          optional_account(accounts, role)?
        end
      }
      return Ok(TokenRewardFixture { pins: pins, epoch: epoch, snapshot: snapshot })
    end
  end
  Err("missing_reward_fixture")
end

pub fn token_reward_identity_fixture(label :: String,
  offset :: Int,
  count :: Int) -> OptionalAccountSlicesAtSlot!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let entries = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(entries)? do
    let item = Json.array_get(entries, index)?
    if text(item, "name")? == label do
      let accounts = Json.object_get(item, "accounts")?
      return Ok(OptionalAccountSlicesAtSlot {
        slot: U64.parse(text(item, "context_slot")?)?,
        accounts: for row in offset..offset + count do
          optional_account(accounts, "attendance_witness" <> Int.to_string(row))?
        end
      })
    end
  end
  Err("missing_reward_fixture")
end
