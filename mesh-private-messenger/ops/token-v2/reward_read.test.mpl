from RewardRead import (
  TokenRewardReadPins,
  token_reward_read_keys,
  decode_token_reward_snapshot
)
from RewardFixture import token_reward_fixture
from Transparency.TokenWrite import TokenRewardWriteContext
from Transparency.TokenChain import decode_token_oracle
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

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

fn replace(snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  value :: Option<AccountSlice>) -> OptionalAccountSlicesAtSlot do
  %{snapshot |
    accounts: for index in 0..List.length(snapshot.accounts) do
      if index == at do
        value
      else
        List.get(snapshot.accounts, index)
      end
    end
  }
end

fn selected(snapshot :: OptionalAccountSlicesAtSlot, at :: Int) -> AccountSlice!String do
  case List.get(snapshot.accounts, at) do
    None -> Err("missing_fixture")
    Some(value) -> Ok(value)
  end
end

fn actual_reader() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let entries = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(entries)? do
    let item = Json.array_get(entries, index)?
    let name = text(item, "name")?
    if name == "token-rewards-finalized" || name == "token-rewards-claimed" do
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
      assert(List.length(keys) == 26)
      let snapshot = OptionalAccountSlicesAtSlot {
        slot: U64.parse(text(item, "context_slot")?)?,
        accounts: for position in 0..26 do
          let role = List.get(names, position)
          assert(List.get(keys, position) == address(accounts, role)?)
          Some(account(accounts, role)?)
        end
      }
      let state = decode_token_reward_snapshot(pins, epoch, snapshot.slot, snapshot)?
      assert(state.status == "finalized" && state.context_slot == snapshot.slot)
      assert(state.code_current
        && state.source_current
        && state.morse_surplus == U64.parse("19")?
        && state.twap == None)
      assert(state.revision_matches == (name == "token-rewards-finalized"))
      assert(state.claimed_usd == if name == "token-rewards-finalized" do
          U64.parse("0")?
        else
          U64.parse(Bytes.read_uint_le(account(accounts, "epoch")?.info.data, 144, 8)?)?
        end)
      assert(state.claimed_morse == U64.parse(if name == "token-rewards-finalized" do
          "0"
        else
          "500000000000"
        end)?)
      for position in 0..26 do
        assert(Result.is_err(decode_token_reward_snapshot(pins,
          epoch,
          snapshot.slot,
          replace(snapshot, position, None))))
        let current = selected(snapshot, position)?
        assert(Result.is_err(decode_token_reward_snapshot(pins,
          epoch,
          snapshot.slot,
          replace(snapshot,
            position,
            Some(%{current |
              info: %{current.info | owner: pubkey("11111111111111111111111111111111")?}
            })))))
      end
      assert(Result.is_err(decode_token_reward_snapshot(pins,
        epoch,
        U64.add(snapshot.slot, U64.parse("1")?)?,
        snapshot)))
      assert(Result.is_err(decode_token_reward_snapshot(%{pins |
          network_started: U64.add(pins.network_started, U64.parse("1")?)?
        },
        epoch,
        snapshot.slot,
        snapshot)))
      assert(Result.is_err(decode_token_reward_snapshot(%{pins |
          service_key: pins.governance.bytes
        },
        epoch,
        snapshot.slot,
        snapshot)))
    end
  end
  Ok(true)
end

fn actual_stages() -> Bool!String do
  let baseline = token_reward_fixture("token-rewards-finalized")?
  for name in [
    "open",
    "collecting",
    "invalidated",
    "source-changed",
    "expired",
    "floor-unfunded",
    "ready",
    "stale-floor-unfunded"
  ] do
    let fixture = token_reward_fixture("token-rewards-" <> name)?
    let state = decode_token_reward_snapshot(baseline.pins,
      fixture.epoch,
      fixture.snapshot.slot,
      fixture.snapshot)?
    assert(state.status == if name == "open" do
        "open"
      else
        "collecting"
      end)
    assert(state.source_current == (name != "source-changed"))
    assert(state.revision_matches == (name != "open"
        && name != "invalidated"
        && name != "source-changed"))
    assert(state.stage_expired == (name == "expired"))
    assert(state.code_current
      && state.claimed_usd == U64.parse("0")?
      && state.claimed_morse == U64.parse("0")?)
  end
  for name in ["empty-finalized", "usdc-only-finalized"] do
    let fixture = token_reward_fixture("token-rewards-" <> name)?
    let state = decode_token_reward_snapshot(baseline.pins,
      fixture.epoch,
      fixture.snapshot.slot,
      fixture.snapshot)?
    assert(state.status == "finalized" && state.code_current && state.source_current)
    let record = case state.record do
      None -> return Err("missing_finalized_record")
      Some(value) -> value
    end
    assert(record.allocated_morse == U64.parse("0")?
      && state.token_pool.liabilities_morse == U64.parse("0")?
      && state.reserve_remaining == U64.parse("150000000000000")?)
    if name == "empty-finalized" do
      assert(List.length(record.rows) == 0 && record.allocated_usd == U64.parse("0")?)
    else
      assert(record.twap == U64.parse("0")?
        && state.twap == None
        && record.allocated_usd == U64.parse("69076744")?)
    end
  end
  Ok(true)
end

test("actual staged revisions and TTL remain visible for cancel while earned claims stay payable") do
  let result = actual_stages()
  case result do
    Err(error) -> IO.eprintln("MORSE_TOKEN_REWARD_STAGE_ERROR " <> error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end

test("finalized v2 reader authenticates actual SBF roles and separate claim liabilities") do
  let result = actual_reader()
  case result do
    Err(error) -> IO.eprintln("MORSE_TOKEN_REWARD_READ_ERROR " <> error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
