from RewardRead import decode_token_reward_snapshot
from RewardFixture import token_reward_fixture, token_reward_identity_fixture
from RewardIdentities import decode_token_reward_append_identities
from Solana.Read import pubkey

fn identities() -> Bool!String do
  let f = token_reward_fixture("token-rewards-collecting")?
  let state = decode_token_reward_snapshot(f.pins, f.epoch, f.snapshot.slot, f.snapshot)?
  let snapshot = token_reward_identity_fixture("token-rewards-collecting", 1, 3)?
  let keys = decode_token_reward_append_identities(f.pins.context, state, snapshot)?
  assert(List.length(keys) == 3)
  let week = case state.attendance do
    None -> return Err("missing_week")
    Some(value) -> value
  end
  for index in 0..3 do
    assert(List.get(keys, index).witness.bytes == List.get(week.rows, 1 + index).witness)
    let account = case List.get(snapshot.accounts, index) do
      None -> return Err("missing_witness")
      Some(value) -> value
    end
    let bad = %{snapshot |
      accounts: for row in 0..3 do
        if row == index do
          Some(%{account |
            info: %{account.info | owner: pubkey("11111111111111111111111111111111")?}
          })
        else
          List.get(snapshot.accounts, row)
        end
      end
    }
    assert(Result.is_err(decode_token_reward_append_identities(f.pins.context, state, bad)))
  end
  assert(Result.is_err(decode_token_reward_append_identities(f.pins.context,
    state,
    %{snapshot | accounts: List.reverse(snapshot.accounts)})))
  assert(Result.is_err(decode_token_reward_append_identities(f.pins.context,
    state,
    %{snapshot | accounts: List.drop(snapshot.accounts, 1)})))
  assert(Result.is_err(decode_token_reward_append_identities(f.pins.context,
    state,
    %{snapshot | slot: U64.subtract(snapshot.slot, U64.parse("1")?)?})))
  Ok(true)
end

test("keeper resolves the next zero-weight attendance identities with owner and canonical PDA checks") do
  let result = identities()
  case result do
    Err(error) -> IO.eprintln("MORSE_TOKEN_APPEND_IDENTITIES_ERROR " <> error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
