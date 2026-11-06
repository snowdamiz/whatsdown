from Transparency.Config import decode_security_config
from Mobile.NetworkCounterPins import NetworkCounterPins
from Mobile.NetworkCounterState import NetworkBondRow, NetworkBondObservation, network_token_value
from Mobile.NetworkCounter import (
  network_counter_output,
  counter_historical,
  attach_counter_history,
  load_network_counter_cache
)
from Mobile.NetworkCounterHistory import retain_counter_slashes, load_counter_slashes
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key, local_context, seal_local
from Storage.Records import compare_and_swap_blobs
from Solana.Read import pubkey
from Tests.Support import repeated, database_path

fn suffix(index :: Int) -> String do
  if index < 10 do
    "0#{index}"
  else
    Int.to_string(index)
  end
end

# Capacity only: these synthetic typed records are never passed to the RPC
# authenticator and are not evidence of any chain account or monetary balance.
fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let entries = for index in 0..16 do
    String.repeat("a", 62)
      <> suffix(index)
      <> " "
      <> Bytes.to_hex(repeated(index + 1, 32)?)
      <> " "
      <> String.repeat("\\", 48)
  end
  let security = decode_security_config(Bytes.from_utf8(String.join([
      "4",
      String.repeat("aa", 32),
      String.repeat("bb", 32),
      "8",
      "9",
      "16"
    ]
      ++ entries
      ++ [
        "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
        "3",
        "https://one.example",
        "https://two.example",
        "https://three.example",
        "-",
        "2",
        "9",
        "16"
      ]
      ++ entries
      ++ [String.repeat("1", 32), "morse-main"],
    "\n")))?
  let maximum = U64.parse("18446744073709551615")?
  let zero = U64.parse("0")?
  let principal = U64.parse("10000000000000000000")?
  let donation = U64.parse("8446744073709551615")?
  let pins = NetworkCounterPins {
    identity: repeated(19, 32)?,
    security: security,
    minimum_slot: maximum,
    judge_slot: maximum,
    log_version: 1,
    legacy_governance: None,
    legacy_authority: None,
    legacy_mint: None,
    collateral: None,
    oracle: None,
    tls_root: None
  }
  let rows = for index in 0..17 do
    NetworkBondRow {
      witness_id: if index == 0 do
        ""
      else
        String.repeat("a", 62) <> suffix(index - 1)
      end,
      public_key: repeated(index, 32)?,
      address: pubkey(Bytes.to_base58(repeated(index + 70, 32)?))?,
      owner: repeated(254, 32)?,
      mint: Some(repeated(252, 32)?),
      vault: Some(repeated(250, 32)?),
      asset: "MORSE",
      layout: 2,
      status: 1,
      principal: Some(principal),
      pending: Some(zero),
      pending_recorded: Some(zero),
      balance: Some(maximum),
      donation: Some(donation),
      opposite_balance: Some(maximum),
      usdc_vault: Some(maximum),
      morse_vault: Some(maximum),
      bonded_at: maximum,
      unbond_at: maximum,
      slashed_at: maximum,
      underwater_since: maximum,
      usd_micros: Some(network_token_value(principal, maximum)?)
    }
  end
  let observation = NetworkBondObservation {
    slot: maximum,
    timestamp: maximum,
    service_slashed: false,
    witnesses_slashed: 0,
    rows: rows,
    digest: repeated(253, 32)?,
    valuation: "available",
    twap: Some(maximum)
  }
  let slashed = %{observation |
    service_slashed: true,
    witnesses_slashed: 16,
    rows: for row in rows do
      %{row |
        status: 3,
        principal: Some(zero),
        pending_recorded: Some(maximum),
        balance: Some(maximum),
        donation: Some(maximum),
        usd_micros: Some(U128.parse("0")?)
      }
    end
  }
  let key = platform_key()?
  let path = database_path("counter-capacity")?
  ensure_schema(path)?
  retain_counter_slashes(path, pins, key, slashed)?
  let facts = load_counter_slashes(path, pins, key)?
  assert(List.length(facts) == 17)
  let current = attach_counter_history(network_counter_output(pins, slashed, maximum)?,
    facts,
    pins)?
  let historical = attach_counter_history(counter_historical(network_counter_output(pins,
        observation,
        maximum)?,
      "capacity-fixture",
      maximum)?,
    facts,
    pins)?
  assert(Bytes.length(current) <= 32768 && Bytes.length(historical) <= 32768)
  let label = "network-counter/v1/" <> Bytes.to_hex(pins.identity)
  let blob = seal_local(historical, key, local_context(label)?)?
  compare_and_swap_blobs(path, [label], [blob], Bytes.empty())?
  let cached = load_network_counter_cache(path, pins, key)?
  assert(cached.wire == historical && cached.slot == maximum && cached.checked == maximum)
  let output = Env.get("MORSE_NETWORK_COUNTER_CAPACITY_OUTPUT", "")
  if output != "" do
    File.write(output, Bytes.to_utf8(historical)?)?
  end
  println("capacity current=#{Bytes.length(current)} historical=#{Bytes.length(historical)} rows=17 facts=17")
  Secret.destroy(key)
  File.delete(path)?
  Ok(true)
end

test("maximum synthetic 17-row counter with 17 retained facts fits native frame and sealed cache") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
