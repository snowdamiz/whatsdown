from Tests.Fixture import operator_fixture_pins, operator_fixture_subject, operator_fixture_text
from Read import (
  collateral_operator_keys,
  decode_collateral_operator_snapshot,
  collateral_operator_quorum,
  validate_collateral_operator_sources
)
from Solana.Read import (
  Pubkey,
  pubkey,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

fn check_rpc() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_RPC_FIXTURE", "")
  let urls = Env.get("MORSE_COLLATERAL_OPERATOR_RPC_SOURCES", "")
  if path == "" || urls == "" do
    return Err("owned HTTP fixture inputs required")
  end
  let row = Json.parse(File.read(path)?)?
  let sources_json = Json.parse(urls)?
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(sources_json, index)?)?
  end
  validate_collateral_operator_sources(sources)?
  assert(Result.is_err(validate_collateral_operator_sources([
    List.get(sources, 0),
    List.get(sources, 0),
    List.get(sources, 2)
  ])))
  let pins = operator_fixture_pins(row)?
  let subject = operator_fixture_subject(row)?
  let operator = pubkey(operator_fixture_text(row, "operator")?)?
  let minimum = U64.parse(operator_fixture_text(row, "clock_slot")?)?
  let reference_time = U64.parse(operator_fixture_text(row, "clock_time")?)?
  let keys = collateral_operator_keys(pins, subject, operator)?
  let client = Http.client()
  let cases = for id in 1..13 do
    let votes = for source in sources do
      let request = get_multiple_accounts_slice_request(id,
        keys,
        "finalized",
        0,
        9216,
        Some(minimum))?
      let response = rpc_send(client, source, request, 2000, 262144)
      case response do
        Err(error)
        Ok(value) -> case optional_accounts_slice_from_response(value) do
          Err(error)
          Ok(snapshot) -> decode_collateral_operator_snapshot(pins,
            subject,
            operator,
            minimum,
            reference_time,
            snapshot)
        end
      end
    end
    let result = collateral_operator_quorum(List.get(votes, 0),
      List.get(votes, 1),
      List.get(votes, 2))
    if id == 1 || id == 2 do
      assert(Result.is_ok(result))
    else
      assert(Result.is_err(result))
    end
    1
  end
  Http.client_close(client)
  assert(List.length(cases) == 12)
  println("owned HTTP historical snapshot replay:12cases/36requests, no fresh-chain claim")
  Ok(true)
end

test("finalized whole-bank quorum rejects stale partial changed code/source redirects and disagreement") do
  case check_rpc() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
