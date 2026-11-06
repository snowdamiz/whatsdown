from Tests.Fixture import operator_fixture_pins, operator_fixture_text
from ProofRead import CollateralProofIntent, collateral_proof_keys
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey, pubkey_string

fn export_queries() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  let output = Env.get("MORSE_COLLATERAL_OPERATOR_EXTRA_KEYS_OUTPUT", "")
  if path == "" || output == "" do
    return Err("explicit fixture input/output required")
  end
  let rows = Json.object_get(Json.parse(File.read(path)?)?, "cases")?
  let requests = for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    let tag = Json.as_int(Json.object_get(row, "tag")?)?
    if tag < 31 || tag == 41 || tag == 42 || tag == 43 || tag == 44 do
      let selected = Json.object_get(row, "keys")?
      let witnesses = for at in 0..Json.array_length(selected)? do
        let value = Json.array_get(selected, at)?
        WitnessKey {
          witness_id: operator_fixture_text(value, "witness_id")?,
          public_key: Bytes.from_hex(operator_fixture_text(value, "public_key")?)?
        }
      end
      let intent = CollateralProofIntent {
        fee_payer: pubkey(operator_fixture_text(row, "fee_payer")?)?,
        submitter: pubkey(operator_fixture_text(row, "submitter")?)?,
        wire: Bytes.from_hex(operator_fixture_text(row, "wire_hex")?)?,
        witnesses: witnesses,
        close: false
      }
      let keys = collateral_proof_keys(operator_fixture_pins(row)?, intent)?
      assert(List.length(keys) <= 97)
      [
        "{\"expected\":#{Json.encode(Json.object_get(row,
          "sdk")?)},\"keys\":[#{String.join(List.map(keys,
            fn(key) do Json.encode_string(pubkey_string(key)) end),
          ",")}]}"
      ]
    else
      []
    end
  end
  let requests = List.flatten(requests)
  assert(List.length(requests) > 60)
  File.write(output, "{\"schema_version\":1,\"requests\":[#{String.join(requests, ",")}]}")?
  println("canonical same-bank proof query packets=#{List.length(requests)}")
  Ok(true)
end

test("Mesh derives bounded exact proof query roles before actual bank observation") do
  case export_queries() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
