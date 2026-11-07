# Transport only. The production worker takes origins exclusively from a
# validated native security frame. Loopback HTTP is used by protocol tests.
# A successful reply acknowledges receipt of the bytes, never an on-chain payout.
pub fn filing_acknowledged(status :: Int, body :: String, hash :: Bytes) -> Bool!String do
  if (status != 200 && status != 202) || Bytes.length(hash) != 32 || String.length(body) > 4096 do
    return Ok(false)
  end
  let value = Json.parse(body)?
  let version = Json.as_int(Json.object_get(value, "schema_version")?)?
  let result = Json.as_string(Json.object_get(value, "status")?)?
  let proof = Json.as_string(Json.object_get(value, "proof_hash")?)?
  Ok(version == 1
    && proof == Bytes.to_hex(hash)
    && ((status == 202 && result == "queued") || (status == 200 && result == "settled")))
end

fn submit_one(origin :: String, wire :: Bytes, hash :: Bytes) -> Bool do
  let response = case (Http.build(:post, origin <> "/v1/fork-evidence")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(wire)
    |> Http.timeout(30000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(4096)
    |> Http.send()) do
    Err(_) -> return false
    Ok(value) -> value
  end
  case filing_acknowledged(response.status, response.body, hash) do
    Err(_) -> false
    Ok(value) -> value
  end
end

pub fn submit_filing(origins :: List<String>, wire :: Bytes, hash :: Bytes) -> Int!String do
  if List.length(origins) > 8
    || Bytes.length(wire) == 0
    || Bytes.length(wire) > 8192
    || Bytes.length(hash) != 32 do
    return Err("invalid_filing_request")
  end
  let results = Job.map(origins, fn(origin) do submit_one(origin, wire, hash) end)
  Ok(List.length(List.filter(results,
    fn(value) do
      case value do
        Ok(accepted) -> accepted
        Err(_) -> false
      end
    end)))
end
