##! Solana JSON-RPC reads. Account reads are what the monitor acts on, so they
##! count only when two providers return the same bytes (plan §5.9). Anything
##! read from a transaction is checked against an agreed account before use.

pub struct RpcAccount do
  owner :: String
  data :: Bytes
  slot :: Int
end

# Two providers' answers that agree: first is used; slot is the older of the
# two finalized slots.

pub struct AgreedAccount do
  owner :: String
  data :: Bytes
  other :: Bytes
  slot :: Int
end

pub struct RpcSignature do
  signature :: String
  slot :: Int
end

pub struct RpcInstruction do
  program :: String
  data :: Bytes
end

fn rpc_call(url :: String, method :: String, params :: String) -> Json!String do
  let body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"#{method}\",\"params\":#{params}}"
  let response = Http.build(:post, url)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(4000000)
    |> Http.send()?
  if response.status != 200 do
    Err("rpc returned #{response.status}")
  else
    let root = Json.parse(response.body)?
    case Json.object_get(root, "error") do
      Ok(error) -> if Json.is_null(error) do
        Json.object_get(root, "result")
      else
        Err("rpc error #{Json.encode(error)}")
      end
      Err(_) -> Json.object_get(root, "result")
    end
  end
end

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn integer(value :: Json, key :: String) -> Int!String do
  Json.as_int(Json.object_get(value, key)?)
end

pub fn monitor_rpc_account(url :: String,
  address :: String,
  offset :: Int,
  length :: Int) -> RpcAccount!String do
  let params = "[#{Json.encode_string(address)},{\"encoding\":\"base64\",\"commitment\":\"finalized\",\"dataSlice\":{\"offset\":#{offset},\"length\":#{length}}}]"
  let result = rpc_call(url, "getAccountInfo", params)?
  let value = Json.object_get(result, "value")?
  if Json.is_null(value) do
    Err("account #{address} not found")
  else
    let data = case Bytes.from_base64(Json.as_string(Json.array_get(Json.object_get(value, "data")?,
      0)?)?) do
      Err(_) -> Err("invalid account data")
      Ok(bytes)
    end?
    if Bytes.length(data) != length do
      Err("account #{address} is shorter than expected")
    else
      Ok(RpcAccount {
        owner: text(value, "owner")?,
        data: data,
        slot: integer(Json.object_get(result, "context")?, "slot")?
      })
    end
  end
end

fn matching(answers :: List<RpcAccount>,
  answer :: RpcAccount,
  same :: Fun(Bytes, Bytes) -> Bool) -> Option<RpcAccount> do
  List.find(answers, fn prior -> prior.owner == answer.owner && same(prior.data, answer.data) end)
end

fn agreed(prior :: RpcAccount, answer :: RpcAccount) -> AgreedAccount do
  AgreedAccount {
    owner: prior.owner,
    data: prior.data,
    other: answer.data,
    slot: if prior.slot < answer.slot do
      prior.slot
    else
      answer.slot
    end
  }
end

fn gather(urls :: List<String>,
  address :: String,
  offset :: Int,
  length :: Int,
  same :: Fun(Bytes, Bytes) -> Bool,
  answers :: List<RpcAccount>) -> AgreedAccount!String do
  case urls do
    [] -> if List.length(answers) < 2 do
      Err("rpc_unavailable: fewer than two providers answered for #{address}")
    else
      Err("rpc_disagree: providers disagree on #{address} at #{offset}")
    end
    url :: rest -> case monitor_rpc_account(url, address, offset, length) do
      Err(_) -> gather(rest, address, offset, length, same, answers)
      Ok(answer) -> case matching(answers, answer, same) do
        Some(prior) -> Ok(agreed(prior, answer))
        None -> gather(rest, address, offset, length, same, List.append(answers, answer))
      end
    end
  end
end

# Reads until two providers agree (same owner, and same bytes by same). One
# retry absorbs a write that landed between two reads.

pub fn monitor_rpc_agree(urls :: List<String>,
  address :: String,
  offset :: Int,
  length :: Int,
  same :: Fun(Bytes, Bytes) -> Bool) -> AgreedAccount!String do
  case gather(urls, address, offset, length, same, List.new()) do
    Ok(value)
    Err(_) -> gather(urls, address, offset, length, same, List.new())
  end
end

pub fn monitor_same_bytes(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

# Newest first, at most 1000, older than before ("" = from the newest).

pub fn monitor_rpc_signatures(url :: String,
  address :: String,
  before :: String) -> List<RpcSignature>!String do
  let cursor = if before == "" do
    ""
  else
    ",\"before\":#{Json.encode_string(before)}"
  end
  let result = rpc_call(url,
    "getSignaturesForAddress",
    "[#{Json.encode_string(address)},{\"limit\":1000,\"commitment\":\"finalized\"#{cursor}}]")?
  let count = Json.array_length(result)?
  Ok(for index in 0..count do
    signature_at(result, index)?
  end)
end

fn signature_at(result :: Json, index :: Int) -> RpcSignature!String do
  let item = Json.array_get(result, index)?
  Ok(RpcSignature { signature: text(item, "signature")?, slot: integer(item, "slot")? })
end

fn instruction(keys :: Json, value :: Json) -> RpcInstruction!String do
  let program = Json.as_string(Json.array_get(keys, integer(value, "programIdIndex")?)?)?
  case Bytes.from_base58(text(value, "data")?) do
    Err(_) -> Err("invalid instruction data")
    Ok(data) -> Ok(RpcInstruction { program: program, data: data })
  end
end

# The top-level instructions of a transaction, with their program IDs.

pub fn monitor_rpc_instructions(url :: String,
  signature :: String) -> List<RpcInstruction>!String do
  let result = rpc_call(url,
    "getTransaction",
    "[#{Json.encode_string(signature)},{\"encoding\":\"json\",\"commitment\":\"finalized\",\"maxSupportedTransactionVersion\":0}]")?
  if Json.is_null(result) do
    Ok(List.new())
  else
    let message = Json.object_get(Json.object_get(result, "transaction")?, "message")?
    let keys = Json.object_get(message, "accountKeys")?
    let instructions = Json.object_get(message, "instructions")?
    let count = Json.array_length(instructions)?
    Ok(for index in 0..count do
      instruction(keys, Json.array_get(instructions, index)?)?
    end)
  end
end
