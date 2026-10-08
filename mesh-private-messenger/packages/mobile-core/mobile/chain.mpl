##! Mobile.Chain: the Solana JSON-RPC reads the phone asks the app to make
##! (protocol/morse-judge-v1.md §4, §11) and the judge account layouts it
##! decodes from the answers. The core never talks to the network: it builds
##! request bodies, the app posts them to pinned RPC URLs, and the answers come
##! back as bytes. On-chain integers are little-endian.
##!
##! Answers are reduced to a canonical projection (owner and the bytes the
##! phone uses); two providers agree when their projections are equal.

pub struct ChainAccount do
  owner :: String
  data :: Bytes
end

pub struct ChainWitness do
  witness_id :: String
  public_key :: Bytes
  account :: String
  since_slot :: Int
end

pub struct ChainLog do
  log_id :: Bytes
  service_key :: Bytes
  ring :: String
  directory_vault :: String
  service_slashed :: Bool
  witnesses :: List<ChainWitness>
end

pub struct ChainRingHeader do
  log_id :: Bytes
  head :: Int
  count :: Int
  last_sequence :: Int
  last_size :: Int
  last_slot :: Int
end

pub struct ChainRingEntry do
  index :: Int
  sequence :: Int
  tree_size :: Int
  root :: Bytes
  hash :: Bytes
  slot :: Int
  bitmap :: Int
  evidence :: Int
end

pub struct ChainTokenAmount do
  mint :: String
  amount :: Int
end

pub struct ChainWitnessState do
  status :: Int
  vault :: String
end

pub struct ChainProof do
  log :: String
  proof_hash :: Bytes
  paid_to :: Bytes
  slot :: Int
end

pub fn chain_spl_token_program() -> String do
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
end

pub fn chain_log_length() -> Int do
  2584
end

pub fn chain_ring_capacity() -> Int do
  4096
end

pub fn chain_entry_offset(index :: Int) -> Int do
  64 + 104 * index
end

# The log ID convention: the log's ASCII name, zero-padded to 32 bytes.

pub fn chain_log_id(name :: String) -> Bytes!String do
  let text = Bytes.from_utf8(name)
  let padding = case Bytes.repeat(0, 32 - Bytes.length(text)) do
    Err(_) -> Err("chain_invalid")
    Ok(value)
  end?
  join([text, padding])
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  join_from(parts, 0, Bytes.empty())
end

fn join_from(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err("chain_invalid")
      Ok(value) -> join_from(parts, index + 1, value)
    end
  end
end

fn marker(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("chain_invalid")
    Ok(encoded)
  end
end

fn slice(data :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(data, offset, length) do
    Err(_) -> Err("chain_invalid")
    Ok(value)
  end
end

fn byte(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(data, offset) do
    Err(_) -> Err("chain_invalid")
    Ok(value)
  end
end

fn wide(value :: U64) -> Int!String do
  case U64.to_int(value) do
    Err(_) -> Err("chain_invalid")
    Ok(parsed)
  end
end

pub fn chain_u64(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u64_le(data, offset) do
    Err(_) -> Err("chain_invalid")
    Ok(value) -> wide(value)
  end
end

fn u32_at(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_le(data, offset) do
    Err(_) -> Err("chain_invalid")
    Ok(value) -> wide(value)
  end
end

fn u16_at(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_le(data, offset) do
    Err(_) -> Err("chain_invalid")
    Ok(value)
  end
end

fn address(data :: Bytes, offset :: Int) -> String!String do
  Ok(Bytes.to_base58(slice(data, offset, 32)?))
end

# JSON-RPC request bodies (commitment finalized, base64 data).

fn envelope(method :: String, params :: String) -> String do
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"#{method}\",\"params\":#{params}}"
end

pub fn chain_account_request(address :: String, offset :: Int, length :: Int) -> String do
  envelope("getAccountInfo",
    "[#{Json.encode_string(address)},{\"encoding\":\"base64\",\"commitment\":\"finalized\",\"dataSlice\":{\"offset\":#{offset},\"length\":#{length}}}]")
end

pub fn chain_accounts_request(addresses :: List<String>, length :: Int) -> String do
  let list = String.join(List.map(addresses, fn value -> Json.encode_string(value) end), ",")
  envelope("getMultipleAccounts",
    "[[#{list}],{\"encoding\":\"base64\",\"commitment\":\"finalized\",\"dataSlice\":{\"offset\":0,\"length\":#{length}}}]")
end

# Program accounts of exactly size bytes whose data holds each (offset, bytes).

pub fn chain_program_request(program :: String,
  size :: Int,
  filters :: List<(Int, Bytes)>) -> String do
  let memcmps = for (offset, bytes) in filters do
    "{\"memcmp\":{\"offset\":#{offset},\"bytes\":#{Json.encode_string(Bytes.to_base58(bytes))}}}"
  end
  let all = String.join(["{\"dataSize\":#{size}}"] ++ memcmps, ",")
  envelope("getProgramAccounts",
    "[#{Json.encode_string(program)},{\"encoding\":\"base64\",\"commitment\":\"finalized\",\"filters\":[#{all}]}]")
end

pub fn chain_block_time_request(slot :: Int) -> String do
  envelope("getBlockTime", "[#{slot}]")
end

fn result_of(body :: Bytes) -> Json!String do
  let text = case Bytes.to_utf8(body) do
    Err(_) -> Err("rpc_invalid")
    Ok(value)
  end?
  let root = case Json.parse(text) do
    Err(_) -> Err("rpc_invalid")
    Ok(value)
  end?
  let failed = case Json.object_get(root, "error") do
    Ok(error) -> !Json.is_null(error)
    Err(_) -> false
  end
  if failed do
    Err("rpc_error")
  else
    case Json.object_get(root, "result") do
      Err(_) -> Err("rpc_invalid")
      Ok(value)
    end
  end
end

fn rpc_text(value :: Json, key :: String) -> String!String do
  case Json.object_get(value, key) do
    Err(_) -> Err("rpc_invalid")
    Ok(field) -> case Json.as_string(field) do
      Err(_) -> Err("rpc_invalid")
      Ok(text)
    end
  end
end

fn account_data(value :: Json) -> Bytes!String do
  Bytes.from_base64(Json.as_string(Json.array_get(Json.object_get(value, "data")?, 0)?)?)
end

fn account_json(value :: Json, length :: Int) -> Bytes!String do
  if Json.is_null(value) do
    marker(0)
  else
    let data = case account_data(value) do
      Err(_) -> Err("rpc_invalid")
      Ok(bytes)
    end?
    if length >= 0 && Bytes.length(data) != length do
      Err("rpc_invalid")
    else
      project(rpc_text(value, "owner")?, data)
    end
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  let length = case U64.parse(Int.to_string(Bytes.length(value))) do
    Err(_) -> Err("chain_invalid")
    Ok(parsed)
  end?
  let prefix = case Bytes.write_u32_be(length) do
    Err(_) -> Err("chain_invalid")
    Ok(encoded)
  end?
  join([prefix, value])
end

fn project(owner :: String, data :: Bytes) -> Bytes!String do
  join([marker(1)?, vector(Bytes.from_utf8(owner))?, vector(data)?])
end

# getAccountInfo: u8 0 (no account) | u8 1 ‖ vector(owner) ‖ vector(data).

pub fn chain_project_account(body :: Bytes, length :: Int) -> Bytes!String do
  let result = result_of(body)?
  case Json.object_get(result, "value") do
    Err(_) -> Err("rpc_invalid")
    Ok(value) -> account_json(value, length)
  end
end

# getMultipleAccounts: the account projections, in the order asked.

pub fn chain_project_accounts(body :: Bytes, count :: Int, length :: Int) -> Bytes!String do
  let result = result_of(body)?
  let values = case Json.object_get(result, "value") do
    Err(_) -> Err("rpc_invalid")
    Ok(value)
  end?
  if Json.array_length(values)? != count do
    Err("rpc_invalid")
  else
    let parts = for index in 0..count do
      vector(account_json(Json.array_get(values, index)?, length)?)?
    end
    join(parts)
  end
end

# getProgramAccounts where at most one account can match: u8 0, or u8 1 ‖
# vector(pubkey) ‖ vector(account projection).

pub fn chain_project_program(body :: Bytes) -> Bytes!String do
  let result = result_of(body)?
  let count = Json.array_length(result)?
  if count == 0 do
    marker(0)
  else if count > 1 do
    Err("rpc_invalid")
  else
    let item = Json.array_get(result, 0)?
    let account = case Json.object_get(item, "account") do
      Err(_) -> Err("rpc_invalid")
      Ok(value)
    end?
    join([
      marker(1)?,
      vector(Bytes.from_utf8(rpc_text(item, "pubkey")?))?,
      vector(account_json(account, -1)?)?
    ])
  end
end

# getBlockTime: unix seconds as decimal text, or empty when the slot has none.

pub fn chain_project_block_time(body :: Bytes) -> Bytes!String do
  let result = result_of(body)?
  if Json.is_null(result) do
    Ok(Bytes.empty())
  else
    let seconds = case Json.as_int(result) do
      Err(_) -> Err("rpc_invalid")
      Ok(value)
    end?
    if seconds < 0 do
      Err("rpc_invalid")
    else
      Ok(Bytes.from_utf8(Int.to_string(seconds)))
    end
  end
end

fn read_vector(data :: Bytes, offset :: Int) -> (Bytes, Int)!String do
  let length = case Bytes.read_u32_be(data, offset) do
    Err(_) -> Err("chain_invalid")
    Ok(value) -> wide(value)
  end?
  Ok((slice(data, offset + 4, length)?, offset + 4 + length))
end

# Reads an account projection back: None when the account does not exist.

pub fn chain_account(projection :: Bytes) -> Option<ChainAccount>!String do
  let (account, _) = account_at(projection, 0)?
  Ok(account)
end

fn account_at(data :: Bytes, offset :: Int) -> (Option<ChainAccount>, Int)!String do
  if byte(data, offset)? == 0 do
    Ok((None, offset + 1))
  else
    let (owner, after_owner) = read_vector(data, offset + 1)?
    let (bytes, next) = read_vector(data, after_owner)?
    let owner_text = case Bytes.to_utf8(owner) do
      Err(_) -> Err("chain_invalid")
      Ok(value)
    end?
    Ok((Some(ChainAccount { owner: owner_text, data: bytes }), next))
  end
end

pub fn chain_accounts(projection :: Bytes, count :: Int) -> List<Option<ChainAccount>>!String do
  accounts_from(projection, 0, count, List.new())
end

fn accounts_from(data :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<Option<ChainAccount>>) -> List<Option<ChainAccount>>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let (item, next) = read_vector(data, offset)?
    let (account, _) = account_at(item, 0)?
    accounts_from(data, next, count, List.append(output, account))
  end
end

# A program-account projection: the matching account's address and data.

pub fn chain_program_account(projection :: Bytes) -> Option<(String, ChainAccount)>!String do
  if byte(projection, 0)? == 0 do
    Ok(None)
  else
    let (pubkey, next) = read_vector(projection, 1)?
    let (item, _) = read_vector(projection, next)?
    let (account, _) = account_at(item, 0)?
    let text = case Bytes.to_utf8(pubkey) do
      Err(_) -> Err("chain_invalid")
      Ok(value)
    end?
    case account do
      None -> Err("chain_invalid")
      Some(value) -> Ok(Some((text, value)))
    end
  end
end

pub fn chain_block_time(projection :: Bytes) -> Int!String do
  if Bytes.length(projection) == 0 do
    Ok(0)
  else
    case Bytes.to_utf8(projection) do
      Err(_) -> Err("chain_invalid")
      Ok(text) -> case String.to_int(text) do
        Some(value) -> Ok(value)
        None -> Err("chain_invalid")
      end
    end
  end
end

fn list_entry(data :: Bytes, index :: Int) -> ChainWitness!String do
  let base = 280 + 144 * index
  let length = byte(data, base)?
  if length < 1 || length > 64 do
    Err("chain_invalid")
  else
    let id = case Bytes.to_utf8(slice(data, base + 1, length)?) do
      Err(_) -> Err("chain_invalid")
      Ok(value)
    end?
    Ok(ChainWitness {
      witness_id: id,
      public_key: slice(data, base + 72, 32)?,
      account: address(data, base + 104)?,
      since_slot: chain_u64(data, base + 136)?
    })
  end
end

# Log account (§4.2). The bytes the phone compares between providers: all but
# the anchor counts (216..280), which every anchor changes.

pub fn chain_log_projection(account :: ChainAccount) -> Bytes!String do
  if Bytes.length(account.data) != chain_log_length() do
    Err("chain_invalid")
  else
    project(account.owner, join([slice(account.data, 0, 216)?, slice(account.data, 280, 2304)?])?)
  end
end

pub fn chain_decode_log(data :: Bytes) -> ChainLog!String do
  let count = byte(data, 4)?
  if Bytes.length(data) != chain_log_length() || byte(data, 0)? != 2 || byte(data, 1)? != 1 do
    Err("chain_invalid")
  else if count > 16 do
    Err("chain_invalid")
  else
    let witnesses = for index in 0..count do
      list_entry(data, index)?
    end
    Ok(ChainLog {
      log_id: slice(data, 16, 32)?,
      service_key: slice(data, 48, 32)?,
      ring: address(data, 112)?,
      directory_vault: address(data, 144)?,
      service_slashed: byte(data, 3)? == 1,
      witnesses: witnesses
    })
  end
end

# The compared Log bytes put back at their offsets (anchor counts zeroed).

pub fn chain_log_from_projection(account :: ChainAccount) -> ChainLog!String do
  if Bytes.length(account.data) != 2520 do
    Err("chain_invalid")
  else
    let zeros = case Bytes.repeat(0, 64) do
      Err(_) -> Err("chain_invalid")
      Ok(value)
    end?
    chain_decode_log(join([slice(account.data, 0, 216)?, zeros, slice(account.data, 216, 2304)?])?)
  end
end

pub fn chain_decode_header(data :: Bytes) -> ChainRingHeader!String do
  if Bytes.length(data) != 64 do
    Err("chain_invalid")
  else
    let header = ChainRingHeader {
      log_id: slice(data, 0, 32)?,
      head: u32_at(data, 32)?,
      count: u32_at(data, 36)?,
      last_sequence: chain_u64(data, 40)?,
      last_size: chain_u64(data, 48)?,
      last_slot: chain_u64(data, 56)?
    }
    if header.head >= chain_ring_capacity() || header.count > chain_ring_capacity() do
      Err("chain_invalid")
    else
      Ok(header)
    end
  end
end

pub fn chain_decode_entry(index :: Int, data :: Bytes) -> ChainRingEntry!String do
  if Bytes.length(data) != 104 do
    Err("chain_invalid")
  else
    Ok(ChainRingEntry {
      index: index,
      sequence: chain_u64(data, 0)?,
      tree_size: chain_u64(data, 8)?,
      root: slice(data, 16, 32)?,
      hash: slice(data, 48, 32)?,
      slot: chain_u64(data, 88)?,
      bitmap: u16_at(data, 96)?,
      evidence: byte(data, 98)?
    })
  end
end

# Witness account (§4.4): status and bond vault. The phone reads 264 bytes.

pub fn chain_decode_witness(data :: Bytes) -> ChainWitnessState!String do
  if Bytes.length(data) < 264 || byte(data, 0)? != 3 do
    Err("chain_invalid")
  else
    Ok(ChainWitnessState { status: byte(data, 3)?, vault: address(data, 232)? })
  end
end

# SPL token account: mint (0..32) and amount (64..72).

pub fn chain_decode_token(data :: Bytes) -> ChainTokenAmount!String do
  if Bytes.length(data) < 72 do
    Err("chain_invalid")
  else
    Ok(ChainTokenAmount { mint: address(data, 0)?, amount: chain_u64(data, 64)? })
  end
end

pub fn chain_address_at(data :: Bytes, offset :: Int) -> String!String do
  address(data, offset)
end

pub fn chain_bytes_at(data :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  slice(data, offset, length)
end

pub fn chain_byte_at(data :: Bytes, offset :: Int) -> Int!String do
  byte(data, offset)
end

pub fn chain_u32_at(data :: Bytes, offset :: Int) -> Int!String do
  u32_at(data, offset)
end

# Proof account (§4.6).

pub fn chain_decode_proof(data :: Bytes) -> ChainProof!String do
  if Bytes.length(data) != 112 || byte(data, 0)? != 5 do
    Err("chain_invalid")
  else
    Ok(ChainProof {
      log: address(data, 8)?,
      proof_hash: slice(data, 40, 32)?,
      paid_to: slice(data, 72, 32)?,
      slot: chain_u64(data, 104)?
    })
  end
end
