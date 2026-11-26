##! A fake outside world for the issuer's tests, on one port: Solana JSON-RPC
##! (/rpc), Pyth Hermes, an LND node, and the directory's issuer-key route.
##!
##! A fake payment's transaction signature carries what it paid: bytes 0–31
##! the deposit address, byte 32 the kind (1 SOL, 2 USDC, 3 failed, 4 late
##! SOL, 5 not yet finalized), bytes 33–40 the amount (u64). sendTransaction
##! checks every signature of the transaction it gets and answers the first.

from Credits.IssuerKey import credits_leaf_kind
from Issuer.Settings import IssuerSettings

pub fn world_port() -> Int do
  18997
end

pub fn world_url() -> String do
  "http://127.0.0.1:18997"
end

pub fn world_token() -> String do
  "issuer-test-token-0123456789abcdef0123456789"
end

pub fn world_mint() -> String do
  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
end

fn filled(value :: Int) -> Bytes do
  case Bytes.repeat(value, 32) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

pub fn world_payer() -> String do
  Bytes.to_base58(filled(7))
end

pub fn world_payer_account() -> String do
  Bytes.to_base58(filled(8))
end

pub fn world_deposit_account() -> String do
  Bytes.to_base58(filled(9))
end

pub fn world_treasury() -> String do
  Bytes.to_base58(filled(10))
end

pub fn world_treasury_account() -> String do
  Bytes.to_base58(filled(11))
end

## The seed of wallet-core's "abandon … about" vector, as the deposit seed.

pub fn world_seed() -> Bytes do
  case Bytes.from_hex("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4") do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

pub fn world_settings(mode :: String) -> IssuerSettings do
  IssuerSettings {
    mode: mode,
    assets: ["usdc", "sol", "btc"],
    issuer_name: "credits.morseapp.io",
    rpc_url: world_url() <> "/rpc",
    usdc_mint: world_mint(),
    oracle_url: world_url(),
    lnd_url: world_url(),
    lnd_macaroon: "00",
    directory_url: world_url(),
    directory_token: world_token(),
    treasury_address: world_treasury(),
    treasury_usdc_account: world_treasury_account(),
    deposit_seed: world_seed(),
    sweep_min_delay_s: 0,
    sweep_max_delay_s: 0,
    split: "20/80",
    quote_difficulty: 4,
    max_open_quotes: 1000
  }
end

fn must<T, E>(value :: Result<T, E>) -> T!String do
  case value do
    Err(_) -> Err("fake world encoding failed")
    Ok(output)
  end
end

## A transaction signature for a fake payment (see the module notes).

pub fn world_payment(deposit :: String, kind :: Int, amount :: Int) -> String!String do
  let head = must(Bytes.concat(must(Bytes.from_base58(deposit))?, must(Bytes.from_list([kind]))?))?
  let amount_bytes = must(Bytes.write_u64_be(must(U64.parse(Int.to_string(amount)))?))?
  let body = must(Bytes.concat(head, amount_bytes))?
  Ok(Bytes.to_base58(must(Bytes.concat(body, must(Bytes.repeat(0, 23))?))?))
end

fn now_s() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now()) / 1000
end

fn ok(result :: String) -> Response do
  HTTP.response(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":" <> result <> "}")
end

fn quoted(value :: String) -> String do
  Json.encode_string(value)
end

fn sol_transaction(deposit :: String, amount :: Int, block_time :: Int, failed :: Bool) -> String do
  let error = if failed do
    "{\"InstructionError\":[0,\"Custom\"]}"
  else
    "null"
  end
  "{\"blockTime\":"
    <> Int.to_string(block_time)
    <> ",\"meta\":{\"err\":"
    <> error
    <> ",\"preBalances\":[1000000000000,0,1],\"postBalances\":["
    <> Int.to_string(1000000000000 - amount - 5000)
    <> ","
    <> Int.to_string(amount)
    <> ",1],\"preTokenBalances\":[],\"postTokenBalances\":[]},\"transaction\":{\"message\":{\"accountKeys\":[{\"pubkey\":"
    <> quoted(world_payer())
    <> ",\"signer\":true},{\"pubkey\":"
    <> quoted(deposit)
    <> ",\"signer\":false},{\"pubkey\":\"11111111111111111111111111111111\",\"signer\":false}]}}}"
end

fn token(index :: Int, owner :: String, amount :: Int) -> String do
  "{\"accountIndex\":"
    <> Int.to_string(index)
    <> ",\"mint\":"
    <> quoted(world_mint())
    <> ",\"owner\":"
    <> quoted(owner)
    <> ",\"uiTokenAmount\":{\"amount\":\""
    <> Int.to_string(amount)
    <> "\",\"decimals\":6}}"
end

fn usdc_transaction(deposit :: String, amount :: Int, block_time :: Int) -> String do
  "{\"blockTime\":"
    <> Int.to_string(block_time)
    <> ",\"meta\":{\"err\":null,\"preBalances\":[1,2,3],\"postBalances\":[1,2,3],\"preTokenBalances\":["
    <> token(1, world_payer(), 900000000)
    <> "],\"postTokenBalances\":["
    <> token(1, world_payer(), 900000000 - amount)
    <> ","
    <> token(2, deposit, amount)
    <> "]},\"transaction\":{\"message\":{\"accountKeys\":[{\"pubkey\":"
    <> quoted(world_payer())
    <> "},{\"pubkey\":"
    <> quoted(world_payer_account())
    <> "},{\"pubkey\":"
    <> quoted(world_deposit_account())
    <> "}]}}}"
end

fn transaction_for(signature :: String) -> String!String do
  let bytes = Bytes.from_base58(signature)?
  let deposit = Bytes.to_base58(Bytes.slice(bytes, 0, 32)?)
  let kind = Bytes.get(bytes, 32)?
  let amount = U64.to_int(must(Bytes.read_u64_be(bytes, 33))?)?
  if kind == 1 do
    Ok(sol_transaction(deposit, amount, now_s(), false))
  else if kind == 2 do
    Ok(usdc_transaction(deposit, amount, now_s()))
  else if kind == 3 do
    Ok(sol_transaction(deposit, amount, now_s(), true))
  else if kind == 4 do
    Ok(sol_transaction(deposit, amount, now_s() + 3600, false))
  else
    Ok("null")
  end
end

fn short(value :: Bytes, offset :: Int) -> (Int, Int)!String do
  let first = Bytes.get(value, offset)?
  if first < 128 do
    Ok((first, offset + 1))
  else
    Ok((first - 128 + 128 * Bytes.get(value, offset + 1)?, offset + 2))
  end
end

fn verified(transaction :: Bytes,
  count :: Int,
  message :: Bytes,
  keys_at :: Int,
  index :: Int) -> Bool!String do
  if index >= count do
    Ok(true)
  else
    let signature = Bytes.slice(transaction, 1 + 64 * index, 64)?
    let key = Bytes.slice(message, keys_at + 32 * index, 32)?
    case Crypto.verify(SigningPublicKey { bytes: key }, message, Signature { bytes: signature }) do
      Ok(true) -> verified(transaction, count, message, keys_at, index + 1)
      _ -> Ok(false)
    end
  end
end

# Checks every signature over the message; the first one names the
# transaction.

fn sent(encoded :: String) -> String!String do
  let transaction = Bytes.from_base64(encoded)?
  let (count, after_count) = short(transaction, 0)?
  let message = Bytes.slice(transaction,
    after_count + 64 * count,
    Bytes.length(transaction) - after_count - 64 * count)?
  let (_keys, keys_at) = short(message, 3)?
  if Bytes.get(message, 0)? != count || !verified(transaction, count, message, keys_at, 0)? do
    Err("signature verification failed")
  else
    Ok(Bytes.to_base58(Bytes.slice(transaction, after_count, 64)?))
  end
end

fn first_param(body :: Json) -> String!String do
  Json.as_string(Json.array_get(Json.object_get(body, "params")?, 0)?)
end

fn rpc_answer(body :: Json, method :: String) -> String!String do
  if method == "getTransaction" do
    transaction_for(first_param(body)?)
  else if method == "getSignaturesForAddress" do
    Ok("[{\"signature\":"
      <> quoted(world_payment(first_param(body)?, 2, 5000000)?)
      <> ",\"err\":null}]")
  else if method == "getLatestBlockhash" do
    Ok("{\"context\":{\"slot\":1},\"value\":{\"blockhash\":"
      <> quoted(Bytes.to_base58(filled(12)))
      <> ",\"lastValidBlockHeight\":100}}")
  else if method == "getBalance" do
    Ok("{\"context\":{\"slot\":1},\"value\":33333334}")
  else if method == "getTokenAccountBalance" do
    Ok("{\"context\":{\"slot\":1},\"value\":{\"amount\":\"5000000\",\"decimals\":6}}")
  else if method == "sendTransaction" do
    Ok(quoted(sent(first_param(body)?)?))
  else if method == "getSignatureStatuses" do
    Ok("{\"context\":{\"slot\":1},\"value\":[{\"slot\":1,\"confirmations\":null,\"err\":null,\"confirmationStatus\":\"finalized\"}]}")
  else
    Err("unknown method")
  end
end

fn handle_rpc(request :: Request) -> Response do
  let answer = case Json.parse(Request.body(request)) do
    Err(error)
    Ok(body) -> case Json.object_get(body, "method") do
      Err(error)
      Ok(method) -> case Json.as_string(method) do
        Err(error)
        Ok(name) -> rpc_answer(body, name)
      end
    end
  end
  case answer do
    Ok(result) -> ok(result)
    Err(error) -> HTTP.response(200,
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32002,\"message\":"
        <> quoted(error)
        <> "}}")
  end
end

fn price(id :: String, value :: String) -> String do
  "{\"id\":"
    <> quoted(id)
    <> ",\"price\":{\"price\":"
    <> quoted(value)
    <> ",\"conf\":\"1000000\",\"expo\":-8,\"publish_time\":"
    <> Int.to_string(now_s())
    <> "}}"
end

# SOL at $150, BTC at $60,000.

fn handle_price(_request :: Request) -> Response do
  HTTP.response(200,
    "{\"binary\":{\"encoding\":\"hex\",\"data\":[]},\"parsed\":["
      <> price("ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d", "15000000000")
      <> ","
      <> price("e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43", "6000000000000")
      <> "]}")
end

fn handle_invoice(request :: Request) -> Response do
  case (Request.header(request, "grpc-metadata-macaroon"), Crypto.random_bytes(32)) do
    (Some(_), Ok(hash)) -> HTTP.response(200,
      "{\"r_hash\":"
        <> quoted(Bytes.to_base64(hash))
        <> ",\"payment_request\":\"lnbcrt83340n1test\",\"add_index\":\"1\"}")
    _ -> HTTP.response(401, "")
  end
end

fn handle_settled(_request :: Request) -> Response do
  HTTP.response(200,
    "{\"state\":\"SETTLED\",\"amt_paid_sat\":\"8334\",\"settle_date\":\""
      <> Int.to_string(now_s())
      <> "\"}")
end

fn handle_leaf(request :: Request) -> Response do
  let kind = credits_leaf_kind(Request.body_bytes(request))
  if Request.header(request, "authorization") != Some("Bearer " <> world_token()) do
    HTTP.response(401, "")
  else if kind == 2 || kind == 3 do
    HTTP.response(201, "")
  else
    HTTP.response(400, "")
  end
end

actor world() do
  HTTP.router()
    |> HTTP.on_post("/rpc", handle_rpc)
    |> HTTP.on_get("/v2/updates/price/latest", handle_price)
    |> HTTP.on_post("/v1/invoices", handle_invoice)
    |> HTTP.on_get("/v1/invoice/:hash", handle_settled)
    |> HTTP.on_post("/internal/v1/credits/issuer-keys", handle_leaf)
    |> HTTP.serve(world_port())
end

pub fn world_start() do
  spawn(world)
  Timer.sleep(150)
end
