from BurnWorker import TokenBurnWorkerConfig
from Transparency.TokenBurnRead import TokenBurnReadPins, token_burn_rpc_sources
from Solana.Read import pubkey

pub struct TokenBurnWorkerCommand do
  config :: TokenBurnWorkerConfig
  journal_path :: String
  key_directory :: String
  ticks :: Int
  interval_ms :: Int
end

fn config_text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn config_wide(root :: Json, name :: String) -> U64!String do
  U64.parse(config_text(root, name)?)
end

fn config_int(root :: Json, name :: String, low :: Int, high :: Int) -> Int!String do
  let text = config_text(root, name)?
  let value = case String.to_int(text) do
    None -> return Err("invalid_burn_worker_config_integer")
    Some(value) -> value
  end
  if value < low || value > high || Int.to_string(value) != text do
    Err("invalid_burn_worker_config_integer")
  else
    Ok(value)
  end
end

pub fn decode_token_burn_worker_config(raw :: String) -> TokenBurnWorkerCommand!String do
  if String.length(raw) > 65536 do
    return Err("invalid_burn_worker_config_size")
  end
  let root = Json.parse(raw)?
  if config_text(root, "schema_version")? != "1" do
    return Err("invalid_burn_worker_config_version")
  end
  let pins = Json.object_get(root, "pins")?
  let urls = Json.object_get(root, "rpc_urls")?
  if Json.array_length(urls)? != 3 do
    return Err("invalid_token_burn_rpc_sources")
  end
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(urls, index)?)?
  end
  let test_mode = Json.as_bool(Json.object_get(root, "test_mode")?)?
  token_burn_rpc_sources(sources, test_mode)?
  if test_mode do
    for source in sources do
      if !String.starts_with(source, "http://127.0.0.1:") do
        return Err("burn_worker_test_requires_loopback")
      end
    end
  end
  let routes = Json.object_get(root, "routes_hex")?
  if Json.array_length(routes)? != 24 do
    return Err("invalid_token_burn_worker_routes")
  end
  let prepared = for index in 0..24 do
    let text = Json.as_string(Json.array_get(routes, index)?)?
    let route = Bytes.from_hex(text)?
    if Bytes.length(route) != 39 || Bytes.to_hex(route) != text do
      return Err("invalid_token_burn_worker_route")
    end
    route
  end
  let path = config_text(root, "journal_path")?
  let directory = config_text(root, "storage_key_directory")?
  if String.length(path) < 1
    || String.length(path) > 4096
    || String.length(directory) < 1
    || String.length(directory) > 4096 do
    return Err("invalid_token_burn_worker_paths")
  end
  Ok(TokenBurnWorkerCommand {
    config: TokenBurnWorkerConfig {
      pins: TokenBurnReadPins {
        program: pubkey(config_text(pins, "program")?)?,
        governance: pubkey(config_text(pins, "governance")?)?,
        program_slot: config_wide(pins, "program_slot")?,
        usdc: pubkey(config_text(pins, "usdc")?)?,
        treasury: pubkey(config_text(pins, "treasury")?)?,
        factory: pubkey(config_text(pins, "factory")?)?
      },
      payer: pubkey(config_text(root, "payer")?)?,
      epoch: config_wide(root, "epoch")?,
      minimum_slot: config_wide(root, "minimum_slot")?,
      urls: sources,
      test_mode: test_mode,
      replace_expired: Json.as_bool(Json.object_get(root, "replace_expired")?)?,
      routes: prepared
    },
    journal_path: path,
    key_directory: directory,
    ticks: config_int(root, "ticks", 1, 64)?,
    interval_ms: config_int(root, "interval_ms", 1000, 60000)?
  })
end
