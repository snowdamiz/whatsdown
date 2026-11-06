from Transparency.TokenChain import (
  TokenAddresses,
  token_addresses,
  token_prepare_instruction,
  token_initialize_instruction,
  token_claim_instruction,
  token_oracle_initialize_instruction,
  token_oracle_observe_instruction,
  decode_token_config,
  decode_token_allocation,
  decode_token_oracle,
  token_oracle_twap,
  token_oracle_spot
)
from Solana.Read import pubkey
from Solana.Tx import Instruction, instruction_report_json

fn text(root :: Json, field :: String) -> String!String do
  Json.as_string(Json.object_get(root, field)?)
end

fn changed(data :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(data, 0, at)?, value)?,
    Bytes.slice(data, at + Bytes.length(value), Bytes.length(data) - at - Bytes.length(value))?)
end

fn compare_instruction(actual :: Instruction, expected :: Json) -> Bool!String do
  let report = Json.parse(instruction_report_json(actual))?
  for field in [
    "schemaVersion",
    "programId",
    "accountCount",
    "accountKeys",
    "signerKeys",
    "writableKeys",
    "dataBase64",
    "dataBytes"
  ] do
    assert(Json.encode(Json.object_get(report, field)?) == Json.encode(Json.object_get(expected,
        field)?))
  end
  Ok(true)
end

fn actual_sbf_replay() -> Bool!String do
  let path = Env.get("MORSE_TOKEN_FIXTURES_PATH", "")
  if path == "" do
    return Err("MORSE_TOKEN_FIXTURES_PATH is required for actual SBF token replay")
  end
  let root = Json.parse(File.read(path)?)?
  let program = pubkey(text(root, "program")?)?
  let payer = pubkey(text(root, "payer")?)?
  let source = pubkey(text(root, "source")?)?
  let feed = Bytes.from_hex(text(root, "feed_hex")?)?
  let receiver = pubkey("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ")?
  let now = U64.parse(text(root, "now")?)?
  let addresses = token_addresses(program)?
  assert(addresses.config == pubkey(text(root, "config_address")?)?)
  assert(addresses.mint == pubkey(text(root, "mint_address")?)?)
  assert(addresses.oracle == pubkey(text(root, "oracle_address")?)?)
  let raw_config = Bytes.from_hex(text(root, "config_hex")?)?
  let config = decode_token_config(raw_config)?
  assert(config.governance == payer && config.mint == addresses.mint)
  let entries = Json.object_get(root, "allocations")?
  assert(Json.array_length(entries)? == 7)
  for kind in 0..7 do
    let entry = Json.array_get(entries, kind)?
    let raw = Bytes.from_hex(text(entry, "data_hex")?)?
    let allocation = decode_token_allocation(raw)?
    assert(List.get(addresses.allocations, kind) == pubkey(text(entry, "address")?)?)
    assert(List.get(addresses.vaults, kind) == pubkey(text(entry, "vault")?)?)
    assert(allocation.kind == kind
      && allocation.config == addresses.config
      && allocation.mint == addresses.mint
      && allocation.started == config.started)
    assert(allocation.beneficiary == List.get(config.beneficiaries, kind)
      && allocation.total == U64.parse(text(entry, "amount")?)?
      && allocation.claimed == U64.parse("0")?)
    assert(Result.is_err(decode_token_allocation(changed(raw, 5, Bytes.from_hex("01")?)?)))
  end
  assert(Result.is_err(decode_token_config(changed(raw_config, 76, Bytes.from_hex("01")?)?)))
  let raw_oracle = Bytes.from_hex(text(root, "oracle_hex")?)?
  let oracle = decode_token_oracle(raw_oracle)?
  assert(oracle.config == addresses.config
    && oracle.mint == addresses.mint
    && oracle.receiver == receiver
    && oracle.source == source
    && oracle.feed == feed
    && oracle.revision == U64.parse("1")?)
  assert(token_oracle_twap(raw_oracle, now)? == U64.parse("2000000")?)
  assert(token_oracle_spot(raw_oracle, now)? == U64.parse("3000000")?)
  assert(Result.is_err(token_oracle_twap(raw_oracle, U64.add(now, U64.parse("61")?)?)))
  let prior = U64.subtract(now, U64.parse("1")?)?
  assert(Result.is_err(token_oracle_twap(raw_oracle, prior)))
  assert(Result.is_err(decode_token_oracle(changed(raw_oracle, 300, Bytes.from_hex("01")?)?)))
  let instructions = Json.object_get(root, "instructions")?
  compare_instruction(token_prepare_instruction(program, payer)?,
    Json.object_get(instructions, "prepare")?)?
  compare_instruction(token_initialize_instruction(program,
      payer,
      payer,
      payer,
      config.beneficiaries)?,
    Json.object_get(instructions, "initialize")?)?
  compare_instruction(token_claim_instruction(program,
      payer,
      List.get(config.beneficiaries, 2),
      2)?,
    Json.object_get(instructions, "claim")?)?
  compare_instruction(token_oracle_initialize_instruction(program,
      payer,
      payer,
      receiver,
      source,
      feed)?,
    Json.object_get(instructions, "oracle_initialize")?)?
  compare_instruction(token_oracle_observe_instruction(program, receiver, source)?,
    Json.object_get(instructions, "observe")?)?
  assert(Result.is_err(token_claim_instruction(program, payer, payer, 4)))
  Ok(true)
end

test("Mesh token codecs and instruction bytes replay actual SBF states and independent Rust SDK metas") do
  assert(actual_sbf_replay() == Ok(true))
end
