from Client.BondsV2Pins import parse_bonds_v2_options
from Transparency.TokenChain import token_addresses
from Solana.Read import Pubkey

fn key(byte :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(byte, 32))
end

fn configuration() -> String!String do
  let token = Pubkey { bytes: key("11")? }
  let pins = "{\"program\":"
    <> Json.encode_string(Bytes.to_base58(token.bytes))
    <> ",\"governance\":"
    <> Json.encode_string(Bytes.to_base58(key("22")?))
    <> ",\"program_slot\":\"0\",\"usdc\":"
    <> Json.encode_string(Bytes.to_base58(key("33")?))
    <> ",\"treasury\":"
    <> Json.encode_string(Bytes.to_base58(key("44")?))
    <> ",\"factory\":"
    <> Json.encode_string(Bytes.to_base58(key("55")?))
    <> "}"
  let collateral = "{\"schema_version\":2,\"judge\":"
    <> Json.encode_string(Bytes.to_base58(key("66")?))
    <> ",\"judge_slot\":\"0\",\"rewards\":"
    <> Json.encode_string(Bytes.to_base58(key("77")?))
    <> ",\"rewards_slot\":\"0\",\"rewards_governance\":"
    <> Json.encode_string(Bytes.to_base58(key("88")?))
    <> ",\"log_name\":\"custody-test\",\"log_version\":1,\"service_public_key\":\""
    <> Bytes.to_hex(key("99")?)
    <> "\",\"morse_mint\":"
    <> Json.encode_string(Bytes.to_base58(token_addresses(token)?.mint.bytes))
    <> ",\"network_started\":\"1\",\"witnesses\":[{\"witness_id\":\"outside\",\"public_key\":\""
    <> Bytes.to_hex(key("aa")?)
    <> "\"}],\"proofs\":[]}"
  Ok("{\"schema_version\":1,\"scope\":\"local-fixture\",\"pins\":"
    <> pins
    <> ",\"endpoints\":[\"http://127.0.0.1:19001\",\"http://127.0.0.1:19002\",\"http://127.0.0.1:19003\"],\"collateral\":"
    <> collateral
    <> ",\"minimum_context_slot\":\"9007199254740993\",\"max_age_seconds\":\"900\"}")
end

fn cases() -> Bool!String do
  let text = configuration()?
  let value = parse_bonds_v2_options(text, "custody-test")?
  assert(value.minimum == U64.parse("9007199254740993")?)
  assert(value.selection.pins.log_version == 1)
  assert(List.length(value.selection.witnesses) == 1)
  assert(value.selection.pins.morse != value.selection.pins.usdc)
  assert(Result.is_err(parse_bonds_v2_options(text, "morse-main")))
  for bad in [
    String.replace(text, "\"schema_version\":1", "\"schema_version\":0"),
    String.replace(text, "\"max_age_seconds\":\"900\"", "\"max_age_seconds\":\"0\""),
    String.replace(text, "\"max_age_seconds\":\"900\"", "\"max_age_seconds\":\"86401\""),
    String.replace(text, "9007199254740993", "09007199254740993"),
    String.replace(text, "9007199254740993", "18446744073709551616"),
    String.replace(text, "19002", "19001"),
    String.replace(text, "local-fixture", "configured-rpc"),
    String.replace(text, "outside", "bad witness"),
    String.replace(text, "\"collateral\":", "\"legacy_collateral\":{},\"collateral\":"),
    String.repeat(" ", 32769)
  ] do
    assert(Result.is_err(parse_bonds_v2_options(bad, "custody-test")))
  end
  Ok(true)
end

test("explicit v2 bond pins reuse bounded public selection schema without legacy fallback or numeric coercion") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
