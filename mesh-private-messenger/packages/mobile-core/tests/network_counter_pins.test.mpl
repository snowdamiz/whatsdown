from Transparency.Config import decode_security_config, encode_security_config
from Mobile.NetworkCounterPins import decode_network_counter_pins
from Solana.Read import pubkey
from Transparency.TokenChain import token_addresses

fn security() -> Bytes do
  Bytes.from_utf8(String.join([
      "4",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "8",
      "1",
      "1",
      "a #{String.repeat("01", 32)} Morse",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "1",
      "1",
      "a #{String.repeat("01", 32)} Morse",
      String.repeat("1", 32),
      "morse-main"
    ],
    "\n"))
end

fn proof() -> Bool!String do
  let s = decode_security_config(security())?
  let token = pubkey(Bytes.to_base58(Bytes.from_hex(String.repeat("66", 32))?))?
  let address = Bytes.to_base58(Bytes.from_hex(String.repeat("77", 32))?)
  let parts = [
    "1",
    Bytes.to_hex(Crypto.sha256(encode_security_config(s)?)),
    "v2",
    "0",
    "2",
    Bytes.to_base58(token.bytes),
    "2",
    address,
    address,
    Bytes.to_base58(token_addresses(token)?.mint.bytes),
    Bytes.to_base58(Bytes.from_hex(String.repeat("88", 32))?),
    "2",
    address,
    "1700000000",
    "-",
    "-",
    "1"
  ]
  let frame = Bytes.from_utf8(String.join(parts, "\n"))
  let pins = decode_network_counter_pins(frame, s)?
  assert(pins.security == s && pins.oracle == None)
  assert(case pins.collateral do
    Some(value) -> List.length(value.witnesses) == 1
    None -> false
  end)
  for changed in [
    %{s | service_public_key: Bytes.from_hex(String.repeat("12", 32))?},
    %{s | witnesses: [%{List.head(s.witnesses) | operator_label: "Other"}]},
    %{s | rpc_urls: ["https://x.example", "https://two.example", "https://three.example"]}
  ] do
    assert(Result.is_err(decode_network_counter_pins(frame, changed)))
  end
  for i in [0, 1, 2, 3, 8, 9, 14, 15, 16] do
    let bad = for index in 0..17 do
      if index == i do
        "invalid"
      else
        List.get(parts, index)
      end
    end
    assert(Result.is_err(decode_network_counter_pins(Bytes.from_utf8(String.join(bad, "\n")), s)))
  end
  assert(Result.is_err(decode_network_counter_pins(Bytes.concat(frame, Bytes.from_utf8("\n"))?, s)))
  let canary = %{s | anchor_log_name: "morse-canary"}
  let bad = for index in 0..17 do
    if index == 1 do
      Bytes.to_hex(Crypto.sha256(encode_security_config(canary)?))
    else
      List.get(parts, index)
    end
  end
  assert(Result.is_err(decode_network_counter_pins(Bytes.from_utf8(String.join(bad, "\n")),
    canary)))
  Ok(true)
end

test("native optional counter pins bind exact security identity, witnesses, providers and main-only context") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
