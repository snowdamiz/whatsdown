from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Mobile.Platform import native_security_config
from Transparency.Config import decode_security_config, encode_security_config
from Solana.Read import pubkey_string

fn frame() -> Bytes do
  Bytes.from_utf8(String.join([
      "4",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "8",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      String.repeat("1", 32),
      "morse-main"
    ],
    "\n"))
end

fn proof(version :: Int) -> Bool!String do
  let initial = %{decode_security_config(frame())? | version: version, wire_version: version}
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(initial)?))
  let config = native_security_config()?
  let pins = case configured_anchor_pins(config)? do
    Some(value) -> value
    None -> return Err("missing native anchor pins")
  end
  assert(pins.log_name == "morse-main" && pubkey_string(pins.program) == String.repeat("1", 32))
  assert(Bytes.secure_equals(pins.log_id, Crypto.sha256(Bytes.from_utf8("morse-main"))))
  assert(pubkey_string(pins.ring) == config.anchor_address && pins.endpoints == config.rpc_urls)
  for invalid in [
    %{config | anchor_log_name: "morse-canary"},
    %{config | anchor_program: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
    %{config | anchor_address: String.repeat("1", 32)}
  ] do
    let encoded = encode_security_config(invalid)?
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), encoded))
    case native_security_config() do
      Err(error) -> assert(error == "invalid_messenger_configuration")
      Ok(_) -> assert(false)
    end
  end
  let disabled = %{config | anchor_address: "-", anchor_program: "-", anchor_log_name: "-"}
  assert(configured_anchor_pins(disabled)? == None)
  let old = %{disabled | version: 3, wire_version: 3, anchor_address: config.anchor_address}
  # A legacy ring-only frame never pretends it pins the judge or log identity.
  assert(configured_anchor_pins(decode_security_config(encode_security_config(old)?)?)? == None)
  Ok(true)
end

test("native anchor activation derives the release-pinned ring and rejects substituted identities") do
  case proof(4) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("native v5 preserves derived anchor identity checks") do
  case proof(5) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
