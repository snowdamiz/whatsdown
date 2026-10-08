from Issuer.Derivation import (
  issuer_deposit_key,
  issuer_fee_payer_index,
  issuer_hmac_sha512,
  issuer_slip10
)

fn hmac_vectors() -> Bool!String do
  let short = issuer_hmac_sha512(Bytes.from_utf8("Jefe"),
    Bytes.from_utf8("what do ya want for nothing?"))?
  let large_key = issuer_hmac_sha512(Bytes.from_hex(String.repeat("aa", 131))?,
    Bytes.from_utf8("Test Using Larger Than Block-Size Key - Hash Key First"))?
  Ok(Bytes.to_hex(short) == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    && Bytes.to_hex(large_key) == "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
end

test("HMAC-SHA-512 matches RFC 4231") do
  assert(hmac_vectors() == Ok(true))
end

# SLIP-0010 test vectors 1 and 2 for ed25519, as wallet-core checks them.

fn slip10(seed :: String, path :: List<Int>, chain :: String, private :: String) -> Bool!String do
  let (key, code) = issuer_slip10(Bytes.from_hex(seed)?, path)?
  Ok(Bytes.to_hex(key) == private && Bytes.to_hex(code) == chain)
end

fn slip10_vectors() -> Bool!String do
  let first = "000102030405060708090a0b0c0d0e0f"
  let second = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
  Ok(slip10(first,
    [],
    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")?
    && slip10(first,
      [0, 1, 2, 2, 1000000000],
      "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
      "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793")?
    && slip10(second,
      [0, 2147483647, 1, 2147483646, 2],
      "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
      "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d")?)
end

test("SLIP-0010 ed25519 derivation matches the published vectors") do
  case slip10_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# wallet-core's own check: the BIP-39 seed of "abandon" × 11 "about" (no
# passphrase) gives what `solana-keygen` gives for accounts 0 and 1. A deposit
# index is an account index, so the issuer and the wallet agree on addresses.

fn wallet_core_vectors() -> Bool!String do
  let seed = Bytes.from_hex("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")?
  let first = issuer_deposit_key(seed, 0)?
  let second = issuer_deposit_key(seed, 1)?
  let refused = case issuer_deposit_key(seed, issuer_fee_payer_index() + 1) do
    Err(_) -> true
    Ok(_) -> false
  end
  Ok(Bytes.to_hex(first.secret) == "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445"
    && first.address == "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    && Bytes.to_hex(second.secret) == "ba5e7b6e3680b4eb81db8e54c8e466b2e9a899355888403355d858ab985d2fc4"
    && second.address == "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"
    && refused)
end

test("deposit addresses match wallet-core's solana-keygen vectors") do
  case wallet_core_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
