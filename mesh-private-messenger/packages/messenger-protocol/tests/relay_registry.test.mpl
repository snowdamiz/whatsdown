from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorBond import bond_witness_identity
from Transparency.AnchorRegistry import CollectibleWitnesses, read_collectible_witnesses
from Transparency.Relay import RelayVerification, verify_relay_fork
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, encode_fork
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  sign_checkpoint,
  sign_witness,
  checkpoint_hash
)

struct Fixture do
  pins :: AnchorPins
  service_key :: Bytes
  log :: Bytes
  header :: Bytes
  records :: List<Bytes>
  addresses :: List<Pubkey>
  proof :: Bytes
  accused :: List<Bytes>
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), cat(List.tail(parts))?)
  end
end

fn zero(length :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", length))
end

fn le(number :: Int, width :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(number), width)
end

fn wide(number :: Int) -> U64!String do
  U64.parse(Int.to_string(number))
end

fn replace(bytes :: Bytes, offset :: Int, value :: Bytes) -> Bytes!String do
  cat([
    Bytes.slice(bytes, 0, offset)?,
    value,
    Bytes.slice(bytes,
      offset + Bytes.length(value),
      Bytes.length(bytes) - offset - Bytes.length(value))?
  ])
end

fn signing() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signing failed")
  end
end

fn fixture() -> Fixture!String do
  let program = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let derived = anchor_addresses(program, "relay-test")?
  let pins = AnchorPins {
    program: program,
    ring: derived.ring,
    log_name: "relay-test",
    log_id: derived.log_id,
    endpoints: []
  }
  let signer = signing()?
  let first = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    [Crypto.sha256(Bytes.from_utf8("left"))],
    zero(32)?,
    wide(1000)?)?
  let second = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    [Crypto.sha256(Bytes.from_utf8("right"))],
    checkpoint_hash(first)?,
    wide(2000)?)?
  # Two historical keys for the same ID can both remain bonded during rotation.
  let signed = for index in 0..3 do
    let pair = signing()?
    let signatures = if index < 2 do
      [
        sign_witness("rotated", pair.private_key, first)?,
        sign_witness("rotated", pair.private_key, second)?
      ]
    else
      []
    end
    (pair.public_key.bytes, signatures)
  end
  let keys = for (key, _) in signed do
    key
  end
  let attestations = List.flat_map(signed, fn((_, signatures)) -> signatures end)
  let records = for index in 0..3 do
    let key = List.get(keys, index)
    cat([
      Bytes.from_hex("4d574901")?,
      le(7, 1)?,
      le(if index == 2 do
          1
        else
          2
        end,
        1)?,
      zero(2)?,
      Bytes.from_utf8("rotated"),
      zero(57)?,
      key,
      signer.public_key.bytes,
      signer.public_key.bytes,
      zero(32)?,
      pins.log_id,
      signer.public_key.bytes,
      le(if index == 2 do
          0
        else
          9
        end,
        8)?,
      zero(48)?
    ])?
  end
  let addresses = for key in keys do
    find_program_address(program,
      [Bytes.from_utf8("witness"), pins.log_id, bond_witness_identity("rotated", key)?])?.address
  end
  let log = cat([
    Bytes.from_hex("4d4c4701")?,
    le(1, 1)?,
    zero(1)?,
    le(10, 1)?,
    zero(1)?,
    Bytes.from_utf8("relay-test"),
    zero(22)?,
    pins.log_id,
    signer.public_key.bytes,
    signer.public_key.bytes,
    pins.ring.bytes,
    zero(32)?,
    zero(8)?,
    le(0, 2)?,
    zero(142)?
  ])?
  let header = cat([Bytes.from_hex("4d524701")?, pins.log_id, zero(28)?])?
  let proof = encode_fork(ForkProof {
    kind: 1,
    finder: signer.public_key.bytes,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: attestations,
    contradiction: None
  })?
  Ok(Fixture {
    pins: pins,
    service_key: signer.public_key.bytes,
    log: log,
    header: header,
    records: records,
    addresses: addresses,
    proof: proof,
    accused: for index in 0..2 do
      List.get(keys, index)
    end
  })
end

fn account(data :: Bytes, owner :: String, mode :: String) -> String do
  let owner = if mode == "owner" do
    "11111111111111111111111111111111"
  else
    owner
  end
  let executable = if mode == "executable" do
    "true"
  else
    "false"
  end
  let lamports = if mode == "empty" do
    "0"
  else
    "10"
  end
  """{"data":["#{Bytes.to_base64(data)}","base64"],"owner":"#{owner}","lamports":#{lamports},"executable":#{executable},"rentEpoch":0}"""
end

fn reply(request :: Request, f :: Fixture, mode :: String) -> String!String do
  let request = Json.parse(Request.body(request))?
  let params = Json.object_get(request, "params")?
  let options = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(options, "commitment")?)? == "finalized")
  let minimum = Json.as_int(Json.object_get(options, "minContextSlot")?)?
  let slot = if mode == "stale" do
    1
  else
    minimum + 1
  end
  let method = Json.as_string(Json.object_get(request, "method")?)?
  let value = if method == "getProgramAccounts" do
    assert(Json.as_bool(Json.object_get(options, "withContext")?)?)
    assert(Json.as_string(Json.array_get(params, 0)?)? == pubkey_string(f.pins.program))
    let filters = Json.object_get(options, "filters")?
    assert(Json.array_length(filters)? == 4)
    assert(Json.as_int(Json.object_get(Json.array_get(filters, 0)?, "dataSize")?)? == 320)
    let expected = [Bytes.from_hex("4d574901")?, f.pins.log_id]
    for index in 0..2 do
      let filter = Json.object_get(Json.array_get(filters, index + 1)?, "memcmp")?
      assert(Json.as_int(Json.object_get(filter, "offset")?)? == if index == 0 do
          0
        else
          200
        end)
      assert(Json.as_string(Json.object_get(filter,
        "bytes")?)? == Bytes.to_base58(List.get(expected, index)))
    end
    let status_filter = Json.object_get(Json.array_get(filters, 3)?, "memcmp")?
    assert(Json.as_int(Json.object_get(status_filter, "offset")?)? == 5)
    let status = Bytes.get(Bytes.from_base58(Json.as_string(Json.object_get(status_filter,
        "bytes")?)?)?,
      0)?
    assert(status == 1 || status == 2)
    let order = if mode == "reverse" do
      [2, 1, 0]
    else
      [0, 1, 2]
    end
    let entries = for index in order when Bytes.get(List.get(f.records, index), 5)? == status do
      let bytes = List.get(f.records, index)
      let bytes = if mode == "padding" do
        replace(bytes, 319, le(1, 1)?)?
      else if mode == "log" do
        replace(bytes, 200, zero(32)?)?
      else if mode == "status" do
        replace(bytes, 5, le(0, 1)?)?
      else if mode == "key" do
        replace(bytes, 72, f.service_key)?
      else if mode == "time" do
        replace(bytes, 264, Bytes.from_hex("ffffffffffffffff")?)?
      else if mode == "changed" && minimum >= 102 do
        replace(bytes, 136, List.get(f.accused, 0))?
      else
        bytes
      end
      let address = if mode == "address" do
        f.pins.program
      else
        List.get(f.addresses, index)
      end
      """{"pubkey":"#{pubkey_string(address)}","account":#{account(bytes,
        pubkey_string(f.pins.program),
        mode)}}"""
    end
    let entries = if mode == "duplicate" do
      entries ++ entries
    else if mode == "overbound" do
      for index in 0..65 do
        List.head(entries)
      end
    else if mode == "missing" do
      []
    else
      entries
    end
    "[" <> String.join(entries, ",") <> "]"
  else
    assert(method == "getAccountInfo")
    let length = Json.as_int(Json.object_get(Json.object_get(options, "dataSlice")?, "length")?)?
    if mode == "no-ring" && length == 64 do
      return Err("ring_not_initialized")
    end
    account(if length == 64 do
        f.header
      else
        f.log
      end,
      pubkey_string(f.pins.program),
      "valid")
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":#{value}}}""")
end

fn respond(request :: Request, f :: Fixture, mode :: String) -> Response do
  if mode == "down" do
    return HTTP.response(503, "offline")
  end
  case reply(request, f, mode) do
    Ok(body) -> HTTP.response(200, body)
    Err(error) -> HTTP.response(400, error)
  end
end

actor server(port :: Int, f :: Fixture) do
  let modes = [
    "no-ring",
    "valid",
    "reverse",
    "down",
    "owner",
    "executable",
    "empty",
    "stale",
    "padding",
    "log",
    "status",
    "key",
    "time",
    "address",
    "duplicate",
    "overbound",
    "missing",
    "changed"
  ]
  let router = List.reduce(modes,
    HTTP.router(),
    fn(router, mode) do HTTP.on_post(router,
      "/" <> mode,
      fn(r :: Request) do respond(r, f, mode) end) end)
  HTTP.serve(router, port)
end

fn pins(f :: Fixture, modes :: List<String>) -> AnchorPins do
  %{f.pins |
    endpoints: for index in 0..3 do
      "http://127.0.0.1:#{19953 + index}/#{List.get(modes, index)}"
    end
  }
end

fn discovery() -> Bool!String do
  let f = fixture()?
  let _one = spawn(server, 19953, f)
  let _two = spawn(server, 19954, f)
  let _three = spawn(server, 19955, f)
  Timer.sleep(100)
  for modes in [["valid", "reverse", "down"], ["down", "valid", "reverse"]] do
    let found = read_collectible_witnesses(pins(f, modes), wide(100)?)?
    assert(List.length(found.keys) == 3 && U64.to_string(found.context_slot) == "104")
  end
  for mode in [
    "owner",
    "executable",
    "empty",
    "stale",
    "padding",
    "log",
    "status",
    "key",
    "time",
    "address",
    "duplicate",
    "overbound",
    "changed"
  ] do
    case read_collectible_witnesses(pins(f, [mode, mode, "down"]), wide(100)?) do
      Ok(_) -> do
        println(mode)
        assert(false)
      end
      Err(_) -> nil
    end
  end
  case read_collectible_witnesses(pins(f, ["valid", "missing", "down"]), wide(100)?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "anchor_rpc_disagree")
  end
  # Generation zero/current membership cannot suppress an older bonded key.
  let verified = verify_relay_fork(pins(f, ["valid", "reverse", "valid"]),
    f.service_key,
    1,
    f.proof,
    wide(100)?)?
  assert(verified.witness_scope == "collectible-registry")
  assert(Bytes.secure_equals(verified.proof, f.proof)
    && Bytes.secure_equals(verified.finder, f.service_key))
  assert(List.length(verified.verdict.witnesses) == 2)
  for key in verified.verdict.witnesses do
    assert(key.witness_id == "rotated" && List.contains(f.accused, key.public_key))
  end
  assert(U64.compare(verified.context_slot, wide(104)?) > 0)
  let without_ring = verify_relay_fork(pins(f, ["no-ring", "no-ring", "no-ring"]),
    f.service_key,
    1,
    f.proof,
    wide(100)?)?
  assert(List.length(without_ring.verdict.witnesses) == 2
    && Bytes.length(without_ring.anchor_header) == 0)
  Ok(true)
end

test("relay discovers rotated collectible keys by authenticated bounded RPC sets, preserving finder and proof") do
  case discovery() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
