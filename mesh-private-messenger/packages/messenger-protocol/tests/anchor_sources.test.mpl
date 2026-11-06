from Transparency.AnchorRpc import (
  validate_anchor_sources,
  validate_anchor_provider_sources,
  read_anchor_quorum,
  read_anchor_time_quorum
)
from Solana.Read import pubkey

fn refuses_host_aliases(endpoints :: List<String>) -> Result<(), String> do
  assert(validate_anchor_sources(endpoints) == Err("invalid_anchor_sources"))
  assert(validate_anchor_provider_sources(endpoints, true) == Err("invalid_anchor_sources"))
  assert(validate_anchor_provider_sources(endpoints, false) == Err("invalid_anchor_sources"))
  let address = pubkey("11111111111111111111111111111111")?
  let zero = U64.parse("0")?
  # Stop at the validator assertion on regression, before any HTTP is possible.
  assert(read_anchor_quorum(endpoints,
    address,
    address,
    0,
    64,
    zero) == Err("invalid_anchor_sources"))
  assert(read_anchor_time_quorum(endpoints, zero) == Err("invalid_anchor_sources"))
  Ok(nil)
end

test("localhost root dot cannot split one fixture origin into two sources") do
  assert(refuses_host_aliases([
    "https://localhost:444/a",
    "https://localhost.:444/b",
    "https://other.example/rpc"
  ]) == Ok(nil))
end

test("canonical IPv4 mapped IPv6 cannot count as a second IPv4 source") do
  assert(refuses_host_aliases([
    "https://192.0.2.1/rpc",
    "https://[::ffff:c000:201]/rpc",
    "https://other.example/rpc"
  ]) == Ok(nil))
end

test("mapped IPv6 spellings are refused without excluding ordinary IPv6") do
  for host in ["[::ffff:0:0]", "[::ffff:7f00:1]", "[::ffff:ffff:ffff]", "[::ffff:192.0.2.1]"] do
    assert(refuses_host_aliases([
      "https://one.example/rpc",
      "https://" <> host <> "/rpc",
      "https://other.example/rpc"
    ]) == Ok(nil))
  end
  for separate in [false, true] do
    assert(validate_anchor_provider_sources([
        "https://[::fffe:c000:201]/rpc",
        "https://[::c000:201]/rpc",
        "https://192.0.2.1/rpc"
      ],
      separate) == Ok(nil))
  end
end

test("nonmapped IPv6 sharing the ffff prefix remains valid") do
  for host in ["[::ffff:1]", "[::ffff:1:2:3]", "[::ffff:0]", "[::ffff:0:0:1]"] do
    let endpoint = "https://" <> host <> "/rpc"
    assert(Http.url_origin(endpoint) == Ok("https://" <> host))
    let endpoints = [endpoint, "https://one.example/rpc", "https://other.example/rpc"]
    assert(validate_anchor_sources(endpoints) == Ok(nil))
    for separate in [false, true] do
      assert(validate_anchor_provider_sources(endpoints, separate) == Ok(nil))
    end
  end
end

fn refuses_aliases() -> Result<(), String> do
  let address = pubkey("11111111111111111111111111111111")?
  let zero = U64.parse("0")?
  for endpoints in [
    ["https://rpc.example:444/a", "https://rpc.example:445/b", "https://other.example/rpc"],
    ["https://rpc.example/rpc", "https://rpc.example./rpc", "https://other.example/rpc"],
    ["https://rpc.example.:444/a", "https://rpc.example:445/b", "https://other.example/rpc"],
    ["https://[2001:db8::1]:444/a", "https://[2001:db8::1]:445/b", "https://other.example/rpc"],
    ["https://192.0.2.1:444/a", "https://192.0.2.1:445/b", "https://other.example/rpc"],
    ["https://rpc.example/a", "https://rpc.example/b", "https://other.example/rpc"],
    ["https://rpc.example/a", "https://RPC.Example/b", "https://other.example/rpc"],
    ["http://127.0.0.1:19011/a", "http://127.0.0.1:19011/b", "http://127.0.0.1:19012/a"]
  ] do
    # Validate first: a regressed validator fails locally before these quorum
    # calls could attempt any of the deliberately non-routable public hosts.
    assert(validate_anchor_sources(endpoints) == Err("invalid_anchor_sources"))
    assert(read_anchor_quorum(endpoints,
      address,
      address,
      0,
      64,
      zero) == Err("invalid_anchor_sources"))
    assert(read_anchor_time_quorum(endpoints, zero) == Err("invalid_anchor_sources"))
  end
  Ok(nil)
end

test("production writers can require distinct loopback hosts as well as public hosts") do
  for host in ["127.0.0.1", "localhost", "[::1]"] do
    let endpoints = [
      "https://" <> host <> ":19011/a",
      "https://" <> host <> ":19012/b",
      "https://" <> host <> ":19013/a"
    ]
    assert(validate_anchor_provider_sources(endpoints, false) == Err("invalid_anchor_sources"))
    assert(validate_anchor_provider_sources(endpoints, true) == Ok(nil))
  end
end

test("anchor account and clock quorums refuse aliases of one public host before HTTP") do
  case refuses_aliases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> nil
  end
end

test("distinct canonical hosts and separate loopback fixture origins remain valid") do
  for endpoints in [
    ["https://one.example:444/a", "https://two.example.:445/b", "https://other.example/rpc"],
    ["https://[2001:db8::1]:444/a", "https://[2001:db8::2]:445/b", "https://192.0.2.1/rpc"],
    ["http://127.0.0.1:19011/a", "http://127.0.0.1:19012/b", "http://127.0.0.1:19013/a"],
    ["https://127.0.0.1:19011/a", "https://127.0.0.1:19012/b", "https://127.0.0.1:19013/a"],
    ["https://localhost:19011/a", "https://localhost:19012/b", "https://localhost:19013/a"],
    ["https://[::1]:19011/a", "https://[::1]:19012/b", "https://[::1]:19013/a"]
  ] do
    assert(validate_anchor_sources(endpoints) == Ok(nil))
  end
end
