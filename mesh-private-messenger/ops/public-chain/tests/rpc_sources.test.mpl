from Transparency.TokenBurnRead import token_burn_rpc_sources

test("burn/public readers count normalized origins once before transport") do
  assert(Result.is_err(token_burn_rpc_sources([
      "https://one.example/a",
      "https://one.example/b",
      "https://three.example"
    ],
    false)))
  assert(Result.is_err(token_burn_rpc_sources([
      "https://one.example",
      "https://one.example:443",
      "https://three.example"
    ],
    false)))
  assert(Result.is_err(token_burn_rpc_sources([
      "https://one.example",
      "https://ONE.example/",
      "https://three.example"
    ],
    false)))
  assert(Result.is_err(token_burn_rpc_sources([
      "http://127.0.0.1:23901/a",
      "http://127.0.0.1:23901/b",
      "http://127.0.0.1:23903"
    ],
    true)))
end

test("burn/public source boundary retains strict HTTPS and owned loopback contracts") do
  assert(Result.is_ok(token_burn_rpc_sources([
      "https://one.example/a",
      "https://two.example/key?token=public-fixture",
      "https://three.example"
    ],
    false)))
  assert(Result.is_ok(token_burn_rpc_sources([
      "http://127.0.0.1:23901",
      "http://127.0.0.1:23902",
      "http://127.0.0.1:23903"
    ],
    true)))
  for url in [
    "https://user:password@one.example",
    "https://one.example/#fragment",
    "https://one.example/\n",
    "https://one.example/\r",
    "http://example.test:1234",
    "http://localhost:1234",
    "https://one.example/" <> String.repeat("a", 2048)
  ] do
    assert(Result.is_err(token_burn_rpc_sources([
        url,
        "https://two.example",
        "https://three.example"
      ],
      true)))
  end
  assert(Result.is_err(token_burn_rpc_sources([
      "http://127.0.0.1:23901",
      "http://127.0.0.1:23902",
      "http://127.0.0.1:23903"
    ],
    false)))
  assert(Result.is_err(token_burn_rpc_sources(["https://one.example", "https://two.example"],
    false)))
end
