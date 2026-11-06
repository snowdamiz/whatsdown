from Store.Large import valid_large_credit_origin

test("paid object credit calls allow only HTTPS, loopback or the fixed private core origin") do
  assert(valid_large_credit_origin("http://credit-core.internal"))
  assert(valid_large_credit_origin("http://127.0.0.1:18700"))
  assert(valid_large_credit_origin("https://core.example"))
  for origin in [
    "http://credit-core.internal/",
    "http://credit-core.internal.evil",
    "http://credit-core.internal:80",
    "http://evil.example",
    "http://127.0.0.1:80@evil.example",
    "http://127.0.0.1:80/path",
    "http://127.0.0.1:0",
    "http://127.0.0.1:65536",
    "https://",
    "http://localhost:18700",
    "http://[::1]:18700"
  ] do
    assert(!valid_large_credit_origin(origin))
  end
end
