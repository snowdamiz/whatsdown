from Mobile.ForkFilingTransport import submit_filing
from Tests.ForkFilingSupport import filing_fixture
from Tests.Support import database_path
from Transparency.Config import SecurityConfig
from Transparency.Fork import ForkProof, encode_fork, fork_hash

fn barrier(base :: String, tries :: Int) -> Bool do
  if File.exists(base <> "1") && File.exists(base <> "2") && File.exists(base <> "3") do
    true
  else if tries == 0 do
    false
  else
    Timer.sleep(10)
    barrier(base, tries - 1)
  end
end

fn response(request :: Request,
  base :: String,
  number :: Int,
  wire :: Bytes,
  hash :: String) -> Response do
  if !Bytes.secure_equals(Request.body_bytes(request), wire) do
    return HTTP.response(400, "wrong body")
  end
  if Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None do
    return HTTP.response(400, "private metadata")
  end
  case File.write(base <> Int.to_string(number), Bytes.to_hex(Request.body_bytes(request))) do
    Err(_) -> return HTTP.response(500, "fixture write failed")
    Ok(_) -> nil
  end
  # A sequential client cannot get any successful acknowledgment: every server
  # waits until all three have received identical FRK bytes.
  if !barrier(base, 100) do
    return HTTP.response(503, "not simultaneous")
  end
  if number == 3 do
    HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  else
    HTTP.response(202, """{"schema_version":1,"status":"queued","proof_hash":"#{hash}"}""")
  end
end

actor relay(port :: Int, base :: String, number :: Int, wire :: Bytes, hash :: String) do
  HTTP.router()
    |> HTTP.on_post("/v1/fork-evidence",
      fn(request :: Request) do response(request, base, number, wire, hash) end)
    |> HTTP.on_post("/untrusted",
      fn(_ :: Request) do
        File.write(base <> "redirected", "bad")
        HTTP.response(200, "bad")
      end)
    |> HTTP.serve(port)
end

fn proof() -> Bool!String do
  let (fork, _config) = filing_fixture()?
  let wire = encode_fork(fork)?
  let hash = fork_hash(fork)?
  let base = database_path("filing-transport")?
  let _a = spawn(relay, 19961, base, 1, wire, Bytes.to_hex(hash))
  let _b = spawn(relay, 19962, base, 2, wire, Bytes.to_hex(hash))
  let _c = spawn(relay, 19963, base, 3, wire, Bytes.to_hex(hash))
  Timer.sleep(100)
  assert(submit_filing([
      "http://127.0.0.1:19961",
      "http://127.0.0.1:19962",
      "http://127.0.0.1:19963"
    ],
    wire,
    hash)? == 2)
  assert(!File.exists(base <> "redirected"))
  for number in [1, 2, 3] do
    assert(File.read(base <> Int.to_string(number))? == Bytes.to_hex(wire))
    File.delete(base <> Int.to_string(number))?
  end
  Ok(true)
end

test("filing sends exact finder-bearing evidence to all relays concurrently without following redirects") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
