from Objects.Grant import ObjectControl, encode_complete, encode_grant, mint_grant

fn bytes(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn post(path :: String, body :: Bytes) -> HttpResponse!String do
  Http.build(:post, Env.get("MESSENGER_EVENT_OBJECT_URL", "") <> path)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(2048)
    |> Http.send()
end

fn download(path :: String, capability :: Bytes) -> HttpResponse!String do
  Http.build(:get, path)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("x-object-capability", Bytes.to_hex(capability))
    |> Http.timeout(5000)
    |> Http.max_response_bytes(2048)
    |> Http.send()
end

fn exercise() -> Bool!String do
  let id = bytes(9, 32)?
  let upload = bytes(1, 32)?
  let read = bytes(2, 32)?
  let body = bytes(42, 128)?
  let now = DateTime.to_unix_ms(DateTime.utc_now())
  let grant = encode_grant(mint_grant(id,
    1,
    U64.parse(Int.to_string(now + 8000))?,
    U64.parse(Int.to_string(now + 60000))?,
    upload,
    read,
    4)?)?
  let granted = post("/v1/attachments/grant", grant)?
  assert(granted.status == 201)
  let path = Env.get("MESSENGER_EVENT_OBJECT_URL", "") <> "/v1/objects/" <> Bytes.to_hex(id) <> "/parts/0"
  let uploaded = Http.build(:put, path)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("x-object-capability", Bytes.to_hex(upload))
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(2048)
    |> Http.send()
  let accepted = uploaded?
  assert(accepted.status == 201)
  let completed = post("/v1/attachments/complete",
    encode_complete(ObjectControl {
      object_id: id,
      capability: upload
    })?)?
  assert(completed.status == 200)
  let fetched = download(path, read)?
  assert(fetched.status == 200)
  assert(Bytes.secure_equals(fetched.body_bytes, body))
  Timer.sleep(9000)
  let expired = download(path, read)?
  assert(expired.status == 404)
  Ok(true)
end

test("opaque parts expire through scheduled jobs without a polling worker") do
  case exercise() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
