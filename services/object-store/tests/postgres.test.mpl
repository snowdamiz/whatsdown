from Store.Service import initialize

test("object metadata opens durable PostgreSQL storage") do
  let url = Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")
  assert(String.length(url) > 0)
  case initialize(url, "/tmp") do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
