from RuntimeJobs import notify

fn register(conn :: borrow PgConn) -> Result <(), String > do
  notify(conn, "directory")
end

fn exercise() -> Bool ! String do
  let database = Pg.connect(Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")) ?
  let result = Pg.transaction(database, register)
  Pg.close(database)
  let succeeded = case result do
    Ok(_) -> true
    Err(_) -> false
  end
  Ok(succeeded)
end

test("wakeup registration controls whether the database transaction commits") do
  case exercise() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(succeeded) -> assert(succeeded == (Env.get("MESSENGER_JOB_EXPECT_FAILURE", "false") != "true"))
  end
end
