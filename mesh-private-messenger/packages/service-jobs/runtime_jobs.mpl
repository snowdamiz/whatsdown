##! Register a durable wakeup while its PostgreSQL transaction is still open.

pub fn enabled() -> Bool do
  String.length(Env.get("MESSENGER_JOBS_URL", "")) > 0
end

## Call only inside an explicit transaction. A failed registration must abort it.

pub fn notify(conn :: borrow PgConn, kind :: String) -> Result <(), String > do
  if !enabled() do
    Ok(nil)
  else
    let rows = Pg.query(conn, "SELECT pg_current_xact_id()::text AS id", []) ?
    let id = Map.get(List.head(rows), "id")
    let request = Http.build(:post, Env.get("MESSENGER_JOBS_URL", "") <> "/" <> kind)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.body(id)
      |> Http.timeout(5000)
      |> Http.max_response_bytes(128)
    let response = Http.send(request) ?
    if response.status == 204 do
      Ok(nil)
    else
      Err("durable wakeup unavailable")
    end
  end
end

pub fn in_progress(conn :: borrow PgConn, id :: String) -> Bool ! String do
  if id == "0" do
    Ok(false)
  else if String.length(id) == 0 || String.length(id) > 20 do
    Err("invalid transaction id")
  else
    let parsed = U64.parse(id) ?
    if U64.to_string(parsed) != id do
      Err("invalid transaction id")
    else
      let rows = Pg.query(conn,
      "SELECT COALESCE(pg_xact_status($1::xid8), 'completed') AS state",
      [id]) ?
      Ok(Map.get(List.head(rows), "state") == "in progress")
    end
  end
end

pub fn due_time(rows :: List < Map < String, String > >) -> Int ! String do
  if List.length(rows) != 1 do
    Err("invalid job deadline")
  else
    case String.to_int(Map.get(List.head(rows), "due")) do
      Some(value) -> if value >= 0 do
        Ok(value)
      else
        Err("invalid job deadline")
      end
      None -> Err("invalid job deadline")
    end
  end
end

pub fn internal_request_authorized(request :: Request, secret :: String) -> Bool do
  if String.length(secret) < 32 || String.length(secret) > 256 do
    false
  else
    let header = case Request.header(request, "Authorization") do
      None -> Request.header(request, "authorization")
      Some(value) -> Some(value)
    end
    case header do
      None -> false
      Some(value) -> Bytes.secure_equals(Crypto.sha256(Bytes.from_utf8(value)),
      Crypto.sha256(Bytes.from_utf8("Bearer " <> secret)))
    end
  end
end
