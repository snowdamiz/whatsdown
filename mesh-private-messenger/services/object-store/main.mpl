from Store.Service import ObjectResult, complete, delete_object, get_part, grant, initialize, purge_expired, put_part
from Store.Service import next_expiry, transaction_in_progress
import RuntimeJobs

fn run_expiry() -> Int ! String do
  let _ = purge_expired(database_path(), storage_root(), current_time() ?, 1) ?
  next_expiry(database_path())
end

fn handle_jobs(request :: Request) -> Response do
  if !RuntimeJobs.internal_request_authorized(request, Env.get("MESSENGER_OBJECT_INTERNAL_TOKEN", "")) do
    HTTP.response(401, "")
  else
    case transaction_in_progress(database_path(), Request.body(request)) do
      Err( _) -> HTTP.response(503, "")
      Ok( true) -> HTTP.response(202, "")
      Ok( false) -> case run_expiry() do
        Err( _) -> HTTP.response(503, "")
        Ok( due) -> HTTP.response(200, Int.to_string(due))
      end
    end
  end
end

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

struct PartRequest do
  object_id :: Bytes
  part_index :: Int
  capability :: Bytes
end

fn database_path() -> String do
  Env.get("MESSENGER_OBJECT_DATABASE_URL", "")
end

fn storage_root() -> String do
  Env.get("MESSENGER_OBJECT_STORAGE_ROOT", "")
end

fn current_time() -> U64 ! String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn respond(result :: ObjectResult) -> Response do
  HTTP.response_bytes(result.status, result.body)
end

fn hex32(value :: String) -> Bytes ! String do
  if String.length(value) != 64 do
    Err("invalid object request")
  else
    let decoded = Bytes.from_hex(value) ?
    if Bytes.length(decoded) == 32 && Bytes.to_hex(decoded) == value do
      Ok(decoded)
    else
      Err("invalid object request")
    end
  end
end

fn part_request(request :: Request) -> PartRequest ! String do
  let object_id = case Request.param(request, "object_id") do
    None -> Err("invalid object request")
    Some( value) -> hex32(value)
  end ?
  let part_index = case Request.param(request, "part_index") do
    None -> Err("invalid object request")
    Some( value) -> case String.to_int(value) do
      None -> Err("invalid object request")
      Some( parsed) -> if Int.to_string(parsed) == value do
        Ok(parsed)
      else
        Err("invalid object request")
      end
    end
  end ?
  let capability_header = case Request.header(request, "X-Object-Capability") do
    None -> Request.header(request, "x-object-capability")
    Some( value) -> Some(value)
  end
  let capability = case capability_header do
    None -> Err("invalid object request")
    Some( value) -> hex32(value)
  end ?
  if part_index < 0 || part_index > 256 do
    Err("invalid object request")
  else
    Ok(PartRequest {
      object_id : object_id,
      part_index : part_index,
      capability : capability
    })
  end
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn purge_loop(database :: String, root :: String, elapsed_ms :: Int) do
  if Process.shutdown_requested() do
    nil
  else
    let next_elapsed = if elapsed_ms >= 60000 do
      case current_time() do
        Err( _) -> println("object expiry worker failed")
        Ok( now) -> case purge_expired(database, root, now, 32) do
          Err( _) -> println("object expiry worker failed")
          Ok( _) -> nil
        end
      end
      0
    else
      elapsed_ms
    end
    Timer.sleep(250)
    purge_loop(database, root, next_elapsed + 250)
  end
end

actor expiry_worker(database :: String, root :: String) do
  purge_loop(database, root, 60000)
end

fn handle_grant(request :: Request) -> Response do
  case current_time() do
    Err( _) -> HTTP.response(500, "")
    Ok( now) -> case U64.parse("300000") do
      Err( _) -> HTTP.response(500, "")
      Ok( maximum_work_future) -> respond(grant(database_path(),
      storage_root(),
      Request.body_bytes(request),
      now,
      maximum_work_future,
      Env.get_int("MESSENGER_OBJECT_WORK_DIFFICULTY", 16)))
    end
  end
end

fn handle_put(request :: Request) -> Response do
  case part_request(request) do
    Err( _) -> HTTP.response(400, "")
    Ok( part) -> case current_time() do
      Err( _) -> HTTP.response(500, "")
      Ok( now) -> respond(put_part(database_path(),
      storage_root(),
      part.object_id,
      part.part_index,
      part.capability,
      Request.body_bytes(request),
      now))
    end
  end
end

fn handle_get(request :: Request) -> Response do
  case part_request(request) do
    Err( _) -> HTTP.response(400, "")
    Ok( part) -> case current_time() do
      Err( _) -> HTTP.response(500, "")
      Ok( now) -> respond(get_part(database_path(),
      storage_root(),
      part.object_id,
      part.part_index,
      part.capability,
      now))
    end
  end
end

fn handle_complete(request :: Request) -> Response do
  case current_time() do
    Err( _) -> HTTP.response(500, "")
    Ok( now) -> respond(complete(database_path(), storage_root(), Request.body_bytes(request), now))
  end
end

fn handle_delete(request :: Request) -> Response do
  case current_time() do
    Err( _) -> HTTP.response(500, "")
    Ok( now) -> respond(delete_object(database_path(),
    storage_root(),
    Request.body_bytes(request),
    now))
  end
end

fn main() do
  Process.install_shutdown_signals()
  let port = Env.get_int("MESSENGER_OBJECT_PORT", 18089)
  let difficulty = Env.get_int("MESSENGER_OBJECT_WORK_DIFFICULTY", 16)
  if port <= 0 || port > 65535 do
    fatal("MESSENGER_OBJECT_PORT must be between 1 and 65535")
  else if difficulty < 1 || difficulty > 24 do
    fatal("MESSENGER_OBJECT_WORK_DIFFICULTY must be between 1 and 24")
  else
    case initialize(database_path(), storage_root()) do
      Err( _) -> fatal("object storage configuration is invalid or unavailable")
      Ok( _) -> do
        if !RuntimeJobs.enabled() do
          spawn(expiry_worker, database_path(), storage_root())
        end
        println("object-store listening on :#{port}")
        let _ = HTTP.serve(HTTP.router()
          |> HTTP.on_get("/health", handle_health)
          |> HTTP.on_post("/internal/v1/jobs/objects", handle_jobs)
          |> HTTP.on_post("/v1/attachments/grant", handle_grant)
          |> HTTP.on_put("/v1/objects/:object_id/parts/:part_index", handle_put)
          |> HTTP.on_get("/v1/objects/:object_id/parts/:part_index", handle_get)
          |> HTTP.on_post("/v1/attachments/complete", handle_complete)
          |> HTTP.on_post("/v1/attachments/delete", handle_delete),
        port)
        if !Process.shutdown_requested() do
          fatal("object-store HTTP server failed")
        else
          nil
        end
      end
    end
  end
end
