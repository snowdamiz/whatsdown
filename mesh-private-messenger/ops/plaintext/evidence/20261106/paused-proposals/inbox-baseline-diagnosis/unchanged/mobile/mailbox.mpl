from Mobile.Codec import random_bytes
from Mobile.MailboxTransport import (
  MobileMailboxStream,
  close_mailbox_stream,
  connect_mailbox_stream,
  read_mailbox_stream
)

struct MailboxSession do
  ticket :: Bytes
  stream :: MobileMailboxStream
  ready :: Bool
end

fn retained_sessions(sessions :: List<MailboxSession>, path :: String) -> List<MailboxSession> do
  for session in List.filter(sessions, fn(item) -> item.stream.database_path == path end) do
    close_mailbox_stream(session.stream)
  end
  List.filter(sessions, fn(item) -> item.stream.database_path != path end)
end

fn execute(sessions :: List<MailboxSession>,
  operation :: Int,
  path :: String,
  ticket :: Bytes) -> (List<MailboxSession>, Result<Bytes, String>) do
  if operation == 0 do
    let kept = retained_sessions(sessions, path)
    if List.length(kept) >= 8 do
      return (kept, Err("mailbox_stream_limit"))
    end
    let ticket = case random_bytes(32) do
      Err(error) -> return (kept, Err(error))
      Ok(value) -> value
    end
    let stream = case connect_mailbox_stream(path) do
      Err(error) -> return (kept, Err(error))
      Ok(value) -> value
    end
    (List.append(kept, MailboxSession { ticket: ticket, stream: stream, ready: false }), Ok(ticket))
  else
    let matches = List.filter(sessions,
      fn(item) -> item.stream.database_path == path && Bytes.secure_equals(item.ticket, ticket) end)
    if List.length(matches) != 1 do
      return (sessions, Err("mailbox_stream_expired"))
    end
    let session = List.head(matches)
    let others = List.filter(sessions, fn(item) -> !Bytes.secure_equals(item.ticket, ticket) end)
    if operation == 2 do
      close_mailbox_stream(session.stream)
      (others, Ok(Bytes.empty()))
    else
      case read_mailbox_stream(session.stream, 200) do
        Err(error) -> (others, Err(error))
        Ok(event) -> if event == "" do
          (sessions, Ok(Bytes.empty()))
        else if (event == "ready" && session.ready)
          || (event == "encrypted-wakeup" && !session.ready) do
          close_mailbox_stream(session.stream)
          (others, Err("invalid_mailbox_stream_order"))
        else
          let updated = %{session | ready: true}
          (List.append(others, updated), Ok(Bytes.from_utf8(event)))
        end
      end
    end
  end
end

service MailboxRegistry do
  fn init() -> List<MailboxSession> do
    List.new()
  end

  call Execute(operation :: Int,
    path :: String,
    ticket :: Bytes) :: Result<Bytes, String> do |sessions|
    execute(sessions, operation, path, ticket)
  end
end

# Registration of the bootstrap itself happens inside an actor. Losing
# initializers return normally; the one retained actor starts/restarts exactly
# one mailbox service without exposing either PID to the embedding caller.
actor mailbox_bootstrap() do
  if Process.register("morse/native-mailbox/bootstrap/v1", self()) == 0 do
    while true do
      case Process.lookup("morse/native-mailbox/v1") do
        Some(_) -> nil
        None ->
          let worker = MailboxRegistry.start()
          Process.register("morse/native-mailbox/v1", worker)
          nil
      end
      receive do
        :ensure -> nil
        _ -> nil
      end
    end
  end
end

fn wait_registry(tries :: Int) -> Pid!String do
  case Process.lookup("morse/native-mailbox/v1") do
    Some(pid) -> Ok(pid)
    None -> if tries == 0 do
      Err("mailbox_registry_unavailable")
    else
      Timer.sleep(1)
      wait_registry(tries - 1)
    end
  end
end

fn registry() -> Pid!String do
  case Process.lookup("morse/native-mailbox/v1") do
    Some(pid) -> Ok(pid)
    None ->
      case Process.lookup("morse/native-mailbox/bootstrap/v1") do
        Some(pid) -> do
          send(pid, :ensure)
          nil
        end
        None -> do
          let _started = spawn(mailbox_bootstrap)
          nil
        end
      end
      wait_registry(100)
  end
end

fn request(operation :: Int, path :: String, ticket :: Bytes) -> Bytes!String do
  if String.length(path) == 0
    || String.length(path) > 4096
    || (operation != 0 && Bytes.length(ticket) != 32) do
    return Err("invalid_mailbox_stream_request")
  end
  MailboxRegistry.execute(registry()?, operation, path, ticket)
end

pub fn open_mailbox(path :: String) -> Bytes!String do
  request(0, path, Bytes.empty())
end

pub fn poll_mailbox(path :: String, ticket :: Bytes) -> Bytes!String do
  request(1, path, ticket)
end

pub fn close_mailbox(path :: String, ticket :: Bytes) -> Bytes!String do
  request(2, path, ticket)
end
