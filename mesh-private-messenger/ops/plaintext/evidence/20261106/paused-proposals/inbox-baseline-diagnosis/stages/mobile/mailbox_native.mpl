from Mobile.Codec import (
  mobile_finish,
  mobile_read_u32,
  mobile_reader,
  mobile_utf8,
  take_fixed,
  take_vector
)
from Mobile.Mailbox import close_mailbox, open_mailbox, poll_mailbox

fn path(input :: Bytes) -> String!String do
  if Bytes.length(input) == 0
    || Bytes.length(input) > 4096
    || List.any(Bytes.to_list(input), fn(value) -> value == 0 end) do
    Err("invalid_database_path")
  else
    mobile_utf8(input, "invalid_database_path")
  end
end

fn session(input :: Bytes) -> (String, Bytes)!String do
  let start = mobile_reader(input, 4144, "invalid_mailbox_stream_request")?
  let count = take_fixed(start, 4)?
  if mobile_read_u32(count.value)? != 2 do
    return Err("invalid_mailbox_stream_request")
  end
  let database = take_vector(count.state, 4096)?
  let ticket = take_vector(database.state, 32)?
  mobile_finish(ticket.state, "invalid_mailbox_stream_request")?
  if Bytes.length(ticket.value) != 32 do
    return Err("invalid_mailbox_stream_request")
  end
  Ok((path(database.value)?, ticket.value))
end

pub fn native_mailbox_open(input :: Bytes) -> Bytes!String do
  open_mailbox(path(input)?)
end

pub fn native_mailbox_poll(input :: Bytes) -> Bytes!String do
  let (database, ticket) = session(input)?
  poll_mailbox(database, ticket)
end

pub fn native_mailbox_close(input :: Bytes) -> Bytes!String do
  let (database, ticket) = session(input)?
  close_mailbox(database, ticket)
end
