##! Frozen storage frames protect restart compatibility and reject truncation.
from Storage.ViewOnce import (
  ViewOnceRecord,
  ViewOncePending,
  ViewOnceReady,
  ViewOnceAvailable,
  decode_view_once_record,
  encode_view_once_record
)
from Tests.Support import append, repeated

fn pending_frame() -> Bytes!String do
  Bytes.from_hex("02564f530100000001ab000000000000000a000000000000000000")
end

fn proof() -> Bool!String do
  let literal = pending_frame()?
  let decoded = decode_view_once_record(literal)?
  let pending_ok = case decoded do
    PendingFetch(value) -> Bytes.secure_equals(value.reference, Bytes.from_hex("ab")?)
      && U64.to_string(value.expires_at) == "10"
      && Option.is_none(value.message_expiry)
    _ -> false
  end
  let written = encode_view_once_record(PendingFetch(ViewOncePending {
    reference: Bytes.from_hex("ab")?,
    expires_at: U64.parse("10")?,
    message_expiry: None
  }))?
  let truncated = Bytes.slice(literal, 0, Bytes.length(literal) - 1)?
  let trailing = append(literal, Bytes.from_utf8("x"))?
  let unknown = Bytes.from_hex("02564f5305")?
  let bad_flag = Bytes.from_hex("02564f530100000001ab000000000000000a020000000000000000")?
  let ready = encode_view_once_record(Ready(ViewOnceReady {
    available: ViewOnceAvailable {
      reference: Bytes.from_hex("ab")?,
      chunk_hashes: [repeated(7, 32)?],
      message_expiry: None
    },
    expires_at: U64.parse("10")?
  }))?
  let retained = case decode_view_once_record(ready)? do
    Ready(value) -> Bytes.secure_equals(value.available.reference, Bytes.from_hex("ab")?)
      && List.length(value.available.chunk_hashes) == 1
    _ -> false
  end
  let empty_ready = encode_view_once_record(Ready(ViewOnceReady {
    available: ViewOnceAvailable {
      reference: Bytes.from_hex("ab")?,
      chunk_hashes: [],
      message_expiry: None
    },
    expires_at: U64.parse("10")?
  }))
  Ok(pending_ok
    && Bytes.secure_equals(written, literal)
    && retained
    && Result.is_err(decode_view_once_record(truncated))
    && Result.is_err(decode_view_once_record(trailing))
    && Result.is_err(decode_view_once_record(unknown))
    && Result.is_err(decode_view_once_record(bad_flag))
    && Result.is_err(empty_ready))
end

test("v2 pending and ready retain restart material with strict canonical bounds") do
  assert(Result.unwrap_or(proof(), false))
end
