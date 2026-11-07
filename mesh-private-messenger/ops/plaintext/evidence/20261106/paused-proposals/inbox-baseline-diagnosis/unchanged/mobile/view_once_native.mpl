##! Native-only selected-image framing. No generic JS bytes, network or caller key.
from Mobile.ViewOnce import (
  ViewOnceSelection,
  ViewOnceImage,
  ViewOnceImageFormat,
  consume_view_once
)
from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_fixed,
  take_vector_error,
  mobile_utf8,
  mobile_byte,
  mobile_vector,
  mobile_join
)

pub fn parse_view_once_native_request(input :: Bytes) -> ViewOnceSelection!String do
  let state = mobile_reader(input, 40271, "view_once_unavailable")?
  let version = take_fixed(state, 1)?
  if !Bytes.secure_equals(version.value, mobile_byte(1)?) do
    return Err("view_once_unavailable")
  end
  let path = take_vector_error(version.state, 4096, "view_once_unavailable")?
  let profile = take_vector_error(path.state, 36134, "view_once_unavailable")?
  let conversation = take_fixed(profile.state, 16)?
  let message = take_fixed(conversation.state, 16)?
  mobile_finish(message.state, "view_once_unavailable")?
  let database_path = mobile_utf8(path.value, "view_once_unavailable")?
  if Bytes.length(path.value) == 0
    || String.contains(database_path, "\0")
    || Bytes.length(profile.value) == 0 do
    return Err("view_once_unavailable")
  end
  Ok(ViewOnceSelection {
    database_path: database_path,
    profile: profile.value,
    conversation_id: conversation.value,
    message_id: message.value
  })
end

fn view_once_native_refused() -> Bytes do
  case Bytes.from_hex("01564f4900") do
    Err(_) -> Bytes.empty()
    Ok(wire) -> wire
  end
end

fn view_once_native_image_frame(image :: Plaintext<ViewOnceImage>) -> Plaintext<Bytes>!String do
  let length = Bytes.length(image.content)
  if length < 1 || length > 16777216 do
    return Err("view_once_unavailable")
  end
  let kind = case image.format do
    ViewOncePng -> 1
    ViewOnceJpeg -> 2
  end
  let header = case Bytes.from_hex("01564f49") do
    Err(_) -> return Err("view_once_unavailable")
    Ok(bytes) -> bytes
  end
  mobile_join([header, mobile_byte(kind)?, mobile_vector(image.content)?], 0, Bytes.empty())
end

pub fn encode_view_once_native_reply(value :: Result<Plaintext<ViewOnceImage>, String>) -> Plaintext<Bytes> do
  case value do
    Err(_) -> view_once_native_refused()
    Ok(image) -> case view_once_native_image_frame(image) do
      Err(_) -> view_once_native_refused()
      Ok(wire) -> wire
    end
  end
end

pub fn native_view_once_consume(input :: Bytes) -> Plaintext<Bytes>!String do
  case parse_view_once_native_request(input) do
    Err(_) -> Ok(view_once_native_refused())
    Ok(selection) -> do
      let completed = consume_view_once(selection)
      Ok(encode_view_once_native_reply(completed))
    end
  end
end
