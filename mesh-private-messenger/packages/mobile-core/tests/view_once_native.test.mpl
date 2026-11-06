from Mobile.ViewOnceNative import (
  parse_view_once_native_request,
  encode_view_once_native_reply,
  native_view_once_consume
)
from Mobile.ViewOnce import ViewOnceImage, ViewOnceImageFormat
from Mobile.Codec import mobile_join, mobile_vector, mobile_byte
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_fixture, view_once_fixture_clear

fn native_test_bytes(value :: Result<Bytes, String>) -> Bytes!String do
  case value do
    Err(_) -> Err("view_once_native_test_bytes")
    Ok(bytes) -> Ok(bytes)
  end
end

fn native_test_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY finite native VOI1 framing and authored view-once fixture assertions; no real image bytes metadata keys profiles errors or caller control")
end

fn native_test_observed(value :: Result<Plaintext<Bool>, String>) -> Bool do
  case value do
    Err(_) -> false
    Ok(valid) -> native_test_observe(valid)
  end
end

fn native_test_wire(version :: Int,
  path :: Bytes,
  profile :: Bytes,
  conversation :: Bytes,
  message :: Bytes) -> Bytes!String do
  mobile_join([
      mobile_byte(version)?,
      mobile_vector(path)?,
      mobile_vector(profile)?,
      conversation,
      message
    ],
    0,
    Bytes.empty())
end

fn native_test_literal() -> Bytes!String do
  native_test_bytes(Bytes.from_hex("01000000086f776e65642e646200000004000102031111111111111111111111111111111122222222222222222222222222222222"))
end

fn native_test_parsed(value :: Bytes) -> Bool do
  case parse_view_once_native_request(value) do
    Err(_) -> false
    Ok(_) -> true
  end
end

fn native_test_request_case() -> Bool!String do
  let literal = native_test_literal()?
  let parsed = parse_view_once_native_request(literal)
  let maximum = native_test_wire(1,
    repeated(97, 4096)?,
    repeated(66, 36134)?,
    repeated(17, 16)?,
    repeated(34, 16)?)?
  if Bytes.length(literal) != 53 || Bytes.length(maximum) != 40271 do
    return Err("view_once_native_test_request_setup")
  end
  println("VO_NATIVE_REQUEST_READY")
  let max_parsed = native_test_parsed(maximum)
  let literal_valid = case parsed do
    Err(_) -> false
    Ok(value) -> value.database_path == "owned.db"
      && Bytes.secure_equals(value.profile, native_test_bytes(Bytes.from_hex("00010203"))?)
      && Bytes.secure_equals(value.conversation_id, repeated(17, 16)?)
      && Bytes.secure_equals(value.message_id, repeated(34, 16)?)
  end
  Ok(literal_valid && max_parsed && Bytes.length(maximum) == 40271)
end

fn native_test_malformed_case() -> Bool!String do
  let literal = native_test_literal()?
  let tail = native_test_bytes(Bytes.concat(literal, Bytes.from_utf8("x")))?
  let short = native_test_bytes(Bytes.slice(literal, 0, Bytes.length(literal) - 1))?
  let path = Bytes.from_utf8("owned.db")
  let profile = repeated(66, 4)?
  let conversation = repeated(17, 16)?
  let message = repeated(34, 16)?
  let invalid = [
    tail,
    short,
    native_test_wire(2, path, profile, conversation, message)?,
    native_test_wire(1, Bytes.empty(), profile, conversation, message)?,
    native_test_wire(1, Bytes.from_utf8("bad\0path"), profile, conversation, message)?,
    native_test_wire(1, native_test_bytes(Bytes.from_hex("ff"))?, profile, conversation, message)?,
    native_test_wire(1, path, Bytes.empty(), conversation, message)?,
    native_test_wire(1, repeated(97, 4097)?, profile, conversation, message)?,
    native_test_wire(1, path, repeated(66, 36135)?, conversation, message)?,
    native_test_wire(1, path, profile, repeated(17, 15)?, message)?,
    native_test_wire(1, path, profile, conversation, repeated(34, 17)?)?
  ]
  println("VO_NATIVE_MALFORMED_READY")
  let outcomes = for wire in invalid do
    !native_test_parsed(wire)
  end
  let all_refused = List.reduce(outcomes, true, fn(valid, item) -> valid && item end)
  Ok(all_refused)
end

fn native_test_reply_matches(value :: Result<Plaintext<Bytes>, String>,
  expected :: Bytes) -> Plaintext<Bool> do
  case value do
    Err(_) -> false
    Ok(wire) -> Bytes.secure_equals(wire, expected)
  end
end

fn native_test_codec_case() -> Plaintext<Bool>!String do
  let small = native_test_bytes(Bytes.from_hex("aabbcc"))?
  let refused = native_test_bytes(Bytes.from_hex("01564f4900"))?
  let png_expected = native_test_bytes(Bytes.from_hex("01564f490100000003aabbcc"))?
  let jpeg_expected = native_test_bytes(Bytes.from_hex("01564f490200000003aabbcc"))?
  let expected_head = native_test_bytes(Bytes.from_hex("01564f490101000000"))?
  let maximum = repeated(3, 16777216)?
  let overflow = repeated(3, 16777217)?
  println("VO_NATIVE_CODEC_READY")
  let png = encode_view_once_native_reply(Ok(ViewOnceImage { format: ViewOncePng, content: small }))
  let jpeg = encode_view_once_native_reply(Ok(ViewOnceImage {
    format: ViewOnceJpeg,
    content: small
  }))
  let error = encode_view_once_native_reply(Err("protected detailed refusal must not cross"))
  let empty = encode_view_once_native_reply(Ok(ViewOnceImage {
    format: ViewOncePng,
    content: Bytes.empty()
  }))
  let max_reply = encode_view_once_native_reply(Ok(ViewOnceImage {
    format: ViewOncePng,
    content: maximum
  }))
  let oversized = encode_view_once_native_reply(Ok(ViewOnceImage {
    format: ViewOnceJpeg,
    content: overflow
  }))
  let max_head = Bytes.slice(max_reply, 0, 9)
  let head_matches = case max_head do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, expected_head)
  end
  Ok(Bytes.secure_equals(png, png_expected)
    && Bytes.secure_equals(jpeg, jpeg_expected)
    && Bytes.secure_equals(error, refused)
    && Bytes.secure_equals(empty, refused)
    && Bytes.secure_equals(oversized, refused)
    && Bytes.length(max_reply) == 16777225
    && head_matches)
end

fn native_test_expected_png(png :: Bytes) -> Bytes!String do
  mobile_join([native_test_bytes(Bytes.from_hex("01564f4901"))?, mobile_vector(png)?],
    0,
    Bytes.empty())
end

fn native_test_expected_matches(value :: Result<Plaintext<Bytes>, String>,
  expected :: Bytes!String) -> Plaintext<Bool> do
  case expected do
    Err(_) -> false
    Ok(wire) -> native_test_reply_matches(value, wire)
  end
end

fn native_test_consume_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let request = native_test_wire(1,
    Bytes.from_utf8(fixture.path),
    fixture.profile,
    fixture.binding.conversation_id,
    fixture.binding.message_id)?
  println("VO_NATIVE_BOUND_REQUEST_READY")
  let first = native_view_once_consume(request)
  let second = native_view_once_consume(request)
  view_once_fixture_clear(fixture)?
  let expected = native_test_expected_png(fixture.png)
  let refused = native_test_bytes(Bytes.from_hex("01564f4900"))?
  Ok(native_test_expected_matches(first, expected) && native_test_reply_matches(second, refused))
end

fn native_test_profile_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let wrong = native_test_wire(1,
    Bytes.from_utf8(fixture.path),
    repeated(55, Bytes.length(fixture.profile))?,
    fixture.binding.conversation_id,
    fixture.binding.message_id)?
  let valid = native_test_wire(1,
    Bytes.from_utf8(fixture.path),
    fixture.profile,
    fixture.binding.conversation_id,
    fixture.binding.message_id)?
  let wrong_parsed = native_test_parsed(wrong)
  println("VO_NATIVE_BOUND_REQUEST_READY")
  let rejected = native_view_once_consume(wrong)
  let opened = native_view_once_consume(valid)
  view_once_fixture_clear(fixture)?
  let refused = native_test_bytes(Bytes.from_hex("01564f4900"))?
  let expected = native_test_expected_png(fixture.png)
  Ok(wrong_parsed
    && native_test_reply_matches(rejected, refused)
    && native_test_expected_matches(opened, expected))
end

test("native view-once request accepts independent canonical and exact maximum frames") do
  assert(native_test_observed(native_test_request_case()))
end

test("native view-once request refuses malformed version bounds framing and UTF8") do
  assert(native_test_observed(native_test_malformed_case()))
end

test("native view-once reply has literal PNG JPEG refusal and exact size boundaries") do
  assert(native_test_observed(native_test_codec_case()))
end

test("native view-once consume emits one authenticated image then finite refusal") do
  assert(native_test_observed(native_test_consume_case()))
end

test("native view-once wrong profile refuses without consuming the valid image") do
  assert(native_test_observed(native_test_profile_case()))
end
