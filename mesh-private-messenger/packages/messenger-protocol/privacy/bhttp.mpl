##! Binary HTTP (RFC 9292), known-length messages: the requests and responses
##! Oblivious HTTP (Privacy.Ohttp) carries between Morse clients and the
##! gateway. Integers are QUIC variable-length integers (RFC 9000 section 16).
##! Missing trailing sections read as empty (section 3.8) and padding must be
##! zeros. Indeterminate-length framing (2 and 3) is refused: no Morse party
##! writes it.

pub struct BhttpField do
  name :: String
  value :: String
end

pub struct BhttpRequest do
  method :: String
  scheme :: String
  authority :: String
  path :: String
  fields :: List<BhttpField>
  content :: Bytes
end

pub struct BhttpResponse do
  status :: Int
  fields :: List<BhttpField>
  content :: Bytes
end

# A section or content length, bounded well below 2^62 (a message is at most
# an OHTTP response, a mebibyte).
fn largest() -> Int do
  16777216
end

fn invalid<T>() -> T!String do
  Err("bhttp_invalid")
end

fn concat(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("bhttp_allocation_failed")
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, concat(output, List.get(parts, index))?)
  end
end

fn bytes_of(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Err(_) -> invalid()
    Ok(value)
  end
end

fn varint(value :: Int) -> Bytes!String do
  if value < 0 || value > largest() do
    invalid()
  else if value < 64 do
    bytes_of([value])
  else if value < 16384 do
    bytes_of([64 + value / 256, value % 256])
  else
    bytes_of([128 + value / 16777216, value / 65536 % 256, value / 256 % 256, value % 256])
  end
end

fn prefixed(value :: Bytes) -> Bytes!String do
  concat(varint(Bytes.length(value))?, value)
end

fn field_line(field :: BhttpField) -> Bytes!String do
  concat(prefixed(Bytes.from_utf8(field.name))?, prefixed(Bytes.from_utf8(field.value))?)
end

fn field_lines(fields :: List<BhttpField>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(fields) do
    Ok(output)
  else
    field_lines(fields, index + 1, concat(output, field_line(List.get(fields, index))?)?)
  end
end

fn field_section(fields :: List<BhttpField>) -> Bytes!String do
  prefixed(field_lines(fields, 0, Bytes.empty())?)
end

# `message` then zeros up to `length` total, when that is longer.

fn padded(message :: Bytes, length :: Int) -> Bytes!String do
  if length <= Bytes.length(message) do
    Ok(message)
  else
    case Bytes.repeat(0, length - Bytes.length(message)) do
      Err(_) -> Err("bhttp_allocation_failed")
      Ok(zeros) -> concat(message, zeros)
    end
  end
end

## A known-length request: headers and content, no trailers, zero-padded to
## `length` bytes when that is longer than the message.

pub fn bhttp_encode_request(request :: BhttpRequest, length :: Int) -> Bytes!String do
  let message = join([
      varint(0)?,
      prefixed(Bytes.from_utf8(request.method))?,
      prefixed(Bytes.from_utf8(request.scheme))?,
      prefixed(Bytes.from_utf8(request.authority))?,
      prefixed(Bytes.from_utf8(request.path))?,
      field_section(request.fields)?,
      prefixed(request.content)?
    ],
    0,
    Bytes.empty())?
  padded(message, length)
end

## A known-length final response: status, headers and content, no trailers.

pub fn bhttp_encode_response(response :: BhttpResponse, length :: Int) -> Bytes!String do
  if response.status < 200 || response.status > 599 do
    invalid()
  else
    let message = join([
        varint(1)?,
        varint(response.status)?,
        field_section(response.fields)?,
        prefixed(response.content)?
      ],
      0,
      Bytes.empty())?
    padded(message, length)
  end
end

# Decoding. Each reader answers the value and the offset after it.

fn byte_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(input, offset) do
    Err(_) -> invalid()
    Ok(value)
  end
end

fn varint_rest(input :: Bytes, offset :: Int, count :: Int, value :: Int) -> (Int, Int)!String do
  if count == 0 do
    Ok((value, offset))
  else
    varint_rest(input, offset + 1, count - 1, value * 256 + byte_at(input, offset)?)
  end
end

fn read_varint(input :: Bytes, offset :: Int) -> (Int, Int)!String do
  let first = byte_at(input, offset)?
  let length = if first >= 192 do
    8
  else if first >= 128 do
    4
  else if first >= 64 do
    2
  else
    1
  end
  let (value, next) = varint_rest(input, offset + 1, length - 1, first % 64)?
  if value > largest() do
    invalid()
  else
    Ok((value, next))
  end
end

fn read_prefixed(input :: Bytes, offset :: Int, limit :: Int) -> (Bytes, Int)!String do
  let (length, start) = read_varint(input, offset)?
  if start + length > limit do
    invalid()
  else if length == 0 do
    Ok((Bytes.empty(), start))
  else
    case Bytes.slice(input, start, length) do
      Err(_) -> invalid()
      Ok(value) -> Ok((value, start + length))
    end
  end
end

fn text(value :: Bytes) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> invalid()
    Ok(output)
  end
end

# Lowercase field-name token characters (RFC 9110 section 5.6.2, lowercase as
# HTTP/2 requires): no pseudo-fields.

fn name_byte(byte :: Int) -> Bool do
  (byte >= 97 && byte <= 122)
    || (byte >= 48 && byte <= 57)
    || List.contains([33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126], byte)
end

# HTTP/2's malformed-value rule (RFC 9113 section 8.2.1).

fn value_valid(value :: Bytes) -> Bool do
  let bytes = Bytes.to_list(value)
  let edges = List.length(bytes) == 0
    || (!List.contains([32, 9], List.get(bytes, 0)) && !List.contains([32, 9], List.last(bytes)))
  edges && List.all(bytes, fn byte -> byte != 0 && byte != 10 && byte != 13 end)
end

fn read_field(input :: Bytes, offset :: Int, limit :: Int) -> (BhttpField, Int)!String do
  let (name, after_name) = read_prefixed(input, offset, limit)?
  let (value, after_value) = read_prefixed(input, after_name, limit)?
  if Bytes.length(name) == 0 || !List.all(Bytes.to_list(name), fn byte -> name_byte(byte) end) do
    invalid()
  else if !value_valid(value) do
    invalid()
  else
    Ok((BhttpField { name: text(name)?, value: text(value)? }, after_value))
  end
end

fn read_fields(input :: Bytes,
  offset :: Int,
  limit :: Int,
  output :: List<BhttpField>) -> List<BhttpField>!String do
  if offset == limit do
    Ok(output)
  else
    let (field, next) = read_field(input, offset, limit)?
    read_fields(input, next, limit, List.append(output, field))
  end
end

# A field section, or none when the message ends here (truncation).

fn read_section(input :: Bytes, offset :: Int) -> (List<BhttpField>, Int)!String do
  if offset >= Bytes.length(input) do
    Ok((List.new(), offset))
  else
    let (length, start) = read_varint(input, offset)?
    if start + length > Bytes.length(input) do
      invalid()
    else
      Ok((read_fields(input, start, start + length, List.new())?, start + length))
    end
  end
end

fn read_content(input :: Bytes, offset :: Int) -> (Bytes, Int)!String do
  if offset >= Bytes.length(input) do
    Ok((Bytes.empty(), offset))
  else
    read_prefixed(input, offset, Bytes.length(input))
  end
end

# Headers, content, trailers (read and dropped), then only zero padding.

fn read_body(input :: Bytes, offset :: Int) -> (List<BhttpField>, Bytes)!String do
  let (fields, after_fields) = read_section(input, offset)?
  let (content, after_content) = read_content(input, after_fields)?
  let (_, after_trailers) = read_section(input, after_content)?
  let padding = Bytes.length(input) - after_trailers
  if padding == 0 do
    Ok((fields, content))
  else
    case (Bytes.slice(input, after_trailers, padding), Bytes.repeat(0, padding)) do
      (Ok(rest), Ok(zeros)) -> if Bytes.secure_equals(rest, zeros) do
        Ok((fields, content))
      else
        invalid()
      end
      _ -> invalid()
    end
  end
end

fn token(value :: Bytes) -> String!String do
  let bytes = Bytes.to_list(value)
  if List.length(bytes) == 0 || !List.all(bytes, fn byte -> byte > 32 && byte < 127 end) do
    invalid()
  else
    text(value)
  end
end

pub fn bhttp_decode_request(input :: Bytes) -> BhttpRequest!String do
  let (framing, after_framing) = read_varint(input, 0)?
  if framing != 0 do
    invalid()
  else
    let limit = Bytes.length(input)
    let (method, after_method) = read_prefixed(input, after_framing, limit)?
    let (scheme, after_scheme) = read_prefixed(input, after_method, limit)?
    let (authority, after_authority) = read_prefixed(input, after_scheme, limit)?
    let (path, after_path) = read_prefixed(input, after_authority, limit)?
    let (fields, content) = read_body(input, after_path)?
    Ok(BhttpRequest {
      method: token(method)?,
      scheme: token(scheme)?,
      authority: text(authority)?,
      path: token(path)?,
      fields: fields,
      content: content
    })
  end
end

# Informational (1xx) responses and their field sections come before the
# final status; they carry nothing Morse uses.

fn read_final_status(input :: Bytes, offset :: Int) -> (Int, Int)!String do
  let (status, next) = read_varint(input, offset)?
  if status >= 100 && status <= 199 do
    if next >= Bytes.length(input) do
      invalid()
    else
      let (_, section_end) = read_section(input, next)?
      read_final_status(input, section_end)
    end
  else if status >= 200 && status <= 599 do
    Ok((status, next))
  else
    invalid()
  end
end

pub fn bhttp_decode_response(input :: Bytes) -> BhttpResponse!String do
  let (framing, after_framing) = read_varint(input, 0)?
  if framing != 1 do
    invalid()
  else
    let (status, after_status) = read_final_status(input, after_framing)?
    let (fields, content) = read_body(input, after_status)?
    Ok(BhttpResponse { status: status, fields: fields, content: content })
  end
end
