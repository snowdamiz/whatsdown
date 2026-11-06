##! RFC 9292 framing only: no network, route selection or header interpretation.
from Ohttp.Types import (
  BhttpError,
  BhttpLimits,
  BhttpField,
  BhttpInformational,
  BhttpRequest,
  BhttpResponse,
  BhttpFraming
)

struct BhttpCursor do
  input :: Bytes
  offset :: Int
  end_offset :: Int
end

struct BhttpReadInt do
  state :: BhttpCursor
  value :: Int
end

struct BhttpReadBytes do
  state :: BhttpCursor
  value :: Bytes
end

struct BhttpFieldBudget do
  count :: Int
  bytes :: Int
end

struct BhttpReadFields do
  state :: BhttpCursor
  fields :: List<BhttpField>
  budget :: BhttpFieldBudget
end

struct BhttpReadHead do
  state :: BhttpCursor
  informational :: List<BhttpInformational>
  status :: Int
  fields :: List<BhttpField>
  budget :: BhttpFieldBudget
end

struct BhttpEncodedFields do
  wire :: Bytes
  budget :: BhttpFieldBudget
end

struct BhttpEncodedInfos do
  parts :: List<Bytes>
  budget :: BhttpFieldBudget
end

fn validate_limits(value :: BhttpLimits) -> Result<(), BhttpError> do
  if value.wire_bytes < 0
    || value.wire_bytes > 1048576
    || value.content_bytes < 0
    || value.content_bytes > 1048576
    || value.field_bytes < 0
    || value.field_bytes > 8192
    || value.field_count < 0
    || value.field_count > 16
    || value.control_bytes < 0
    || value.control_bytes > 4096
    || value.informational_count < 0
    || value.informational_count > 4
    || value.content_chunks < 0
    || value.content_chunks > 1024 do
    Err(BhttpInvalidLimits)
  else
    Ok(nil)
  end
end

fn start(input :: Bytes, limits :: BhttpLimits) -> BhttpCursor!BhttpError do
  validate_limits(limits)?
  if Bytes.length(input) > limits.wire_bytes do
    Err(BhttpInputTooLarge)
  else
    Ok(BhttpCursor { input: input, offset: 0, end_offset: Bytes.length(input) })
  end
end

fn byte_at(input :: Bytes, offset :: Int) -> Int!BhttpError do
  case Bytes.get(input, offset) do
    Err(_) -> Err(BhttpUnexpectedEnd)
    Ok(value)
  end
end

fn take(state :: BhttpCursor, count :: Int) -> BhttpReadBytes!BhttpError do
  # Subtract before addition; every cursor end is already inside the wire cap.
  if count < 0 || count > state.end_offset - state.offset do
    Err(BhttpUnexpectedEnd)
  else
    case Bytes.slice(state.input, state.offset, count) do
      Err(_) -> Err(BhttpUnexpectedEnd)
      Ok(value) -> Ok(BhttpReadBytes {
        state: %{state | offset: state.offset + count},
        value: value
      })
    end
  end
end

fn integer_tail(state :: BhttpCursor, left :: Int, value :: Int) -> BhttpReadInt!BhttpError do
  if left == 0 do
    Ok(BhttpReadInt { state: state, value: value })
  else
    let byte = byte_at(state.input, state.offset)?
    # QUIC has at most 62 value bits. The first byte was masked to six bits;
    # all intermediate values and this multiply/add fit signed Mesh Int.
    integer_tail(%{state | offset: state.offset + 1}, left - 1, value * 256 + byte)
  end
end

fn integer(state :: BhttpCursor) -> BhttpReadInt!BhttpError do
  if state.offset >= state.end_offset do
    return Err(BhttpUnexpectedEnd)
  end
  let first = byte_at(state.input, state.offset)?
  let width = if first < 64 do
    1
  else if first < 128 do
    2
  else if first < 192 do
    4
  else
    8
  end
  if width > state.end_offset - state.offset do
    return Err(BhttpUnexpectedEnd)
  end
  # Nonminimal integer encodings are legal RFC 9292 input.
  integer_tail(%{state | offset: state.offset + 1}, width - 1, first % 64)
end

fn vector(state :: BhttpCursor, maximum :: Int) -> BhttpReadBytes!BhttpError do
  let size = integer(state)?
  if size.value > maximum do
    Err(BhttpLimitExceeded)
  else
    take(size.state, size.value)
  end
end

fn equal(left :: Bytes, right :: String) -> Bool do
  Bytes.secure_equals(left, Bytes.from_utf8(right))
end

fn token(value :: Bytes) -> Bool do
  case Bytes.to_utf8(value) do
    Err(_) -> false
    Ok(text) -> Regex.is_match(~r/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/, text)
  end
end

fn visible(value :: Bytes, offset :: Int) -> Bool!BhttpError do
  if offset >= Bytes.length(value) do
    Ok(true)
  else
    let byte = byte_at(value, offset)?
    if byte < 33 || byte > 126 do
      Ok(false)
    else
      visible(value, offset + 1)
    end
  end
end

fn request_control(method :: Bytes,
  scheme :: Bytes,
  authority :: Bytes,
  path :: Bytes) -> Result<(), BhttpError> do
  let connect = equal(method, "CONNECT")
  let valid_scheme = if connect && Bytes.length(scheme) == 0 do
    true
  else
    case Bytes.to_utf8(scheme) do
      Err(_) -> false
      Ok(text) -> Regex.is_match(~r/^[A-Za-z][A-Za-z0-9+.-]*$/, text)
    end
  end
  if !token(method)
    || !valid_scheme
    || (!connect && Bytes.length(path) == 0)
    || !visible(authority, 0)?
    || !visible(path, 0)? do
    Err(BhttpInvalidControl)
  else
    # Scheme/authority/path admission and Host/URI normalization belong to the
    # later gateway. No target is selected or fetched by this codec.
    Ok(nil)
  end
end

fn value_bytes(value :: Bytes, offset :: Int) -> Bool!BhttpError do
  if offset >= Bytes.length(value) do
    Ok(true)
  else
    let byte = byte_at(value, offset)?
    if byte == 0 || byte == 10 || byte == 13 do
      Ok(false)
    else
      value_bytes(value, offset + 1)
    end
  end
end

fn valid_value(value :: Bytes) -> Bool!BhttpError do
  if Bytes.length(value) == 0 do
    return Ok(true)
  end
  let first = byte_at(value, 0)?
  let last = byte_at(value, Bytes.length(value) - 1)?
  Ok(first != 9 && first != 32 && last != 9 && last != 32 && value_bytes(value, 0)?)
end

fn pseudo(value :: BhttpField) -> Bool!BhttpError do
  if Bytes.length(value.name) == 0 do
    Err(BhttpInvalidField)
  else
    Ok(byte_at(value.name, 0)? == 58)
  end
end

fn validate_field(value :: BhttpField,
  prior :: List<BhttpField>,
  trailers :: Bool,
  ordinary_seen :: Bool) -> Bool!BhttpError do
  let special = pseudo(value)?
  let name = if special do
    take(BhttpCursor { input: value.name, offset: 1, end_offset: Bytes.length(value.name) },
      Bytes.length(value.name) - 1)?.value
  else
    value.name
  end
  if !token(name) || !valid_value(value.value)? do
    return Err(BhttpInvalidField)
  end
  if special do
    if trailers
      || ordinary_seen
      || equal(value.name, ":method")
      || equal(value.name, ":scheme")
      || equal(value.name, ":authority")
      || equal(value.name, ":path")
      || equal(value.name, ":status")
      || List.any(prior,
        fn(entry :: BhttpField) -> Bytes.secure_equals(entry.name, value.name) end) do
      return Err(BhttpInvalidField)
    end
  end
  Ok(ordinary_seen || !special)
end

fn field_budget(budget :: BhttpFieldBudget,
  limits :: BhttpLimits,
  name_size :: Int,
  value_size :: Int) -> BhttpFieldBudget!BhttpError do
  if budget.count >= limits.field_count
    || name_size > limits.field_bytes - budget.bytes
    || value_size > limits.field_bytes - budget.bytes - name_size do
    Err(BhttpLimitExceeded)
  else
    Ok(BhttpFieldBudget { count: budget.count + 1, bytes: budget.bytes + name_size + value_size })
  end
end

fn fields_loop(state :: BhttpCursor,
  indeterminate :: Bool,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  fields :: List<BhttpField>,
  trailers :: Bool,
  ordinary_seen :: Bool) -> BhttpReadFields!BhttpError do
  if state.offset == state.end_offset do
    if indeterminate do
      return Err(BhttpUnexpectedEnd)
    else
      return Ok(BhttpReadFields { state: state, fields: fields, budget: budget })
    end
  end
  let name_size = integer(state)?
  if indeterminate && name_size.value == 0 do
    return Ok(BhttpReadFields { state: name_size.state, fields: fields, budget: budget })
  end
  if name_size.value == 0 do
    return Err(BhttpInvalidField)
  end
  if budget.count >= limits.field_count || name_size.value > limits.field_bytes - budget.bytes do
    return Err(BhttpLimitExceeded)
  end
  let name = take(name_size.state, name_size.value)?
  let value = vector(name.state, limits.field_bytes - budget.bytes - name_size.value)?
  let next = field_budget(budget, limits, name_size.value, Bytes.length(value.value))?
  let entry = BhttpField { name: name.value, value: value.value }
  let ordinary = validate_field(entry, fields, trailers, ordinary_seen)?
  fields_loop(value.state,
    indeterminate,
    limits,
    next,
    List.append(fields, entry),
    trailers,
    ordinary)
end

fn read_fields(state :: BhttpCursor,
  indeterminate :: Bool,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  trailers :: Bool) -> BhttpReadFields!BhttpError do
  # An entirely absent trailing empty section is legal. EOF in an already
  # started nonempty section is handled separately by fields_loop.
  if state.offset == state.end_offset do
    return Ok(BhttpReadFields { state: state, fields: [], budget: budget })
  end
  if indeterminate do
    fields_loop(state, true, limits, budget, [], trailers, false)
  else
    let size = integer(state)?
    # At most two eight-byte length prefixes per remaining field. This is an
    # encoded-section cap; the aggregate name/value byte cap is checked too.
    if size.value > limits.field_bytes - budget.bytes + (limits.field_count - budget.count) * 16 do
      return Err(BhttpLimitExceeded)
    end
    if size.value > size.state.end_offset - size.state.offset do
      return Err(BhttpUnexpectedEnd)
    end
    let end_offset = size.state.offset + size.value
    let section = fields_loop(%{size.state | end_offset: end_offset},
      false,
      limits,
      budget,
      [],
      trailers,
      false)?
    Ok(%{section | state: %{size.state | offset: end_offset}})
  end
end

fn join(parts :: List<Bytes>, maximum :: Int) -> Bytes!BhttpError do
  case Bytes.concat_many(parts, maximum) do
    Err(_) -> Err(BhttpOutputTooLarge)
    Ok(output)
  end
end

fn body_chunks(state :: BhttpCursor,
  limits :: BhttpLimits,
  parts :: List<Bytes>,
  size :: Int,
  count :: Int) -> BhttpReadBytes!BhttpError do
  let chunk_size = integer(state)?
  if chunk_size.value == 0 do
    return Ok(BhttpReadBytes { state: chunk_size.state, value: join(parts, limits.content_bytes)? })
  end
  if count >= limits.content_chunks || chunk_size.value > limits.content_bytes - size do
    return Err(BhttpLimitExceeded)
  end
  let chunk = take(chunk_size.state, chunk_size.value)?
  body_chunks(chunk.state,
    limits,
    List.append(parts, chunk.value),
    size + chunk_size.value,
    count + 1)
end

fn read_body(state :: BhttpCursor,
  indeterminate :: Bool,
  limits :: BhttpLimits) -> BhttpReadBytes!BhttpError do
  if state.offset == state.end_offset do
    Ok(BhttpReadBytes { state: state, value: Bytes.empty() })
  else if indeterminate do
    body_chunks(state, limits, [], 0, 0)
  else
    vector(state, limits.content_bytes)
  end
end

fn padding(state :: BhttpCursor) -> Result<(), BhttpError> do
  if state.offset == state.end_offset do
    return Ok(nil)
  end
  # A bounded block comparison avoids byte-recursion proportional to a full
  # MiB of padding and keeps temporary strings <=8KiB each.
  let remaining = state.end_offset - state.offset
  let count = if remaining > 4096 do
    4096
  else
    remaining
  end
  let block = take(state, count)?
  if Bytes.to_hex(block.value) != String.repeat("00", count) do
    Err(BhttpInvalidPadding)
  else
    padding(block.state)
  end
end

pub fn decode_request(input :: Bytes, limits :: BhttpLimits) -> BhttpRequest!BhttpError do
  let frame = integer(start(input, limits)?)?
  if frame.value != 0 && frame.value != 2 do
    return Err(BhttpInvalidFraming)
  end
  let method = vector(frame.state, limits.control_bytes)?
  let scheme = vector(method.state, limits.control_bytes - Bytes.length(method.value))?
  let authority = vector(scheme.state,
    limits.control_bytes - Bytes.length(method.value) - Bytes.length(scheme.value))?
  let path = vector(authority.state,
    limits.control_bytes - Bytes.length(method.value) - Bytes.length(scheme.value) - Bytes.length(authority.value))?
  request_control(method.value, scheme.value, authority.value, path.value)?
  let fields = read_fields(path.state,
    frame.value == 2,
    limits,
    BhttpFieldBudget { count: 0, bytes: 0 },
    false)?
  let body = read_body(fields.state, frame.value == 2, limits)?
  let trailers = read_fields(body.state, frame.value == 2, limits, fields.budget, true)?
  padding(trailers.state)?
  Ok(BhttpRequest {
    method: method.value,
    scheme: scheme.value,
    authority: authority.value,
    path: path.value,
    fields: fields.fields,
    content: body.value,
    trailers: trailers.fields
  })
end

fn response_head(state :: BhttpCursor,
  indeterminate :: Bool,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  informational :: List<BhttpInformational>) -> BhttpReadHead!BhttpError do
  let status = integer(state)?
  if status.value < 100 || status.value > 599 do
    return Err(BhttpInvalidStatus)
  end
  if status.value < 200 && List.length(informational) >= limits.informational_count do
    return Err(BhttpLimitExceeded)
  end
  let fields = read_fields(status.state, indeterminate, limits, budget, false)?
  if status.value < 200 do
    response_head(fields.state,
      indeterminate,
      limits,
      fields.budget,
      List.append(informational,
        BhttpInformational { status: status.value, fields: fields.fields }))
  else
    Ok(BhttpReadHead {
      state: fields.state,
      informational: informational,
      status: status.value,
      fields: fields.fields,
      budget: fields.budget
    })
  end
end

pub fn decode_response(input :: Bytes, limits :: BhttpLimits) -> BhttpResponse!BhttpError do
  let frame = integer(start(input, limits)?)?
  if frame.value != 1 && frame.value != 3 do
    return Err(BhttpInvalidFraming)
  end
  let head = response_head(frame.state,
    frame.value == 3,
    limits,
    BhttpFieldBudget { count: 0, bytes: 0 },
    [])?
  let body = read_body(head.state, frame.value == 3, limits)?
  let trailers = read_fields(body.state, frame.value == 3, limits, head.budget, true)?
  padding(trailers.state)?
  Ok(BhttpResponse {
    informational: head.informational,
    status: head.status,
    fields: head.fields,
    content: body.value,
    trailers: trailers.fields
  })
end

fn encode_integer(value :: Int) -> Bytes!BhttpError do
  # Every emitted value is bounded by the complete-wire cap (or status 599).
  if value < 0 || value > 1048576 do
    return Err(BhttpLimitExceeded)
  end
  let parts = if value < 64 do
    [value]
  else if value < 16384 do
    [64 + value / 256, value % 256]
  else
    [128 + value / 16777216, (value / 65536) % 256, (value / 256) % 256, value % 256]
  end
  case Bytes.from_list(parts) do
    Err(_) -> Err(BhttpOutputTooLarge)
    Ok(output)
  end
end

fn encode_fields_loop(fields :: List<BhttpField>,
  index :: Int,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  trailers :: Bool,
  ordinary_seen :: Bool,
  parts :: List<Bytes>) -> BhttpEncodedInfos!BhttpError do
  if index >= List.length(fields) do
    return Ok(BhttpEncodedInfos { parts: parts, budget: budget })
  end
  let entry = List.get(fields, index)
  let next = field_budget(budget, limits, Bytes.length(entry.name), Bytes.length(entry.value))?
  let ordinary = validate_field(entry, List.take(fields, index), trailers, ordinary_seen)?
  encode_fields_loop(fields,
    index + 1,
    limits,
    next,
    trailers,
    ordinary,
    List.concat(parts,
      [
        encode_integer(Bytes.length(entry.name))?,
        entry.name,
        encode_integer(Bytes.length(entry.value))?,
        entry.value
      ]))
end

fn encode_fields(fields :: List<BhttpField>,
  indeterminate :: Bool,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  trailers :: Bool) -> BhttpEncodedFields!BhttpError do
  if List.length(fields) > limits.field_count - budget.count do
    return Err(BhttpLimitExceeded)
  end
  let encoded = encode_fields_loop(fields, 0, limits, budget, trailers, false, [])?
  let body = join(encoded.parts, 8448)?
  let wire = if indeterminate do
    join([body, encode_integer(0)?], 8449)?
  else
    join([encode_integer(Bytes.length(body))?, body], 8452)?
  end
  Ok(BhttpEncodedFields { wire: wire, budget: encoded.budget })
end

fn encode_body(content :: Bytes,
  indeterminate :: Bool,
  limits :: BhttpLimits) -> List<Bytes>!BhttpError do
  if Bytes.length(content) > limits.content_bytes do
    return Err(BhttpLimitExceeded)
  end
  if indeterminate && Bytes.length(content) > 0 do
    if limits.content_chunks == 0 do
      return Err(BhttpLimitExceeded)
    end
    Ok([encode_integer(Bytes.length(content))?, content, encode_integer(0)?])
  else
    Ok([encode_integer(Bytes.length(content))?, content])
  end
end

pub fn encode_request(value :: BhttpRequest,
  framing :: BhttpFraming,
  limits :: BhttpLimits) -> Bytes!BhttpError do
  validate_limits(limits)?
  let method_size = Bytes.length(value.method)
  if method_size > limits.control_bytes do
    return Err(BhttpLimitExceeded)
  end
  let scheme_size = Bytes.length(value.scheme)
  if scheme_size > limits.control_bytes - method_size do
    return Err(BhttpLimitExceeded)
  end
  let authority_size = Bytes.length(value.authority)
  if authority_size > limits.control_bytes - method_size - scheme_size do
    return Err(BhttpLimitExceeded)
  end
  if Bytes.length(value.path) > limits.control_bytes - method_size - scheme_size - authority_size do
    return Err(BhttpLimitExceeded)
  end
  request_control(value.method, value.scheme, value.authority, value.path)?
  let code = case framing do
    BhttpKnownLength -> 0
    BhttpIndeterminateLength -> 2
  end
  let fields = encode_fields(value.fields,
    code == 2,
    limits,
    BhttpFieldBudget { count: 0, bytes: 0 },
    false)?
  let body = encode_body(value.content, code == 2, limits)?
  let trailers = encode_fields(value.trailers, code == 2, limits, fields.budget, true)?
  join(List.concat([
        encode_integer(code)?,
        encode_integer(Bytes.length(value.method))?,
        value.method,
        encode_integer(Bytes.length(value.scheme))?,
        value.scheme,
        encode_integer(Bytes.length(value.authority))?,
        value.authority,
        encode_integer(Bytes.length(value.path))?,
        value.path,
        fields.wire
      ],
      List.append(body, trailers.wire)),
    limits.wire_bytes)
end

fn encode_infos(values :: List<BhttpInformational>,
  index :: Int,
  indeterminate :: Bool,
  limits :: BhttpLimits,
  budget :: BhttpFieldBudget,
  parts :: List<Bytes>) -> BhttpEncodedInfos!BhttpError do
  if index >= List.length(values) do
    return Ok(BhttpEncodedInfos { parts: parts, budget: budget })
  end
  let entry = List.get(values, index)
  if entry.status < 100 || entry.status > 199 do
    return Err(BhttpInvalidStatus)
  end
  let fields = encode_fields(entry.fields, indeterminate, limits, budget, false)?
  encode_infos(values,
    index + 1,
    indeterminate,
    limits,
    fields.budget,
    List.concat(parts, [encode_integer(entry.status)?, fields.wire]))
end

pub fn encode_response(value :: BhttpResponse,
  framing :: BhttpFraming,
  limits :: BhttpLimits) -> Bytes!BhttpError do
  validate_limits(limits)?
  if value.status < 200 || value.status > 599 do
    return Err(BhttpInvalidStatus)
  end
  if List.length(value.informational) > limits.informational_count do
    return Err(BhttpLimitExceeded)
  end
  let code = case framing do
    BhttpKnownLength -> 1
    BhttpIndeterminateLength -> 3
  end
  let infos = encode_infos(value.informational,
    0,
    code == 3,
    limits,
    BhttpFieldBudget { count: 0, bytes: 0 },
    [])?
  let fields = encode_fields(value.fields, code == 3, limits, infos.budget, false)?
  let body = encode_body(value.content, code == 3, limits)?
  let trailers = encode_fields(value.trailers, code == 3, limits, fields.budget, true)?
  join(List.concat([encode_integer(code)?],
      List.concat(infos.parts,
        List.concat([encode_integer(value.status)?, fields.wire],
          List.append(body, trailers.wire)))),
    limits.wire_bytes)
end
