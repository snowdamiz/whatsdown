from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_vector,
  mobile_write_u32,
  mobile_read_byte,
  mobile_read_u32,
  take_vector
)
from Mobile.Types import MobileHistoryEntry
from Mobile.HistoryLimits import (
  history_max_entries,
  history_max_entry_bytes,
  history_max_plaintext_bytes
)
from Protocol.EnvelopeWire import (
  encode_inner_envelope,
  decode_inner_envelope
)
from Protocol.V1 import InnerEnvelope

##! Canonical bounded local-history framing; database access is in Mobile.History.

fn history_inner_bytes(value :: InnerEnvelope) -> Bytes!String do
  case encode_inner_envelope(value) do
    Err(_) -> Err("inner_encoding_failed")
    Ok(encoded)
  end
end

fn encode_history_entry(value :: MobileHistoryEntry) -> Bytes!String do
  mobile_join([
      mobile_vector(mobile_byte(value.direction)?)?,
      mobile_vector(history_inner_bytes(value.inner)?)?
    ],
    0,
    Bytes.empty())
end

# Retain a balanced tree rather than every growing whole-history prefix.
fn combine_entries(parts :: List<Bytes>, start :: Int, count :: Int) -> Bytes!String do
  if count == 0 do
    Ok(Bytes.empty())
  else if count == 1 do
    Ok(List.get(parts, start))
  else
    let left_count = count / 2
    mobile_append(combine_entries(parts, start, left_count)?,
      combine_entries(parts, start + left_count, count - left_count)?)
  end
end

fn encode_history_fields(values :: List<MobileHistoryEntry>) -> Bytes!String do
  let bounded = if List.length(values) > history_max_entries() do
    List.drop(values, List.length(values) - history_max_entries())
  else
    values
  end
  let frames = [mobile_vector(mobile_write_u32(List.length(bounded))?)?]
    ++ for entry in bounded do
      mobile_vector(encode_history_entry(entry)?)?
    end
  let encoded = combine_entries(frames, 0, List.length(frames))?
  if Bytes.length(encoded) > history_max_plaintext_bytes() do
    Err("history_capacity")
  else
    Ok(encoded)
  end
end

pub fn encode_history(values :: List<MobileHistoryEntry>) -> Plaintext<Bytes>!String do
  let encoded = encode_history_fields(values)
  let code = case encoded do
    Ok(_) -> 0
    Err("byte_concatenation_failed") -> 1
    Err("invalid_wide_integer") -> 2
    Err("integer_encoding_failed") -> 3
    Err("inner_encoding_failed") -> 4
    Err("history_capacity") -> 5
    Err(_) -> 6
  end
  let status = declassify(code,
    "canonical local-history framing discloses only success or its closed framing, integer, envelope-admission and capacity error classes; encoded entries and arbitrary error strings remain private")
  case status do
    0 -> Ok(Result.unwrap_or(encoded, Bytes.empty()))
    1 -> Err("byte_concatenation_failed")
    2 -> Err("invalid_wide_integer")
    3 -> Err("integer_encoding_failed")
    4 -> Err("inner_encoding_failed")
    5 -> Err("history_capacity")
    _ -> Err("history_encoding_failed")
  end
end

fn parse_history_entry(input :: Bytes) -> MobileHistoryEntry!String do
  case reader(input, history_max_entry_bytes()) do
    Err(_) -> Err("invalid_history")
    Ok(state) -> do
      let direction = take_vector(state, 1)?
      let inner = take_vector(direction.state, 65536)?
      case finish(inner.state) do
        Err(_) -> Err("invalid_history")
        Ok(_) -> do
          let direction_value = mobile_read_byte(direction.value)?
          if direction_value != 1 && direction_value != 2 do
            Err("invalid_history")
          else
            case decode_inner_envelope(inner.value) do
              Err(_) -> Err("invalid_history")
              Ok(value) -> Ok(MobileHistoryEntry { direction: direction_value, inner: value })
            end
          end
        end
      end
    end
  end
end

fn parse_history_parts(state :: BinaryReader,
  count :: Int,
  index :: Int,
  values :: List<MobileHistoryEntry>) -> List<MobileHistoryEntry>!String do
  if index >= count do
    case finish(state) do
      Err(_) -> Err("invalid_history")
      Ok(_) -> Ok(values)
    end
  else
    let entry = take_vector(state, history_max_entry_bytes())?
    parse_history_parts(entry.state,
      count,
      index + 1,
      List.append(values, parse_history_entry(entry.value)?))
  end
end

pub fn decode_history(input :: Bytes) -> List<MobileHistoryEntry>!String do
  case reader(input, history_max_plaintext_bytes()) do
    Err(_) -> Err("invalid_history")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let count_value = mobile_read_u32(count.value)?
      if count_value > history_max_entries() do
        Err("invalid_history")
      else
        parse_history_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end
