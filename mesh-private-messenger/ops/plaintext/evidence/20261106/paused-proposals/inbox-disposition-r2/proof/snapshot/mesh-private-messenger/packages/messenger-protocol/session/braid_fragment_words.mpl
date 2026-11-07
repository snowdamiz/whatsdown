##! Inactive public carrier words. No authentication, acknowledgement or scheduling.
from Protocol.V1 import ProtocolError
from Binary.Erasure import encode_erasure_chunk, decode_erasure_chunks
from Session.BraidFragment import (
  BraidFragment,
  BraidFragmentKind,
  braid_fragment_source_length,
  encode_braid_fragment
)

fn same_carrier(left :: BraidFragmentKind, right :: BraidFragmentKind) -> Bool do
  let left_vector = left == BraidVectorFragment || left == BraidVectorAckFragment
  let right_vector = right == BraidVectorFragment || right == BraidVectorAckFragment
  left == right || (left_vector && right_vector)
end

pub fn emit_braid_fragment(kind :: BraidFragmentKind,
  configuration :: Bytes,
  session :: Bytes,
  epoch :: U64,
  carrier :: Bytes,
  index :: Int) -> BraidFragment!ProtocolError do
  let length = braid_fragment_source_length(kind)
  if Bytes.length(carrier) != length do
    return Err(InvalidFieldLength)
  end
  let word = if length == 0 do
    Bytes.empty()
  else
    case encode_erasure_chunk(carrier, 64, index) do
      Ok(v) -> v
      Err(_) -> return Err(MalformedEncoding)
    end
  end
  let value = BraidFragment {
    kind: kind,
    configuration: configuration,
    session: session,
    epoch: epoch,
    index: index,
    word: word
  }
  # The wire codec owns the shared canonical scope/control/index checks.
  encode_braid_fragment(value)?
  Ok(value)
end

## At most72 supplied words before deduplication. The two vector kinds share
## carrier bytes, but this function returns no acknowledgement authority.
pub fn recover_braid_carrier(kind :: BraidFragmentKind,
  configuration :: Bytes,
  session :: Bytes,
  epoch :: U64,
  fragments :: List<BraidFragment>) -> Option<Bytes>!ProtocolError do
  if List.length(fragments) > 72 do
    return Err(MalformedEncoding)
  end
  let length = braid_fragment_source_length(kind)
  if length == 0 do
    return Err(InvalidPolicy)
  end
  # Validate the expected scope even when there are no fragments.
  encode_braid_fragment(BraidFragment {
    kind: NoBraidFragment,
    configuration: configuration,
    session: session,
    epoch: epoch,
    index: 0,
    word: Bytes.empty()
  })?
  for fragment in fragments do
    if !same_carrier(kind, fragment.kind)
      || !Bytes.secure_equals(configuration, fragment.configuration)
      || !Bytes.secure_equals(session, fragment.session)
      || U64.compare(epoch, fragment.epoch) != 0 do
      return Err(InvalidPolicy)
    end
    encode_braid_fragment(fragment)?
  end
  let indices = for fragment in fragments do
    fragment.index
  end
  let words = for fragment in fragments do
    fragment.word
  end
  case decode_erasure_chunks(length, 64, indices, words) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end
