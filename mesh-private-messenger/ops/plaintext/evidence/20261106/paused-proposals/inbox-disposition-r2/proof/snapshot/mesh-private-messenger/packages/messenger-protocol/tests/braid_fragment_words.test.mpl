##! Public words and carrier recovery; reconstructed bytes still need authentication.
from Protocol.V1 import ProtocolError
from Session.BraidFragment import (
  BraidFragment,
  BraidFragmentKind,
  encode_braid_fragment,
  decode_braid_fragment
)
from Session.BraidFragmentWords import emit_braid_fragment, recover_braid_carrier

fn check(value :: Bool) -> Unit!ProtocolError do
  if value do
    Ok(nil)
  else
    Err(InvalidPolicy)
  end
end

fn fill(value :: Int, count :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(value, count) do
    Ok(v)
    Err(_) -> Err(InvalidFieldLength)
  end
end

fn epoch(value :: String) -> U64!ProtocolError do
  case U64.parse(value) do
    Ok(v)
    Err(_) -> Err(InvalidPolicy)
  end
end

fn payload(length :: Int) -> Bytes!ProtocolError do
  case Bytes.from_list(for i in 0..length do
    (i * 19 + 7) % 256
  end) do
    Ok(v)
    Err(_) -> Err(InvalidFieldLength)
  end
end

fn emit(kind :: BraidFragmentKind, carrier :: Bytes, index :: Int) -> BraidFragment!ProtocolError do
  emit_braid_fragment(kind, fill(1, 32)?, fill(2, 32)?, epoch("1")?, carrier, index)
end

fn recover(kind :: BraidFragmentKind,
  fragments :: List<BraidFragment>) -> Option<Bytes>!ProtocolError do
  recover_braid_carrier(kind, fill(1, 32)?, fill(2, 32)?, epoch("1")?, fragments)
end

fn all_carriers() -> Bool!ProtocolError do
  for (kind, length) in [
    (BraidHeaderFragment, 96),
    (BraidVectorFragment, 1152),
    (BraidVectorAckFragment, 1152),
    (BraidFirstFragment, 960),
    (BraidSecondFragment, 160)
  ] do
    let input = payload(length)?
    let count = (length + 63) / 64
    let words = for i in 0..count do
      let word = emit(kind, input, 65535 - i * 997)?
      decode_braid_fragment(encode_braid_fragment(word)?, fill(1, 32)?, fill(2, 32)?)?
    end
    check(recover(kind, List.take(words, count - 1))? == None)?
    check(recover(kind, List.reverse(words))? == Some(input))?
    let first = emit(kind, input, 0)?
    check(first.word == payload(64)?)?
  end
  Ok(true)
end

fn duplicates_and_surplus() -> Bool!ProtocolError do
  let input = payload(96)?
  let first = emit(BraidHeaderFragment, input, 0)?
  let second = emit(BraidHeaderFragment, input, 1)?
  let repair = emit(BraidHeaderFragment, input, 65535)?
  check(recover(BraidHeaderFragment, [first, first])? == None)?
  check(recover(BraidHeaderFragment, [first, second, first, repair])? == Some(input))?
  check(case recover(BraidHeaderFragment, [first, %{first | word: fill(0, 64)?}]) do
    Err(_) -> true
    _ -> false
  end)?
  check(case recover(BraidHeaderFragment, [first, second, %{repair | word: fill(0, 64)?}]) do
    Err(_) -> true
    _ -> false
  end)?
  let repeated = for _ in 0..72 do
    first
  end
  check(recover(BraidHeaderFragment, repeated)? == None)?
  check(case recover(BraidHeaderFragment, List.append(repeated, first)) do
    Err(_) -> true
    _ -> false
  end)?
  Ok(true)
end

fn validation() -> Bool!ProtocolError do
  let word = emit(BraidHeaderFragment, payload(96)?, 0)?
  for invalid in [
    %{word | configuration: fill(3, 32)?},
    %{word | session: fill(3, 32)?},
    %{word | epoch: epoch("2")?},
    %{word | epoch: epoch("0")?},
    %{word | kind: BraidSecondFragment},
    %{word | index: -1},
    %{word | index: 65536},
    %{word | word: fill(0, 63)?}
  ] do
    check(case recover(BraidHeaderFragment, [invalid]) do
      Err(_) -> true
      _ -> false
    end)?
  end
  check(recover(BraidHeaderFragment, [])? == None)?
  check(case emit(BraidHeaderFragment, payload(95)?, 0) do
    Err(_) -> true
    _ -> false
  end)?
  check(case emit(BraidHeaderFragment, payload(96)?, -1) do
    Err(_) -> true
    _ -> false
  end)?
  check(case emit(BraidHeaderFragment, payload(96)?, 65536) do
    Err(_) -> true
    _ -> false
  end)?
  check(case recover_braid_carrier(BraidHeaderFragment,
    fill(1, 31)?,
    fill(2, 32)?,
    epoch("1")?,
    []) do
    Err(_) -> true
    _ -> false
  end)?
  check(case recover_braid_carrier(BraidHeaderFragment,
    fill(1, 32)?,
    fill(2, 32)?,
    epoch("0")?,
    []) do
    Err(_) -> true
    _ -> false
  end)?
  Ok(true)
end

fn controls_and_vector_family() -> Bool!ProtocolError do
  for kind in [NoBraidFragment, BraidAckFragment] do
    let control = emit(kind, Bytes.empty(), 0)?
    check(Bytes.length(encode_braid_fragment(control)?) == 78)?
    check(case emit(kind, payload(1)?, 0) do
      Err(_) -> true
      _ -> false
    end)?
    check(case emit(kind, Bytes.empty(), 1) do
      Err(_) -> true
      _ -> false
    end)?
    check(case recover(kind, [control]) do
      Err(_) -> true
      _ -> false
    end)?
    check(case recover(BraidHeaderFragment, [control]) do
      Err(_) -> true
      _ -> false
    end)?
  end
  let input = payload(1152)?
  let words = for i in 0..18 do
    emit(if i % 2 == 0 do
        BraidVectorFragment
      else
        BraidVectorAckFragment
      end,
      input,
      i)?
  end
  check(recover(BraidVectorFragment, words)? == Some(input))?
  check(recover(BraidVectorAckFragment, words)? == Some(input))?
  # Bytes are returned without any acknowledgement authority or MAC claim.
  let altered = fill(9, 96)?
  check(recover(BraidHeaderFragment,
    [
      emit(BraidHeaderFragment, altered, 0)?,
      emit(BraidHeaderFragment, altered, 1)?
    ])? == Some(altered))?
  Ok(true)
end

test("CBF1 recovers every public carrier from repair-only words after wire parsing") do
  assert(all_carriers() == Ok(true))
end

test("CBF1 deduplicates bounded words and rejects conflicts and inconsistent surplus") do
  assert(duplicates_and_surplus() == Ok(true))
end

test("CBF1 validates scope epoch kind width and indices before carrier recovery") do
  assert(validation() == Ok(true))
end

test("CBF1 controls have no carrier and vector kinds share data without granting ACK") do
  assert(controls_and_vector_family() == Ok(true))
end
