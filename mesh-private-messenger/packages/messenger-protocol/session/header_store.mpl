##! Canonical bounded header-key slot directory; no private key bytes leave opaque resources.
from Session.State import RatchetState, RatchetError
from Session.HeaderWire import he_join, he_slice, he_read_u32, he_u32

pub fn header_slot_names(index :: Bytes,
  remote :: Bytes,
  generation :: Int) -> List<Bytes>!RatchetError do
  if Bytes.length(index) > 2560 || Bytes.length(index) % 40 != 0 || generation < 0 do
    return Err(InvalidMessage)
  end
  let fixed = if generation == 0 do
    [Bytes.from_utf8("sending"), Bytes.from_utf8("next-sending"), Bytes.from_utf8("next-receiving")]
  else
    [
      Bytes.from_utf8("sending"),
      Bytes.from_utf8("receiving"),
      Bytes.from_utf8("next-sending"),
      Bytes.from_utf8("next-receiving")
    ]
  end
  old_slots(index, remote, generation, 0, fixed, List.new(), List.new())
end

fn old_slots(index :: Bytes,
  remote :: Bytes,
  generation :: Int,
  offset :: Int,
  names :: List<Bytes>,
  owners :: List<Bytes>,
  generations :: List<Int>) -> List<Bytes>!RatchetError do
  if offset >= Bytes.length(index) do
    return Ok(names)
  end
  let owner = he_slice(index, offset, 32)?
  let kept = he_read_u32(index, offset + 36)?
  if kept > generation || kept <= generation - 5 do
    return Err(InvalidMessage)
  end
  let current = Bytes.secure_equals(owner, remote)
  if (current && kept != generation) || (!current && kept == generation) do
    return Err(InvalidMessage)
  end
  let position = owner_position(owners, owner, 0)
  let known = case position do
    None -> false
    Some(i) -> do
      if List.get(generations, i) != kept do
        return Err(InvalidMessage)
      end
      true
    end
  end
  if known || current do
    return old_slots(index, remote, generation, offset + 40, names, owners, generations)
  end
  if List.contains(generations, kept) do
    return Err(InvalidMessage)
  end
  let names = List.append(names, he_join([Bytes.from_utf8("old/"), owner])?)
  if List.length(names) > 9 do
    return Err(InvalidMessage)
  end
  old_slots(index,
    remote,
    generation,
    offset + 40,
    names,
    List.append(owners, owner),
    List.append(generations, kept))
end

pub fn checked_header_names(state :: borrow RatchetState) -> List<Bytes>!RatchetError do
  let names = header_slot_names(state.skipped_index,
    state.remote_ratchet_public.bytes,
    state.receive_generation)?
  for name in names do
    if !SecretMap.contains(state.header_keys, name) do
      return Err(InvalidMessage)
    end
  end
  Ok(names)
end

fn name_parts(names :: List<Bytes>,
  index :: Int,
  parts :: List<Bytes>) -> List<Bytes>!RatchetError do
  if index >= List.length(names) do
    return Ok(parts)
  end
  let name = List.get(names, index)
  name_parts(names, index + 1, List.append(List.append(parts, he_u32(Bytes.length(name))?), name))
end

pub fn encode_header_names(names :: List<Bytes>) -> Bytes!RatchetError do
  if List.length(names) < 3 || List.length(names) > 9 do
    return Err(InvalidMessage)
  end
  he_join(name_parts(names, 0, [he_u32(List.length(names))?])?)
end

fn owner_position(owners :: List<Bytes>, owner :: Bytes, index :: Int) -> Option<Int> do
  if index >= List.length(owners) do
    None
  else if Bytes.secure_equals(List.get(owners, index), owner) do
    Some(index)
  else
    owner_position(owners, owner, index + 1)
  end
end
