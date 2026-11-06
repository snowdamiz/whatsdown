from Protocol.V1 import ProtocolError
from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  encode_text_archive,
  decode_text_archive
)

fn ta_check(value :: Bool) -> Unit!ProtocolError do
  if value do
    Ok(nil)
  else
    Err(InvalidPolicy)
  end
end

fn ta_hex(value :: String) -> Bytes!ProtocolError do
  case Bytes.from_hex(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn ta_repeat(value :: Int, count :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(value, count) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn ta_join(parts :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, 16777217) do
    Err(_) -> Err(OversizedInput)
    Ok(v)
  end
end

fn ta_wide(text :: String) -> U64!ProtocolError do
  case U64.parse(text) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn ta_u32(value :: Int) -> Bytes!ProtocolError do
  case Bytes.write_u32_be(ta_wide(Int.to_string(value))?) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn ta_replace(input :: Bytes, offset :: Int, value :: Bytes) -> Bytes!ProtocolError do
  let left = case Bytes.slice(input, 0, offset) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  let right = case Bytes.slice(input,
    offset + Bytes.length(value),
    Bytes.length(input) - offset - Bytes.length(value)) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  ta_join([left, value, right])
end

fn ta_record(ordinal :: Int,
  direction :: Int,
  id :: Bytes,
  text :: Bytes,
  flag :: Bool) -> BackupArchiveRecord!ProtocolError do
  Ok(BackupArchiveRecord {
    ordinal: ordinal,
    direction: direction,
    message_id: id,
    sender_account: ta_repeat(if direction == 1 do
        17
      else
        34
      end,
      32)?,
    sender_device: ta_repeat(102, 16)?,
    timestamp: ta_wide("18446744073709551615")?,
    attachment_omitted: flag,
    text: text
  })
end

fn ta_source() -> BackupTextArchive!ProtocolError do
  Ok(BackupTextArchive {
    backup_id: ta_repeat(51, 32)?,
    owner_account: ta_repeat(17, 32)?,
    owner_authorization_key: ta_repeat(68, 32)?,
    service_realm: ta_repeat(85, 32)?,
    created_at: ta_wide("18446744073709551615")?,
    candidate_count: 7,
    omitted_timed: 1,
    omitted_unknown: 1,
    omitted_nontext: 1,
    omitted_empty: 1,
    attachment_messages: 2,
    scopes: [
      BackupArchiveScope {
        kind: 1,
        id: ta_repeat(1, 16)?,
        peer: ta_repeat(34, 32)?,
        name: "Peer",
        entries: [ta_record(7, 2, ta_repeat(119, 16)?, Bytes.from_utf8("hello\n"), false)?]
      },
      BackupArchiveScope {
        kind: 2,
        id: ta_repeat(2, 32)?,
        peer: Bytes.empty(),
        name: "Group",
        entries: [
          ta_record(0, 1, Bytes.empty(), Bytes.empty(), true)?,
          ta_record(255, 2, ta_repeat(136, 32)?, Bytes.from_utf8("é"), false)?
        ]
      }
    ]
  })
end

fn ta_literal() -> Bytes!ProtocolError do
  ta_hex("014d54413333333333333333333333333333333333333333333333333333333333333333111111111111111111111111111111111111111111111111111111111111111144444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555ffffffffffffffff000200000003000000070000000100000001000000010000000100000002000000a1010000001001010101010101010101010101010101000000202222222222222222222222222222222222222222222222222222222222222222000000045065657200010000005a0007020000001077777777777777777777777777777777222222222222222222222222222222222222222222222222222222222222222266666666666666666666666666666666ffffffffffffffff000000000668656c6c6f0a000000e602000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000020000004400000100000000111111111111111111111111111111111111111111111111111111111111111166666666666666666666666666666666ffffffffffffffff01000000000000006600ff02000000208888888888888888888888888888888888888888888888888888888888888888222222222222222222222222222222222222222222222222222222222222222266666666666666666666666666666666ffffffffffffffff0000000002c3a9")
end

fn ta_refused(input :: Bytes) -> Bool do
  case decode_text_archive(input) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn ta_bad(value :: BackupTextArchive) -> Bool do
  case encode_text_archive(value) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn ta_literal_proof() -> Bool!ProtocolError do
  let literal = ta_literal()?
  let encoded = encode_text_archive(ta_source()?)?
  let restored = decode_text_archive(literal)?
  ta_check(Bytes.secure_equals(encoded, literal))?
  ta_check(Bytes.secure_equals(encode_text_archive(restored)?, literal))?
  let independent = ta_hex("014d5441101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff000000000548656c6c6f000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b71111111111111111111111111111111111111111111111111111111111111111454545454545454545454545454545450000000000000000000000000867726f757020cf800000007d0200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c656761637900010000004400ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080100000000")?
  let root_value = decode_text_archive(independent)?
  ta_check(List.length(root_value.scopes) == 3)?
  ta_check(Bytes.secure_equals(encode_text_archive(root_value)?, independent))?
  ta_check(U64.compare(restored.created_at, ta_wide("18446744073709551615")?) == 0)?
  ta_check(List.length(restored.scopes) == 2
    && List.length(List.get(restored.scopes, 1).entries) == 2)?
  Ok(true)
end

fn ta_shapes() -> Bool!ProtocolError do
  let source = ta_source()?
  let _ = encode_text_archive(source)?
  let direct = List.head(source.scopes)
  let entry = List.head(direct.entries)
  let direct_max = %{source |
    scopes: [%{direct | entries: [%{entry | text: ta_repeat(97, 32768)?}]}],
    candidate_count: 5
  }
  let direct_wire = encode_text_archive(direct_max)?
  ta_check(Bytes.length(direct_wire) == 33097)?
  let _ = decode_text_archive(direct_wire)?
  let variants = [
    %{entry | ordinal: -1},
    %{entry | ordinal: 256},
    %{entry | direction: 0},
    %{entry | message_id: Bytes.empty()},
    %{entry | sender_account: source.owner_account},
    %{entry | sender_device: Bytes.empty()},
    %{entry | text: ta_hex("ff")?},
    %{entry | text: Bytes.empty()},
    %{entry | text: ta_repeat(65, 32769)?}
  ]
  ta_check(List.all(variants,
    fn(v) -> ta_bad(%{source | scopes: [%{direct | entries: [v]}], candidate_count: 5}) end))?
  let controls = ["\n", "\0", "", ""]
  ta_check(List.all(controls,
    fn(name) -> ta_bad(%{source | scopes: [%{direct | name: name}], candidate_count: 5}) end))?
  ta_check(ta_bad(%{source |
    scopes: [
      %{direct |
        name: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      }
    ],
    candidate_count: 5
  }))?
  ta_check(ta_bad(%{source | backup_id: Bytes.empty()}))?
  ta_check(ta_bad(%{source | owner_authorization_key: Bytes.empty()}))?
  ta_check(ta_bad(%{source | service_realm: Bytes.empty()}))?
  ta_check(ta_bad(%{source | candidate_count: 8}))?
  ta_check(ta_bad(%{source | omitted_timed: -1}))?
  ta_check(ta_bad(%{source | attachment_messages: 0}))?
  let group = List.get(source.scopes, 1)
  ta_check(ta_bad(%{source |
    scopes: [%{group | entries: [%{List.get(group.entries, 1) | text: ta_repeat(65, 65347)?}]}],
    candidate_count: 5
  }))?
  Ok(true)
end

fn ta_order() -> Bool!ProtocolError do
  let source = ta_source()?
  let _ = encode_text_archive(source)?
  let direct = List.head(source.scopes)
  let group = List.get(source.scopes, 1)
  ta_check(ta_bad(%{source | scopes: [group, direct]}))?
  ta_check(ta_bad(%{source | scopes: [direct, direct], candidate_count: 6}))?
  ta_check(ta_bad(%{source |
    scopes: [direct, %{direct | id: ta_repeat(3, 16)?}],
    candidate_count: 6
  }))?
  let entry = List.head(direct.entries)
  ta_check(ta_bad(%{source |
    scopes: [%{direct | entries: [entry, %{entry | ordinal: 8}]}],
    candidate_count: 6
  }))?
  ta_check(ta_bad(%{source |
    scopes: [%{group | entries: List.reverse(group.entries)}],
    candidate_count: 6
  }))?
  let valid_name = "éééééééééééééééééééééééééééééééééééééééééééééééé"
  let valid = %{source | scopes: [%{group | name: valid_name}], candidate_count: 6}
  let _ = decode_text_archive(encode_text_archive(valid)?)?
  Ok(true)
end

fn ta_hostile() -> Bool!ProtocolError do
  let _ = ta_literal_proof()?
  let literal = ta_literal()?
  let variants = [
    ta_replace(literal, 0, ta_hex("02")?)?,
    ta_replace(literal, 140, ta_hex("0021")?)?,
    ta_replace(literal, 142, ta_hex("ffffffff")?)?,
    ta_replace(literal, 146, ta_hex("ffffffff")?)?,
    ta_replace(literal, 150, ta_hex("ffffffff")?)?,
    ta_replace(literal, 170, ta_hex("ffffffff")?)?,
    ta_replace(literal, 174, ta_hex("03")?)?,
    ta_replace(literal, 175, ta_hex("ffffffff")?)?,
    ta_replace(literal, 239, ta_hex("0101")?)?,
    ta_replace(literal, 324, ta_hex("02")?)?,
    ta_replace(literal, 329, ta_hex("ff")?)?,
    ta_join([literal, ta_hex("00")?])?
  ]
  ta_check(List.all(variants, ta_refused))?
  # Refuse the actual per-scope budget before a hostile record vector is read.
  let over_budget = ta_replace(ta_replace(literal, 142, ta_u32(2)?)?, 391, ta_hex("ffffffff")?)?
  case decode_text_archive(over_budget) do
    Err(OversizedInput) -> nil
    _ -> return Err(InvalidPolicy)
  end
  case decode_text_archive(ta_replace(literal, 142, ta_u32(1)?)?) do
    Err(OversizedInput) -> nil
    _ -> return Err(InvalidPolicy)
  end
  ta_check(ta_refused(ta_repeat(0, 16777217)?))?
  for n in 0..Bytes.length(literal) do
    let shortened = case Bytes.slice(literal, 0, n) do
      Err(_) -> return Err(MalformedEncoding)
      Ok(v) -> v
    end
    ta_check(ta_refused(shortened))?
  end
  Ok(true)
end

fn ta_many(scopes :: Int, per_scope :: Int) -> BackupTextArchive!ProtocolError do
  let source = ta_source()?
  let entries = for i in 0..per_scope do
    ta_record(i, 2, Bytes.empty(), Bytes.empty(), true)?
  end
  let groups = for i in 0..scopes do
    BackupArchiveScope {
      kind: 2,
      id: ta_join([ta_repeat(0, 28)?, ta_u32(i)?])?,
      peer: Bytes.empty(),
      name: "",
      entries: entries
    }
  end
  Ok(%{source |
    candidate_count: scopes * per_scope,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: scopes * per_scope,
    scopes: groups
  })
end

fn ta_counts() -> Bool!ProtocolError do
  let _ = ta_literal_proof()?
  let _ = decode_text_archive(encode_text_archive(ta_many(32, 1)?)?)?
  let _ = decode_text_archive(encode_text_archive(ta_many(16, 256)?)?)?
  ta_check(ta_bad(ta_many(33, 1)?))?
  ta_check(ta_bad(ta_many(17, 256)?))?
  case encode_text_archive(ta_many(1, 257)?) do
    Err(OversizedInput) -> nil
    _ -> return Err(InvalidPolicy)
  end
  Ok(true)
end

fn ta_maximum() -> Bool!ProtocolError do
  let source = ta_source()?
  let page = ta_repeat(97, 65346)?
  let entries = for i in 0..256 do
    ta_record(i, 2, ta_join([ta_u32(i)?, ta_repeat(153, 28)?])?, page, false)?
  end
  let group = List.get(source.scopes, 1)
  let last = ta_record(0,
    2,
    ta_join([ta_u32(256)?, ta_repeat(153, 28)?])?,
    ta_repeat(97, 21640)?,
    false)?
  let maximum = %{source |
    candidate_count: 257,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    scopes: [
      %{group | name: "", entries: entries},
      %{group | id: ta_repeat(3, 32)?, name: "", entries: [last]}
    ]
  }
  let encoded = encode_text_archive(maximum)?
  ta_check(Bytes.length(encoded) == 16777216)?
  ta_check(Bytes.secure_equals(Crypto.sha256(encoded),
    ta_hex("7c831a4b09ffd8330f695bf38179d0ecd8158301960ba20208d2a21d95230763")?))?
  ta_check(Bytes.secure_equals(encode_text_archive(decode_text_archive(encoded)?)?, encoded))?
  let plus = %{maximum |
    scopes: [
      %{group | name: "", entries: entries},
      %{group |
        id: ta_repeat(3, 32)?,
        name: "",
        entries: [%{last | text: ta_repeat(97, 21640 + 1)?}]
      }
    ]
  }
  case encode_text_archive(plus) do
    Err(OversizedInput) -> nil
    _ -> return Err(InvalidPolicy)
  end
  Ok(true)
end

test("D4 text archive matches independent canonical direct group and legacy literals") do
  assert(case ta_literal_proof() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 text archive validates identifiers direction UTF8 names text and omission counts") do
  assert(case ta_shapes() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 text archive refuses scope aliases duplicate messages and noncanonical order") do
  assert(case ta_order() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 text archive rejects hostile lengths counts truncations and trailing bytes") do
  assert(case ta_hostile() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 text archive enforces exact scope entry and total record counts") do
  assert(case ta_counts() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 text archive accepts exact16MiB independent digest and rejects one extra byte") do
  assert(case ta_maximum() do
    Ok(true) -> true
    _ -> false
  end)
end
