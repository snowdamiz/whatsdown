from Store.Large import purge_large, initialize_large
from Attachments.Protocol import (
  AttachmentManifest,
  generate_attachment_key,
  generate_attachment_id,
  seal_manifest,
  seal_bound_chunk
)
from Attachments.Layout import attachment_bucket_capacity
from Credits.Attachment import (
  CreditAttachmentGrant,
  encode_credit_attachment_grant,
  decode_credit_attachment_grant,
  credit_attachment_result
)
from Objects.Grant import ObjectControl, mint_grant, encode_grant, encode_complete
from Store.Service import initialize, grant, put_part, complete, get_part

fn bytes(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture byte allocation failed")
    Ok(value)
  end
end

fn text(row :: Map<String, DbValue>, key :: String) -> String!String do
  case Map.get(row, key) do
    Text(value) -> Ok(value)
    _ -> Err("fixture row is not text")
  end
end

fn free_boundary(url :: String, root :: String, size :: Int) -> Result<(), String> do
  let key = case generate_attachment_key() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key failed")
  end
  let id = case generate_attachment_id() do
    Ok(value) -> value
    Err(_) -> return Err("fixture id failed")
  end
  let now = U64.parse("1800000000000")?
  let expires = U64.parse("1800000600000")?
  let work = U64.parse("1800000150000")?
  let count = (size + 65535) / 65536
  let upload = bytes(17, 32)?
  let download = bytes(34, 32)?
  let manifest = case seal_manifest(key,
    AttachmentManifest {
      version: 4,
      attachment_id: id,
      chunk_size: 65536,
      chunk_count: count,
      plaintext_size: size,
      filename: Bytes.from_utf8("fixture.bin"),
      mime_type: Bytes.from_utf8("application/octet-stream"),
      expires_at: expires
    }) do
    Ok(value) -> value
    Err(_) -> return Err("fixture manifest failed")
  end
  assert(Bytes.length(manifest) == 514)
  let request = encode_grant(mint_grant(id, count + 1, expires, work, upload, download, 4)?)?
  assert(grant(url, root, request, now, U64.parse("300000")?, 4).status == 201)
  assert(put_part(url, root, id, 0, upload, manifest, now).status == 201)
  let full = bytes(53, 65536)?
  for index in 0..count do
    let length = if index == count - 1 do
      size - index * 65536
    else
      65536
    end
    let raw = if length == 65536 do
      full
    else
      bytes(53, length)?
    end
    let sealed = case seal_bound_chunk(key, manifest, index, raw) do
      Ok(value) -> value
      Err(_) -> return Err("fixture chunk failed")
    end
    assert(Bytes.length(sealed) == 65576)
    assert(put_part(url, root, id, index + 1, upload, sealed, now).status == 201)
  end
  let control = ObjectControl { object_id: id, capability: upload }
  assert(complete(url, root, encode_complete(control)?, now).status == 200)
  let expected_total = 514 + count * 65576
  assert(expected_total == if size == 1 do
      66090
    else
      16787970
    end)
  let conn = Pg.connect(url)?
  let rows = Pg.query_values(conn,
    "SELECT part_count::text,total_bytes::text,completed::text FROM objects WHERE object_id=$1",
    [Binary(id)])?
  assert(List.length(rows) == 1)
  let row = List.head(rows)
  assert(text(row, "part_count")? == Int.to_string(count + 1))
  assert(text(row, "total_bytes")? == Int.to_string(expected_total))
  assert(text(row, "completed")? == "1")
  let parts = Pg.query_values(conn,
    "SELECT part_index::text,size::text FROM object_parts WHERE object_id=$1 ORDER BY object_parts.part_index",
    [Binary(id)])?
  assert(List.length(parts) == count + 1)
  for index in 0..(count + 1) do
    let part = List.get(parts, index)
    assert(text(part, "part_index")? == Int.to_string(index))
    assert(text(part, "size")? == if index == 0 do
        "514"
      else
        "65576"
      end)
  end
  Pg.close(conn)
  let fetched_manifest = get_part(url, root, id, 0, download, now)
  assert(fetched_manifest.status == 200 && Bytes.secure_equals(fetched_manifest.body, manifest))
  assert(Bytes.length(get_part(url, root, id, count, download, now).body) == 65576)
  println("public free parts="
    <> Int.to_string(count + 1)
    <> " manifest=514 chunk=65576 actual_total="
    <> Int.to_string(expected_total))
  Secret.destroy(key)
  Ok(nil)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")
  let root = Env.get("MESSENGER_OBJECT_STORAGE_ROOT", "")
  if !String.contains(url, "/attachments_object_test?") || !String.starts_with(root, "/") do
    return Err("owned fixture database and directory required")
  end
  initialize(url, root)?
  free_boundary(url, root, 1)?
  free_boundary(url, root, 16777216)?
  # One byte more requires 258 parts and cannot acquire a free object grant.
  let id = bytes(51, 32)?
  let expires = U64.parse("1800000600000")?
  assert(Result.is_err(mint_grant(id,
    258,
    expires,
    U64.parse("1800000150000")?,
    bytes(17, 32)?,
    bytes(34, 32)?,
    4)))
  let capacity = attachment_bucket_capacity(16777217)?
  assert(capacity == 16842752)
  let paid = CreditAttachmentGrant {
    layout_version: 2,
    operation_nonce: bytes(85, 32)?,
    object_id: id,
    upload_capability: bytes(17, 32)?,
    download_capability: bytes(34, 32)?,
    size_bytes: capacity,
    manifest_size: 514,
    manifest_sha256: bytes(102, 32)?,
    expires_at_ms: expires,
    action_expires_at: U64.parse("1800000600")?
  }
  let encoded = encode_credit_attachment_grant(paid)?
  assert(Bytes.get(encoded, 0) == Ok(2))
  let decoded = decode_credit_attachment_grant(encoded)?
  assert(decoded.layout_version == 2 && decoded.size_bytes == capacity)
  assert(credit_attachment_result(decoded)?.part_count == 258)
  # The HTTP proof left one genuine signed-core entitlement after its race.
  # Expire it using only this direct fixture clock, preserving its stored CAR
  # and receipt-bound expiry bytes. No service clock is overridden.
  let conn = Pg.connect(url)?
  if Env.get("CREDIT_ATTACHMENT_LAYOUT", "2") == "1" do
    # Recreate the precise old table shape around a genuine legacy row.
    Pg.execute(conn, "ALTER TABLE large_objects DROP COLUMN layout_version", [])?
    initialize_large(url, root)?
    let old = Pg.query_values(conn,
      "SELECT layout_version::text AS version FROM large_objects",
      [])?
    assert(List.length(old) == 1 && text(List.head(old), "version")? == "1")
  end
  let rows = Pg.query_values(conn,
    "SELECT expires_at::text AS expiry,encode(receipt,'hex') AS receipt FROM large_objects",
    [])?
  assert(List.length(rows) == 1)
  let row = List.head(rows)
  let expiry = U64.parse(text(row, "expiry")?)?
  let receipt = text(row, "receipt")?
  Pg.close(conn)
  assert(purge_large(url, root, U64.parse("1")?).status == 204)
  assert(purge_large(url, root, expiry).status == 202)
  let check = Pg.connect(url)?
  let saved = Pg.query_values(check,
    "SELECT encode(receipt,'hex') AS receipt,expires_at::text AS expiry,purge_index::text AS cursor FROM large_objects",
    [])?
  assert(List.length(saved) == 1)
  assert(text(List.head(saved), "receipt")? == receipt)
  assert(text(List.head(saved), "expiry")? == U64.to_string(expiry))
  assert(text(List.head(saved), "cursor")? == "128")
  Pg.close(check)
  assert(purge_large(url, root, expiry).status == 202)
  assert(purge_large(url, root, expiry).status == 204)
  Ok(true)
end

test("actual free store accepts padded1byte and exact16MiB while1byteover needsLAG2") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
