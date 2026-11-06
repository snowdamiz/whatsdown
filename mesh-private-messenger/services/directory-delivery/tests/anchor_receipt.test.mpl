from Api.Anchors import anchor_receipt_request_for, record_anchor_receipt_request
from Api.Binary import BinaryResult
from Api.Router import build_router
from Runtime.Registry import start_registry
from Storage.TransparencyRetention import prune_on_connection
from Transparency.AnchorReceipt import AnchorReceipt, encode_anchor_receipt, anchor_receipt_json
from Transparency.Merkle import TransparencyCheckpoint, sign_tree_checkpoint_for, checkpoint_hash

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

actor receipt_server() do
  build_router()
    |> HTTP.serve(19096)
end

fn http_proof(receipt :: AnchorReceipt) -> Result<(), String> do
  let url = "http://127.0.0.1:19096/v"
    <> Int.to_string(receipt.log_version)
    <> "/transparency/anchor/7"
  let response = Http.build(:get, url)
    |> Http.max_response_bytes(1024)
    |> Http.timeout(3000)
    |> Http.send()?
  assert(response.status == 200)
  assert(Map.get(response.headers, "cache-control") == "no-store")
  assert(Map.get(response.headers, "content-type") == "application/json")
  assert(Bytes.secure_equals(response.body_bytes, Bytes.from_utf8(anchor_receipt_json(receipt)?)))
  let write_url = "http://127.0.0.1:19096/internal/v1/transparency/anchors"
  for bearer in ["", "Bearer wrong"] do
    let refused = Http.build(:post, write_url)
      |> Http.header("Authorization", bearer)
      |> Http.body_bytes(encode_anchor_receipt(receipt)?)
      |> Http.timeout(3000)
      |> Http.send()?
    assert(refused.status == 401)
  end
  let secret = Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")
  let retried = Http.build(:post, write_url)
    |> Http.header("Authorization", "Bearer " <> secret)
    |> Http.body_bytes(encode_anchor_receipt(receipt)?)
    |> Http.timeout(3000)
    |> Http.send()?
  assert(retried.status == if String.length(secret) >= 32 && String.length(secret) <= 256 do
      200
    else
      401
    end)
  let public_write = Http.build(:post, url)
    |> Http.body_bytes(encode_anchor_receipt(receipt)?)
    |> Http.timeout(3000)
    |> Http.send()?
  assert(public_write.status == 404)
  Ok(nil)
end

fn insert(pool :: PoolHandle, value :: TransparencyCheckpoint) -> Result<(), String> do
  let table = if value.version == 1 do
    "transparency_checkpoints"
  else
    "transparency_v2_checkpoints"
  end
  Pool.execute_values(pool,
    "INSERT INTO "
      <> table
      <> " (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature, created_at) VALUES ($1::bigint, $2::bigint, $3, $4, $5::bigint, $6, $7, now() - interval '40 days')",
    [
      Text(U64.to_string(value.sequence)),
      Text(U64.to_string(value.tree_size)),
      Binary(value.tree_root),
      Binary(value.previous_checkpoint_hash),
      Text(U64.to_string(value.timestamp)),
      Binary(value.service_public_key),
      Binary(value.signature)
    ])?
  Ok(nil)
end

fn check_version(pool :: PoolHandle, version :: Int) -> Result<(), String> do
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let root = Crypto.sha256(Bytes.from_utf8("anchor tree"))
  let checkpoint = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(7)?,
    wide(3)?,
    root,
    root,
    wide(1000)?)?
  insert(pool, checkpoint)?
  insert(pool,
    sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(8)?,
      wide(3)?,
      root,
      checkpoint_hash(checkpoint)?,
      wide(2000)?)?)?
  insert(pool,
    sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(9)?,
      wide(3)?,
      root,
      root,
      wide(3000)?)?)?
  let receipt = AnchorReceipt {
    log_version: version,
    sequence: wide(7)?,
    tree_size: wide(3)?,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    ring_index: 4095,
    transaction_signature: Bytes.concat(root, root)?,
    slot: U64.parse("9007199254740993")?
  }
  assert(anchor_receipt_request_for(pool, version, "7").status == 404)
  for invalid in [%{receipt | tree_size: wide(4)?}, %{receipt | checkpoint_hash: root}] do
    assert(record_anchor_receipt_request(pool, encode_anchor_receipt(invalid)?).status == 409)
  end
  assert(record_anchor_receipt_request(pool,
    encode_anchor_receipt(%{receipt | sequence: wide(6)?})?).status == 404)
  let frame = encode_anchor_receipt(receipt)?
  let attempts = Job.map([0, 1, 2, 3, 4, 5, 6, 7],
    fn(_index) do record_anchor_receipt_request(pool, frame).status end)
  let statuses = for attempt in attempts do
    attempt?
  end
  assert(List.length(List.filter(statuses, fn(status) do status == 201 end)) == 1)
  assert(List.length(List.filter(statuses, fn(status) do status == 200 end)) == 7)
  assert(record_anchor_receipt_request(pool, encode_anchor_receipt(receipt)?).status == 200)
  # A retry may have submitted a second idempotent chain transaction. Keep the
  # first receipt's signature and timestamp; the anchor's coordinates must agree.
  let retry = %{receipt | transaction_signature: Bytes.concat(checkpoint.service_public_key, root)?}
  assert(record_anchor_receipt_request(pool, encode_anchor_receipt(retry)?).status == 200)
  for conflict in [
    %{receipt | ring_index: 0},
    %{receipt | slot: wide(4)?},
    %{receipt |
      log_version: if version == 1 do
        2
      else
        1
      end
    }
  ] do
    let result = record_anchor_receipt_request(pool, encode_anchor_receipt(conflict)?)
    assert(result.status == if conflict.log_version != version && version == 1 do
        404
      else
        409
      end)
  end
  assert(record_anchor_receipt_request(pool,
    encode_anchor_receipt(%{receipt | slot: U64.parse("9223372036854775808")?})?).status == 400)
  let response = anchor_receipt_request_for(pool, version, "7")
  assert(response.status == 200)
  assert(Bytes.secure_equals(response.body, Bytes.from_utf8(anchor_receipt_json(receipt)?)))
  let table = if version == 1 do
    "transparency_anchors"
  else
    "transparency_v2_anchors"
  end
  let count = Pool.query(pool, "SELECT count(*)::text AS count FROM " <> table, [])?
  assert(Map.get(List.head(count), "count") == "1")
  http_proof(receipt)?
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    4,
    5000)?
  start_registry(pool)
  let _server = spawn(receipt_server)
  Timer.sleep(100)
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints, transparency_maintenance",
    [])?
  for version in [1, 2] do
    check_version(pool, version)?
    for missing in ["1", "6", "8", "18446744073709551615"] do
      assert(anchor_receipt_request_for(pool, version, missing).status == 404)
    end
    for malformed in ["", "0", "07", "-1", "+7", "7 ", "18446744073709551616"] do
      assert(anchor_receipt_request_for(pool, version, malformed).status == 400)
    end
  end
  assert(anchor_receipt_request_for(pool, 3, "7").status == 400)
  assert(record_anchor_receipt_request(pool, Bytes.empty()).status == 400)
  let pruned = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prune_on_connection(conn, false, 100, 100) end)?
  assert(pruned.checkpoints == 2)
  for table in ["transparency_checkpoints", "transparency_v2_checkpoints"] do
    let rows = Pool.query(pool,
      "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS sequences FROM " <> table,
      [])?
    assert(Map.get(List.head(rows), "sequences") == "7,9")
  end
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints, transparency_maintenance",
    [])?
  Process.request_shutdown()
  Timer.sleep(50)
  Pool.close(pool)
  Ok(true)
end

test("anchor receipts are version-bound, immutable, retry-safe and protect the exact checkpoint from retention") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
