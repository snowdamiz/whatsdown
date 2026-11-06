from Api.Binary import BinaryResult, checkpoint_request
from Storage.TransparencyTree import append_tree_leaf
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  sign_checkpoint,
  verify_checkpoint
)
from Transparency.Wire import decode_checkpoint

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, witness_signatures, transparency_checkpoints, transparency_nodes",
    [])?
  assert(checkpoint_request(pool).status == 404)
  let material = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Ok(value) -> value
    Err(_) -> return Err("invalid test signer")
  end
  let signer = case Crypto.signing_from_secret(material) do
    Ok(value) -> value
    Err(_) -> return Err("invalid test signer")
  end
  let leaf = Crypto.sha256(Bytes.from_utf8("polling"))
  Repo.transaction(pool, fn(conn :: borrow PgConn) do append_tree_leaf(conn, 0, leaf) end)?
  let prior = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    [leaf],
    Crypto.sha256(Bytes.empty()),
    U64.parse("1000")?)?
  Pool.execute_values(pool,
    "INSERT INTO transparency_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES (1, 1, $1, $2, 1000, $3, $4)",
    [
      Binary(prior.tree_root),
      Binary(prior.previous_checkpoint_hash),
      Binary(prior.service_public_key),
      Binary(prior.signature)
    ])?
  let response = checkpoint_request(pool)
  assert(response.status == 200)
  let current = decode_checkpoint(response.body)?
  assert(U64.to_int(current.sequence)? == 2)
  assert(Bytes.secure_equals(current.previous_checkpoint_hash, checkpoint_hash(prior)?))
  assert(Bytes.secure_equals(current.tree_root, prior.tree_root))
  assert(verify_checkpoint(current, signer.public_key)?)
  assert(Bytes.secure_equals(checkpoint_request(pool).body, response.body))
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, witness_signatures, transparency_checkpoints, transparency_nodes",
    [])?
  Pool.close(pool)
  Ok(true)
end

test("pull witness polling refreshes an idle log without waiting for a user lookup") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
