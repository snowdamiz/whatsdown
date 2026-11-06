from Api.Binary import BinaryResult, leaf_proof_request_for
from Storage.TransparencyTree import append_tree_leaf_for
from Transparency.LeafProof import LeafQuery, LeafProof, encode_leaf_query, decode_leaf_proof
from Transparency.Merkle import InclusionProof, merkle_root_for, verify_inclusion

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Pool.execute(pool, "TRUNCATE transparency_nodes, transparency_v2_nodes", [])?
  for version in [1, 2] do
    let leaves = for index in 0..9 do
      Crypto.sha256(Bytes.from_utf8("leaf/#{version}/#{index}"))
    end
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        for index in 0..9 do
          append_tree_leaf_for(conn, version, index, List.get(leaves, index))?
        end
        Ok(nil)
      end)?
    # The tree has grown beyond the requested checkpoint. Return only that
    # exact prefix, including its original leaf hash, without signing anything.
    for size in [1, 3, 7, 9] do
      for index in 0..size do
        let response = leaf_proof_request_for(pool,
          version,
          encode_leaf_query(LeafQuery { leaf_index: index, tree_size: size })?)
        assert(response.status == 200)
        let value = decode_leaf_proof(response.body)?
        assert(value.inclusion.version == version + 1)
        assert(value.inclusion.tree_size == size && value.inclusion.leaf_index == index)
        assert(Bytes.secure_equals(value.leaf_hash, List.get(leaves, index)))
        assert(verify_inclusion(value.leaf_hash,
          value.inclusion,
          merkle_root_for(version, List.take(leaves, size))?)?)
      end
    end
    for size in [10, 4294967295] do
      assert(leaf_proof_request_for(pool,
        version,
        encode_leaf_query(LeafQuery { leaf_index: 0, tree_size: size })?).status == 404)
    end
    for invalid in [
      Bytes.empty(),
      Bytes.from_hex("014b54510000000700000007")?,
      Bytes.from_hex("014b5451000000000000000000")?
    ] do
      assert(leaf_proof_request_for(pool, version, invalid).status == 400)
    end
  end
  assert(leaf_proof_request_for(pool,
    3,
    encode_leaf_query(LeafQuery { leaf_index: 0, tree_size: 1 })?).status == 400)
  Pool.close(pool)
  Ok(true)
end

test("historical leaf responses use the selected log and exact prefix after growth and reject unavailable sizes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
