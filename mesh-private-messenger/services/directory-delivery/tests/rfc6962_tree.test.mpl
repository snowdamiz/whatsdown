from Storage.TransparencyTree import (
  append_tree_leaf_for,
  tree_root_for,
  tree_size_for,
  tree_inclusion_for,
  tree_consistency_for
)
from Transparency.Merkle import leaf_hash_for, merkle_root_for, verify_inclusion, verify_consistency

fn transaction_proof(conn :: borrow PgConn) -> Bool!String do
  Pg.execute_values(conn, "DELETE FROM transparency_nodes", [])?
  Pg.execute_values(conn, "DELETE FROM transparency_v2_nodes", [])?
  let legacy = [
    leaf_hash_for(1, Bytes.from_utf8("legacy-a"))?,
    leaf_hash_for(1, Bytes.from_utf8("legacy-b"))?
  ]
  for index in 0..2 do
    append_tree_leaf_for(conn, 1, index, List.get(legacy, index))?
  end
  let legacy_root = tree_root_for(conn, 1, 2)?
  let values = for index in 0..33 do
    leaf_hash_for(2, Bytes.from_utf8("RFC-tree/#{index}"))?
  end
  assert(tree_size_for(conn, 2)? == 0)
  assert(Bytes.secure_equals(tree_root_for(conn, 2, 0)?, merkle_root_for(2, List.new())?))
  for index in 0..33 do
    append_tree_leaf_for(conn, 2, index, List.get(values, index))?
    let prefix = for i in 0..(index + 1) do
      List.get(values, i)
    end
    let root = merkle_root_for(2, prefix)?
    assert(Bytes.secure_equals(tree_root_for(conn, 2, index + 1)?, root))
    for old in 0..(index + 2) do
      let previous = for i in 0..old do
        List.get(values, i)
      end
      let proof = tree_consistency_for(conn, 2, old, index + 1)?
      assert(proof.version == 3)
      assert(verify_consistency(merkle_root_for(2, previous)?, root, proof)?)
    end
    for leaf in 0..(index + 1) do
      let proof = tree_inclusion_for(conn, 2, leaf, index + 1)?
      assert(proof.version == 3)
      assert(verify_inclusion(List.get(values, leaf), proof, root)?)
    end
    assert(tree_size_for(conn, 1)? == 2)
    assert(Bytes.secure_equals(tree_root_for(conn, 1, 2)?, legacy_root))
  end
  let historical = for i in 0..7 do
    List.get(values, i)
  end
  assert(Bytes.secure_equals(tree_root_for(conn, 2, 7)?, merkle_root_for(2, historical)?))
  case append_tree_leaf_for(conn, 2, 32, List.head(values)) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case tree_size_for(conn, 3) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(tree_size_for(conn, 2)? == 33)
  assert(Bytes.secure_equals(tree_root_for(conn, 1, 2)?, merkle_root_for(1, legacy)?))
  Ok(true)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  let result :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      transaction_proof(conn)?
      Err("rfc_tree_test_rollback")
    end)
  Pool.close(pool)
  case result do
    Err(error) -> if error == "rfc_tree_test_rollback" do
      Ok(true)
    else
      Err(error)
    end
    Ok(_) -> Err("tree test did not roll back")
  end
end

test("RFC 6962 stored nodes preserve legacy history and prove every new prefix") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
