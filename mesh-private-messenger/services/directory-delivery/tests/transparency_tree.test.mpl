from Storage.TransparencyTree import (
  append_tree_leaf,
  tree_consistency,
  tree_inclusion,
  tree_root,
  tree_size
)
from Transparency.Merkle import leaf_hash, merkle_root, verify_consistency, verify_inclusion

fn reset(conn :: borrow PgConn) -> Result<(), String> do
  Pg.execute_values(conn, "DELETE FROM transparency_nodes", [])?
  Ok(nil)
end

fn append_and_check(conn :: borrow PgConn, values :: List<Bytes>) -> Bool!String do
  for index in 0..List.length(values) do
    assert(tree_size(conn)? == index)
    append_tree_leaf(conn, index, List.get(values, index))?
    assert(tree_size(conn)? == index + 1)
    let prefix = for i in 0..(index + 1) do
      List.get(values, i)
    end
    assert(Bytes.secure_equals(tree_root(conn, index + 1)?, merkle_root(prefix)?))
    for old_size in 0..(index + 2) do
      let old_values = for i in 0..old_size do
        List.get(values, i)
      end
      assert(verify_consistency(merkle_root(old_values)?,
        merkle_root(prefix)?,
        tree_consistency(conn, old_size, index + 1)?)?)
    end
    for leaf in 0..(index + 1) do
      assert(verify_inclusion(List.get(values, leaf),
        tree_inclusion(conn, leaf, index + 1)?,
        merkle_root(prefix)?)?)
    end
  end
  Ok(true)
end

fn transaction_proof(conn :: borrow PgConn) -> Bool!String do
  reset(conn)?
  let values = for index in 0..33 do
    Crypto.sha256(Bytes.from_utf8("tree/#{index}"))
  end
  assert(append_and_check(conn, values)?)
  # A stale append may neither overwrite a node nor advance the committed size.
  case append_tree_leaf(conn, 32, Crypto.sha256(Bytes.from_utf8("fork"))) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  assert(tree_size(conn)? == 33)
  assert(Bytes.secure_equals(tree_root(conn, 33)?, merkle_root(values)?))
  case tree_inclusion(conn, 33, 33) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  case tree_consistency(conn, 33, 34) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  # Historical roots and proofs must not start using a newer right subtree.
  assert(Bytes.secure_equals(tree_root(conn, 7)?,
    merkle_root(for i in 0..7 do
      List.get(values, i)
    end)?))
  Ok(true)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  let result :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      transaction_proof(conn)?
      Err("tree_test_rollback")
    end)
  Pool.close(pool)
  case result do
    Err(error) -> if error == "tree_test_rollback" do
      Ok(true)
    else
      Err(error)
    end
    Ok(_) -> Err("tree test did not roll back")
  end
end

test("incremental stored nodes prove every historical prefix and reject stale appends") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
