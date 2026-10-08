from Transparency.Tree import tlog_list_oracle

## An oracle holding only the wanted nodes of a tree over `leaves`.

pub fn dtree_list_oracle_subset(tree :: Int,
  leaves :: List<Bytes>,
  wanted :: List<DtreeNode>) -> Fun(Int, Int) -> Bytes!String do
  let full = tlog_list_oracle(tree, leaves)
  let pairs = List.filter(List.map(wanted,
      fn node -> (node_key(node.level, node.index), full(node.level, node.index)) end),
    fn pair -> case pair do
      (_, Ok(_)) -> true
      _ -> false
    end end)
  let found = for (key, hash) in pairs do
    case hash do
      Ok(value) -> (key, value)
      Err(_) -> (key, Bytes.empty())
    end
  end
  dtree_oracle(Map.from_list(found))
end
