##! Shared durable log identity. Callers hold the append advisory lock before
##! using a writable version or changing the cutover phase in a transaction.
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint

pub fn cutover_phase(conn :: borrow PgConn) -> String!String do
  let rows = Pg.query(conn, "SELECT phase FROM transparency_log_cutover", [])?
  if List.length(rows) == 0 do
    Ok("legacy")
  else
    Ok(Map.get(List.head(rows), "phase"))
  end
end

pub fn writable_log_version(conn :: borrow PgConn) -> Int!String do
  case cutover_phase(conn)? do
    "legacy" -> Ok(1)
    "active" -> Ok(2)
    _ -> Err("transparency_migration_in_progress")
  end
end

pub fn legacy_seal(conn :: borrow PgConn) -> Option<TransparencyCheckpoint>!String do
  let rows = Pg.query_values(conn, "SELECT legacy_checkpoint FROM transparency_log_cutover", [])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    case Map.get(List.head(rows), "legacy_checkpoint") do
      Binary(value) -> Ok(Some(decode_checkpoint(value)?))
      _ -> Err("invalid legacy seal")
    end
  end
end

# These identifiers are closed allowlists, never supplied SQL from a request.
pub fn checkpoint_table(version :: Int) -> String!String do
  case version do
    1 -> Ok("transparency_checkpoints")
    2 -> Ok("transparency_v2_checkpoints")
    _ -> Err("invalid transparency log version")
  end
end

pub fn witness_table(version :: Int) -> String!String do
  case version do
    1 -> Ok("witness_signatures")
    2 -> Ok("witness_v2_signatures")
    _ -> Err("invalid transparency log version")
  end
end

pub fn anchor_table(version :: Int) -> String!String do
  case version do
    1 -> Ok("transparency_anchors")
    2 -> Ok("transparency_v2_anchors")
    _ -> Err("invalid transparency log version")
  end
end
