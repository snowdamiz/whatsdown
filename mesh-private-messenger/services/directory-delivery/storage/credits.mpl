##! Credits in the core (protocol/credits-v1.md): issuer keys as log leaves,
##! the spent set, and holds.
##!
##! - A token counts when its key's `issuer-key-v1` leaf is in the log, the key
##!   is unrevoked, of the purpose this deployment redeems, and inside its
##!   two-epoch window, and the token verifies under it.
##! - A redemption inserts every nullifier and one hold in one transaction; one
##!   nullifier already spent refuses the whole frame, and any database failure
##!   refuses it too (fail closed).
##! - A hold is taken once, by the action it names, inside that action's own
##!   transaction. Nothing here stores anything the issuer knows.

from Credits.CreditCrypto import credits_verify_token
from Credits.IssuerKey import (
  IssuerKey,
  IssuerKeyRevocation,
  credits_decode_issuer_key,
  credits_decode_revocation,
  credits_encode_issuer_keys,
  credits_epoch_length,
  credits_issuer_key,
  credits_leaf_kind,
  credits_purpose_code,
  credits_purpose_name
)
from Credits.CreditToken import credits_decode_token, credits_nullifier
from Credits.CreditFrames import CreditFrame, CreditRedemption
from Storage.Transparency import (
  create_configured_checkpoint,
  transparency_current_checkpoint_on_connection
)
from Storage.TransparencyTree import (
  dtree_append_on_connection,
  dtree_consistency_on_connection,
  dtree_inclusion_on_connection,
  dtree_size_on_connection,
  dtree_view_on_connection
)
from Storage.TransparencyWitnesses import transparency_attestations_on_connection
from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyEvidenceV2,
  transparency_encode_evidence_v2
)
from Transparency.Merkle import TransparencyCheckpoint, leaf_hash

pub type RedeemOutcome do
  Redeemed(redemption :: CreditRedemption)
  RedeemRefused
  RedeemSpent
  RedeemClosed
end

pub type IssuerLeafWrite do
  IssuerLeafStored
  IssuerLeafDuplicate
  IssuerLeafConflict
  IssuerLeafInvalid
end

struct StoredKey do
  key :: IssuerKey
  token_key_id :: Bytes
  entry_sequence :: Int
  revoked :: Bool
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid credit row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid credit row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid credit integer")
    Some(output) -> Ok(output)
  end
end

## MORSE_CREDITS_MODE: off (the default), test or live.

pub fn credits_mode() -> String!String do
  let mode = Env.get("MORSE_CREDITS_MODE", "off")
  if mode == "off" || mode == "test" || mode == "live" do
    Ok(mode)
  else
    Err("MORSE_CREDITS_MODE must be off, test or live")
  end
end

## Records the mode the core started with. Leaving test or live for off keeps
## that purpose redeemable for 7 days from the change.

pub fn credits_record_mode(pool :: PoolHandle, mode :: String) -> Result<(), String> do
  let purpose = if mode == "off" do
    ""
  else
    mode
  end
  Pool.execute_values(pool,
    "INSERT INTO credit_mode (mode, purpose) VALUES ($1, NULLIF($2, '')) ON CONFLICT (singleton) DO UPDATE SET mode = EXCLUDED.mode, purpose = COALESCE(EXCLUDED.purpose, credit_mode.purpose), changed_at = CASE WHEN credit_mode.mode = EXCLUDED.mode THEN credit_mode.changed_at ELSE now() END",
    [Text(mode), Text(purpose)])?
  Ok(nil)
end

fn purpose_on_connection(conn :: borrow PgConn, mode :: String) -> Option<String>!String do
  if mode == "test" || mode == "live" do
    Ok(Some(mode))
  else
    let rows = Pg.query_values(conn,
      "SELECT purpose FROM credit_mode WHERE mode = 'off' AND purpose IS NOT NULL AND changed_at > now() - interval '7 days'",
      [])?
    case rows do
      [row] -> Ok(Some(text(Map.get(row, "purpose"))?))
      _ -> Ok(None)
    end
  end
end

fn stored_key(row :: Map<String, DbValue>) -> StoredKey!String do
  let key = credits_issuer_key(credits_purpose_code(text(Map.get(row, "purpose"))?)?,
    text(Map.get(row, "issuer_name"))?,
    integer(Map.get(row, "epoch"))?,
    binary(Map.get(row, "spki"))?)?
  Ok(StoredKey {
    key: key,
    token_key_id: binary(Map.get(row, "token_key_id"))?,
    entry_sequence: integer(Map.get(row, "entry_sequence"))?,
    revoked: text(Map.get(row, "revoked"))? == "true"
  })
end

fn key_columns() -> String do
  "SELECT token_key_id, purpose, issuer_name, epoch::text AS epoch, spki, entry_sequence::text AS entry_sequence, (revocation_sequence IS NOT NULL)::text AS revoked FROM credit_issuer_keys"
end

# Unrevoked keys of a purpose whose two-epoch window holds now.

fn accepted_keys_on_connection(conn :: borrow PgConn,
  purpose :: String,
  now_ms :: Int) -> List<StoredKey>!String do
  let rows = Pg.query_values(conn,
    key_columns()
      <> " WHERE revocation_sequence IS NULL AND purpose = $1 AND epoch * $3::bigint <= $2::bigint AND $2::bigint < (epoch + 2) * $3::bigint ORDER BY epoch DESC",
    [Text(purpose), Text(Int.to_string(now_ms)), Text(Int.to_string(credits_epoch_length()))])?
  let keys = for row in rows do
    stored_key(row)?
  end
  Ok(keys)
end

## How many keys of `purpose` a token could be redeemed under now.

pub fn credits_accepted_key_count(pool :: PoolHandle,
  purpose :: String,
  now_ms :: Int) -> Int!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> accepted_count_on_connection(conn, purpose, now_ms) end)
end

fn accepted_count_on_connection(conn :: borrow PgConn,
  purpose :: String,
  now_ms :: Int) -> Int!String do
  Ok(List.length(accepted_keys_on_connection(conn, purpose, now_ms)?))
end

# The epoch of the accepted key a token verifies under, or None.

fn token_epoch(keys :: List<StoredKey>, token :: Bytes) -> Option<Int>!String do
  let value = credits_decode_token(token)?
  case List.find(keys,
    fn stored -> Bytes.secure_equals(stored.token_key_id, value.token_key_id) end) do
    None -> Ok(None)
    Some(stored) -> if credits_verify_token(stored.key, token)? do
      Ok(Some(stored.key.epoch))
    else
      Ok(None)
    end
  end
end

fn joined(values :: List<String>) -> String do
  String.join(values, ",")
end

fn spend_on_connection(conn :: borrow PgConn,
  keys :: List<StoredKey>,
  action :: Int,
  frame :: CreditFrame) -> RedeemOutcome!String do
  let epochs = for token in frame.tokens do
    token_epoch(keys, token)?
  end
  if List.any(epochs, fn epoch -> epoch == None end) do
    return Ok(RedeemRefused)
  end
  let nullifiers = for token in frame.tokens do
    Bytes.to_hex(credits_nullifier(token)?)
  end
  let spent = Pg.execute_values(conn,
    "INSERT INTO credit_spent (nullifier, key_epoch) SELECT decode(spent.nullifier, 'hex'), spent.key_epoch FROM unnest(string_to_array($1, ','), string_to_array($2, ',')::bigint[]) AS spent (nullifier, key_epoch) ON CONFLICT DO NOTHING",
    [
      Text(joined(nullifiers)),
      Text(joined(List.map(epochs,
        fn epoch -> case epoch do
          Some(value) -> Int.to_string(value)
          None -> "0"
        end end)))
    ])?
  if spent != List.length(nullifiers) do
    # Rolls back the nullifiers this frame did insert.
    Err("credit_spent")
  else
    let id = case Crypto.random_bytes(16) do
      Err(_) -> Err("credit hold generation failed")
      Ok(value)
    end?
    Pg.execute_values(conn,
      "INSERT INTO credit_holds (redemption_id, action, binding, credits) VALUES ($1, $2::smallint, $3, $4::smallint)",
      [
        Binary(id),
        Text(Int.to_string(action)),
        Binary(frame.binding),
        Text(Int.to_string(List.length(nullifiers)))
      ])?
    # Per-week totals by action for settlement: never anything per sender.
    Pg.execute_values(conn,
      "INSERT INTO credit_spend_totals (week_start, action, credits) VALUES (date_trunc('week', now() AT TIME ZONE 'UTC')::date, $1::smallint, $2::bigint) ON CONFLICT (week_start, action) DO UPDATE SET credits = credit_spend_totals.credits + EXCLUDED.credits",
      [Text(Int.to_string(action)), Text(Int.to_string(List.length(nullifiers)))])?
    Ok(Redeemed(CreditRedemption { redemption_id: id, credits: List.length(nullifiers) }))
  end
end

## Redeems a frame inside the caller's transaction: for a core route whose
## action shares that transaction (priority sign-up, storage), or through
## credits_redeem for the internal route. Err "credit_spent" when any token was
## spent before; the caller's transaction must then roll back.

pub fn credits_redeem_on_connection(conn :: borrow PgConn,
  mode :: String,
  action :: Int,
  frame :: CreditFrame,
  now_ms :: Int) -> RedeemOutcome!String do
  case purpose_on_connection(conn, mode)? do
    None -> Ok(RedeemClosed)
    Some(purpose) -> spend_on_connection(conn,
      accepted_keys_on_connection(conn, purpose, now_ms)?,
      action,
      frame)
  end
end

## The internal redeem route's transaction. Err only when the spent set could
## not be read or written: the caller refuses the request.

pub fn credits_redeem(pool :: PoolHandle,
  mode :: String,
  action :: Int,
  frame :: CreditFrame,
  now_ms :: Int) -> RedeemOutcome!String do
  let outcome = Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> credits_redeem_on_connection(conn,
      mode,
      action,
      frame,
      now_ms) end)
  case outcome do
    Err(error) -> if String.contains(error, "credit_spent") do
      Ok(RedeemSpent)
    else
      Err(error)
    end
    Ok(value)
  end
end

## Takes a hold for `action` once, within an hour of the redemption, in the
## caller's transaction: Some((credits, binding)), or None when there is no
## such hold to take.

pub fn credits_take_hold_on_connection(conn :: borrow PgConn,
  redemption_id :: Bytes,
  action :: Int) -> Option<(Int, Bytes)>!String do
  let rows = Pg.query_values(conn,
    "UPDATE credit_holds SET taken_at = now() WHERE redemption_id = $1 AND action = $2::smallint AND taken_at IS NULL AND held_at > now() - interval '1 hour' RETURNING credits::text AS credits, binding",
    [Binary(redemption_id), Text(Int.to_string(action))])?
  case rows do
    [row] -> Ok(Some((integer(Map.get(row, "credits"))?, binary(Map.get(row, "binding"))?)))
    _ -> Ok(None)
  end
end

## Spent tokens of keys no longer accepted for 7 days, and holds older than a
## day, go. Returns how many nullifiers went.

pub fn credits_prune(pool :: PoolHandle, now_ms :: Int) -> Int!String do
  # A key of epoch e is accepted until (e + 2) epochs; its spent tokens are
  # kept 7 days (604,800,000 ms) longer.
  let last = (now_ms - 604800000) / credits_epoch_length() - 2
  let removed = if last < 0 do
    0
  else
    Pool.execute_values(pool,
      "DELETE FROM credit_spent WHERE key_epoch <= $1::bigint",
      [Text(Int.to_string(last))])?
  end
  Pool.execute_values(pool,
    "DELETE FROM credit_holds WHERE held_at < now() - interval '1 day'",
    [])?
  Ok(removed)
end

pub fn credits_prune_scheduled(pool :: PoolHandle) -> Int!String do
  credits_prune(pool, DateTime.to_unix_ms(DateTime.utc_now()))
end

fn commitment(label :: String, key_id :: Bytes) -> Bytes!String do
  case Bytes.concat(Bytes.from_utf8(label), key_id) do
    Err(_) -> Err("credit allocation failed")
    Ok(joined) -> Ok(Crypto.sha256(joined))
  end
end

# A leaf that is not a device set keeps its bytes: pruning only supersedes an
# entry by a newer one under the same commitment, and these commitments are
# one per key and one per revocation.

fn append_leaf_on_connection(conn :: borrow PgConn,
  account_commitment :: Bytes,
  entry :: Bytes) -> Int!String do
  let hash = leaf_hash(entry)?
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let index = dtree_size_on_connection(conn)?
  let rows = Pg.query_values(conn,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash, leaf_index) VALUES ($1, $2, $3, $4::bigint) RETURNING sequence::text AS sequence",
    [Binary(account_commitment), Binary(entry), Binary(hash), Text(Int.to_string(index))])?
  dtree_append_on_connection(conn, index, hash)?
  case rows do
    [row] -> integer(Map.get(row, "sequence"))
    _ -> Err("credit leaf append failed")
  end
end

fn key_by_id_on_connection(conn :: borrow PgConn, key_id :: Bytes) -> Option<StoredKey>!String do
  let rows = Pg.query_values(conn,
    key_columns() <> " WHERE token_key_id = $1 FOR UPDATE",
    [Binary(key_id)])?
  case rows do
    [row] -> Ok(Some(stored_key(row)?))
    _ -> Ok(None)
  end
end

fn same_leaf(conn :: borrow PgConn, sequence :: Int, entry :: Bytes) -> Bool!String do
  let rows = Pg.query_values(conn,
    "SELECT entry_bytes FROM transparency_entries WHERE sequence = $1::bigint",
    [Text(Int.to_string(sequence))])?
  case rows do
    [row] -> Ok(Bytes.secure_equals(binary(Map.get(row, "entry_bytes"))?, entry))
    _ -> Ok(false)
  end
end

fn announce_key_on_connection(conn :: borrow PgConn,
  entry :: Bytes,
  key :: IssuerKey) -> IssuerLeafWrite!String do
  let spki_valid = case Crypto.blind_rsa_public_from_spki(key.spki) do
    Err(_) -> false
    Ok(_) -> true
  end
  let key_id = Crypto.sha256(key.spki)
  if !spki_valid do
    return Ok(IssuerLeafInvalid)
  end
  case key_by_id_on_connection(conn, key_id)? do
    Some(stored) -> if same_leaf(conn, stored.entry_sequence, entry)? do
      Ok(IssuerLeafDuplicate)
    else
      Ok(IssuerLeafConflict)
    end
    None -> do
      let purpose = credits_purpose_name(key.purpose)?
      let taken = Pg.query_values(conn,
        "SELECT 1 FROM credit_issuer_keys WHERE purpose = $1 AND epoch = $2::bigint AND revocation_sequence IS NULL",
        [Text(purpose), Text(Int.to_string(key.epoch))])?
      if List.length(taken) > 0 do
        Ok(IssuerLeafConflict)
      else
        let sequence = append_leaf_on_connection(conn,
          commitment("morse-credits/v1/issuer-key", key_id)?,
          entry)?
        Pg.execute_values(conn,
          "INSERT INTO credit_issuer_keys (token_key_id, purpose, issuer_name, epoch, spki, entry_sequence) VALUES ($1, $2, $3, $4::bigint, $5, $6::bigint)",
          [
            Binary(key_id),
            Text(purpose),
            Text(key.issuer_name),
            Text(Int.to_string(key.epoch)),
            Binary(key.spki),
            Text(Int.to_string(sequence))
          ])?
        Ok(IssuerLeafStored)
      end
    end
  end
end

fn revoked_sequence(conn :: borrow PgConn, key_id :: Bytes) -> Int!String do
  let rows = Pg.query_values(conn,
    "SELECT revocation_sequence::text AS sequence FROM credit_issuer_keys WHERE token_key_id = $1",
    [Binary(key_id)])?
  case rows do
    [row] -> integer(Map.get(row, "sequence"))
    _ -> Err("credit key missing")
  end
end

fn revoke_key_on_connection(conn :: borrow PgConn,
  entry :: Bytes,
  revocation :: IssuerKeyRevocation) -> IssuerLeafWrite!String do
  case key_by_id_on_connection(conn, revocation.token_key_id)? do
    None -> Ok(IssuerLeafInvalid)
    Some(stored) -> if stored.key.purpose != revocation.purpose
      || stored.key.epoch != revocation.epoch
      || stored.key.issuer_name != revocation.issuer_name do
      Ok(IssuerLeafInvalid)
    else if stored.revoked do
      if same_leaf(conn, revoked_sequence(conn, revocation.token_key_id)?, entry)? do
        Ok(IssuerLeafDuplicate)
      else
        Ok(IssuerLeafConflict)
      end
    else
      let sequence = append_leaf_on_connection(conn,
        commitment("morse-credits/v1/issuer-key-revocation", revocation.token_key_id)?,
        entry)?
      Pg.execute_values(conn,
        "UPDATE credit_issuer_keys SET revocation_sequence = $2::bigint WHERE token_key_id = $1",
        [Binary(revocation.token_key_id), Text(Int.to_string(sequence))])?
      Ok(IssuerLeafStored)
    end
  end
end

fn issuer_leaf_on_connection(conn :: borrow PgConn, entry :: Bytes) -> IssuerLeafWrite!String do
  let kind = credits_leaf_kind(entry)
  if kind == 2 do
    case credits_decode_issuer_key(entry) do
      Err(_) -> Ok(IssuerLeafInvalid)
      Ok(key) -> announce_key_on_connection(conn, entry, key)
    end
  else if kind == 3 do
    case credits_decode_revocation(entry) do
      Err(_) -> Ok(IssuerLeafInvalid)
      Ok(revocation) -> revoke_key_on_connection(conn, entry, revocation)
    end
  else
    Ok(IssuerLeafInvalid)
  end
end

## Appends an `issuer-key-v1` or revocation leaf the issuer sends. The same
## leaf twice is a duplicate; a second unrevoked key for a purpose and epoch,
## or a different leaf for a key already announced, is a conflict.

pub fn credits_append_issuer_leaf(pool :: PoolHandle, entry :: Bytes) -> IssuerLeafWrite!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> issuer_leaf_on_connection(conn, entry) end)
end

fn key_evidence(conn :: borrow PgConn,
  stored :: StoredKey,
  checkpoint :: TransparencyCheckpoint,
  size :: Int,
  previous_tree_size :: Int) -> Bytes!String do
  let rows = Pg.query_values(conn,
    "SELECT entry_bytes, leaf_index::text AS leaf_index FROM transparency_entries WHERE sequence = $1::bigint",
    [Text(Int.to_string(stored.entry_sequence))])?
  let row = case rows do
    [value] -> Ok(value)
    _ -> Err("credit key leaf missing")
  end?
  let index = integer(Map.get(row, "leaf_index"))?
  let witnesses = transparency_attestations_on_connection(conn, checkpoint.sequence)?
  let (c2sp_root, c2sp_path) = if List.any(witnesses, fn value -> value.kind == 2 end) do
    dtree_view_on_connection(conn, 2, index, size)?
  else
    (Bytes.empty(), List.new())
  end
  transparency_encode_evidence_v2(TransparencyEvidenceV2 {
    entry_bytes: binary(Map.get(row, "entry_bytes"))?,
    inclusion: CompactInclusion {
      leaf_index: index,
      tree_size: size,
      path: dtree_inclusion_on_connection(conn, 1, index, size)?
    },
    consistency: CompactConsistency {
      old_size: previous_tree_size,
      new_size: size,
      path: dtree_consistency_on_connection(conn, 1, previous_tree_size, size)?
    },
    checkpoint: checkpoint,
    witnesses: witnesses,
    c2sp_root: c2sp_root,
    c2sp_path: c2sp_path
  })
end

fn listing_on_connection(conn :: borrow PgConn,
  previous_tree_size :: Int,
  now_ms :: Int) -> Bytes!String do
  let checkpoint = case transparency_current_checkpoint_on_connection(conn)? do
    None -> Err("transparency checkpoint not found")
    Some(value) -> Ok(value)
  end?
  let size = U64.to_int(checkpoint.tree_size)?
  if previous_tree_size < 0 || previous_tree_size > size do
    return Err("invalid consistency size")
  end
  let live = accepted_keys_on_connection(conn, "live", now_ms)?
  let test = accepted_keys_on_connection(conn, "test", now_ms)?
  let evidence = for stored in live ++ test do
    key_evidence(conn, stored, checkpoint, size, previous_tree_size)?
  end
  credits_encode_issuer_keys(evidence)
end

## CIK: every unrevoked key of either purpose accepted now, each with KTE v2
## evidence (consistency from previous_tree_size) on one fresh checkpoint.

pub fn credits_issuer_keys(pool :: PoolHandle,
  previous_tree_size :: Int,
  now_ms :: Int) -> Bytes!String do
  create_configured_checkpoint(pool)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> listing_on_connection(conn, previous_tree_size, now_ms) end)
end

## Credits spent in the week starting `week_start` (a Monday, UTC), by action:
## (envelope, storage, sign-up, file).

pub fn credits_spend_totals(pool :: PoolHandle,
  week_start :: String) -> (Int, Int, Int, Int)!String do
  let rows = Pool.query_values(pool,
    "SELECT COALESCE(sum(credits) FILTER (WHERE action = 1), 0)::text AS envelope, COALESCE(sum(credits) FILTER (WHERE action = 2), 0)::text AS storage, COALESCE(sum(credits) FILTER (WHERE action = 3), 0)::text AS signup, COALESCE(sum(credits) FILTER (WHERE action = 4), 0)::text AS file FROM credit_spend_totals WHERE week_start = $1::date AND extract(isodow FROM $1::date) = 1",
    [Text(week_start)])?
  case rows do
    [row] -> Ok((integer(Map.get(row, "envelope"))?,
      integer(Map.get(row, "storage"))?,
      integer(Map.get(row, "signup"))?,
      integer(Map.get(row, "file"))?))
    _ -> Err("credit totals failed")
  end
end
