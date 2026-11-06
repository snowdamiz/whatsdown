from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Policy import issuer_epoch
from Storage.Issuance import insert_issuer_key
from Transparency.Wire import decode_checkpoint

pub struct ManagedIssuerKey do
  key :: CreditIssuerKey
  admitted :: Bool
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid_issuer_row")
  end
end

pub fn ensure_current_key(pool :: PoolHandle,
  purpose :: Int,
  now :: U64,
  open_key :: Fun() -> Result<StorageKey, String>,
  service_key :: Bytes) -> ManagedIssuerKey!String do
  if purpose != 0 && purpose != 1 do
    return Err("invalid_credit_purpose")
  end
  let epoch = issuer_epoch(now)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do # Same transaction lock as insert/admit; two processes never publish
      # competing keys for the same epoch, even on an empty database.
      Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365490)", [])?
      let rows = Pg.query_values(conn,
        "SELECT key_id, spki, quote_public_key, admitted_evidence FROM issuer_keys WHERE epoch = $1::numeric AND purpose = $2::smallint",
        [Text(U64.to_string(epoch)), Text(Int.to_string(purpose))])?
      if List.length(rows) == 1 do
        let row = List.head(rows)
        let key = CreditIssuerKey {
          epoch: epoch,
          purpose: purpose,
          spki: binary(Map.get(row, "spki"))?,
          quote_public_key: binary(Map.get(row, "quote_public_key"))?
        }
        if !Bytes.secure_equals(issuer_key_id(key)?, binary(Map.get(row, "key_id"))?) do
          return Err("invalid_issuer_row")
        end
        return Ok(ManagedIssuerKey {
          key: key,
          admitted: case Map.get(row, "admitted_evidence") do
            Binary(_) -> true
            _ -> false
          end
        })
      end
      let wrapping = open_key()?
      let private = case Crypto.blind_rsa_generate() do
        Ok(value) -> value
        Err(_) -> return Err("issuer_key_generation_failed")
      end
      let public = case Crypto.blind_rsa_public(private) do
        Ok(value) -> value
        Err(_) -> return Err("issuer_key_generation_failed")
      end
      let quote_signer = case Crypto.signing_generate() do
        Ok(value) -> value
        Err(_) -> return Err("issuer_quote_key_generation_failed")
      end
      let key = CreditIssuerKey {
        epoch: epoch,
        purpose: purpose,
        spki: public.bytes,
        quote_public_key: quote_signer.public_key.bytes
      }
      insert_issuer_key(conn, key, private, quote_signer.private_key, wrapping, service_key)?
      Ok(ManagedIssuerKey { key: key, admitted: false })
    end)
end

pub fn issuer_cursor(pool :: PoolHandle) -> Bytes!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT checkpoint FROM issuer_transparency_cursor WHERE singleton",
        [])?
      if List.length(rows) == 0 do
        Ok(Bytes.empty())
      else
        binary(Map.get(List.head(rows), "checkpoint"))
      end
    end)
end

pub fn issuer_cursor_size(pool :: PoolHandle) -> U64!String do
  let cursor = issuer_cursor(pool)?
  if Bytes.length(cursor) == 0 do
    Ok(U64.parse("0")?)
  else
    Ok(decode_checkpoint(cursor)?.tree_size)
  end
end
