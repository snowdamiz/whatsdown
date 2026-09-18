from Prekeys.Pool import OneTimePrekeyPublic, PrekeyClaimRequest, PrekeyPublishRequest, encode_prekey_claim, encode_prekey_publish, prekey_publish_signing_bytes
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.V1 import PrekeyBundle, decode_device_credential, decode_prekey_bundle, encode_prekey_bundle

pub type PrekeyPublishWrite do
  PrekeysPublished( active_ids :: List < U64 >)

  PrekeysUnchanged( active_ids :: List < U64 >)

  PrekeysUnauthorized

  PrekeysConflict

  PrekeyPoolFull
end

pub type PrekeyClaimWrite do
  PrekeyClaimed( bundle :: PrekeyBundle)

  PrekeyClaimExhausted

  PrekeyClaimMissing
end

struct PublicationCheck do
  new_count :: Int
  conflict :: Bool
end

struct StoredClaim do
  account_id :: Bytes
  device_id :: Bytes
  base_bundle_hash :: Bytes
  claimed :: OneTimePrekeyPublic
  response :: Option < Bytes >
end

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( output) -> Ok(output)
    _ -> Err("invalid prekey row")
  end
end

fn optional_binary(value :: DbValue) -> Option < Bytes > ! String do
  case value do
    Binary( output) -> Ok(Some(output))
    Null -> Ok(None)
    _ -> Err("invalid optional prekey row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid prekey row")
  end
end

fn wide(value :: DbValue) -> U64 ! String do
  U64.parse(text(value) ?)
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid prekey row")
    Some( output) -> Ok(output)
  end
end

fn active_bundle(conn :: borrow PgConn, account_id :: Bytes, device_id :: Bytes, exclusive :: Bool) -> Option < Bytes > ! String do
  let rows = if exclusive do
    Pg.query_values(conn,
    "SELECT device.prekey_bundle FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.account_id = $1 AND device.device_id = $2 AND device.revoked_at IS NULL AND mailbox.active FOR UPDATE OF device, mailbox",
    [Binary(account_id), Binary(device_id)])
  else
    Pg.query_values(conn,
    "SELECT device.prekey_bundle FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.account_id = $1 AND device.device_id = $2 AND device.revoked_at IS NULL AND mailbox.active FOR SHARE OF device, mailbox",
    [Binary(account_id), Binary(device_id)])
  end ?
  if List.length(rows) == 0 do
    Ok(None)
  else if List.length(rows) == 1 do
    Ok(Some(binary(Map.get(List.head(rows), "prekey_bundle")) ?))
  else
    Err("duplicate active prekey device")
  end
end

fn signing_key(encoded_bundle :: Bytes) -> Bytes ! String do
  let bundle = case decode_prekey_bundle(encoded_bundle) do
    Err( _) -> Err("invalid stored prekey bundle")
    Ok( output) -> Ok(output)
  end ?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err( _) -> Err("invalid stored device credential")
    Ok( output) -> Ok(output)
  end ?
  Ok(credential.signing_public_key)
end

fn publication_check(conn :: borrow PgConn,
request :: PrekeyPublishRequest,
index :: Int,
new_count :: Int) -> PublicationCheck ! String do
  if index >= List.length(request.prekeys) do
    Ok(PublicationCheck {
      new_count : new_count,
      conflict : false
    })
  else
    let value = List.get(request.prekeys, index)
    let rows = Pg.query_values(conn,
    "SELECT public_key FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2 AND prekey_id = $3::bigint",
    [Binary(request.account_id), Binary(request.device_id), Text(U64.to_string(value.id))]) ?
    if List.length(rows) == 0 do
      publication_check(conn, request, index + 1, new_count + 1)
    else if List.length(rows) == 1 && Bytes.secure_equals(binary(Map.get(List.head(rows),
    "public_key")) ?,
    value.public_key) do
      publication_check(conn, request, index + 1, new_count)
    else
      Ok(PublicationCheck {
        new_count : new_count,
        conflict : true
      })
    end
  end
end

fn insert_prekeys(conn :: borrow PgConn, request :: PrekeyPublishRequest, index :: Int) -> Result <(), String > do
  if index >= List.length(request.prekeys) do
    Ok(nil)
  else
    let value = List.get(request.prekeys, index)
    let _ = Pg.execute_values(conn,
    "INSERT INTO messenger_one_time_prekeys (account_id, device_id, prekey_id, public_key) VALUES ($1, $2, $3::bigint, $4) ON CONFLICT DO NOTHING",
    [Binary(request.account_id), Binary(request.device_id), Text(U64.to_string(value.id)), Binary(value.public_key)]) ?
    insert_prekeys(conn, request, index + 1)
  end
end

fn prekey_row_ids(rows :: List < Map < String, DbValue > >, index :: Int, output :: List < U64 >) -> List < U64 > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    prekey_row_ids(rows,
    index + 1,
    List.append(output, wide(Map.get(List.get(rows, index), "prekey_id")) ?))
  end
end

fn active_prekey_ids(conn :: borrow PgConn, account_id :: Bytes, device_id :: Bytes) -> List < U64 > ! String do
  let rows = Pg.query_values(conn,
  "SELECT prekey_id::text FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2 AND consumed_at IS NULL ORDER BY messenger_one_time_prekeys.prekey_id",
  [Binary(account_id), Binary(device_id)]) ?
  if List.length(rows) > 64 do
    Err("prekey pool overflow")
  else
    prekey_row_ids(rows, 0, List.new())
  end
end

fn publish_on_connection(conn :: borrow PgConn, request :: PrekeyPublishRequest) -> PrekeyPublishWrite ! String do
  case active_bundle(conn, request.account_id, request.device_id, true) ? do
    None -> Ok(PrekeysUnauthorized)
    Some( encoded_bundle) -> do
      let verified = case Crypto.verify(SigningPublicKey { bytes : signing_key(encoded_bundle) ? },
      prekey_publish_signing_bytes(request) ?,
      Signature { bytes : request.signature }) do
        Err( _) -> false
        Ok( output) -> output
      end
      if !verified do
        Ok(PrekeysUnauthorized)
      else
        let checked = publication_check(conn, request, 0, 0) ?
        if checked.conflict do
          Ok(PrekeysConflict)
        else
          let counts = Pg.query_values(conn,
          "SELECT count(*)::text AS available_count FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2 AND consumed_at IS NULL",
          [Binary(request.account_id), Binary(request.device_id)]) ?
          if List.length(counts) != 1 do
            Err("prekey pool count failed")
          else if integer(Map.get(List.head(counts), "available_count")) ? + checked.new_count > 64 do
            Ok(PrekeyPoolFull)
          else
            if checked.new_count > 0 do
              insert_prekeys(conn, request, 0) ?
            end
            let active_ids = active_prekey_ids(conn, request.account_id, request.device_id) ?
            if checked.new_count == 0 do
              Ok(PrekeysUnchanged(active_ids))
            else
              Ok(PrekeysPublished(active_ids))
            end
          end
        end
      end
    end
  end
end

pub fn publish_prekeys(pool :: PoolHandle, request :: PrekeyPublishRequest) -> PrekeyPublishWrite ! String do
  let _ = encode_prekey_publish(request) ?
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> publish_on_connection(conn, request) end)
end

pub fn seed_registration_prekey_on_connection(conn :: borrow PgConn,
account_id :: Bytes,
device_id :: Bytes,
prekey :: Option < OneTimePrekeyPublic >) -> Result <(), String > do
  case prekey do
    None -> Ok(nil)
    Some( value) -> do
      let changed = Pg.execute_values(conn,
      "INSERT INTO messenger_one_time_prekeys (account_id, device_id, prekey_id, public_key) VALUES ($1, $2, $3::bigint, $4)",
      [Binary(account_id), Binary(device_id), Text(U64.to_string(value.id)), Binary(value.public_key)]) ?
      if changed == 1 do
        Ok(nil)
      else
        Err("registration prekey insertion failed")
      end
    end
  end
end

fn resolved_bundle(encoded :: Bytes, claimed :: OneTimePrekeyPublic) -> PrekeyBundle ! String do
  let stored = case decode_prekey_bundle(encoded) do
    Err( _) -> Err("invalid stored prekey bundle")
    Ok( output) -> Ok(output)
  end ?
  let resolved = PrekeyBundle {
    version : stored.version,
    suite : stored.suite,
    device_credential : stored.device_credential,
    identity_dh_public_key : stored.identity_dh_public_key,
    signing_public_key : stored.signing_public_key,
    signed_prekey_id : stored.signed_prekey_id,
    signed_prekey : stored.signed_prekey,
    signed_prekey_signature : stored.signed_prekey_signature,
    one_time_prekey_id : claimed.id,
    one_time_prekey : claimed.public_key,
    post_quantum_prekey : stored.post_quantum_prekey,
    supported_suites : stored.supported_suites,
    expires_at : stored.expires_at,
    extensions : stored.extensions
  }
  let _ = case encode_prekey_bundle(resolved) do
    Err( _) -> Err("invalid resolved prekey bundle")
    Ok( output) -> Ok(output)
  end ?
  Ok(resolved)
end

fn claimed_prekey(rows :: List < Map < String, DbValue > >) -> Option < OneTimePrekeyPublic > ! String do
  if List.length(rows) == 0 do
    Ok(None)
  else if List.length(rows) == 1 do
    let row = List.head(rows)
    Ok(Some(OneTimePrekeyPublic {
      id : wide(Map.get(row, "prekey_id")) ?,
      public_key : binary(Map.get(row, "public_key")) ?
    }))
  else
    Err("multiple prekeys claimed")
  end
end

fn stored_claim(rows :: List < Map < String, DbValue > >) -> Option < StoredClaim > ! String do
  if List.length(rows) == 0 do
    Ok(None)
  else if List.length(rows) == 1 do
    let row = List.head(rows)
    Ok(Some(StoredClaim {
      account_id : binary(Map.get(row, "account_id")) ?,
      device_id : binary(Map.get(row, "device_id")) ?,
      base_bundle_hash : binary(Map.get(row, "claim_base_bundle_hash")) ?,
      claimed : OneTimePrekeyPublic {
        id : wide(Map.get(row, "prekey_id")) ?,
        public_key : binary(Map.get(row, "public_key")) ?
      },
      response : optional_binary(Map.get(row, "claim_response")) ?
    }))
  else
    Err("multiple prekey claims share a reservation")
  end
end

fn existing_claim(conn :: borrow PgConn, request :: PrekeyClaimRequest) -> Option < StoredClaim > ! String do
  let rows = Pg.query_values(conn,
  "SELECT account_id, device_id, prekey_id::text, public_key, claim_base_bundle_hash, claim_response FROM messenger_one_time_prekeys WHERE claim_id_hash = $1 FOR SHARE",
  [Binary(Crypto.sha256(request.reservation_id))]) ?
  stored_claim(rows)
end

fn claim_binding_matches(stored :: borrow StoredClaim, request :: PrekeyClaimRequest) -> Bool do
  Bytes.secure_equals(stored.account_id, request.account_id) && Bytes.secure_equals(stored.device_id,
  request.device_id) && Bytes.secure_equals(stored.base_bundle_hash, request.base_bundle_hash)
end

fn encoded_bundle(bundle :: PrekeyBundle) -> Bytes ! String do
  case encode_prekey_bundle(bundle) do
    Err( _) -> Err("invalid resolved prekey bundle")
    Ok( output) -> Ok(output)
  end
end

fn stored_response_bundle(stored :: borrow StoredClaim,
request :: PrekeyClaimRequest,
encoded :: Bytes) -> PrekeyBundle ! String do
  let bundle = case decode_prekey_bundle(encoded) do
    Err( _) -> Err("invalid stored prekey claim response")
    Ok( output) -> Ok(output)
  end ?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err( _) -> Err("invalid stored prekey claim credential")
    Ok( output) -> Ok(output)
  end ?
  let base = case normalize_prekey_bundle(bundle) do
    Err( _) -> Err("invalid stored prekey claim base")
    Ok( output) -> Ok(output)
  end ?
  let canonical = encoded_bundle(bundle) ?
  let base_hash = Crypto.sha256(encoded_bundle(base) ?)
  let common = Bytes.secure_equals(canonical, encoded) && Bytes.secure_equals(credential.account_id,
  request.account_id) && Bytes.secure_equals(credential.device_id, request.device_id) && Bytes.secure_equals(base_hash,
  request.base_bundle_hash)
  let claimed = U64.compare(bundle.one_time_prekey_id, stored.claimed.id) == 0 && Bytes.secure_equals(bundle.one_time_prekey,
  stored.claimed.public_key)
  if common && claimed do
    Ok(bundle)
  else if common && Bytes.length(bundle.one_time_prekey) == 0 do
    resolved_bundle(encoded, stored.claimed)
  else
    Err("invalid stored prekey claim binding")
  end
end

fn lock_claim_reservation(conn :: borrow PgConn, request :: PrekeyClaimRequest) -> Result <(), String > do
  let _ = Pg.query_values(conn,
  "SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 1835365485))",
  [Binary(Crypto.sha256(request.reservation_id))]) ?
  Ok(nil)
end

fn claim_candidate(conn :: borrow PgConn, request :: PrekeyClaimRequest) -> Option < OneTimePrekeyPublic > ! String do
  let rows = Pg.query_values(conn,
  "SELECT prekey_id::text, public_key FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2 AND consumed_at IS NULL ORDER BY messenger_one_time_prekeys.prekey_id FOR UPDATE SKIP LOCKED LIMIT 1",
  [Binary(request.account_id), Binary(request.device_id)]) ?
  claimed_prekey(rows)
end

fn reserve_claim(conn :: borrow PgConn,
request :: PrekeyClaimRequest,
claimed :: OneTimePrekeyPublic,
response :: Bytes) -> Result <(), String > do
  let changed = Pg.execute_values(conn,
  "UPDATE messenger_one_time_prekeys SET consumed_at = clock_timestamp(), claim_id_hash = $4, claim_base_bundle_hash = $5, claim_response = $6 WHERE account_id = $1 AND device_id = $2 AND prekey_id = $3::bigint AND consumed_at IS NULL",
  [Binary(request.account_id), Binary(request.device_id), Text(U64.to_string(claimed.id)), Binary(Crypto.sha256(request.reservation_id)), Binary(request.base_bundle_hash), Binary(response)]) ?
  if changed == 1 do
    Ok(nil)
  else
    Err("prekey claim changed concurrently")
  end
end

fn store_legacy_claim_response(conn :: borrow PgConn,
request :: PrekeyClaimRequest,
claimed :: OneTimePrekeyPublic,
response :: Bytes) -> Result <(), String > do
  let changed = Pg.execute_values(conn,
  "UPDATE messenger_one_time_prekeys SET claim_response = $6 WHERE account_id = $1 AND device_id = $2 AND prekey_id = $3::bigint AND claim_id_hash = $4 AND claim_base_bundle_hash = $5 AND claim_response IS NULL",
  [Binary(request.account_id), Binary(request.device_id), Text(U64.to_string(claimed.id)), Binary(Crypto.sha256(request.reservation_id)), Binary(request.base_bundle_hash), Binary(response)]) ?
  if changed == 1 do
    Ok(nil)
  else
    Err("legacy prekey claim response changed concurrently")
  end
end

fn replace_legacy_claim_response(conn :: borrow PgConn,
request :: PrekeyClaimRequest,
claimed :: OneTimePrekeyPublic,
legacy :: Bytes,
response :: Bytes) -> Result <(), String > do
  let changed = Pg.execute_values(conn,
  "UPDATE messenger_one_time_prekeys SET claim_response = $7 WHERE account_id = $1 AND device_id = $2 AND prekey_id = $3::bigint AND claim_id_hash = $4 AND claim_base_bundle_hash = $5 AND claim_response = $6",
  [Binary(request.account_id), Binary(request.device_id), Text(U64.to_string(claimed.id)), Binary(Crypto.sha256(request.reservation_id)), Binary(request.base_bundle_hash), Binary(legacy), Binary(response)]) ?
  if changed == 1 do
    Ok(nil)
  else
    Err("legacy prekey claim response changed concurrently")
  end
end

fn claim_on_connection(conn :: borrow PgConn, request :: PrekeyClaimRequest) -> PrekeyClaimWrite ! String do
  case active_bundle(conn, request.account_id, request.device_id, false) ? do
    None -> Ok(PrekeyClaimMissing)
    Some( current_bundle) -> do
      lock_claim_reservation(conn, request) ?
      case existing_claim(conn, request) ? do
        Some( stored) -> if !claim_binding_matches(stored, request) do
          Ok(PrekeyClaimMissing)
        else
          case stored.response do
            Some( response) -> do
              let bundle = stored_response_bundle(stored, request, response) ?
              let exact = encoded_bundle(bundle) ?
              if !Bytes.secure_equals(exact, response) do
                replace_legacy_claim_response(conn, request, stored.claimed, response, exact) ?
              end
              Ok(PrekeyClaimed(bundle))
            end
            None -> if !Bytes.secure_equals(Crypto.sha256(current_bundle), request.base_bundle_hash) do
              Ok(PrekeyClaimMissing)
            else
              let bundle = resolved_bundle(current_bundle, stored.claimed) ?
              store_legacy_claim_response(conn, request, stored.claimed, encoded_bundle(bundle) ?) ?
              Ok(PrekeyClaimed(bundle))
            end
          end
        end
        None -> if !Bytes.secure_equals(Crypto.sha256(current_bundle), request.base_bundle_hash) do
          Ok(PrekeyClaimMissing)
        else
          case claim_candidate(conn, request) ? do
            None -> Ok(PrekeyClaimExhausted)
            Some( claimed) -> do
              let bundle = resolved_bundle(current_bundle, claimed) ?
              reserve_claim(conn, request, claimed, encoded_bundle(bundle) ?) ?
              Ok(PrekeyClaimed(bundle))
            end
          end
        end
      end
    end
  end
end

pub fn claim_prekey(pool :: PoolHandle, request :: PrekeyClaimRequest) -> PrekeyClaimWrite ! String do
  let _ = encode_prekey_claim(request) ?
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> claim_on_connection(conn, request) end)
end
