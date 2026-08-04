fn store_legacy_prekey_fixture(database_path :: String,
prekey_label :: String,
legacy_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, "one-time-prekey/v1", legacy_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case delete_blobs(database,
          [prekey_label, "one-time-prekeys/v1", "one-time-prekey-active/v1", "one-time-prekey-next-id/v1"],
          0) do
            Err( error) -> Err(error)
            Ok( _) -> case Sqlite.commit(database) do
              Err( _) -> Err("database_write_failed")
              Ok( _) -> Ok(nil)
            end
          end
        end
      end
      case result do
        Err( error) -> do
          let _ = Sqlite.rollback(database)
          Sqlite.close(database)
          Err(error)
        end
        Ok( _) -> do
          Sqlite.close(database)
          Ok(nil)
        end
      end
    end
  end
end

pub fn prepare_legacy_prekey_fixture_path(database_path :: String) -> Result <(), String > do
  ensure_schema(database_path) ?
  let profile = parse_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let id = profile.bundle.one_time_prekey_id
  let label = one_time_prekey_label(id)
  let current_context = one_time_prekey_context(profile, id) ?
  let legacy_context = context(profile.account_id, profile.device_id, "one-time-prekey/v1", 10) ?
  let entries = load_prekey_pool(profile, wrapping_key, database_path) ?
  if List.length(entries) != 1 do
    Err("invalid_legacy_prekey_fixture")
  else
    let private_key = open_x25519(load_blob(database_path, label) ?, wrapping_key, current_context) ?
    let legacy_blob = seal_x25519(private_key, wrapping_key, legacy_context) ?
    store_legacy_prekey_fixture(database_path, label, legacy_blob)
  end
end

pub fn migrated_prekey_matches_profile_path(database_path :: String) -> Bool ! String do
  let profile = parse_profile(load_profile(database_path) ?) ?
  let id = profile.bundle.one_time_prekey_id
  let private_key = open_x25519(load_blob(database_path, one_time_prekey_label(id)) ?,
  platform_key() ?,
  one_time_prekey_context(profile, id) ?) ?
  case Crypto.x25519_public(private_key) do
    Err( _) -> Err("invalid_migrated_prekey")
    Ok( public_key) -> Ok(Bytes.secure_equals(public_key.bytes, profile.bundle.one_time_prekey))
  end
end
