from Storage.Blobs import insert_blob, put_blob
from Storage.Records import delete_blobs, put_blobs

##! Storage.Groups implementation.

pub fn store_new_group(database_path :: String,
state_label :: String,
state_blob :: Bytes,
index_blob :: Bytes,
baseline_label :: String,
baseline_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case insert_blob(database, baseline_label, baseline_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "groups/v1", index_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case Sqlite.commit(database) do
                Err( _) -> Err("database_write_failed")
                Ok( _) -> Ok(nil)
              end
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

pub fn store_group_outbound(database_path :: String,
state_label :: String,
state_blob :: Bytes,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes,
extra_labels :: List < String >,
extra_blobs :: List < Bytes >) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blobs(database, outbox_labels, outbox_blobs, 0) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "outbox/v1", outbox_index_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case put_blobs(database, extra_labels, extra_blobs, 0) do
                Err( error) -> Err(error)
                Ok( _) -> case Sqlite.commit(database) do
                  Err( _) -> Err("database_write_failed")
                  Ok( _) -> Ok(nil)
                end
              end
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

pub fn store_group_message_outbound(database_path :: String,
state_label :: String,
state_blob :: Bytes,
history_labels :: List < String >,
history_blobs :: List < Bytes >,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blobs(database, history_labels, history_blobs, 0) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blobs(database, outbox_labels, outbox_blobs, 0) do
              Err( error) -> Err(error)
              Ok( _) -> case put_blob(database, "outbox/v1", outbox_index_blob) do
                Err( error) -> Err(error)
                Ok( _) -> case Sqlite.commit(database) do
                  Err( _) -> Err("database_write_failed")
                  Ok( _) -> Ok(nil)
                end
              end
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

pub fn store_group_state_history(database_path :: String,
state_label :: String,
state_blob :: Bytes,
history_labels :: List < String >,
history_blobs :: List < Bytes >) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blobs(database, history_labels, history_blobs, 0) do
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

pub fn store_group_join(database_path :: String,
state_label :: String,
state_blob :: Bytes,
index_blob :: Bytes,
baseline_label :: String,
baseline_blob :: Bytes,
package_label :: String,
init_label :: String,
leaf_label :: String) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case insert_blob(database, baseline_label, baseline_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "groups/v1", index_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case delete_blobs(database, [package_label, init_label, leaf_label], 0) do
                Err( error) -> Err(error)
                Ok( _) -> case Sqlite.commit(database) do
                  Err( _) -> Err("database_write_failed")
                  Ok( _) -> Ok(nil)
                end
              end
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
