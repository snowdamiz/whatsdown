from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local

##! The objects of attachments whose disappearing messages were deleted, kept
##! sealed until the app collects them (`mesh_messenger_expiry_purge`) and
##! deletes what it cached of them. Whatever deletes an expired message adds to
##! it in the same transaction (`Mobile.Expiry`, `Mobile.History`,
##! `Mobile.GroupState`).

pub fn expired_objects_label() -> String do
  "expired-objects/v1"
end

# At most this many object IDs wait for the app; the oldest go first.

fn expired_objects_limit() -> Int do
  512
end

pub fn expired_objects_load(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let label = expired_objects_label()
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok([])
    else
      Err(error)
    end
    Ok(blob) -> do
      let value = open_local(blob, wrapping_key, local_context(label)?)?
      if Bytes.length(value) % 32 != 0 do
        return Err("invalid_expired_objects")
      end
      Ok(for index in 0..Bytes.length(value) / 32 do
        Bytes.slice(value, index * 32, 32)?
      end)
    end
  end
end

pub fn expired_objects_sealed(values :: List<Bytes>,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let kept = if List.length(values) > expired_objects_limit() do
    List.drop(values, List.length(values) - expired_objects_limit())
  else
    values
  end
  let joined = List.reduce(kept,
    Bytes.empty(),
    fn(output, value) do
      case Bytes.concat(output, value) do
        Err(_) -> output
        Ok(next) -> next
      end
    end)
  seal_local(joined, wrapping_key, local_context(expired_objects_label())?)
end

## The label and blob that add `objects` to what waits for the app.

pub fn expired_objects_added(database_path :: String,
  wrapping_key :: borrow StorageKey,
  objects :: List<Bytes>) -> Result<(String, Bytes), String> do
  let pending = List.concat(expired_objects_load(database_path, wrapping_key)?, objects)
  Ok((expired_objects_label(), expired_objects_sealed(pending, wrapping_key)?))
end
