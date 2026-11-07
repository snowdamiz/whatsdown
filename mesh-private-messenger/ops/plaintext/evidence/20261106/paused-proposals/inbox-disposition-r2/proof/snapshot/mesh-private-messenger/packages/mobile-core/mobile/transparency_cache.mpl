from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local

pub fn cached_transparency_bytes(path :: String,
  key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, key, local_context(label)?)
  end
end

pub fn cached_checkpoint_bytes(path :: String, key :: borrow StorageKey) -> Bytes!String do
  cached_transparency_bytes(path, key, "transparency-checkpoint/v1")
end
