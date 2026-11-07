from Mobile.ContactAddress import outgoing_extensions
from Mobile.Gossip import outgoing_gossip_hint
from Protocol.V1 import ProtocolExtension

pub fn direct_extensions(path :: String,
  key :: borrow StorageKey) -> List<ProtocolExtension>!String do
  let extensions = outgoing_extensions(path, key)?
  let hint = outgoing_gossip_hint(path, key)?
  if Bytes.length(hint) == 0 do
    Ok(extensions)
  else
    Ok(List.append(extensions, ProtocolExtension { id: 2, mandatory: false, value: hint }))
  end
end
