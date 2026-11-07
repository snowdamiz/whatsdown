# Historical authority counterexample: an explicitly private body, public claimed identities, and no private caller branch.
from Mobile.GroupInvitesState import received_invitation_writes
from Protocol.V1 import InnerEnvelope
from Transport.Packet import ClientProfile

fn invitation_private_input(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  inner :: InnerEnvelope,
  body :: Plaintext<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  received_invitation_writes(path, key, local, "public peer", %{inner | body: body})
end

fn main() do nil end
