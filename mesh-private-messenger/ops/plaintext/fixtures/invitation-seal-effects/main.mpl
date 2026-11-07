from Mobile.Codec import encode_output_list
from Mobile.GroupInvitesState import GroupInvitation, invitation_blob
from Storage.Keys import local_context, open_local, seal_local

fn record(state :: Int) -> GroupInvitation!String do
  Ok(GroupInvitation {
    id: Bytes.from_utf8(String.repeat("1", 16)),
    group_id: Bytes.from_utf8(String.repeat("2", 32)),
    inviter_account: Bytes.from_utf8(String.repeat("3", 32)),
    inviter_device: Bytes.from_utf8(String.repeat("4", 16)),
    recipient_account: Bytes.from_utf8(String.repeat("5", 32)),
    recipient_device: Bytes.from_utf8(String.repeat("6", 16)),
    username: "synthetic",
    baseline: Bytes.from_utf8(String.repeat("7", 188)),
    expires_at: U64.parse("1")?,
    state: state,
    key_package: Bytes.empty(),
    inviter_signing_key: Bytes.empty()
  })
end

fn observation(mode :: String, key :: borrow StorageKey) -> Bool!String do
  if mode == "init" do
    Ok(true)
  else if mode == "empty-list" do
    let expected = encode_output_list([])?
    let context = local_context("group-invitations/v1")?
    Ok(case invitation_blob([], key) do
      Err(_) -> false
      Ok(blob) -> case open_local(blob, key, context) do
        Err(_) -> false
        Ok(opened) -> Bytes.length(blob) == 75 && Bytes.secure_equals(opened, expected)
      end
    end)
  else if mode == "over-limit" do
    let value = record(0)?
    let values = for _ in 0..129 do value end
    Ok(case invitation_blob(values, key) do
      Err(error) -> error == "group_invitation_limit"
      Ok(_) -> false
    end)
  else if mode == "malformed-record" do
    let value = record(256)?
    Ok(case invitation_blob([value], key) do
      Err(error) -> error == "integer_encoding_failed"
      Ok(_) -> false
    end)
  else if mode == "invalid-context" do
    Ok(case seal_local(Bytes.empty(), key, Bytes.empty()) do
      Err(error) -> error == "local_state_seal_failed"
      Ok(_) -> false
    end)
  else if mode == "empty-fallback" do
    let context = local_context("group-invitations/v1")?
    Ok(case seal_local(Bytes.empty(), key, context) do
      Err(_) -> false
      Ok(blob) -> case open_local(blob, key, context) do
        Err(_) -> false
        Ok(opened) -> Bytes.length(blob) == 67 && Bytes.length(opened) == 0
      end
    end)
  else
    Ok(false)
  end
end

fn run(mode :: String, directory :: String) -> Bool do
  case StorageKey.file(directory) do
    Err(_) -> false
    Ok(key) -> do
      let observed = observation(mode, key)
      Secret.destroy(key)
      case observed do
        Ok(value) -> value
        Err(_) -> false
      end
    end
  end
end

fn main() do
  let args = Env.args()
  let observed = run(List.get(args, 1), List.get(args, 2))
  if declassify(observed,
    "fixture-only Boolean for controlled synthetic invitation sealing: exact expected error or ciphertext roundtrip; no body error payload or key material is disclosed") do
    println("invitation-seal-fixture:pass")
  else
    println("invitation-seal-fixture:fail")
    Process.exit(1)
  end
end
