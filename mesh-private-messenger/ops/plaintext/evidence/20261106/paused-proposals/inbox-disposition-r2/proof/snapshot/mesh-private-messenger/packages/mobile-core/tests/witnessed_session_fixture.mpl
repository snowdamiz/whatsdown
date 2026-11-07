##! Bounded real signed own/peer evidence for legacy session fixtures.
from Mobile.Codec import current_time
from Mobile.Profile import load_profile
from MobileCore import verify_transparency_export
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.DirectoryWire import encode_device_set
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet
from Tests.GroupConsistencySupport import request
from Tests.Support import install_security_config
from Transparency.Merkle import (
  consistency_proof,
  inclusion_proof,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Transport.Packet import decode_client_profile

fn signing() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("witnessed_fixture_signer_failed")
    Ok(value)
  end
end

fn normalized_set(path :: String) -> Bytes!String do
  let profile = decode_client_profile(load_profile(path)?)?
  let bundle = case normalize_prekey_bundle(profile.bundle) do
    Err(_) -> return Err("witnessed_fixture_bundle_failed")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("witnessed_fixture_bundle_encoding_failed")
    Ok(value) -> value
  end
  case encode_device_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: profile.entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [%{profile.entry | prekey_bundle: wire}],
    revoked_device_ids: []
  }) do
    Err(_) -> Err("witnessed_fixture_set_encoding_failed")
    Ok(value)
  end
end

# Every account gets the same service-signed checkpoint and two actual witness
# signatures over real canonical own/peer sets, through the public verifier.
# This is fixture setup only; no production trust or admission check is bypassed.
pub fn install_witnessed_session_fixtures(paths :: List<String>) -> Unit!String do
  if List.length(paths) < 1 || List.length(paths) > 5 do
    return Err("witnessed_fixture_paths_invalid")
  end
  let sets = for path in paths do
    normalized_set(path)?
  end
  let leaves = for devices in sets do
    leaf_hash(devices)?
  end
  let service_pair = signing()?
  let first = signing()?
  let second = signing()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("witnessed_fixture_delivery_failed")
    Ok(value) -> value
  end
  if !install_security_config(service_pair.public_key.bytes,
    first.public_key.bytes,
    second.public_key.bytes,
    delivery.public_key.bytes,
    1) do
    return Err("witnessed_fixture_security_failed")
  end
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://core.example/v1/mailbox/stream\n1")) do
    return Err("witnessed_fixture_network_failed")
  end
  let zero = case Bytes.repeat(0, 32) do
    Err(_) -> return Err("witnessed_fixture_zero_failed")
    Ok(value) -> value
  end
  let checkpoint = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    U64.parse("1")?,
    leaves,
    zero,
    current_time()?)?
  let witnesses = [
    sign_witness("witness-a", first.private_key, checkpoint)?,
    sign_witness("witness-b", second.private_key, checkpoint)?
  ]
  for path in paths do
    for index in 0..List.length(sets) do
      let devices = List.get(sets, index)
      let profile = decode_client_profile(load_profile(List.get(paths, index))?)?
      let evidence = encode_transparency_evidence(TransparencyEvidence {
        entry_bytes: devices,
        inclusion: inclusion_proof(leaves, index)?,
        consistency: consistency_proof(if index == 0 do
            []
          else
            leaves
          end,
          leaves)?,
        checkpoint: checkpoint,
        witnesses: witnesses
      })?
      verify_transparency_export(request([
        Bytes.from_utf8(path),
        Bytes.from_utf8(profile.username),
        evidence,
        Bytes.from_utf8("https://core.example")
      ])?)?
    end
  end
  Ok(nil)
end
