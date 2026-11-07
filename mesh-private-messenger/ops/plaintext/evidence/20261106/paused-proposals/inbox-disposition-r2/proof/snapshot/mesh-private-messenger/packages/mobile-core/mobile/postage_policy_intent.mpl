##! One signed policy intent survives uncertain transport without re-signing.

from Credits.PostagePolicy import (
  PostagePolicy,
  decode_postage_policy,
  encode_postage_policy,
  verify_postage_policy
)
from Protocol.V1 import AccountIdentity
from Storage.Blobs import load_blob
from Storage.Records import compare_and_swap_blobs
from Storage.Keys import local_context, seal_local, open_local
from Transparency.Config import SecurityConfig

fn label() -> String do
  "postage-policy-intent/v1"
end

fn binding(account :: AccountIdentity, device :: Bytes, config :: SecurityConfig) -> Bytes!String do
  local_context(label()
    <> "/"
    <> Bytes.to_hex(account.account_id)
    <> "/"
    <> Bytes.to_hex(device)
    <> "/"
    <> Bytes.to_hex(config.service_public_key)
    <> "/"
    <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(config.issuer_origin))))
end

fn open_intent(blob :: Bytes,
  wrapping :: borrow StorageKey,
  account :: AccountIdentity,
  device :: Bytes,
  config :: SecurityConfig) -> PostagePolicy!String do
  let value = decode_postage_policy(open_local(blob, wrapping, binding(account, device, config)?)?)?
  if !Bytes.secure_equals(value.account_id, account.account_id)
    || !Bytes.secure_equals(value.publisher_device_id, device)
    || !verify_postage_policy(value, account)? do
    return Err("invalid_postage_policy_intent")
  end
  Ok(value)
end

pub fn load_postage_policy_intent(path :: String,
  wrapping :: borrow StorageKey,
  account :: AccountIdentity,
  device :: Bytes,
  config :: SecurityConfig) -> PostagePolicy!String do
  open_intent(load_blob(path, label())?, wrapping, account, device, config)
end

pub fn retain_postage_policy_intent(path :: String,
  wrapping :: borrow StorageKey,
  account :: AccountIdentity,
  device :: Bytes,
  config :: SecurityConfig,
  candidate :: PostagePolicy) -> Bytes!String do
  let previous = case load_blob(path, label()) do
    Ok(value) -> value
    Err(error) -> if error == "local_state_not_found" do
      Bytes.empty()
    else
      return Err(error)
    end
  end
  if Bytes.length(previous) > 0 do
    let stored = open_intent(previous, wrapping, account, device, config)?
    if stored.revision == candidate.revision
      && stored.expected_device_set_revision == candidate.expected_device_set_revision do
      if stored.credits != candidate.credits do
        return Err("postage_policy_pending")
      end
      return encode_postage_policy(stored)
    end
    if U64.compare(candidate.revision, stored.revision) < 0
      || U64.compare(candidate.expected_device_set_revision,
        stored.expected_device_set_revision) <= 0 do
      return Err("postage_policy_changed")
    end
  end
  let encoded = encode_postage_policy(candidate)?
  let sealed = seal_local(encoded, wrapping, binding(account, device, config)?)?
  compare_and_swap_blobs(path, [label()], [sealed], previous)?
  Ok(encoded)
end
