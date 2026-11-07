from Identity.Device import AccountKeys
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import AccountIdentity, DeviceSet, PrekeyBundle, ProtocolExtension

# Account-owned mutable policy, independently signed rather than relying on
# unsigned prekey extensions. AccountIdentity bytes remain unchanged.
pub struct PostagePolicy do
  account_id :: Bytes
  publisher_device_id :: Bytes
  revision :: U64
  expected_device_set_revision :: U64
  credits :: Int
  issued_at_ms :: U64
  signature :: Bytes
end

pub fn postage_policy_extension_id() -> Int do
  3
end

fn policy_join(parts :: List<Bytes>) -> Bytes!String do
  let builder = case BytesBuilder.new(256) do
    Err(_) -> return Err("invalid_postage_policy")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_postage_policy")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_postage_policy")
    Ok(value)
  end
end

fn policy_wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_postage_policy")
    Ok(value)
  end
end

fn policy_number(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_postage_policy")
    Ok(value)
  end
end

pub fn encode_postage_policy(value :: PostagePolicy) -> Bytes!String do
  if Bytes.length(value.account_id) != 32
    || Bytes.to_hex(value.account_id) == String.repeat("00", 32)
    || Bytes.length(value.publisher_device_id) != 16
    || Bytes.to_hex(value.publisher_device_id) == String.repeat("00", 16)
    || value.revision == U64.parse("0")?
    || value.expected_device_set_revision == U64.parse("0")?
    || value.issued_at_ms == U64.parse("0")?
    || !List.contains([0, 1, 5, 25], value.credits)
    || Bytes.length(value.signature) != 64 do
    return Err("invalid_postage_policy")
  end
  let level = case Bytes.from_list([value.credits]) do
    Err(_) -> return Err("invalid_postage_policy")
    Ok(value) -> value
  end
  policy_join([
    Bytes.from_hex("01505059")?,
    value.account_id,
    value.publisher_device_id,
    policy_wide(value.revision)?,
    policy_wide(value.expected_device_set_revision)?,
    level,
    policy_wide(value.issued_at_ms)?,
    value.signature
  ])
end

pub fn decode_postage_policy(input :: Bytes) -> PostagePolicy!String do
  if Bytes.length(input) != 141 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01505059" do
    return Err("invalid_postage_policy")
  end
  let value = PostagePolicy {
    account_id: Bytes.slice(input, 4, 32)?,
    publisher_device_id: Bytes.slice(input, 36, 16)?,
    revision: policy_number(input, 52)?,
    expected_device_set_revision: policy_number(input, 60)?,
    credits: Bytes.get(input, 68)?,
    issued_at_ms: policy_number(input, 69)?,
    signature: Bytes.slice(input, 77, 64)?
  }
  encode_postage_policy(value)?
  Ok(value)
end

fn policy_signing_bytes(value :: PostagePolicy) -> Bytes!String do
  let zero = case Bytes.repeat(0, 64) do
    Err(_) -> return Err("invalid_postage_policy")
    Ok(value) -> value
  end
  policy_join([
    Bytes.from_utf8("morse-credit-postage-policy-v1"),
    encode_postage_policy(%{value | signature: zero})?
  ])
end

pub fn sign_postage_policy(owner :: borrow AccountKeys,
  publisher_device_id :: Bytes,
  revision :: U64,
  expected_device_set_revision :: U64,
  credits :: Int,
  issued_at_ms :: U64) -> PostagePolicy!String do
  let zero = case Bytes.repeat(0, 64) do
    Err(_) -> return Err("invalid_postage_policy")
    Ok(value) -> value
  end
  let value = PostagePolicy {
    account_id: owner.account_id,
    publisher_device_id: publisher_device_id,
    revision: revision,
    expected_device_set_revision: expected_device_set_revision,
    credits: credits,
    issued_at_ms: issued_at_ms,
    signature: zero
  }
  let signature = case Crypto.sign(owner.private_key, policy_signing_bytes(value)?) do
    Err(_) -> return Err("postage_policy_signing_failed")
    Ok(value) -> value
  end
  Ok(%{value | signature: signature.bytes})
end

# The account must come from the caller's authenticated witnessed snapshot or
# existing server registry. A self-supplied identity never establishes trust.
pub fn verify_postage_policy(value :: PostagePolicy, account :: AccountIdentity) -> Bool!String do
  encode_postage_policy(value)?
  if !Bytes.secure_equals(value.account_id, account.account_id)
    || Bytes.length(account.authorization_public_key) != 32 do
    return Ok(false)
  end
  case Crypto.verify(SigningPublicKey { bytes: account.authorization_public_key },
    policy_signing_bytes(value)?,
    Signature { bytes: value.signature }) do
    Err(_) -> Ok(false)
    Ok(value)
  end
end

pub fn strip_postage_policy_extension(bundle :: PrekeyBundle) -> PrekeyBundle do
  %{bundle |
    extensions: List.filter(bundle.extensions,
      fn(value) do value.id != postage_policy_extension_id() end)
  }
end

pub fn bundle_with_postage_policy(bundle :: PrekeyBundle,
  policy :: PostagePolicy) -> PrekeyBundle!String do
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> return Err("invalid_postage_policy_bundle")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(credential.account_id, policy.account_id) do
    return Err("invalid_postage_policy_bundle")
  end
  let extensions = strip_postage_policy_extension(bundle).extensions
    ++ [
      ProtocolExtension {
        id: postage_policy_extension_id(),
        mandatory: false,
        value: encode_postage_policy(policy)?
      }
    ]
  let ordered = List.sort(extensions,
    fn(left, right) do
      if left.id < right.id do
        -1
      else if left.id == right.id do
        0
      else
        1
      end
    end)
  let output = %{bundle | extensions: ordered}
  case encode_prekey_bundle(output) do
    Err(_) -> return Err("invalid_postage_policy_bundle")
    Ok(_) -> nil
  end
  Ok(output)
end

# This extracts a consistently mirrored, account-signed policy. It does not
# authenticate a raw DeviceSet: callers must verify its transparency evidence.
pub fn postage_policy_from_device_set(value :: DeviceSet) -> Option<PostagePolicy>!String do
  case encode_device_set(value) do
    Err(_) -> return Err("invalid_postage_policy_set")
    Ok(_) -> nil
  end
  let account = case decode_account_identity(value.account_identity) do
    Err(_) -> return Err("invalid_postage_policy_set")
    Ok(value) -> value
  end
  let policies = for entry in value.devices do
    let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
      Err(_) -> return Err("invalid_postage_policy_set")
      Ok(value) -> value
    end
    let policies = List.filter(bundle.extensions,
      fn(item) do item.id == postage_policy_extension_id() end)
    if List.length(policies) == 0 do
      Bytes.empty()
    else
      let encoded = List.head(policies).value
      decode_postage_policy(encoded)?
      encoded
    end
  end
  let present = List.filter(policies, fn(item) do Bytes.length(item) > 0 end)
  if List.length(present) == 0 do
    return Ok(None)
  end
  if List.length(present) != List.length(policies) do
    return Err("inconsistent_postage_policy_set")
  end
  let first = List.head(present)
  for policy in present do
    if !Bytes.secure_equals(policy, first) do
      return Err("inconsistent_postage_policy_set")
    end
  end
  let policy = decode_postage_policy(first)?
  if !verify_postage_policy(policy, account)?
    || U64.compare(policy.expected_device_set_revision, value.sequence) >= 0 do
    return Err("unverified_postage_policy_set")
  end
  Ok(Some(policy))
end
