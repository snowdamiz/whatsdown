from Credits.Postage import (
  CreditPostageRequest,
  CreditPostageResult,
  encode_credit_postage_request,
  decode_credit_postage_request,
  credit_postage_action,
  credit_postage_effect_id,
  credit_postage_request_for_devices,
  encode_credit_postage_result,
  verify_credit_postage_receipt
)
from Credits.PostagePolicy import sign_postage_policy, bundle_with_postage_policy
from Credits.ActionWire import CreditActionSubmission, sign_credit_action_receipt
from Credits.Wire import CreditToken, CreditTokenInput, CreditFrame
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import generate_signed_prekey, generate_one_time_prekey, build_prekey_bundle
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, PrekeyBundle
from Privacy.Edge import SealedDelivery, encode_sealed_delivery

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn bundle(owner :: borrow AccountKeys, device :: borrow DeviceKeys) -> PrekeyBundle!String do
  let credential = case issue_device_credential(owner,
    device,
    U64.parse("1")?,
    U64.parse("1000")?,
    U64.parse("2000000")?,
    U64.parse("1")?) do
    Err(_) -> return Err("test credential failed")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device,
    credential,
    U64.parse("1")?,
    U64.parse("2000000")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("1")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  case build_prekey_bundle(credential, signed, once) do
    Err(_) -> Err("test bundle failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let (owner, identity) = case generate_account(U64.parse("1000")?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let device = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  let reply = case Crypto.x25519_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let policy = sign_postage_policy(owner,
    device.device_id,
    U64.parse("1")?,
    U64.parse("1")?,
    1,
    U64.parse("1000000")?)?
  let encoded_identity = case encode_account_identity(identity) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let encoded_bundle = case encode_prekey_bundle(bundle_with_postage_policy(bundle(owner, device)?,
    policy)?) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let devices = DeviceSet {
    version: 1,
    username: "postage-owner",
    account_identity: encoded_identity,
    sequence: U64.parse("2")?,
    devices: [
      DirectoryEntry {
        version: 1,
        username: "postage-owner",
        account_identity: encoded_identity,
        prekey_bundle: encoded_bundle,
        mailbox_token: bytes(31, 32)?
      }
    ],
    revoked_device_ids: []
  }
  let deliveries = [
    encode_sealed_delivery(SealedDelivery {
      ephemeral_public_key: bytes(41, 32)?,
      nonce: bytes(42, 12)?,
      ciphertext: bytes(43, 512)?
    })?
  ]
  let request = credit_postage_request_for_devices(devices,
    deliveries,
    bytes(51, 32)?,
    reply.public_key,
    U64.parse("1600")?)?
  let encoded = encode_credit_postage_request(request)?
  assert(Bytes.length(encoded) == 188)
  assert(Bytes.secure_equals(encode_credit_postage_request(decode_credit_postage_request(encoded)?)?,
    encoded))
  let maximum = %{request |
    policy_revision: U64.parse("18446744073709551615")?,
    device_set_revision: U64.parse("18446744073709551615")?,
    action_expires_at: U64.parse("18446744073709551615")?
  }
  assert(decode_credit_postage_request(encode_credit_postage_request(maximum)?)?.policy_revision == maximum.policy_revision)
  assert(Result.is_err(decode_credit_postage_request(Bytes.concat(encoded, bytes(0, 1)?)?)))
  assert(Result.is_err(encode_credit_postage_request(%{request | reply_public_key: bytes(0, 32)?})))
  let changed_reply = credit_postage_action(%{request | reply_public_key: bytes(52, 32)?})?
  let action = credit_postage_action(request)?
  assert(!Bytes.secure_equals(changed_reply.request_sha256, action.request_sha256))
  let frame = CreditFrame {
    binding: Crypto.sha256(encoded),
    tokens: [
      CreditToken {
        input: CreditTokenInput {
          nonce: bytes(61, 32)?,
          challenge_digest: bytes(62, 32)?,
          token_key_id: bytes(63, 32)?
        },
        authenticator: bytes(64, 256)?
      }
    ]
  }
  let submission = CreditActionSubmission { action: action, request_body: encoded, frame: frame }
  let result = CreditPostageResult {
    recipient_account_id: request.recipient_account_id,
    batch_digest: request.batch_digest,
    policy_revision: request.policy_revision,
    device_set_revision: request.device_set_revision,
    enqueued_count: 1,
    charged_credits: 1
  }
  let receipt = sign_credit_action_receipt(signer.private_key,
    submission,
    credit_postage_effect_id(action)?,
    U64.parse("1000")?,
    encode_credit_postage_result(result)?)?
  assert(verify_credit_postage_receipt(receipt,
    signer.public_key,
    submission,
    devices,
    deliveries)?)
  let wrong_count = sign_credit_action_receipt(signer.private_key,
    submission,
    receipt.effect_id,
    receipt.applied_at,
    encode_credit_postage_result(%{result | enqueued_count: 2})?)?
  assert(!verify_credit_postage_receipt(wrong_count,
    signer.public_key,
    submission,
    devices,
    deliveries)?)
  let wrong_price = sign_credit_action_receipt(signer.private_key,
    submission,
    receipt.effect_id,
    receipt.applied_at,
    encode_credit_postage_result(%{result | charged_credits: 5})?)?
  assert(!verify_credit_postage_receipt(wrong_price,
    signer.public_key,
    submission,
    devices,
    deliveries)?)
  let expired = sign_credit_action_receipt(signer.private_key,
    submission,
    receipt.effect_id,
    request.action_expires_at,
    receipt.result)?
  assert(!verify_credit_postage_receipt(expired,
    signer.public_key,
    submission,
    devices,
    deliveries)?)
  assert(!verify_credit_postage_receipt(receipt,
    signer.public_key,
    submission,
    %{devices | sequence: U64.parse("3")?},
    deliveries)?)
  assert(Result.is_err(verify_credit_postage_receipt(receipt,
    signer.public_key,
    %{submission | frame: %{frame | tokens: frame.tokens ++ frame.tokens}},
    devices,
    deliveries)))
  Ok(true)
end

test("postage binds one full recipient snapshot, reply key, frame and exact enqueue result") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
