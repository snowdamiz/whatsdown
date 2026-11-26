##! Mailbox extras paid in credits (protocol/credits-v1.md "Extras").
##!
##! - MBP, a mailbox policy: `mailbox_hash32 ‖ u64 sequence ‖ u8 postage ‖
##!   sig64`, signed by the device that owns the mailbox over
##!   "mesh-msg/v1/mailbox-policy" ‖ the frame without its signature. Postage is
##!   0, 1, 5 or 25 credits for an envelope reaching the device's public address.
##!   The directory stores and serves it but cannot sign one, so it cannot raise
##!   a price; a sender checks it under the device key from the logged device set.
##! - MRT, a storage request: `mailbox_hash32 ‖ u8 periods (1–5) ‖ u64
##!   issued_at_ms ‖ sig64`, signed over "mesh-msg/v1/mailbox-retention" ‖ the
##!   frame without its signature. Each period is 30 more days, for 10 credits.
##! - MRA, the core's answer to a storage purchase: `u16 retention_days ‖ u64
##!   entitled_until_ms`.
##! - PKC, the answer to a version 2 prekey claim: `vector32(PKB) ‖
##!   vector32(MBP or nothing)`.

from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)

pub struct MailboxPolicy do
  mailbox_hash :: Bytes
  sequence :: Int
  postage :: Int
  signature :: Bytes
end

pub struct MailboxRetention do
  mailbox_hash :: Bytes
  periods :: Int
  issued_at :: Int
  signature :: Bytes
end

pub fn credits_postage_valid(postage :: Int) -> Bool do
  postage == 0 || postage == 1 || postage == 5 || postage == 25
end

## 30 days more per period, on the 30 days every mailbox keeps.

pub fn credits_retention_days(periods :: Int) -> Int do
  30 + 30 * periods
end

pub fn credits_retention_price(periods :: Int) -> Int do
  10 * periods
end

fn header(magic :: String) -> Bytes!String do
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8(magic)])
end

fn policy_body(mailbox_hash :: Bytes, sequence :: Int, postage :: Int) -> Bytes!String do
  if Bytes.length(mailbox_hash) != 32 || sequence < 0 || !credits_postage_valid(postage) do
    Err("invalid mailbox policy")
  else
    tcodec_join([header("MBP")?, mailbox_hash, tcodec_u64(sequence)?, tcodec_u8(postage)?])
  end
end

fn signing_input(label :: String, body :: Bytes) -> Bytes!String do
  tcodec_join([Bytes.from_utf8(label), body])
end

fn sign(key :: borrow SigningPrivateKey, message :: Bytes) -> Bytes!String do
  case Crypto.sign(key, message) do
    Err(_) -> Err("mailbox signing failed")
    Ok(signature) -> Ok(signature.bytes)
  end
end

fn verified(public_key :: Bytes, message :: Bytes, signature :: Bytes) -> Bool do
  case Crypto.verify(SigningPublicKey { bytes: public_key },
    message,
    Signature { bytes: signature }) do
    Ok(valid) -> valid
    Err(_) -> false
  end
end

## A policy signed by the mailbox's own device key.

pub fn credits_sign_policy(key :: borrow SigningPrivateKey,
  mailbox_hash :: Bytes,
  sequence :: Int,
  postage :: Int) -> Bytes!String do
  let body = policy_body(mailbox_hash, sequence, postage)?
  tcodec_join([body, sign(key, signing_input("mesh-msg/v1/mailbox-policy", body)?)?])
end

pub fn credits_encode_policy(value :: MailboxPolicy) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    Err("invalid mailbox policy")
  else
    tcodec_join([policy_body(value.mailbox_hash, value.sequence, value.postage)?, value.signature])
  end
end

fn policy_from(input :: Bytes) -> MailboxPolicy!String do
  let hash = tcodec_take_fixed(tcodec_start(input, 109, 1, "MBP")?, 32)?
  let sequence = tcodec_take_u64(hash.state)?
  let postage = tcodec_take_u8(sequence.state)?
  let signature = tcodec_take_fixed(postage.state, 64)?
  tcodec_done(signature.state)?
  if !credits_postage_valid(postage.value) do
    Err("invalid postage")
  else
    Ok(MailboxPolicy {
      mailbox_hash: hash.value,
      sequence: sequence.value,
      postage: postage.value,
      signature: signature.value
    })
  end
end

pub fn credits_decode_policy(input :: Bytes) -> MailboxPolicy!String do
  case policy_from(input) do
    Err(_) -> Err("invalid mailbox policy")
    Ok(value)
  end
end

## Whether the device key `public_key` signed this policy.

pub fn credits_verify_policy(value :: MailboxPolicy, public_key :: Bytes) -> Bool do
  case policy_body(value.mailbox_hash, value.sequence, value.postage) do
    Err(_) -> false
    Ok(body) -> case signing_input("mesh-msg/v1/mailbox-policy", body) do
      Err(_) -> false
      Ok(message) -> verified(public_key, message, value.signature)
    end
  end
end

fn retention_body(mailbox_hash :: Bytes, periods :: Int, issued_at :: Int) -> Bytes!String do
  if Bytes.length(mailbox_hash) != 32 || periods < 1 || periods > 5 || issued_at < 0 do
    Err("invalid storage request")
  else
    tcodec_join([header("MRT")?, mailbox_hash, tcodec_u8(periods)?, tcodec_u64(issued_at)?])
  end
end

pub fn credits_sign_retention(key :: borrow SigningPrivateKey,
  mailbox_hash :: Bytes,
  periods :: Int,
  issued_at :: Int) -> Bytes!String do
  let body = retention_body(mailbox_hash, periods, issued_at)?
  tcodec_join([body, sign(key, signing_input("mesh-msg/v1/mailbox-retention", body)?)?])
end

fn retention_from(input :: Bytes) -> MailboxRetention!String do
  let hash = tcodec_take_fixed(tcodec_start(input, 109, 1, "MRT")?, 32)?
  let periods = tcodec_take_u8(hash.state)?
  let issued_at = tcodec_take_u64(periods.state)?
  let signature = tcodec_take_fixed(issued_at.state, 64)?
  tcodec_done(signature.state)?
  retention_body(hash.value, periods.value, issued_at.value)?
  Ok(MailboxRetention {
    mailbox_hash: hash.value,
    periods: periods.value,
    issued_at: issued_at.value,
    signature: signature.value
  })
end

pub fn credits_decode_retention(input :: Bytes) -> MailboxRetention!String do
  case retention_from(input) do
    Err(_) -> Err("invalid storage request")
    Ok(value)
  end
end

pub fn credits_verify_retention(value :: MailboxRetention, public_key :: Bytes) -> Bool do
  case retention_body(value.mailbox_hash, value.periods, value.issued_at) do
    Err(_) -> false
    Ok(body) -> case signing_input("mesh-msg/v1/mailbox-retention", body) do
      Err(_) -> false
      Ok(message) -> verified(public_key, message, value.signature)
    end
  end
end

pub fn credits_encode_claim_answer(bundle :: Bytes, policy :: Option<Bytes>) -> Bytes!String do
  let encoded = case policy do
    None -> Bytes.empty()
    Some(value) -> value
  end
  tcodec_join([header("PKC")?, tcodec_vector(bundle)?, tcodec_vector(encoded)?])
end

fn claim_from(input :: Bytes) -> (Bytes, Option<MailboxPolicy>)!String do
  let bundle = tcodec_take_vector(tcodec_start(input, 20000, 1, "PKC")?, 19312)?
  let policy = tcodec_take_vector(bundle.state, 109)?
  tcodec_done(policy.state)?
  if Bytes.length(policy.value) == 0 do
    Ok((bundle.value, None))
  else
    Ok((bundle.value, Some(credits_decode_policy(policy.value)?)))
  end
end

pub fn credits_decode_claim_answer(input :: Bytes) -> (Bytes, Option<MailboxPolicy>)!String do
  case claim_from(input) do
    Err(_) -> Err("invalid prekey claim answer")
    Ok(pair)
  end
end

pub fn credits_encode_retention_answer(days :: Int, until_ms :: Int) -> Bytes!String do
  if days < 60 || days > 180 || until_ms < 0 do
    Err("invalid storage answer")
  else
    case Bytes.write_u16_be(days) do
      Err(_) -> Err("invalid storage answer")
      Ok(encoded) -> tcodec_join([header("MRA")?, encoded, tcodec_u64(until_ms)?])
    end
  end
end

fn answer_from(input :: Bytes) -> (Int, Int)!String do
  let days = tcodec_take_fixed(tcodec_start(input, 14, 1, "MRA")?, 2)?
  let until_ms = tcodec_take_u64(days.state)?
  tcodec_done(until_ms.state)?
  case Bytes.read_u16_be(days.value, 0) do
    Err(_) -> Err("invalid storage answer")
    Ok(value) -> Ok((value, until_ms.value))
  end
end

## (retention days, entitled until in Unix ms).

pub fn credits_decode_retention_answer(input :: Bytes) -> (Int, Int)!String do
  case answer_from(input) do
    Err(_) -> Err("invalid storage answer")
    Ok(pair)
  end
end
