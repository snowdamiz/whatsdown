from Credits.Policy import issuer_epoch_accepted
from Transparency.Client import verify_evidence, checkpoint_fresh_at
from Transparency.Merkle import WitnessKey, verify_witnesses_at
from Transparency.Wire import TransparencyEvidence

pub struct CreditIssuerKey do
  epoch :: U64
  # 0 = live, 1 = test. Separate keys are mandatory for these two purposes.
  purpose :: Int
  spki :: Bytes
  quote_public_key :: Bytes
end

pub fn issuer_public_key(value :: CreditIssuerKey) -> BlindRsaPublicKey!String do
  if (value.purpose != 0 && value.purpose != 1)
    || Bytes.length(value.quote_public_key) != 32
    || Bytes.to_hex(value.quote_public_key) == String.repeat("00", 32) do
    return Err("invalid_credit_issuer_purpose")
  end
  case Crypto.blind_rsa_public_from_spki(value.spki) do
    Err(_) -> Err("invalid_credit_issuer_key")
    Ok(key)
  end
end

pub fn issuer_key_id(value :: CreditIssuerKey) -> Bytes!String do
  issuer_public_key(value)?
  Ok(Crypto.sha256(value.spki))
end

pub fn encode_issuer_key(value :: CreditIssuerKey) -> Bytes!String do
  issuer_public_key(value)?
  let epoch = case Bytes.write_u64_be(value.epoch) do
    Err(_) -> return Err("invalid_credit_issuer_epoch")
    Ok(encoded) -> encoded
  end
  let purpose = case Bytes.from_list([value.purpose]) do
    Err(_) -> return Err("invalid_credit_issuer_purpose")
    Ok(encoded) -> encoded
  end
  Bytes.concat(Bytes.concat(Bytes.from_hex("02494b59")?, epoch)?,
    Bytes.concat(Bytes.concat(purpose, value.spki)?, value.quote_public_key)?)
end

pub fn decode_issuer_key(input :: Bytes) -> CreditIssuerKey!String do
  if Bytes.length(input) != 387 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "02494b59" do
    return Err("invalid_credit_issuer_leaf")
  end
  let epoch = case Bytes.read_u64_be(input, 4) do
    Err(_) -> return Err("invalid_credit_issuer_epoch")
    Ok(value) -> value
  end
  let value = CreditIssuerKey {
    epoch: epoch,
    purpose: Bytes.get(input, 12)?,
    spki: Bytes.slice(input, 13, 342)?,
    quote_public_key: Bytes.slice(input, 355, 32)?
  }
  issuer_public_key(value)?
  Ok(value)
end

# This is the network trust boundary. A raw SPKI or a successful RSA verification
# alone never admits an issuer. The checkpoint must extend the caller's cache.
pub fn verify_issuer_key(evidence :: TransparencyEvidence,
  trusted_service_key :: SigningPublicKey,
  trusted_witnesses :: List<WitnessKey>,
  witness_threshold :: Int,
  previous_checkpoint_bytes :: Bytes,
  now_seconds :: U64,
  purpose :: Int) -> CreditIssuerKey!String do
  if witness_threshold < 1
    || evidence.checkpoint.version != 2
    || !checkpoint_fresh_at(evidence.checkpoint.timestamp,
      U64.multiply(now_seconds, U64.parse("1000")?)?)
    || !verify_evidence(evidence,
      trusted_service_key,
      trusted_witnesses,
      witness_threshold,
      previous_checkpoint_bytes)?
    || !verify_witnesses_at(evidence.checkpoint,
      evidence.witnesses,
      trusted_witnesses,
      witness_threshold,
      U64.multiply(now_seconds, U64.parse("1000")?)?)? do
    return Err("unverified_credit_issuer")
  end
  let key = decode_issuer_key(evidence.entry_bytes)?
  if key.purpose != purpose || !issuer_epoch_accepted(key.epoch, now_seconds)? do
    return Err("inactive_credit_issuer")
  end
  Ok(key)
end

# Call only after verify_issuer_key. Retain both acceptance epochs, and refuse
# silent replacement of any key already authenticated for an epoch/purpose.
pub fn retain_issuer_key(previous :: List<CreditIssuerKey>,
  admitted :: CreditIssuerKey,
  now_seconds :: U64,
  purpose :: Int) -> List<CreditIssuerKey>!String do
  issuer_public_key(admitted)?
  if List.length(previous) > 2
    || admitted.purpose != purpose
    || !issuer_epoch_accepted(admitted.epoch, now_seconds)? do
    return Err("inactive_credit_issuer")
  end
  for index in 0..List.length(previous) do
    let key = List.get(previous, index)
    issuer_public_key(key)?
    if key.purpose != purpose do
      return Err("invalid_credit_issuer_cache")
    end
    if key.epoch == admitted.epoch
      && (!Bytes.secure_equals(key.spki, admitted.spki)
        || !Bytes.secure_equals(key.quote_public_key, admitted.quote_public_key)) do
      return Err("credit_issuer_changed")
    end
    for earlier in 0..index do
      if List.get(previous, earlier).epoch == key.epoch do
        return Err("invalid_credit_issuer_cache")
      end
    end
  end
  let retained = List.filter(previous,
    fn(key) do key.epoch != admitted.epoch
      && case issuer_epoch_accepted(key.epoch, now_seconds) do
        Ok(active) -> active
        Err(_) -> false
      end end)
  Ok([admitted] ++ retained)
end
