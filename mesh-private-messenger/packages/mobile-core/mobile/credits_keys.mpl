from Credits.CreditToken import credits_issuer_name
from Credits.IssuerKey import (
  IssuerKey,
  credits_decode_issuer_key,
  credits_decode_issuer_keys,
  credits_key_valid_at,
  credits_leaf_kind
)
from Mobile.CreditsBuy import (
  CreditPurchase,
  credits_fields,
  credits_http,
  credits_issuer_origin,
  credits_load_purchases,
  credits_now,
  credits_path,
  credits_purchases_write,
  credits_service_url,
  credits_state_issued,
  credits_state_reissue,
  credits_store_writes
)
from Mobile.CreditsStore import (
  CreditKeys,
  credits_clock,
  credits_key_id,
  credits_keys_write,
  credits_load_keys,
  credits_load_shelves,
  credits_merge_writes,
  credits_prune_shelves,
  credits_shelves_write
)
from Mobile.Oblivious import oblivious_exchange, oblivious_pin
from Mobile.Platform import native_security_config
from Mobile.Transparency import load_transparency_view, transparency_checkpoint_bytes
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig, security_config_witness_keys
from Storage.Keys import platform_key
from Transparency.Client import checkpoint_fresh_at, transparency_verify_evidence_v2
from Transparency.CompactWire import TransparencyEvidenceV2, transparency_decode_evidence_v2
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint
from Transparency.Codec import tcodec_u8

##! Mobile.CreditsKeys: the issuer keys this device spends and blinds for
##! (protocol/credits-v1.md "Issuer keys in the transparency log").
##!
##! Every key in the directory's listing comes with KTE v2 evidence. A key
##! counts only when that evidence verifies under the pinned service key and
##! witnesses and is consistent with the log this device has already seen, so
##! the issuer cannot give one person a key of its own to tag their tokens.
##!
##! Which keys a build accepts follows from the issuer origin it pins, which
##! only a new release changes (plan I3, §11.1): a build that pins Morse's
##! production issuer takes `live` keys only; every other build (local,
##! staging) takes `test` keys only. Keys of another issuer are ignored.
##!
##! A key that leaves the listing before its window ends was revoked, as far as
##! this device can tell: its tokens stop being spent (but are kept, in case a
##! listing only left it out) and the purchases it signed can be collected
##! again. They go when the key's window ends.

pub fn credits_production_origin() -> String do
  "https://credits.morseapp.io"
end

## 1 live for a build that pins the production issuer, else 2 test.

pub fn credits_build_purpose(origin :: String) -> Int do
  if origin == credits_production_origin() do
    1
  else
    2
  end
end

fn previous_size(checkpoint :: Bytes) -> Int!String do
  if Bytes.length(checkpoint) == 0 do
    Ok(0)
  else
    U64.to_int(decode_checkpoint(checkpoint)?.tree_size)
  end
end

fn logged_key(evidence :: Bytes,
  config :: MobileSecurityConfig,
  previous :: Bytes,
  now :: U64) -> Option<IssuerKey>!String do
  case transparency_decode_evidence_v2(evidence) do
    Err(_) -> Ok(None)
    Ok(value) -> do
      let verified = case transparency_verify_evidence_v2(value,
        SigningPublicKey { bytes: config.transparency_service_public_key },
        security_config_witness_keys(config.config),
        config.config.threshold,
        config.config.c2sp_origin,
        previous,
        now) do
        Err(_) -> false
        Ok(valid) -> valid
      end
      if !verified
        || !checkpoint_fresh_at(value.checkpoint.timestamp, now)
        || credits_leaf_kind(value.entry_bytes) != 2 do
        Ok(None)
      else
        case credits_decode_issuer_key(value.entry_bytes) do
          Err(_) -> Ok(None)
          Ok(key) -> Ok(Some(key))
        end
      end
    end
  end
end

fn wanted(key :: IssuerKey, issuer_name :: String, purpose :: Int, now :: Int) -> Bool do
  key.issuer_name == issuer_name && key.purpose == purpose && credits_key_valid_at(key, now)
end

fn listed_in(keys :: List<IssuerKey>, key_id :: Bytes) -> Bool do
  List.any(keys, fn kept -> Bytes.secure_equals(credits_key_id(kept), key_id) end)
end

# Keys seen before, gone from this listing inside their window: revoked, as
# far as this device can tell. Their tokens wait (unspent) in case they come back.

fn retired_keys(before :: CreditKeys, listed :: List<IssuerKey>, now :: Int) -> List<IssuerKey> do
  List.reduce(before.keys ++ before.retired,
    List.new(),
    fn found, key -> if !credits_key_valid_at(key, now)
      || listed_in(listed, credits_key_id(key))
      || listed_in(found, credits_key_id(key)) do
      found
    else
      List.append(found, key)
    end end)
end

# A purchase whose key was retired can be collected again (the issuer signs a
# new batch for a revoked key's quote); one whose key is listed again is issued.

fn reissued(values :: List<CreditPurchase>,
  retired :: List<IssuerKey>,
  listed :: List<IssuerKey>) -> List<CreditPurchase> do
  List.map(values,
    fn value -> if value.state == credits_state_issued() && listed_in(retired, value.key_id) do
      %{value | state: credits_state_reissue()}
    else if value.state == credits_state_reissue() && listed_in(listed, value.key_id) do
      %{value | state: credits_state_issued()}
    else
      value
    end end)
end

## Accepts the keys of a CIK listing: only logged, current keys of this
## build's issuer and purpose. Returns how many it holds now.

pub fn credits_accept_listing(path :: String, listing :: Bytes) -> Int!String do
  let config = native_security_config()?
  let origin = credits_issuer_origin()?
  let issuer_name = credits_issuer_name(origin)?
  let purpose = credits_build_purpose(origin)
  let wrapping_key = platform_key()?
  let previous = transparency_checkpoint_bytes(path, wrapping_key)?
  if Bytes.length(previous) > 0
    && !Bytes.secure_equals(load_transparency_view(path, wrapping_key)?.service_public_key,
      config.transparency_service_public_key) do
    return Err("transparency_trust_mismatch")
  end
  let evidence = case credits_decode_issuer_keys(listing) do
    Err(_) -> Err("credits_keys_invalid")
    Ok(value)
  end?
  let now_wide = credits_clock()?
  let now = credits_now()
  let found = for item in evidence do
    logged_key(item, config, previous, now_wide)?
  end
  let accepted = List.filter(List.flat_map(found,
      fn value -> case value do
        Some(key) -> [key]
        None -> List.new()
      end end),
    fn key -> wanted(key, issuer_name, purpose, now) end)
  let before = credits_load_keys(path, wrapping_key)?
  let retired = retired_keys(before, accepted, now)
  let (shelves, dropped) = credits_prune_shelves(credits_load_shelves(path, wrapping_key)?,
    accepted ++ retired,
    now)
  let purchases = reissued(credits_load_purchases(path, wrapping_key)?, retired, accepted)
  credits_store_writes(path,
    credits_merge_writes(credits_merge_writes(credits_keys_write(CreditKeys {
            fetched_at: now,
            keys: accepted,
            retired: retired
          },
          wrapping_key)?,
        credits_merge_writes(credits_shelves_write(shelves, wrapping_key)?, dropped)),
      credits_purchases_write(purchases, wrapping_key)?))?
  Ok(List.length(accepted))
end

## Fetches the directory's issuer-key listing, consistent from this device's
## view of the log, and accepts it. Request: vector32(path) ||
## vector32(directory URL). Answer: u8 the number of keys held.

pub fn credits_refresh_keys(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 2)?
  let path = credits_path(List.get(fields, 0))?
  let directory = credits_service_url(List.get(fields, 1))?
  credits_issuer_origin()?
  let previous = transparency_checkpoint_bytes(path, platform_key()?)?
  let size = previous_size(previous)?
  let target = "/v1/credits/issuer-keys?previous_tree_size=" <> Int.to_string(size)
  # Through the privacy edge when the build pins an OHTTP gateway.
  let (status, body) = case oblivious_pin()? do
    Some(pin) -> case oblivious_exchange(pin, "GET", target, Bytes.empty(), 15000) do
      Err(_) -> Err("credits_network")
      Ok(value)
    end?
    None -> do
      let answer = credits_http("GET", directory <> target, Bytes.empty(), 262144)?
      (answer.status, answer.body)
    end
  end
  if status != 200 || Bytes.length(body) > 262144 do
    Err("credits_keys_unavailable")
  else
    tcodec_u8(credits_accept_listing(path, body)?)
  end
end
