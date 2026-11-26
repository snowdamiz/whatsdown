##! Morse credit tokens: Privacy Pass tokens of type 0x0002 (RFC 9577 §2,
##! RFC 9578 §6), blind RSA with 2,048-bit keys. One token is one credit.
##!
##! This module is bytes only, so every consumer of the protocol package still
##! builds without `Crypto.BlindRsa`; verifying a token's signature lives in
##! `Credits.CreditCrypto` (packages/messenger-credits).
##!
##! - TokenChallenge: u16 token_type ‖ u16-length issuer_name ‖ u8-length
##!   redemption_context (0 or 32) ‖ u16-length origin_info.
##! - Morse's challenge: token_type 2, issuer_name = the issuer origin's host,
##!   an empty redemption context, origin_info "morseapp.io". Every Morse token
##!   of one issuer carries the same challenge digest.
##! - Token (354 bytes): u16 2 ‖ nonce32 ‖ SHA-256(challenge) ‖ token_key_id32 ‖
##!   authenticator256. The first 98 bytes are the token input the issuer
##!   blind-signs; token_key_id = SHA-256(the key's 342-byte SPKI).
##! - Nullifier: SHA-256(token input), what a redeemer records as spent.

from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, reader
from Transparency.Codec import tcodec_join, tcodec_u16, tcodec_u8

pub struct CreditChallenge do
  token_type :: Int
  issuer_name :: String
  redemption_context :: Bytes
  origin_info :: String
end

pub struct CreditToken do
  nonce :: Bytes
  challenge_digest :: Bytes
  token_key_id :: Bytes
  authenticator :: Bytes
end

pub fn credits_token_type() -> Int do
  2
end

pub fn credits_origin_info() -> String do
  "morseapp.io"
end

pub fn credits_token_size() -> Int do
  354
end

pub fn credits_input_size() -> Int do
  98
end

# A hostname: lowercase letters, digits, '-' and '.', 1 to 253 bytes, no
# leading or trailing dot.

pub fn credits_valid_host(host :: String) -> Bool do
  let bytes = Bytes.to_list(Bytes.from_utf8(host))
  List.length(bytes) > 0
    && List.length(bytes) <= 253
    && List.all(bytes,
      fn byte -> byte >= 97 && byte <= 122
        || byte >= 48 && byte <= 57
        || byte == 45
        || byte == 46 end)
    && !String.starts_with(host, ".")
    && !String.ends_with(host, ".")
end

## The issuer name for an issuer origin as the security config pins it:
## `https://<host>`, nothing else.

pub fn credits_issuer_name(origin :: String) -> String!String do
  if !String.starts_with(origin, "https://") do
    Err("invalid credit issuer origin")
  else
    let host = String.slice(origin, 8, String.length(origin))
    if credits_valid_host(host) do
      Ok(host)
    else
      Err("invalid credit issuer origin")
    end
  end
end

fn text_field(value :: String, maximum :: Int) -> Bytes!String do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) > maximum do
    Err("credit challenge field too long")
  else
    tcodec_join([tcodec_u16(Bytes.length(bytes))?, bytes])
  end
end

pub fn credits_encode_challenge(value :: CreditChallenge) -> Bytes!String do
  let context_length = Bytes.length(value.redemption_context)
  if value.token_type < 0 || value.token_type > 65535 do
    Err("invalid credit challenge")
  else if context_length != 0 && context_length != 32 do
    Err("invalid credit challenge")
  else if String.length(value.issuer_name) == 0 do
    Err("invalid credit challenge")
  else
    tcodec_join([
      tcodec_u16(value.token_type)?,
      text_field(value.issuer_name, 65535)?,
      tcodec_u8(context_length)?,
      value.redemption_context,
      text_field(value.origin_info, 65535)?
    ])
  end
end

fn take_u16(state :: BinaryReader) -> (BinaryReader, Int)!String do
  case read_u16_be(state) do
    Err(_) -> Err("invalid credit token")
    Ok(pair)
  end
end

fn take(state :: BinaryReader, length :: Int) -> (BinaryReader, Bytes)!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid credit token")
    Ok(pair)
  end
end

fn take_text(state :: BinaryReader) -> (BinaryReader, String)!String do
  let (after_length, length) = take_u16(state)?
  let (next, bytes) = take(after_length, length)?
  case Bytes.to_utf8(bytes) do
    Err(_) -> Err("invalid credit token")
    Ok(text) -> Ok((next, text))
  end
end

fn challenge_from(state :: BinaryReader) -> CreditChallenge!String do
  let (after_type, token_type) = take_u16(state)?
  let (after_issuer, issuer_name) = take_text(after_type)?
  let (after_length, context_length) = case read_u8(after_issuer) do
    Err(_) -> Err("invalid credit token")
    Ok(pair)
  end?
  if context_length != 0 && context_length != 32 || String.length(issuer_name) == 0 do
    Err("invalid credit challenge")
  else
    let (after_context, context) = take(after_length, context_length)?
    let (last, origin_info) = take_text(after_context)?
    case finish(last) do
      Err(_) -> Err("invalid credit token")
      Ok(_) -> Ok(CreditChallenge {
        token_type: token_type,
        issuer_name: issuer_name,
        redemption_context: context,
        origin_info: origin_info
      })
    end
  end
end

## Decodes a TokenChallenge (RFC 9577 §2.1), refusing trailing bytes.

pub fn credits_decode_challenge(input :: Bytes) -> CreditChallenge!String do
  case reader(input, 196611) do
    Err(_) -> Err("invalid credit token")
    Ok(state) -> challenge_from(state)
  end
end

## Morse's challenge for tokens of the issuer named `issuer_name` (a host).

pub fn credits_challenge(issuer_name :: String) -> Bytes!String do
  if !credits_valid_host(issuer_name) do
    Err("invalid credit issuer name")
  else
    credits_encode_challenge(CreditChallenge {
      token_type: credits_token_type(),
      issuer_name: issuer_name,
      redemption_context: Bytes.empty(),
      origin_info: credits_origin_info()
    })
  end
end

pub fn credits_challenge_digest(issuer_name :: String) -> Bytes!String do
  Ok(Crypto.sha256(credits_challenge(issuer_name)?))
end

pub fn credits_token_key_id(spki :: Bytes) -> Bytes do
  Crypto.sha256(spki)
end

## The 98 bytes the issuer blind-signs.

pub fn credits_token_input(nonce :: Bytes,
  challenge_digest :: Bytes,
  token_key_id :: Bytes) -> Bytes!String do
  if Bytes.length(nonce) != 32
    || Bytes.length(challenge_digest) != 32
    || Bytes.length(token_key_id) != 32 do
    Err("invalid credit token input")
  else
    tcodec_join([tcodec_u16(credits_token_type())?, nonce, challenge_digest, token_key_id])
  end
end

pub fn credits_encode_token(value :: CreditToken) -> Bytes!String do
  if Bytes.length(value.authenticator) != 256 do
    Err("invalid credit token")
  else
    tcodec_join([
      credits_token_input(value.nonce, value.challenge_digest, value.token_key_id)?,
      value.authenticator
    ])
  end
end

fn token_from(state :: BinaryReader) -> CreditToken!String do
  let (after_type, token_type) = take_u16(state)?
  let (after_nonce, nonce) = take(after_type, 32)?
  let (after_digest, digest) = take(after_nonce, 32)?
  let (after_key, key_id) = take(after_digest, 32)?
  let (last, authenticator) = take(after_key, 256)?
  if token_type != credits_token_type() do
    Err("unsupported credit token type")
  else
    case finish(last) do
      Err(_) -> Err("invalid credit token")
      Ok(_) -> Ok(CreditToken {
        nonce: nonce,
        challenge_digest: digest,
        token_key_id: key_id,
        authenticator: authenticator
      })
    end
  end
end

## Decodes exactly one 354-byte token of type 0x0002.

pub fn credits_decode_token(input :: Bytes) -> CreditToken!String do
  if Bytes.length(input) != credits_token_size() do
    Err("invalid credit token")
  else
    case reader(input, credits_token_size()) do
      Err(_) -> Err("invalid credit token")
      Ok(state) -> token_from(state)
    end
  end
end

## SHA-256 of the token input: the value a redeemer marks as spent.

pub fn credits_nullifier(token :: Bytes) -> Bytes!String do
  let value = credits_decode_token(token)?
  Ok(Crypto.sha256(credits_token_input(value.nonce, value.challenge_digest, value.token_key_id)?))
end
