from Credits.Issuance import encode_credit_quote
from Payment.Treasury import TreasuryChainConfig, treasury_message
from Storage.Treasury import TreasuryMovement
from Solana.Nonce import NonceAccountState
from Solana.Read import Signature
from Solana.Tx import serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction

pub fn sign_treasury_bytes(key :: borrow SigningPrivateKey, message :: Bytes) -> Signature!String do
  case Crypto.sign(key, message) do
    Ok(value)
    Err(_) -> Err("treasury_signing_unavailable")
  end
end

pub fn check_treasury_key(key :: borrow SigningPrivateKey, public :: Bytes) -> Result<(), String> do
  let challenge = Bytes.from_utf8("morse-credit-treasury-signer-binding-v1")
  let signed = sign_treasury_bytes(key, challenge)?
  let valid = case Crypto.verify(SigningPublicKey { bytes: public }, challenge, signed) do
    Ok(value) -> value
    Err(_) -> false
  end
  if !valid do
    return Err("treasury_signing_key_mismatch")
  end
  Ok(nil)
end

# The worker supplies opaque privileged signers, never byte seeds or a broad
# signing callback. Reconstruct and match the already durable intended message.
pub fn sign_treasury_packet(movement :: TreasuryMovement,
  config :: TreasuryChainConfig,
  nonce :: NonceAccountState,
  deposit :: borrow SigningPrivateKey,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey) -> Bytes!String do
  let message = treasury_message(movement, config, nonce)?
  let encoded = serialize_legacy_message(message)?
  if movement.state != 0
    || Bytes.length(movement.batch_id) != 0
    || !Bytes.secure_equals(encoded, movement.message) do
    return Err("treasury_message_not_reserved")
  end
  check_treasury_key(deposit, movement.quote.deposit_owner)?
  check_treasury_key(fee_payer, config.fee_payer)?
  check_treasury_key(nonce_authority, config.nonce_authority)?
  let signatures = for index in 0..message.header.num_required_signatures do
    let public = List.get(message.account_keys, index).bytes
    if Bytes.secure_equals(public, config.fee_payer) do
      sign_treasury_bytes(fee_payer, encoded)?
    else if Bytes.secure_equals(public, config.nonce_authority) do
      sign_treasury_bytes(nonce_authority, encoded)?
    else if Bytes.secure_equals(public, movement.quote.deposit_owner) do
      sign_treasury_bytes(deposit, encoded)?
    else
      return Err("unexpected_treasury_signer")
    end
  end
  serialize_signed_legacy_transaction(message, signatures)
end

pub fn load_treasury_deposit_sealed(conn :: borrow PgConn,
  movement :: TreasuryMovement) -> Bytes!String do
  let rows = Pg.query_values(conn,
    "SELECT quote,sealed_deposit_key FROM issuer_quotes WHERE quote_id=$1",
    [Binary(movement.quote.quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let row = List.head(rows)
  let stored_quote = case Map.get(row, "quote") do
    Binary(value) -> value
    _ -> return Err("invalid_treasury_row")
  end
  if !Bytes.secure_equals(stored_quote, encode_credit_quote(movement.quote)?) do
    return Err("treasury_deposit_quote_mismatch")
  end
  case Map.get(row, "sealed_deposit_key") do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_treasury_row")
  end
end

pub fn unseal_treasury_deposit_key(sealed :: Bytes,
  movement :: TreasuryMovement,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> SigningPrivateKey!String do
  if Bytes.length(service_key) != 32 do
    return Err("invalid_treasury_storage_context")
  end
  let context = Bytes.from_hex("01"
    <> Bytes.to_hex(service_key)
    <> String.repeat("00", 48)
    <> Bytes.to_hex(movement.quote.quote_id)
    <> "00060000000000000001")?
  let deposit = case SigningPrivateKey.unseal_from_storage(sealed, wrapping, context) do
    Ok(value) -> value
    Err(_) -> return Err("treasury_deposit_key_unavailable")
  end
  check_treasury_key(deposit, movement.quote.deposit_owner)?
  Ok(deposit)
end
