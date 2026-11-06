from Storage.TreasuryKeys import (
  TreasuryKeyRecord,
  validate_treasury_key_scope,
  load_treasury_key_records,
  insert_treasury_key
)

pub struct TreasuryOperationalKeys do
  fee_payer :: Bytes
  nonce_authority :: Bytes
end

fn key_context(service_key :: Bytes, purpose :: Int, role :: Int) -> Bytes!String do
  validate_treasury_key_scope(service_key, purpose)?
  if role != 0 && role != 1 do
    return Err("invalid_treasury_key_role")
  end
  let domain = Crypto.sha256(Bytes.from_utf8("morse-credit-treasury-operational-key-v1/"
    <> Int.to_string(purpose)
    <> "/"
    <> Int.to_string(role)))
  Bytes.from_hex("01"
    <> Bytes.to_hex(service_key)
    <> String.repeat("00", 48)
    <> Bytes.to_hex(domain)
    <> "00060000000000000001")
end

fn open_record(record :: TreasuryKeyRecord,
  service_key :: Bytes,
  purpose :: Int,
  wrapping :: borrow StorageKey) -> SigningPrivateKey!String do
  let key = case SigningPrivateKey.unseal_from_storage(record.sealed_key,
    wrapping,
    key_context(service_key, purpose, record.role)?) do
    Ok(value) -> value
    Err(_) -> return Err("treasury_operational_key_unavailable")
  end
  let challenge = Bytes.from_utf8("morse-credit-treasury-operational-key-binding-v1")
  let signature = case Crypto.sign(key, challenge) do
    Ok(value) -> value
    Err(_) -> return Err("treasury_operational_key_unavailable")
  end
  case Crypto.verify(SigningPublicKey { bytes: record.public_key }, challenge, signature) do
    Ok(true) -> Ok(key)
    _ -> Err("treasury_operational_key_mismatch")
  end
end

fn public_keys(records :: List<TreasuryKeyRecord>) -> TreasuryOperationalKeys!String do
  if List.length(records) != 2 do
    return Err("treasury_keys_not_provisioned")
  end
  Ok(TreasuryOperationalKeys {
    fee_payer: List.get(records, 0).public_key,
    nonce_authority: List.get(records, 1).public_key
  })
end

# Both roles are one durable transaction. Existing or damaged material is never
# replaced on retry. The wrapping-key callback is evaluated inside that lock.
pub fn provision_treasury_keys(pool :: PoolHandle,
  service_key :: Bytes,
  purpose :: Int,
  open_key :: Fun() -> Result<StorageKey, String>) -> TreasuryOperationalKeys!String do
  validate_treasury_key_scope(service_key, purpose)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365493)", [])?
      let records = load_treasury_key_records(conn, service_key, purpose)?
      let wrapping = open_key()?
      if List.length(records) == 2 do
        for record in records do
          let key = open_record(record, service_key, purpose, wrapping)?
          Secret.destroy(key)
        end
        return public_keys(records)
      end
      let created = for role in [0, 1] do
        let pair = case Crypto.signing_generate() do
          Ok(value) -> value
          Err(_) -> return Err("treasury_key_generation_failed")
        end
        let sealed = case SigningPrivateKey.seal_for_storage(pair.private_key,
          wrapping,
          key_context(service_key, purpose, role)?) do
          Ok(value) -> value
          Err(_) -> return Err("treasury_key_seal_failed")
        end
        let record = TreasuryKeyRecord {
          role: role,
          public_key: pair.public_key.bytes,
          sealed_key: sealed
        }
        insert_treasury_key(conn, service_key, purpose, record)?
        record
      end
      public_keys(created)
    end)
end

pub fn treasury_operational_keys(pool :: PoolHandle,
  service_key :: Bytes,
  purpose :: Int) -> TreasuryOperationalKeys!String do
  public_keys(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_treasury_key_records(conn, service_key, purpose) end)?)
end

pub fn open_treasury_signer(pool :: PoolHandle,
  service_key :: Bytes,
  purpose :: Int,
  role :: Int,
  expected :: Bytes,
  wrapping :: borrow StorageKey) -> SigningPrivateKey!String do
  key_context(service_key, purpose, role)?
  let records = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_treasury_key_records(conn, service_key, purpose) end)?
  public_keys(records)?
  let record = List.get(records, role)
  if !Bytes.secure_equals(record.public_key, expected) do
    return Err("treasury_operational_key_pin_mismatch")
  end
  open_record(record, service_key, purpose, wrapping)
end
