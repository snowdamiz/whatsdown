-- Immutable multi-payment packets. Existing single-payment journal stays valid.
CREATE TABLE issuer_treasury_batches (
  batch_id BYTEA PRIMARY KEY CHECK(octet_length(batch_id)=32),
  config_hash BYTEA NOT NULL CHECK(octet_length(config_hash)=32),
  member_hash BYTEA NOT NULL CHECK(octet_length(member_hash)=32),
  member_count SMALLINT NOT NULL CHECK(member_count BETWEEN 1 AND 4),
  state SMALLINT NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 4),
  nonce_address BYTEA CHECK(octet_length(nonce_address)=32),
  nonce_value BYTEA CHECK(octet_length(nonce_value)=32),
  message BYTEA CHECK(octet_length(message) BETWEEN 1 AND 1232),
  packet BYTEA CHECK(octet_length(packet) BETWEEN 1 AND 1232),
  transaction_signature BYTEA UNIQUE CHECK(octet_length(transaction_signature)=64),
  finalized_slot NUMERIC(20,0) CHECK(finalized_slot>0 AND finalized_slot<=18446744073709551615),
  execution_error TEXT CHECK(octet_length(execution_error)<=2048),
  fee NUMERIC(20,0) CHECK(fee>=0 AND fee<=18446744073709551615),
  rent NUMERIC(20,0) CHECK(rent>=0 AND rent<=18446744073709551615),
  CHECK((message IS NULL AND nonce_address IS NULL AND nonce_value IS NULL)
    OR(message IS NOT NULL AND nonce_address IS NOT NULL AND nonce_value IS NOT NULL)),
  CHECK((state=0 AND packet IS NULL AND transaction_signature IS NULL)
    OR(state IN(1,2,3,4) AND message IS NOT NULL AND packet IS NOT NULL AND transaction_signature IS NOT NULL)),
  CHECK((state IN(0,1,4) AND finalized_slot IS NULL AND fee IS NULL AND rent IS NULL AND execution_error IS NULL)
    OR(state=2 AND finalized_slot IS NOT NULL AND fee IS NOT NULL AND rent IS NOT NULL AND execution_error IS NULL)
    OR(state=3 AND finalized_slot IS NOT NULL AND fee IS NOT NULL AND rent=0 AND execution_error IS NOT NULL))
);
ALTER TABLE issuer_treasury_movements ADD COLUMN batch_id BYTEA REFERENCES issuer_treasury_batches(batch_id);
ALTER TABLE issuer_treasury_movements ADD COLUMN rent NUMERIC(20,0) NOT NULL DEFAULT 0 CHECK(rent>=0 AND rent<=18446744073709551615);
ALTER TABLE issuer_treasury_movements ADD CONSTRAINT issuer_move_batch_pair UNIQUE(movement_id,batch_id);
ALTER TABLE issuer_treasury_movements DROP CONSTRAINT issuer_treasury_movements_transaction_signature_key;
DROP INDEX issuer_treasury_active_nonce;
CREATE UNIQUE INDEX issuer_treasury_active_nonce ON issuer_treasury_movements(nonce_address)
  WHERE batch_id IS NULL AND nonce_address IS NOT NULL AND state IN(0,1,4);
CREATE TABLE issuer_treasury_batch_members (
  movement_id BYTEA PRIMARY KEY,
  batch_id BYTEA NOT NULL REFERENCES issuer_treasury_batches(batch_id),
  ordinal SMALLINT NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
  UNIQUE(batch_id,ordinal),
  FOREIGN KEY(movement_id,batch_id) REFERENCES issuer_treasury_movements(movement_id,batch_id)
);
CREATE TABLE issuer_treasury_nonce_lanes (
  nonce_address BYTEA PRIMARY KEY CHECK(octet_length(nonce_address)=32),
  owner_kind SMALLINT NOT NULL CHECK(owner_kind IN(0,1)),
  owner_id BYTEA NOT NULL CHECK(octet_length(owner_id)=32)
);
INSERT INTO issuer_treasury_nonce_lanes(nonce_address,owner_kind,owner_id)
  SELECT nonce_address,0,movement_id FROM issuer_treasury_movements
  WHERE nonce_address IS NOT NULL AND state IN(0,1,4);
CREATE TABLE issuer_treasury_batch_attempts (
  transaction_signature BYTEA PRIMARY KEY CHECK(octet_length(transaction_signature)=64),
  batch_id BYTEA NOT NULL REFERENCES issuer_treasury_batches(batch_id),
  nonce_address BYTEA NOT NULL CHECK(octet_length(nonce_address)=32),
  nonce_value BYTEA NOT NULL CHECK(octet_length(nonce_value)=32),
  message BYTEA NOT NULL CHECK(octet_length(message) BETWEEN 1 AND 1232),
  packet BYTEA NOT NULL CHECK(octet_length(packet) BETWEEN 1 AND 1232),
  state SMALLINT NOT NULL CHECK(state IN(1,2,3)),
  finalized_slot NUMERIC(20,0),execution_error TEXT,
  fee NUMERIC(20,0),rent NUMERIC(20,0),
  UNIQUE(batch_id,nonce_address,nonce_value),
  CHECK((state=1 AND finalized_slot IS NULL AND execution_error IS NULL AND fee IS NULL AND rent IS NULL)
    OR(state=2 AND finalized_slot>0 AND execution_error IS NULL AND fee>=0 AND rent>=0)
    OR(state=3 AND finalized_slot>0 AND execution_error IS NOT NULL AND fee>=0 AND rent=0))
);
CREATE TABLE issuer_treasury_batch_costs (
  transaction_signature BYTEA NOT NULL REFERENCES issuer_treasury_batch_attempts(transaction_signature),
  movement_id BYTEA NOT NULL REFERENCES issuer_treasury_batch_members(movement_id),
  fee NUMERIC(20,0) NOT NULL CHECK(fee>=0 AND fee<=18446744073709551615),
  rent NUMERIC(20,0) NOT NULL CHECK(rent>=0 AND rent<=18446744073709551615),
  PRIMARY KEY(transaction_signature,movement_id)
);
