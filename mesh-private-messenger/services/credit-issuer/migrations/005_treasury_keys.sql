-- Operational signers are generated explicitly. Only wrapped opaque keys leave
-- the Mesh secret runtime; there is no seed export or automatic key rotation.
CREATE TABLE issuer_treasury_keys (
  service_key BYTEA NOT NULL CHECK(octet_length(service_key)=32),
  purpose SMALLINT NOT NULL CHECK(purpose IN(0,1)),
  role SMALLINT NOT NULL CHECK(role IN(0,1)), -- fee payer / nonce authority
  public_key BYTEA NOT NULL CHECK(octet_length(public_key)=32),
  sealed_key BYTEA NOT NULL CHECK(octet_length(sealed_key) BETWEEN 68 AND 1024),
  PRIMARY KEY(service_key,purpose,role),
  UNIQUE(public_key)
);
