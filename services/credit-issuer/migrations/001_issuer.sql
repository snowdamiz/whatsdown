-- The credit issuer's own database (services/credit-issuer/README.md). It
-- holds quotes, payments, refunds, sweeps and its sealed signing keys. It
-- never learns a token, a nullifier or a redemption: those exist only in the
-- directory-delivery core, and no column here shares a name with the core's
-- spent set or holds (tests/linkability.test.mjs).

-- Signing keys, one per purpose and epoch (a new one only after a revocation).
-- sealed_key is the PKCS#8 key HPKE-sealed to the key-wrapping key; the SPKI
-- is what the transparency log announces.
CREATE TABLE issuer_keys (
  key_id BYTEA PRIMARY KEY CHECK (octet_length(key_id) = 32),
  purpose TEXT NOT NULL CHECK (purpose IN ('live', 'test')),
  epoch BIGINT NOT NULL CHECK (epoch BETWEEN 0 AND 4294967295),
  spki BYTEA NOT NULL CHECK (octet_length(spki) = 342),
  sealed_key BYTEA NOT NULL CHECK (octet_length(sealed_key) BETWEEN 1 AND 4096),
  provisioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  announced_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  CHECK (key_id = sha256(spki))
);

CREATE UNIQUE INDEX issuer_keys_unrevoked ON issuer_keys (purpose, epoch) WHERE revoked_at IS NULL;

-- Solana deposit addresses are derived per quote from this counter
-- (m/44'/501'/index'/0'); 2147483645 is the fee payer's.
CREATE SEQUENCE deposit_index_seq AS INTEGER MINVALUE 0 START WITH 0 MAXVALUE 2147483644 NO CYCLE;

-- A quote: what to pay, where, until when; then how it was settled.
CREATE TABLE quotes (
  quote_id BYTEA PRIMARY KEY CHECK (octet_length(quote_id) = 32),
  purpose TEXT NOT NULL CHECK (purpose IN ('live', 'test')),
  pack SMALLINT NOT NULL CHECK (pack BETWEEN 1 AND 3),
  batch INTEGER NOT NULL CHECK (batch IN (100, 500, 2000)),
  asset TEXT NOT NULL CHECK (asset IN ('usdc', 'sol', 'btc')),
  amount BIGINT NOT NULL CHECK (amount > 0),
  price_micro_usd BIGINT NOT NULL CHECK (price_micro_usd > 0),
  deposit_index INTEGER UNIQUE CHECK (deposit_index BETWEEN 0 AND 2147483644),
  deposit_address TEXT UNIQUE,
  invoice_hash BYTEA UNIQUE CHECK (invoice_hash IS NULL OR octet_length(invoice_hash) = 32),
  payment_request TEXT NOT NULL,
  quoted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'paid', 'issued', 'underpaid', 'late', 'refunded')),
  batch_hash BYTEA CHECK (batch_hash IS NULL OR octet_length(batch_hash) = 32),
  signing_key_id BYTEA REFERENCES issuer_keys (key_id),
  blind_signatures BYTEA,
  issued_at TIMESTAMPTZ,
  sweep_after TIMESTAMPTZ,
  sweep_signature TEXT,
  swept_at TIMESTAMPTZ,
  CHECK ((asset = 'btc') = (invoice_hash IS NOT NULL)),
  CHECK ((asset = 'btc') = (deposit_address IS NULL)),
  CHECK ((state = 'issued') = (issued_at IS NOT NULL)),
  CHECK (issued_at IS NULL OR (batch_hash IS NOT NULL AND signing_key_id IS NOT NULL AND blind_signatures IS NOT NULL))
);

CREATE INDEX quotes_due_sweeps ON quotes (sweep_after) WHERE swept_at IS NULL AND sweep_after IS NOT NULL;
CREATE INDEX quotes_issued_at ON quotes (issued_at) WHERE issued_at IS NOT NULL;

-- A verified payment. One transaction (or one Lightning invoice) pays one
-- quote. payer and payer_account are where a refund goes.
CREATE TABLE payments (
  tx_reference TEXT PRIMARY KEY,
  quote_id BYTEA NOT NULL UNIQUE REFERENCES quotes (quote_id),
  received BIGINT NOT NULL CHECK (received > 0),
  payer TEXT,
  payer_account TEXT,
  deposit_account TEXT,
  paid_at TIMESTAMPTZ NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A refund an operator confirmed (underpaid or late quotes only).
CREATE TABLE refunds (
  quote_id BYTEA PRIMARY KEY REFERENCES quotes (quote_id),
  refund_signature TEXT NOT NULL UNIQUE,
  refunded_amount BIGINT NOT NULL CHECK (refunded_amount > 0),
  destination TEXT NOT NULL,
  refunded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sweep transactions, each moving a batch of deposits to the treasury.
CREATE TABLE sweeps (
  sweep_signature TEXT PRIMARY KEY,
  asset TEXT NOT NULL CHECK (asset IN ('usdc', 'sol')),
  deposits INTEGER NOT NULL CHECK (deposits BETWEEN 1 AND 16),
  sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finalized_at TIMESTAMPTZ,
  failed_at TIMESTAMPTZ
);
