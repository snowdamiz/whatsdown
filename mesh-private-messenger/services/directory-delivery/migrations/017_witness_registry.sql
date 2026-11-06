-- Registry membership never grants client trust. Native releases pin keys.
CREATE TABLE transparency_witness_registry (
  witness_id TEXT PRIMARY KEY CHECK (witness_id ~ '^[a-z0-9-]{1,64}$'),
  public_key BYTEA NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
  operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 48
    AND operator ~ '^[ -~]+$' AND operator = btrim(operator)),
  status TEXT NOT NULL CHECK (status IN ('shadow', 'pinned', 'retired')),
  software TEXT NOT NULL CHECK (software IN ('mesh', 'c2sp')),
  push_url TEXT CHECK (push_url IS NULL OR (length(push_url) <= 2048 AND push_url LIKE 'https://%')),
  morse_run BOOLEAN NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ,
  CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);
CREATE INDEX transparency_witness_registry_active
  ON transparency_witness_registry (status, added_at DESC, witness_id);
