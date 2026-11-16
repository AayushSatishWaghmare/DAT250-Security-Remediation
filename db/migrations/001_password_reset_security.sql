BEGIN;

CREATE TABLE IF NOT EXISTS password_reset_limits (
  key_hash VARCHAR(64) PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL
);

-- Existing links use insecure plaintext tokens and must no longer work.
DELETE FROM password_reset_tokens;

COMMIT;
