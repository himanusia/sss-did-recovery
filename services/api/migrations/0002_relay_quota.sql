-- Per-IP budget for relayed transactions. The relayer pays gas for every
-- registration and recovery step, so each address gets a fixed hourly window.

CREATE TABLE IF NOT EXISTS relay_quota (
    ip      text NOT NULL,
    bucket  timestamptz NOT NULL,   -- start of the hour
    count   integer NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, bucket)
);
CREATE INDEX IF NOT EXISTS relay_quota_bucket_idx ON relay_quota (bucket);
