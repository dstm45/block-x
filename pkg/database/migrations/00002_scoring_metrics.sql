-- +goose Up
-- Add metrics and scoring columns required by HIDS Scoring Service
ALTER TABLE logs 
ADD COLUMN IF NOT EXISTS tid INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS executable TEXT NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS syscall INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS target TEXT DEFAULT '',
ADD COLUMN IF NOT EXISTS return_value BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS duration BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS processed BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS anomaly_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
ADD COLUMN IF NOT EXISTS anomaly BOOLEAN NOT NULL DEFAULT FALSE;

-- Composite index to optimize tracing of syscalls per process over time
CREATE INDEX IF NOT EXISTS idx_logs_pid_timestamp ON logs (pid, timestamp DESC);

-- Partial index for anomalies to speed up dashboard queries and keep index footprint tiny
CREATE INDEX IF NOT EXISTS idx_logs_anomaly_timestamp ON logs (anomaly, timestamp DESC) WHERE anomaly = TRUE;

-- Index process names for search efficiency
CREATE INDEX IF NOT EXISTS idx_logs_comm_timestamp ON logs (comm, timestamp DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_logs_comm_timestamp;
DROP INDEX IF EXISTS idx_logs_anomaly_timestamp;
DROP INDEX IF EXISTS idx_logs_pid_timestamp;

ALTER TABLE logs
DROP COLUMN IF EXISTS tid,
DROP COLUMN IF EXISTS executable,
DROP COLUMN IF EXISTS syscall,
DROP COLUMN IF EXISTS target,
DROP COLUMN IF EXISTS return_value,
DROP COLUMN IF EXISTS duration,
DROP COLUMN IF EXISTS processed,
DROP COLUMN IF EXISTS anomaly_score,
DROP COLUMN IF EXISTS anomaly;
