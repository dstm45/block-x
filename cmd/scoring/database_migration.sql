-- DDL Migration for Block-X Host Intrusion Detection System (HIDS) logs
-- This file provides the PostgreSQL schema required to track system call telemetry and scoring outputs.
-- Designed for high-throughput logging with target indexes optimized for querying anomalies.

-- 1. Create or alter the logs table
CREATE TABLE IF NOT EXISTS logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Core metrics
    pid             INTEGER NOT NULL,                     -- Process ID
    tid             INTEGER NOT NULL,                     -- Thread ID
    uid             INTEGER NOT NULL,                     -- User ID
    gid             INTEGER NOT NULL,                     -- Group ID
    comm            VARCHAR(16) NOT NULL,                 -- Command name (Linux kernel limit is 16 chars)
    executable      TEXT NOT NULL,                        -- Absolute path to the executable binary
    
    -- Action details
    syscall         INTEGER NOT NULL,                     -- Syscall ID (integer representing the system call)
    target          TEXT,                                 -- Target filepath, IP address, port, or resource
    return_value    BIGINT NOT NULL,                      -- Return code (often negative for errors)
    duration        BIGINT NOT NULL,                      -- Time taken to execute (microseconds or nanoseconds)
    
    -- Scoring outputs
    processed       BOOLEAN NOT NULL DEFAULT FALSE,       -- Has the sequence been scored by HIDS?
    anomaly_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,-- Numerical anomaly score [0.0 - 1.0]
    anomaly         BOOLEAN NOT NULL DEFAULT FALSE        -- True if anomaly_score >= threshold
);

-- 2. Indexing Strategy for High-Throughput Inserts & Fast Reads:
-- To prevent sequential insert degradation (which is a primary bottleneck for logging pipelines),
-- we avoid over-indexing. We only introduce high-value composite indexes:

-- A. Primary Chronological Index:
-- Essential for rendering dashboards of recent events.
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);

-- B. Process Flow Investigation Index (Composite):
-- Used by engineers when tracing the exact timeline of a specific suspect PID.
-- Ordering by timestamp DESC allows quick retrieval of the latest events for a given PID.
CREATE INDEX IF NOT EXISTS idx_logs_pid_timestamp ON logs (pid, timestamp DESC);

-- C. Partial Anomaly Search Index:
-- High-priority query: "Find all anomalies in the last 24 hours."
-- By using a PARTIAL index (WHERE anomaly = TRUE), we dramatically decrease the physical index size.
-- This keeps memory usage low, speeds up index updates during normal inserts (since 99.9% of rows are ignored),
-- and provides instant lookups for security alerts.
CREATE INDEX IF NOT EXISTS idx_logs_anomaly_timestamp ON logs (anomaly, timestamp DESC) WHERE anomaly = TRUE;

-- D. Process Name Search Index (Optional, for search by utility e.g. "nginx"):
-- Useful for checking executions of specific services.
CREATE INDEX IF NOT EXISTS idx_logs_comm_timestamp ON logs (comm, timestamp DESC);
