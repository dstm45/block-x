-- +goose Up
CREATE TABLE IF NOT EXISTS metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    uptime_seconds BIGINT NOT NULL,
    cpu_usage_percent NUMERIC(5, 2) NOT NULL,
    memory_used_bytes BIGINT NOT NULL,
    memory_total_bytes BIGINT NOT NULL,
    memory_used_percent NUMERIC(5, 2) NOT NULL,
    disk_free_bytes BIGINT NOT NULL,
    disk_total_bytes BIGINT NOT NULL,
    network_bytes_sent BIGINT NOT NULL,
    network_bytes_recv BIGINT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS metrics;
