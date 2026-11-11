-- name: SaveMetrics :exec
INSERT INTO metrics (
  timestamp,
  hostname,
  os,
  uptime_seconds,
  cpu_usage_percent,
  memory_used_percent,
  memory_total_bytes,
  memory_used_bytes,
  disk_total_bytes,
  disk_free_bytes,
  network_bytes_recv,
  network_bytes_sent
) VALUES( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
