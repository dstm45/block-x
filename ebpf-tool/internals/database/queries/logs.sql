-- name: SaveLogs :copyfrom
INSERT INTO logs(timestamp, uid, gid, pid, ppid, comm, executable, tid, syscall, target, return_value, duration) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

