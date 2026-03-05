-- name: SaveLogs :copyfrom
INSERT INTO logs(timestamp, uid, gid, pid, ppid, comm) VALUES($1, $2, $3, $4, $5, $6);
