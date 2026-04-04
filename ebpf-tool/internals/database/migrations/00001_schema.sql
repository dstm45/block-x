-- +goose Up
CREATE TABLE logs (
    id          BIGSERIAL PRIMARY KEY,
    -- Précision à la microseconde pour l'ordre des syscalls
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Identification de l'utilisateur
    uid         INTEGER NOT NULL,
    gid         INTEGER NOT NULL, -- Utile pour voir les changements de privilèges
    
    -- Détails du processus
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL, -- Parent PID pour l'arbre généalogique
    comm        VARCHAR(16) NOT NULL -- Nom du processus (limite kernel 16 chars)
    
    -- Action effectuée
    -- syscall_type VARCHAR(32) NOT NULL, -- ex: "openat", "execve", "unlink"
    
    -- Cible (Fichier)
    -- target_path TEXT, 
    
    -- Métadonnées de sécurité (pour ton futur Scoring)
    -- severity    SMALLINT NOT NULL DEFAULT 0, -- 0 à 10
    -- is_blocked  BOOLEAN NOT NULL DEFAULT FALSE, -- Si la police LSM a dit "Deny"
    
    -- Hash du binaire (très utile pour l'IA/Honey Pot plus tard)
    -- exe_hash    VARCHAR(64) 
);

CREATE TABLE process_events (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type TEXT,    -- 'FORK', 'EXEC', 'EXIT'
    pid INTEGER,
    ppid INTEGER,
    comm TEXT,          -- Nom du processus
    exe_path TEXT,      -- Chemin réel vers le binaire
    uid INTEGER
);

CREATE INDEX idx_logs_timestamp ON logs (timestamp DESC);
CREATE INDEX idx_logs_pid ON logs (pid);

-- +goose Down
DROP INDEX idx_logs_pid;
DROP INDEX idx_logs_timestamp;
DROP TABLE logs;
DROP TABLE process_events;
