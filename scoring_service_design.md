# Block-X HIDS Scoring Service: Architecture & Design

The Block-X HIDS Scoring Service is a high-throughput, database-agnostic, event-driven module designed to score and detect anomalous Linux system call sequences in real time. It uses an online-learning 5-gram model with Add-k smoothing, maintains memory-safe process state management, and exposes a clean async FastAPI endpoint.

---

## 1. Database Migration Design (PostgreSQL DDL)

The Orchestrator service manages the database. To support core logging telemetry and scoring outputs, the database uses the following schema in `logs`. It optimizes write performance and read throughput using composite and partial indexes.

```sql
-- DDL Migration for Block-X Host Intrusion Detection System (HIDS) logs
-- Location: scoring/database_migration.sql

CREATE TABLE IF NOT EXISTS logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Core metrics
    pid             INTEGER NOT NULL,                     -- Process ID
    tid             INTEGER NOT NULL,                     -- Thread ID
    uid             INTEGER NOT NULL,                     -- User ID
    gid             INTEGER NOT NULL,                     -- Group ID
    comm            VARCHAR(16) NOT NULL,                 -- Command name (kernel limit 16 chars)
    executable      TEXT NOT NULL,                        -- Absolute path to binary
    
    -- Syscall metrics
    syscall         INTEGER NOT NULL,                     -- Integer syscall ID
    target          TEXT,                                 -- Target filepath, IP address, or port
    return_value    BIGINT NOT NULL,                      -- Return code (negative for errors)
    duration        BIGINT NOT NULL,                      -- Execution duration in microseconds/nanoseconds
    
    -- Scoring outputs
    processed       BOOLEAN NOT NULL DEFAULT FALSE,       -- Scored by HIDS
    anomaly_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,-- Normalized anomaly score [0.0 - 1.0]
    anomaly         BOOLEAN NOT NULL DEFAULT FALSE        -- True if anomaly_score >= threshold
);

-- Indexing Strategy:
-- Avoid over-indexing to keep insert speed high.

-- Chronological Timeline
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);

-- Investigate PID lineage/flow over time
CREATE INDEX IF NOT EXISTS idx_logs_pid_timestamp ON logs (pid, timestamp DESC);

-- High-speed anomaly search index. A PARTIAL index is used because anomalies are rare (<0.1%).
-- This reduces physical disk space, minimizes write overhead, and provides instant alerts search.
CREATE INDEX IF NOT EXISTS idx_logs_anomaly_timestamp ON logs (anomaly, timestamp DESC) WHERE anomaly = TRUE;

-- Process identification
CREATE INDEX IF NOT EXISTS idx_logs_comm_timestamp ON logs (comm, timestamp DESC);
```

---

## 2. Statistical 5-Gram Model Core

The model evaluates a rolling window of 5 syscalls: $S = (w_1, w_2, w_3, w_4, w_5)$.
- The **context** is the sequence of the first 4 syscalls: $C = (w_1, w_2, w_3, w_4)$
- The **target** is the 5th syscall: $T = w_5$

### Probability Engine (Add-k Smoothing)
The conditional probability of seeing a target $T$ given the context $C$ is computed using Add-k smoothing (where $k = 0.01$):
$$P(T \mid C) = \frac{\text{Count}(C, T) + k}{\text{Count}(C) + k \times |V|}$$

Where:
- $\text{Count}(C, T)$ is the number of times context $C$ transitioned to target $T$.
- $\text{Count}(C)$ is the number of times context $C$ was seen.
- $|V|$ is the size of the vocabulary (number of unique system call IDs observed so far).

### Anomaly Score Definition
The anomaly score represents the "surprise" or rarity of the transition, bounded strictly between $0.0$ and $1.0$:
$$\text{Anomaly Score} = 1.0 - P(T \mid C)$$

If a transition is unseen or context is new, the probability will be small (determined by $k$), driving the anomaly score close to $1.0$. If a transition is frequent, the probability approaches $1.0$, dropping the anomaly score close to $0.0$.

---

## 3. State Management & Memory Safety

To guarantee constant-memory operations and prevent RAM bloat:
1. **Rolling Windows**: Active process histories are stored in `collections.deque(maxlen=5)`.
2. **LRU Cache Limit**: At most 10,000 active PIDs are tracked concurrently via `collections.OrderedDict`. If a new process starts when the cache is full, the least recently used process is evicted.
3. **Exit Hook Purging**: The system actively inspects incoming syscall IDs. If the syscall matches an exit command (e.g. `sys_exit = 60` or `sys_exit_group = 231` on x86_64), the process history is removed from RAM immediately.

---

## 4. Model Persistence & Serialization

To allow the scoring model to persist its learned transition probabilities and vocabulary across application restarts, the system supports model serialization:

1. **Automatic Lifecycle Loading & Saving**:
   - If the environment variable `MODEL_PATH` is set, the FastAPI service will automatically load the model state from the specified path at startup (`startup` event).
   - The service will automatically save the model state back to `MODEL_PATH` when the server is stopped (`shutdown` event).

2. **On-Demand Serialization Endpoints**:
   - `POST /save`: Manually triggers saving the model state. An optional custom filepath can be passed in the JSON payload `{"filepath": "path/to/model.pkl"}`.
   - `POST /load`: Manually triggers loading the model state. An optional custom filepath can be passed in the JSON payload `{"filepath": "path/to/model.pkl"}`.

*Note: Since standard `pickle` serialization does not support pickling of local/lambda default factories, the scorer converts internal nested `defaultdict` structures to standard dictionaries before serialization and reconstructs them upon load.*

---

## 5. Code Layout

The implementation is modular and structured as follows:

- [config.py](file:///home/monga/code/go/block-x/scoring/config.py): Holds system thresholds, N-gram sizing, smoothing factor, LRU limits, exit syscall sets, and `MODEL_PATH`.
- [model/interface.py](file:///home/monga/code/go/block-x/scoring/model/interface.py): Abstract base class defining `train`, `score`, `save`, `load`, and `reset` hooks.
- [model/ngram.py](file:///home/monga/code/go/block-x/scoring/model/ngram.py): Mathematical implementation of N-gram probability scoring with Add-k smoothing, along with `pickle` serialization.
- [worker.py](file:///home/monga/code/go/block-x/scoring/worker.py): Processes batches, handles rolling deques, enforces the LRU limit, and cleans up memory on system exits.
- [main.py](file:///home/monga/code/go/block-x/scoring/main.py): FastAPI asynchronous API presenting the high-throughput endpoints `/score`, `/train`, `/config`, `/save`, `/load`, `/reset`, and `/health`.

---

## 5. Go Orchestrator

The Go Orchestrator (located in [orchestrator/cmd/main.go](file:///home/monga/code/go/block-x/orchestrator/cmd/main.go)) is responsible for fetching unprocessed eBPF system call logs from PostgreSQL, batching them, submitting them to the Scoring Service API, and persisting the results back to the database.

It supports two modes:
1. **Scoring Mode (Default)**: Sends telemetry to the `/score` API endpoint to evaluate sequences and flag anomalies.
2. **Training/Learning Mode**: Enabled via the `-train` command-line flag or the `TRAINING_MODE=true` environment variable. In this mode, telemetry is sent to the `/train` API endpoint, updating the model's transitions and vocabulary without triggering alerts (anomalies are marked as `False` in the database).

---

## 6. Running the Tests

We provide robust unit and integration test suites:
1. **[test_integration.py](file:///home/monga/code/go/block-x/scoring/test_integration.py)**: Validates the probability engine, LRU caching limits, exit hook purging, and FastAPI endpoints (including `/train` and `/config`) in-memory.
2. **[test_interaction.py](file:///home/monga/code/go/block-x/scoring/test_interaction.py)**: Simulates the end-to-end integration between `ebpf-tool` and `scoring` by writing events to PostgreSQL, polling unprocessed entries, scoring them via the API, and updating database anomaly attributes.
3. **Go Orchestrator Tests ([main_test.go](file:///home/monga/code/go/block-x/orchestrator/cmd/main_test.go))**: Tests database log querying, mock-server integration for `/score` and `/train` batches, and transactional database updates.

To run the Python unit/endpoint tests:
```bash
# From the project root (/home/monga/code/go/block-x)
./scoring/venv/bin/python scoring/test_integration.py
```

To run the database-to-API interaction test:
```bash
# Ensure postgres is running and database is migrated
./scoring/venv/bin/python scoring/test_interaction.py
```

To run the Go orchestrator tests:
```bash
# Ensure postgres is running on local port 5432
cd orchestrator && go test -v ./cmd/...
```

To run the live orchestrator simulator (Python):
```bash
# Ensure postgres is running, database is migrated, and ebpf-tool is running
./scoring/venv/bin/python scoring/test_live_scoring.py
```

To run the Go orchestrator service:
```bash
cd orchestrator
# Build the binary
go build -o orchestrator-bin ./cmd/main.go
# Run in default scoring mode
./orchestrator-bin
# Run in training mode
./orchestrator-bin -train
```

