package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
)

type SyscallEvent struct {
	ID           int64   `json:"-"` // Internal DB identity, not sent to API
	PID          int32   `json:"pid"`
	TID          int32   `json:"tid"`
	UID          int32   `json:"uid"`
	GID          int32   `json:"gid"`
	Comm         string  `json:"comm"`
	Executable   string  `json:"executable"`
	Syscall      int32   `json:"syscall"`
	Target       string  `json:"target"`
	ReturnValue  int64   `json:"return_value"`
	Duration     float64 `json:"duration"`
	Processed    bool    `json:"processed"`
	AnomalyScore float64 `json:"anomaly_score"`
	Anomaly      bool    `json:"anomaly"`
}

type ScoreBatchRequest struct {
	Events []SyscallEvent `json:"events"`
}

type ScoreBatchResponse struct {
	Events []SyscallEvent `json:"events"`
}

func main() {
	log.Println("[+] Starting Block-X Go Orchestrator Service...")

	// 1. Load configuration from environment / .env
	loadEnv()

	// Parse command-line flags
	trainFlag := flag.Bool("train", false, "Enable training/learning mode (sends events to the training endpoint)")
	flag.Parse()

	// Determine if training mode is enabled via flag or env var
	trainingMode := *trainFlag || os.Getenv("TRAINING_MODE") == "true"

	dbURI := os.Getenv("DATABASE_URI")
	if dbURI == "" {
		// Fallback to goose DB string if present
		dbURI = os.Getenv("GOOSE_DBSTRING")
	}
	if dbURI == "" {
		log.Fatalln("[-] DATABASE_URI is not set in environment or .env file")
	}

	scoringURL := resolveScoringURL(os.Getenv("SCORING_SERVICE_URL"), trainingMode)

	if trainingMode {
		log.Printf("[+] Running in TRAINING mode. Sending events to: %s", scoringURL)
	} else {
		log.Printf("[+] Running in SCORING mode. Sending events to: %s", scoringURL)
	}

	// 2. Establish PostgreSQL database connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := pgx.Connect(ctx, dbURI)
	if err != nil {
		log.Fatalf("[-] Database connection failed: %v", err)
	}
	defer conn.Close(ctx)
	log.Println("[+] Connected to PostgreSQL database.")

	// 3. Graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Tick loop duration
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	log.Println("[+] Orchestration polling loop active. Waiting for events...")

	for {
		select {
		case <-sigChan:
			log.Println("[-] Shutdown signal received. Exiting Go Orchestrator...")
			return
		case <-ticker.C:
			// Run orchestration batch step
			if err := runBatchStep(ctx, conn, client, scoringURL); err != nil {
				log.Printf("[-] Error in batch step: %v", err)
			}
		}
	}
}

func resolveScoringURL(envScoringURL string, trainingMode bool) string {
	if envScoringURL == "" {
		if trainingMode {
			return "http://localhost:8000/train"
		}
		return "http://localhost:8000/score"
	}
	if trainingMode {
		if strings.HasSuffix(envScoringURL, "/score") {
			return strings.TrimSuffix(envScoringURL, "/score") + "/train"
		}
	}
	return envScoringURL
}

func runBatchStep(ctx context.Context, conn *pgx.Conn, client *http.Client, scoringURL string) error {
	// 1. Fetch unprocessed event logs from DB
	// We read a batch of up to 100 logs
	rows, err := conn.Query(ctx, `
		SELECT id, pid, tid, uid, gid, comm, executable, syscall, target, return_value, duration 
		FROM logs 
		WHERE processed = FALSE 
		ORDER BY id ASC 
		LIMIT 100;
	`)
	if err != nil {
		return fmt.Errorf("failed to query unprocessed logs: %w", err)
	}
	defer rows.Close()

	var events []SyscallEvent
	for rows.Next() {
		var ev SyscallEvent
		var durationRaw int64 // DB stores duration as BIGINT
		err := rows.Scan(
			&ev.ID, &ev.PID, &ev.TID, &ev.UID, &ev.GID, &ev.Comm,
			&ev.Executable, &ev.Syscall, &ev.Target, &ev.ReturnValue, &durationRaw,
		)
		if err != nil {
			return fmt.Errorf("failed to scan log row: %w", err)
		}
		ev.Duration = float64(durationRaw)
		events = append(events, ev)
	}

	if len(events) == 0 {
		return nil
	}

	log.Printf("[+] Processing a batch of %d unprocessed events...", len(events))

	// 2. Prepare JSON request payload
	reqPayload := ScoreBatchRequest{Events: events}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	// 3. Post to scoring service API
	req, err := http.NewRequestWithContext(ctx, "POST", scoringURL, bytes.NewBuffer(reqBytes))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http call to scoring service failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scoring service returned non-200 status code: %d", resp.StatusCode)
	}

	// 4. Decode JSON response payload
	var respPayload ScoreBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&respPayload); err != nil {
		return fmt.Errorf("failed to decode json response: %w", err)
	}

	if len(respPayload.Events) != len(events) {
		return fmt.Errorf("mismatch between batch request and response sizes (%d vs %d)", len(events), len(respPayload.Events))
	}

	// 5. Update database rows using a Transaction to ensure consistency
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin database transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for i, scored := range respPayload.Events {
		dbID := events[i].ID
		_, err := tx.Exec(ctx, `
			UPDATE logs 
			SET processed = $1, anomaly_score = $2, anomaly = $3 
			WHERE id = $4;
		`, scored.Processed, scored.AnomalyScore, scored.Anomaly, dbID)
		if err != nil {
			return fmt.Errorf("failed to update log ID %d: %w", dbID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("[+] Scored and updated %d logs successfully.", len(events))
	return nil
}

func loadEnv() {
	// Try loading from workspace root or current directory
	envFiles := []string{
		".env",
		"../.env",
		"../../.env",
	}

	for _, file := range envFiles {
		// Convert to absolute path to be safe
		absPath, err := filepath.Abs(file)
		if err == nil {
			if err := godotenv.Load(absPath); err == nil {
				log.Printf("[+] Loaded environment configurations from: %s", absPath)
				return
			}
		}
	}
	log.Println("[!] No .env file loaded, relying on active environment variables.")
}
