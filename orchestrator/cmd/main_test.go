package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestOrchestratorBatchStep(t *testing.T) {
	// 1. Get database URI from env or fallback to default test DB
	dbURI := os.Getenv("DATABASE_URI")
	if dbURI == "" {
		dbURI = os.Getenv("GOOSE_DBSTRING")
	}
	if dbURI == "" {
		dbURI = "postgres://postgres:12345@localhost:5432/block_x?sslmode=disable"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURI)
	if err != nil {
		t.Skipf("Skipping integration test: database connection failed: %v", err)
		return
	}
	defer conn.Close(ctx)

	// 2. Reset logs table
	_, err = conn.Exec(ctx, "DELETE FROM logs;")
	if err != nil {
		t.Fatalf("Failed to truncate logs table: %v", err)
	}

	// 3. Insert some dummy unprocessed system call logs
	dummyEvents := []struct {
		pid     int
		comm    string
		syscall int
	}{
		{1001, "nginx", 257},
		{1001, "nginx", 0},
		{1001, "nginx", 1},
		{1001, "nginx", 3},
		{1001, "nginx", 5},
	}

	for _, ev := range dummyEvents {
		_, err := conn.Exec(ctx, `
			INSERT INTO logs (pid, ppid, tid, uid, gid, comm, executable, syscall, target, return_value, duration, processed)
			VALUES ($1, $1 - 1, $1, 1000, 1000, $2, '/usr/sbin/nginx', $3, '', 0, 15, FALSE);
		`, ev.pid, ev.comm, ev.syscall)
		if err != nil {
			t.Fatalf("Failed to insert dummy log: %v", err)
		}
	}

	// 4. Setup mock HTTP scoring service
	serverCalls := 0
	mockScoringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json Content-Type, got %s", r.Header.Get("Content-Type"))
		}

		var req ScoreBatchRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Errorf("Failed to decode JSON request body: %v", err)
		}

		if len(req.Events) != len(dummyEvents) {
			t.Errorf("Expected %d events in request, got %d", len(dummyEvents), len(req.Events))
		}

		// Prepare mock response (flag everything as processed with a specific score)
		respEvents := make([]SyscallEvent, len(req.Events))
		for i, ev := range req.Events {
			respEvents[i] = ev
			respEvents[i].Processed = true
			respEvents[i].AnomalyScore = 0.123
			respEvents[i].Anomaly = false
		}

		respPayload := ScoreBatchResponse{Events: respEvents}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(respPayload)
	}))
	defer mockScoringServer.Close()

	// 5. Run the batch step pointing to the mock server URL
	client := &http.Client{Timeout: 2 * time.Second}
	err = runBatchStep(ctx, conn, client, mockScoringServer.URL)
	if err != nil {
		t.Fatalf("runBatchStep failed: %v", err)
	}

	if serverCalls != 1 {
		t.Errorf("Expected mock server to be called once, was called %d times", serverCalls)
	}

	// 6. Verify that the database was updated correctly
	rows, err := conn.Query(ctx, "SELECT processed, anomaly_score, anomaly FROM logs ORDER BY id ASC;")
	if err != nil {
		t.Fatalf("Failed to query logs from database: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var processed bool
		var anomalyScore float64
		var anomaly bool
		err := rows.Scan(&processed, &anomalyScore, &anomaly)
		if err != nil {
			t.Fatalf("Failed to scan log row: %v", err)
		}
		if !processed {
			t.Errorf("Log row %d expected to be processed", count)
		}
		if anomalyScore != 0.123 {
			t.Errorf("Log row %d expected anomaly score 0.123, got %f", count, anomalyScore)
		}
		if anomaly {
			t.Errorf("Log row %d expected anomaly to be false, got true", count)
		}
		count++
	}

	if count != len(dummyEvents) {
		t.Errorf("Expected %d updated rows in DB, got %d", len(dummyEvents), count)
	}
}

func TestResolveScoringURL(t *testing.T) {
	tests := []struct {
		name         string
		envURL       string
		trainingMode bool
		expected     string
	}{
		{
			name:         "empty URL, scoring mode",
			envURL:       "",
			trainingMode: false,
			expected:     "http://localhost:8000/score",
		},
		{
			name:         "empty URL, training mode",
			envURL:       "",
			trainingMode: true,
			expected:     "http://localhost:8000/train",
		},
		{
			name:         "custom scoring URL, scoring mode",
			envURL:       "http://hids.internal:9000/score",
			trainingMode: false,
			expected:     "http://hids.internal:9000/score",
		},
		{
			name:         "custom scoring URL, training mode",
			envURL:       "http://hids.internal:9000/score",
			trainingMode: true,
			expected:     "http://hids.internal:9000/train",
		},
		{
			name:         "custom non-score URL, training mode",
			envURL:       "http://hids.internal:9000/api/v1/custom",
			trainingMode: true,
			expected:     "http://hids.internal:9000/api/v1/custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveScoringURL(tt.envURL, tt.trainingMode)
			if got != tt.expected {
				t.Errorf("resolveScoringURL(%q, %t) = %q; want %q", tt.envURL, tt.trainingMode, got, tt.expected)
			}
		})
	}
}
