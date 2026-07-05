import os
import sys
import time
import psycopg2
from fastapi.testclient import TestClient

# Ensure root of project is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scoring.main import app, worker, model

DB_URI = "postgres://postgres:12345@localhost:5432/block_x?sslmode=disable"

def run_live_orchestrator():
    print("=================================================================")
    print("   BLOCK-X HIDS LIVE SCORING ORCHESTRATOR SIMULATOR              ")
    print("   Monitoring database and scoring incoming events...           ")
    print("   Press Ctrl+C to stop.                                         ")
    print("=================================================================\n")
    
    try:
        conn = psycopg2.connect(DB_URI)
        cur = conn.cursor()
    except Exception as e:
        print(f"[-] Database connection failed: {e}")
        sys.exit(1)

    client = TestClient(app)
    
    # Keep track of statistics
    events_scored = 0
    anomalies_flagged = 0

    try:
        while True:
            # 1. Fetch unprocessed events
            cur.execute(
                """
                SELECT id, pid, tid, uid, gid, comm, executable, syscall, target, return_value, duration 
                FROM logs 
                WHERE processed = FALSE 
                ORDER BY id ASC 
                LIMIT 50;
                """
            )
            rows = cur.fetchall()
            
            if not rows:
                # No new events, wait a short duration
                time.sleep(0.5)
                continue
                
            # 2. Format payload
            events_payload = []
            for row in rows:
                events_payload.append({
                    "pid": row[1],
                    "tid": row[2],
                    "uid": row[3],
                    "gid": row[4],
                    "comm": row[5],
                    "executable": row[6],
                    "syscall": row[7],
                    "target": row[8],
                    "return_value": row[9],
                    "duration": float(row[10])
                })

            # 3. Call Scoring API
            response = client.post("/score", json={"events": events_payload})
            if response.status_code != 200:
                print(f"[-] Scoring API error: {response.text}")
                time.sleep(1)
                continue
                
            scored_events = response.json()["events"]
            
            # 4. Update Database and Print Results
            for idx, scored in enumerate(scored_events):
                db_log_id = rows[idx][0]
                cur.execute(
                    """
                    UPDATE logs 
                    SET processed = %s, anomaly_score = %s, anomaly = %s 
                    WHERE id = %s;
                    """,
                    (scored["processed"], scored["anomaly_score"], scored["anomaly"], db_log_id)
                )
                
                events_scored += 1
                
                # Report anomalies
                if scored["anomaly"]:
                    anomalies_flagged += 1
                    print(f"[⚠️ ANOMALY DETECTED] Process '{scored['comm']}' (PID {scored['pid']}) "
                          f"triggered anomaly threshold! Score: {scored['anomaly_score']:.4f} | "
                          f"Syscall: {scored['syscall']} | Target: {scored['target']}")
                else:
                    print(f"[Info] Scored event for '{scored['comm']}' (PID {scored['pid']}) - "
                          f"Score: {scored['anomaly_score']:.4f}")
                          
            conn.commit()
            
    except KeyboardInterrupt:
        print("\n\n[-] Orchestrator stopping...")
        print(f"    Total Events Scored: {events_scored}")
        print(f"    Total Anomalies Flagged: {anomalies_flagged}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    run_live_orchestrator()
