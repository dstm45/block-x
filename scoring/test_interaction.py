import os
import sys
import psycopg2
from fastapi.testclient import TestClient

# Ensure root of project is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scoring.main import app, worker, model

DB_URI = "postgres://postgres:12345@localhost:5432/block_x?sslmode=disable"

def run_integration_test():
    print("=== STARTING EBPF-TOOL TO SCORING INTEGRATION TEST ===")
    
    # 1. Connect to PostgreSQL database
    try:
        conn = psycopg2.connect(DB_URI)
        cur = conn.cursor()
        print("[+] Connected to PostgreSQL successfully.")
    except Exception as e:
        print(f"[-] Database connection failed: {e}")
        sys.exit(1)

    # 2. Reset database logs table and scoring service state
    cur.execute("DELETE FROM logs;")
    conn.commit()
    model.reset()
    worker.reset()
    worker.anomaly_threshold = 0.75
    print("[+] Database logs table and Scoring service state reset.")

    # 3. Simulate ebpf-tool writing normal syscall logs (PID 9999)
    # 257=openat, 0=read, 1=write, 3=close, 5=fstat
    normal_syscalls = [257, 0, 1, 3, 5]
    print("[+] Simulating ebpf-tool capturing and saving normal events for PID 9999...")
    for idx, sys_id in enumerate(normal_syscalls):
        cur.execute(
            """
            INSERT INTO logs (pid, ppid, tid, uid, gid, comm, executable, syscall, target, return_value, duration, processed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (9999, 9998, 9999, 1000, 1000, "nginx", "/usr/sbin/nginx", sys_id, "/var/www/html" if sys_id == 257 else "", 0 if sys_id != 0 else 1024, 15, False)
        )
    conn.commit()
    print(f"[+] Saved {len(normal_syscalls)} events to database.")

    # 4. Fetch unprocessed logs from the database (simulating Orchestrator job)
    cur.execute(
        """
        SELECT id, pid, tid, uid, gid, comm, executable, syscall, target, return_value, duration 
        FROM logs 
        WHERE processed = FALSE 
        ORDER BY id ASC;
        """
    )
    rows = cur.fetchall()
    print(f"[+] Orchestrator fetched {len(rows)} unprocessed events from DB.")

    # Format into API payload
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

    # 5. Score events using FastAPI Client (simulating Orchestrator API request)
    client = TestClient(app)
    print("[+] Sending event batch to Scoring Service /score endpoint...")
    response = client.post("/score", json={"events": events_payload})
    
    if response.status_code != 200:
        print(f"[-] API scoring request failed: {response.text}")
        sys.exit(1)
        
    scored_events = response.json()["events"]
    print(f"[+] Received scored response containing {len(scored_events)} events.")

    # 6. Update database with scored metrics (simulating Orchestrator updating DB)
    print("[+] Updating database logs table with computed anomaly scores...")
    for idx, scored in enumerate(scored_events):
        db_log_id = rows[idx][0]  # Match with original database row ID
        cur.execute(
            """
            UPDATE logs 
            SET processed = %s, anomaly_score = %s, anomaly = %s 
            WHERE id = %s;
            """,
            (scored["processed"], scored["anomaly_score"], scored["anomaly"], db_log_id)
        )
    conn.commit()
    print("[+] Database logs table updated successfully.")

    # 7. Verification: check that the 5th event has been scored and is marked as not anomalous
    cur.execute("SELECT processed, anomaly_score, anomaly FROM logs ORDER BY id ASC;")
    final_rows = cur.fetchall()
    
    # 5th event check (index 4)
    p, score, anomaly = final_rows[4]
    print(f"\nVerification for normal sequence (PID 9999):")
    print(f"  Processed: {p}")
    print(f"  Anomaly Score: {score:.4f}")
    print(f"  Anomaly Flagged: {anomaly}")
    
    assert p == True, "Expected 5th event to be processed"
    assert anomaly == False, "Expected normal sequence to NOT be flagged as anomaly"
    print("[+] Normal sequence verification passed.")

    # 8. Simulate ebpf-tool capturing anomalous events for a new PID (PID 8888)
    # 33=dup2, 33=dup2, 33=dup2, 59=execve, 60=exit
    anomalous_syscalls = [33, 33, 33, 59, 60]
    print("\n[+] Simulating ebpf-tool capturing anomalous events for PID 8888 (reverse shell)...")
    for sys_id in anomalous_syscalls:
        cur.execute(
            """
            INSERT INTO logs (pid, ppid, tid, uid, gid, comm, executable, syscall, target, return_value, duration, processed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (8888, 8887, 8888, 1000, 1000, "bash", "/bin/bash", sys_id, "stdin/stdout" if sys_id == 33 else "/bin/sh", 0, 10, False)
        )
    conn.commit()

    # Orchestrator fetch unprocessed
    cur.execute("SELECT id, pid, tid, uid, gid, comm, executable, syscall, target, return_value, duration FROM logs WHERE processed = FALSE ORDER BY id ASC;")
    rows_anom = cur.fetchall()
    print(f"[+] Orchestrator fetched {len(rows_anom)} unprocessed events from DB.")

    events_payload_anom = []
    for row in rows_anom:
        events_payload_anom.append({
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

    # API call
    response = client.post("/score", json={"events": events_payload_anom})
    scored_events_anom = response.json()["events"]
    
    # Update DB
    for idx, scored in enumerate(scored_events_anom):
        db_log_id = rows_anom[idx][0]
        cur.execute(
            """
            UPDATE logs 
            SET processed = %s, anomaly_score = %s, anomaly = %s 
            WHERE id = %s;
            """,
            (scored["processed"], scored["anomaly_score"], scored["anomaly"], db_log_id)
        )
    conn.commit()
    print("[+] Database logs table updated for PID 8888.")

    # Verification: check 5th event of anomalous sequence
    cur.execute("SELECT processed, anomaly_score, anomaly FROM logs WHERE pid = 8888 ORDER BY id ASC;")
    final_rows_anom = cur.fetchall()
    p_anom, score_anom, anomaly_anom = final_rows_anom[4]
    
    print(f"\nVerification for anomalous sequence (PID 8888):")
    print(f"  Processed: {p_anom}")
    print(f"  Anomaly Score: {score_anom:.4f}")
    print(f"  Anomaly Flagged: {anomaly_anom}")
    
    assert p_anom == True, "Expected 5th event to be processed"
    assert anomaly_anom == True, "Expected anomalous sequence to be flagged as anomaly"
    print("[+] Anomalous sequence verification passed.")

    # 9. Verify state cleanup on exit syscall (60)
    # The scoring worker's active process cache should NOT contain PID 8888 (since 60 is exit syscall)
    # But it should contain PID 9999 (since no exit syscall was sent for it yet)
    print("\nVerification for Memory Safety state cleanup:")
    print(f"  Active PIDs in memory: {list(worker.pid_windows.keys())}")
    assert 8888 not in worker.pid_windows, "Expected PID 8888 to be purged from memory after exit syscall"
    assert 9999 in worker.pid_windows, "Expected PID 9999 to remain in memory"
    print("[+] Memory safety verification passed.")

    cur.close()
    conn.close()
    print("\n=== ALL INTEGRATION TESTS PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_integration_test()
