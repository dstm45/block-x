import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root of project is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scoring.model.ngram import NGramScorer
from scoring.worker import ScoringWorker
from scoring.main import app, worker, model

class TestHIDSScoringSystem(unittest.TestCase):
    def setUp(self):
        # Reset model and worker states before each test
        model.reset()
        worker.reset()
        # Use a lower threshold (0.75) for test scenario since mock vocab size is very small
        worker.anomaly_threshold = 0.75

    def test_ngram_probability_and_online_learning(self):
        """
        Verify that the N-Gram model correctly calculates probabilities,
        applies Add-k smoothing, and updates its counts dynamically.
        """
        scorer = NGramScorer(n=5, k=0.01)
        
        # Define normal baseline transition sequence
        # openat=257, read=0, write=1, close=3, fstat=5
        normal_seq = [257, 0, 1, 3, 5]
        
        # Initially, the model has seen nothing. Vocabulary is empty.
        # Scoring should yield a low probability (high anomaly) because V=1 (fallback)
        initial_score = scorer.score(normal_seq)
        self.assertGreaterEqual(initial_score, 0.0)
        
        # Train on the normal sequence once
        scorer.train(normal_seq)
        
        # After training once, the transition is known
        # The vocab contains {257, 0, 1, 3, 5} -> size 5
        # P(5 | 257, 0, 1, 3) = (count(seq) + k) / (count(context) + k * |V|)
        #                     = (1 + 0.01) / (1 + 0.01 * 5) = 1.01 / 1.05 = 0.9619
        # Anomaly score should be 1 - 0.9619 = 0.0381
        score_after_train = scorer.score(normal_seq)
        self.assertAlmostEqual(score_after_train, 0.038095238, places=4)
        
        # Now score a completely unseen sequence: [33, 33, 33, 59, 60] (dup2/execve/exit)
        unseen_seq = [33, 33, 33, 59, 60]
        unseen_score = scorer.score(unseen_seq)
        # Context is new, count is 0. Target count is 0.
        # P(60 | 33,33,33,59) = k / (0 + k * |V|) = 1 / |V|
        # Vocab size was 5. So P = 0.01 / (0.01 * 5) = 0.2
        # Anomaly score = 1 - 0.2 = 0.8
        self.assertAlmostEqual(unseen_score, 0.8, places=4)

    def test_state_manager_exit_hook(self):
        """
        Verify that exit syscalls (60, 231) cause the process state
        to be completely wiped from memory.
        """
        temp_worker = ScoringWorker(model=NGramScorer(5), exit_syscalls={60, 231})
        
        # Simulate syscalls for pid 1234
        temp_worker.process_event({"pid": 1234, "syscall": 257})
        temp_worker.process_event({"pid": 1234, "syscall": 0})
        
        self.assertIn(1234, temp_worker.pid_windows)
        self.assertEqual(len(temp_worker.pid_windows[1234]), 2)
        
        # Now process exit syscall (60)
        temp_worker.process_event({"pid": 1234, "syscall": 60})
        
        # State should be purged from memory
        self.assertNotIn(1234, temp_worker.pid_windows)

    def test_state_manager_lru_eviction(self):
        """
        Verify that the LRU eviction policy works when the number of PIDs exceeds max_pids.
        """
        # Set max_pids to a small number (3) for easy testing
        temp_worker = ScoringWorker(model=NGramScorer(5), max_pids=3)
        
        # Feed events from 4 different PIDs
        temp_worker.process_event({"pid": 1, "syscall": 10})
        temp_worker.process_event({"pid": 2, "syscall": 20})
        temp_worker.process_event({"pid": 3, "syscall": 30})
        
        self.assertEqual(len(temp_worker.pid_windows), 3)
        self.assertIn(1, temp_worker.pid_windows)
        
        # Add a fourth PID, which should trigger eviction of the oldest (PID 1)
        temp_worker.process_event({"pid": 4, "syscall": 40})
        
        self.assertEqual(len(temp_worker.pid_windows), 3)
        self.assertNotIn(1, temp_worker.pid_windows)
        self.assertIn(2, temp_worker.pid_windows)
        self.assertIn(3, temp_worker.pid_windows)
        self.assertIn(4, temp_worker.pid_windows)

        # Access PID 2, making it the most recently used
        temp_worker.process_event({"pid": 2, "syscall": 21})
        
        # Now add PID 5, which should evict PID 3 (since PID 2 was recently accessed, and PID 3 is now oldest)
        temp_worker.process_event({"pid": 5, "syscall": 50})
        self.assertNotIn(3, temp_worker.pid_windows)
        self.assertIn(2, temp_worker.pid_windows)
        self.assertIn(4, temp_worker.pid_windows)
        self.assertIn(5, temp_worker.pid_windows)

    def test_fastapi_endpoints(self):
        """
        Test the HTTP API endpoints using FastAPI TestClient to simulate
        payload delivery from the orchestrator.
        """
        client = TestClient(app)
        
        # 1. Check health check
        health_resp = client.get("/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.json()["status"], "healthy")
        
        # 2. Build normal trace baseline logs
        # We will feed a series of events for pid 5000 to establish baseline
        normal_events = [
            {"pid": 5000, "tid": 5000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 257, "target": "/var/www/html", "return_value": 3, "duration": 12.5},
            {"pid": 5000, "tid": 5000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 0, "target": "", "return_value": 1024, "duration": 5.1},
            {"pid": 5000, "tid": 5000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 1, "target": "", "return_value": 1024, "duration": 8.4},
            {"pid": 5000, "tid": 5000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 3, "target": "", "return_value": 0, "duration": 2.1},
            {"pid": 5000, "tid": 5000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 5, "target": "", "return_value": 0, "duration": 3.7},
        ]
        
        # Post first batch of 5 events. The 5th event completes the 5-gram.
        # Since it's the first time the model has ever seen this, the anomaly score should be moderately high,
        # but it will be processed and learned.
        resp = client.post("/score", json={"events": normal_events})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["events"]
        self.assertEqual(len(data), 5)
        
        # Check that the 5th event was processed
        self.assertFalse(data[0]["processed"])
        self.assertTrue(data[4]["processed"])
        
        # 3. Repeat the exact sequence for a new process (pid 5001)
        # It should now be recognized as normal behavior because the model has learned it.
        trained_events = [
            {"pid": 5001, "tid": 5001, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 257, "target": "/var/www/html", "return_value": 3, "duration": 12.5},
            {"pid": 5001, "tid": 5001, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 0, "target": "", "return_value": 1024, "duration": 5.1},
            {"pid": 5001, "tid": 5001, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 1, "target": "", "return_value": 1024, "duration": 8.4},
            {"pid": 5001, "tid": 5001, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 3, "target": "", "return_value": 0, "duration": 2.1},
            {"pid": 5001, "tid": 5001, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 5, "target": "", "return_value": 0, "duration": 3.7},
        ]
        
        resp = client.post("/score", json={"events": trained_events})
        self.assertEqual(resp.status_code, 200)
        data_trained = resp.json()["events"]
        
        # The anomaly score for the 5th event of the learned sequence should be very low
        scored_event = data_trained[4]
        self.assertTrue(scored_event["processed"])
        self.assertLess(scored_event["anomaly_score"], 0.2)
        self.assertFalse(scored_event["anomaly"])
        
        # 4. Now send an anomalous unseen transition: [33, 33, 33, 59, 60] (dup2, execve, exit)
        anomalous_events = [
            {"pid": 5002, "tid": 5002, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stdin", "return_value": 0, "duration": 1.5},
            {"pid": 5002, "tid": 5002, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stdout", "return_value": 1, "duration": 1.2},
            {"pid": 5002, "tid": 5002, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stderr", "return_value": 2, "duration": 1.1},
            {"pid": 5002, "tid": 5002, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 59, "target": "/bin/sh", "return_value": 0, "duration": 22.4},
            {"pid": 5002, "tid": 5002, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 60, "target": "", "return_value": 0, "duration": 0.9},
        ]
        
        resp = client.post("/score", json={"events": anomalous_events})
        self.assertEqual(resp.status_code, 200)
        data_anom = resp.json()["events"]
        
        # The 5th event of this unseen sequence should trigger an anomaly
        scored_anom = data_anom[4]
        self.assertTrue(scored_anom["processed"])
        self.assertGreaterEqual(scored_anom["anomaly_score"], 0.8)
        self.assertTrue(scored_anom["anomaly"])

        # Verification of state cleanup for PID 5002 (since exit syscall 60 was processed)
        health_resp = client.get("/health")
        self.assertEqual(health_resp.json()["metrics"]["active_pids_tracked"], 2) # Only 5000 and 5001 remain

    def test_config_and_train_endpoints(self):
        """
        Verify that dynamic configuration works and that the /train endpoint
        updates the model without flagging anomalies.
        """
        client = TestClient(app)
        
        # 1. Verify GET /config
        resp = client.get("/config")
        self.assertEqual(resp.status_code, 200)
        config_data = resp.json()
        self.assertIn("training_mode", config_data)
        self.assertIn("anomaly_threshold", config_data)
        
        # 2. Verify POST /config updates config
        resp = client.post("/config", json={"training_mode": True, "anomaly_threshold": 0.85})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["config"]["training_mode"])
        self.assertEqual(resp.json()["config"]["anomaly_threshold"], 0.85)
        
        # Restore configuration
        client.post("/config", json={"training_mode": False, "anomaly_threshold": 0.75})
        
        # 3. Establish baseline vocabulary first so unseen sequences have high surprise
        baseline_events = [
            {"pid": 6000, "tid": 6000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 257, "target": "/var/www/html", "return_value": 3, "duration": 12.5},
            {"pid": 6000, "tid": 6000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 0, "target": "", "return_value": 1024, "duration": 5.1},
            {"pid": 6000, "tid": 6000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 1, "target": "", "return_value": 1024, "duration": 8.4},
            {"pid": 6000, "tid": 6000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 3, "target": "", "return_value": 0, "duration": 2.1},
            {"pid": 6000, "tid": 6000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 5, "target": "", "return_value": 0, "duration": 3.7},
        ]
        client.post("/train", json={"events": baseline_events})

        # 4. Verify POST /train trains but does NOT trigger anomaly
        # We send an unseen sequence to /train
        unseen_events = [
            {"pid": 7000, "tid": 7000, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stdin", "return_value": 0, "duration": 1.5},
            {"pid": 7000, "tid": 7000, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stdout", "return_value": 1, "duration": 1.2},
            {"pid": 7000, "tid": 7000, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 33, "target": "stderr", "return_value": 2, "duration": 1.1},
            {"pid": 7000, "tid": 7000, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 59, "target": "/bin/sh", "return_value": 0, "duration": 22.4},
            {"pid": 7000, "tid": 7000, "uid": 1000, "gid": 1000, "comm": "bash", "executable": "/bin/bash", "syscall": 12, "target": "", "return_value": 0, "duration": 0.9},
        ]
        
        # Send to /train: even though it is an unseen sequence, it should not flag anomaly
        resp = client.post("/train", json={"events": unseen_events})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["events"]
        # The 5th event should be processed, have a high anomaly score, but anomaly must be False
        scored_event = data[4]
        self.assertTrue(scored_event["processed"])
        self.assertGreaterEqual(scored_event["anomaly_score"], 0.8)
        self.assertFalse(scored_event["anomaly"]) # Anomaly is False because it was training
        
        # Verify the model learned the sequence: next time we score it, the score should be very low
        resp_score = client.post("/score", json={"events": unseen_events})
        self.assertEqual(resp_score.status_code, 200)
        scored_data = resp_score.json()["events"][4]
        self.assertLess(scored_data["anomaly_score"], 0.2)
        self.assertFalse(scored_data["anomaly"])

    def test_save_load_endpoints(self):
        """
        Verify that the model state can be saved to a file and loaded back
        successfully using the /save and /load endpoints.
        """
        import tempfile
        import os
        client = TestClient(app)

        # 1. Train the model on some data
        baseline_events = [
            {"pid": 8000, "tid": 8000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 257, "target": "/var/www/html", "return_value": 3, "duration": 12.5},
            {"pid": 8000, "tid": 8000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 0, "target": "", "return_value": 1024, "duration": 5.1},
            {"pid": 8000, "tid": 8000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 1, "target": "", "return_value": 1024, "duration": 8.4},
            {"pid": 8000, "tid": 8000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 3, "target": "", "return_value": 0, "duration": 2.1},
            {"pid": 8000, "tid": 8000, "uid": 1000, "gid": 1000, "comm": "nginx", "executable": "/usr/sbin/nginx", "syscall": 5, "target": "", "return_value": 0, "duration": 3.7},
        ]
        client.post("/train", json={"events": baseline_events})

        orig_vocab_size = len(model.vocab)
        self.assertGreater(orig_vocab_size, 0)

        # 2. Save model state to a temporary file
        fd, temp_path = tempfile.mkstemp(suffix=".pkl")
        os.close(fd)
        try:
            save_resp = client.post("/save", json={"filepath": temp_path})
            self.assertEqual(save_resp.status_code, 200)
            self.assertEqual(save_resp.json()["status"], "success")
            self.assertTrue(os.path.exists(temp_path))

            # 3. Reset/clear the model
            client.post("/reset")
            self.assertEqual(len(model.vocab), 0)

            # 4. Load model state back from the temporary file
            load_resp = client.post("/load", json={"filepath": temp_path})
            self.assertEqual(load_resp.status_code, 200)
            self.assertEqual(load_resp.json()["status"], "success")

            # Check that vocabulary has been restored
            self.assertEqual(len(model.vocab), orig_vocab_size)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

if __name__ == "__main__":
    unittest.main()
