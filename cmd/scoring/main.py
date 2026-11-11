import os
import sys
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# Ensure root of project is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import (
    ANOMALY_THRESHOLD,
    EXIT_SYSCALLS,
    MAX_TRACKED_PIDS,
    MODEL_PATH,
    NGRAM_SIZE,
    SMOOTHING_K,
    TRAINING_MODE,
)
from model.ngram import NGramScorer
from worker import ScoringWorker

app = FastAPI(
    title="Block-X Scoring Service",
    description="Online-learning 5-gram Host Intrusion Detection System (HIDS) scoring engine.",
    version="1.0.0",
)

# Initialize the stateless components and runtime state
model = NGramScorer(n=NGRAM_SIZE, k=SMOOTHING_K)
worker = ScoringWorker(
    model=model,
    max_pids=MAX_TRACKED_PIDS,
    n_gram_size=NGRAM_SIZE,
    exit_syscalls=EXIT_SYSCALLS,
    anomaly_threshold=ANOMALY_THRESHOLD,
    training_mode=TRAINING_MODE,
)


@app.on_event("startup")
def startup_event():
    if MODEL_PATH and os.path.exists(MODEL_PATH):
        try:
            model.load(MODEL_PATH)
            print(f"[+] Loaded model state from {MODEL_PATH}")
        except Exception as e:
            print(f"[-] Failed to load model state from {MODEL_PATH}: {e}")


@app.on_event("shutdown")
def shutdown_event():
    if MODEL_PATH:
        try:
            model.save(MODEL_PATH)
            print(f"[+] Saved model state to {MODEL_PATH}")
        except Exception as e:
            print(f"[-] Failed to save model state to {MODEL_PATH}: {e}")


class SyscallEvent(BaseModel):
    pid: int = Field(..., description="Process ID")
    tid: int = Field(..., description="Thread ID")
    uid: int = Field(..., description="User ID")
    gid: int = Field(..., description="Group ID")
    comm: str = Field(..., max_length=16, description="Command name")
    executable: str = Field(..., description="Absolute path to binary")
    syscall: int = Field(..., description="Integer syscall ID")
    target: str = Field(..., description="Target object/path/IP of syscall")
    return_value: int = Field(..., description="Return value of the syscall")
    duration: float = Field(
        ..., description="Duration of the syscall in microseconds/nanoseconds"
    )

    # Metadata fields computed/filled by the Scoring Service
    processed: bool | None = Field(
        default=False, description="Flag indicating if the sequence was scored"
    )
    anomaly_score: float | None = Field(
        default=0.0, description="Computed anomaly score [0.0 - 1.0]"
    )
    anomaly: bool | None = Field(
        default=False, description="Flag indicating if the score exceeded threshold"
    )


class ScoreBatchRequest(BaseModel):
    events: list[SyscallEvent]


class ScoreBatchResponse(BaseModel):
    events: list[SyscallEvent]


@app.post(
    "/score",
    response_model=ScoreBatchResponse,
    summary="Score a batch of system call events",
)
async def score_endpoint(payload: ScoreBatchRequest):
    """
    Score a batch of incoming system call events from the orchestrator.

    Returns the scored events inline with anomaly assessments.
    """
    try:
        # Convert events to list of dictionaries
        events_data = [event.model_dump() for event in payload.events]
        # Process events sequentially through worker
        scored_data = worker.process_events(events_data)
        # Convert back to Pydantic objects
        scored_events = [SyscallEvent(**event) for event in scored_data]
        # Auto-save model state if online learning occurred
        if MODEL_PATH and any(event.get("processed") for event in scored_data):
            try:
                model.save(MODEL_PATH)
            except Exception as e:
                print(f"[-] Failed to auto-save model state to {MODEL_PATH}: {e}")
        return ScoreBatchResponse(events=scored_events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scoring pipeline error: {str(e)}")


@app.post("/reset", summary="Reset all state tracked by the model and worker")
async def reset_endpoint():
    """
    Resets the underlying n-gram counts, vocabulary, and active process sliding windows.
    """
    model.reset()
    worker.reset()
    if MODEL_PATH:
        try:
            model.save(MODEL_PATH)
        except Exception as e:
            print(f"[-] Failed to save model state after reset: {e}")
    return {
        "status": "success",
        "message": "Scoring service model and cache reset successfully.",
    }


@app.get("/health", summary="Perform a system health check")
async def health_endpoint():
    """
    Return service health metrics and statistics.
    """
    return {
        "status": "healthy",
        "configuration": {
            "n_gram_size": NGRAM_SIZE,
            "smoothing_k": SMOOTHING_K,
            "anomaly_threshold": ANOMALY_THRESHOLD,
            "max_tracked_pids": MAX_TRACKED_PIDS,
            "exit_syscalls": list(EXIT_SYSCALLS),
        },
        "metrics": {
            "vocabulary_size": len(model.vocab),
            "active_pids_tracked": len(worker.pid_windows),
        },
    }


class ConfigUpdateRequest(BaseModel):
    training_mode: Optional[bool] = Field(
        default=None,
        description="Set to True to put scoring service in learning/training mode",
    )
    anomaly_threshold: Optional[float] = Field(
        default=None, description="Adjust the anomaly threshold"
    )


@app.get("/config", summary="Retrieve current configuration settings")
async def get_config():
    """
    Get the active configuration parameters of the scoring engine.
    """
    return {
        "training_mode": worker.training_mode,
        "anomaly_threshold": worker.anomaly_threshold,
        "n_gram_size": worker.n_gram_size,
        "max_tracked_pids": worker.max_pids,
    }


@app.post("/config", summary="Update scoring service configuration dynamically")
async def update_config(payload: ConfigUpdateRequest):
    """
    Update configuration options (like training_mode and anomaly_threshold) on-the-fly.
    """
    if payload.training_mode is not None:
        worker.training_mode = payload.training_mode
    if payload.anomaly_threshold is not None:
        worker.anomaly_threshold = payload.anomaly_threshold
    return {
        "status": "success",
        "message": "Configuration updated successfully",
        "config": {
            "training_mode": worker.training_mode,
            "anomaly_threshold": worker.anomaly_threshold,
        },
    }


@app.post(
    "/train",
    response_model=ScoreBatchResponse,
    summary="Train the model on a batch of system call events without flagging anomalies",
)
async def train_endpoint(payload: ScoreBatchRequest):
    """
    Train the model on a batch of incoming system call events from the orchestrator.

    This updates the model's transition counts and vocabulary without raising anomalies.
    """
    try:
        events_data = [event.model_dump() for event in payload.events]
        # Temporarily enable training mode for this batch execution
        old_mode = worker.training_mode
        worker.training_mode = True
        try:
            scored_data = worker.process_events(events_data)
        finally:
            worker.training_mode = old_mode

        scored_events = [SyscallEvent(**event) for event in scored_data]
        # Auto-save model state if online learning occurred
        if MODEL_PATH and any(event.get("processed") for event in scored_data):
            try:
                model.save(MODEL_PATH)
            except Exception as e:
                print(f"[-] Failed to auto-save model state to {MODEL_PATH}: {e}")
        return ScoreBatchResponse(events=scored_events)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Training pipeline error: {str(e)}"
        )


class ModelFileRequest(BaseModel):
    filepath: Optional[str] = Field(
        default=None,
        description="Optional custom file path to save/load the model. Defaults to configured MODEL_PATH.",
    )


@app.post("/save", summary="Save model state to a file")
async def save_model_endpoint(payload: Optional[ModelFileRequest] = None):
    path = (
        payload.filepath if payload and payload.filepath else MODEL_PATH
    ) or "model.pkl"
    try:
        model.save(path)
        return {"status": "success", "message": f"Model saved successfully to {path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save model: {str(e)}")


@app.post("/load", summary="Load model state from a file")
async def load_model_endpoint(payload: Optional[ModelFileRequest] = None):
    path = (
        payload.filepath if payload and payload.filepath else MODEL_PATH
    ) or "model.pkl"
    if not os.path.exists(path):
        raise HTTPException(
            status_code=400, detail=f"Model file does not exist: {path}"
        )
    try:
        model.load(path)
        return {
            "status": "success",
            "message": f"Model loaded successfully from {path}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {str(e)}")
