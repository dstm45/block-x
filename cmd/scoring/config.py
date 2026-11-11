import os

# N-gram size and modeling parameters
NGRAM_SIZE = int(os.getenv("NGRAM_SIZE", "5"))
SMOOTHING_K = float(os.getenv("SMOOTHING_K", "0.01"))
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.9"))

# State management limits
MAX_TRACKED_PIDS = int(os.getenv("MAX_TRACKED_PIDS", "10000"))

# System exit syscall IDs (Default to x86_64: sys_exit=60, sys_exit_group=231)
EXIT_SYSCALLS = {int(x) for x in os.getenv("EXIT_SYSCALLS", "60,231").split(",")}

# Server parameters
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Training/Learning Mode parameter
# In training mode, anomaly scores are computed and the model learns, but anomalies are never flagged (anomaly = False)
TRAINING_MODE = os.getenv("TRAINING_MODE", "false").lower() in ("true", "1", "t", "yes")

# Model Persistence Path
# If specified, the model state will be saved/loaded automatically on shutdown/startup
MODEL_PATH = os.getenv("MODEL_PATH", "/home/monga/code/go/block-x/scoring/model_states")
