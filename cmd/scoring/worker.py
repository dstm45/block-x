from collections import OrderedDict, deque
from typing import Any

from model.interface import BaseModel


class ScoringWorker:
    def __init__(
        self,
        model: BaseModel,
        max_pids: int = 10000,
        n_gram_size: int = 5,
        exit_syscalls: set[int] = {60, 231},
        anomaly_threshold: float = 0.9,
        training_mode: bool = False,
    ):
        """
        Initialize the Scoring Worker.

        Args:
            model: An instance of BaseModel (e.g. NGramScorer).
            max_pids: Max active PIDs to track concurrently before LRU eviction.
            n_gram_size: The sliding window sequence size.
            exit_syscalls: Set of system call IDs representing process termination.
            anomaly_threshold: Threshold to determine if a score signifies an anomaly.
        """
        self.model = model
        self.max_pids = max_pids
        self.n_gram_size = n_gram_size
        self.exit_syscalls = exit_syscalls
        self.anomaly_threshold = anomaly_threshold
        self.training_mode = training_mode

        # Maps PID -> deque(maxlen=n_gram_size)
        # We use OrderedDict to track access order for LRU eviction
        self.pid_windows: OrderedDict[int, deque] = OrderedDict()

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Process a single system call event.

        Updates sliding windows, scores sequences, runs online learning,
        and cleans up process history on termination/eviction.

        Args:
            event: A dictionary representing the system call log.

        Returns:
            The modified event dictionary with scoring results.
        """
        pid = event.get("pid")
        syscall = event.get("syscall")

        # Ensure we have the required keys
        if pid is None or syscall is None:
            event["processed"] = False
            event["anomaly_score"] = 0.0
            event["anomaly"] = False
            return event

        # Ensure types are correct
        try:
            pid = int(pid)
            syscall = int(syscall)
        except (ValueError, TypeError):
            event["processed"] = False
            event["anomaly_score"] = 0.0
            event["anomaly"] = False
            return event

        # 1. Manage PID State cache
        if pid in self.pid_windows:
            window = self.pid_windows[pid]
            # Move to end to mark as recently used
            self.pid_windows.move_to_end(pid)
        else:
            window = deque(maxlen=self.n_gram_size)
            self.pid_windows[pid] = window

            # Enforce LRU cache limits
            if len(self.pid_windows) > self.max_pids:
                # Pop the oldest (least recently used) PID
                self.pid_windows.popitem(last=False)

        # 2. Add current syscall to the sliding window
        window.append(syscall)

        # 3. Score sequence if window is fully populated
        if len(window) == self.n_gram_size:
            seq = list(window)

            # Evaluate surprise / anomaly score
            score = self.model.score(seq)

            event["processed"] = True
            event["anomaly_score"] = score
            event["anomaly"] = (
                (score >= self.anomaly_threshold) if not self.training_mode else False
            )

            # Update the online learning model
            self.model.train(seq)
        else:
            # We don't have enough history to score this yet
            event["processed"] = False
            event["anomaly_score"] = 0.0
            event["anomaly"] = False

        # 4. Check for system exit syscalls
        if syscall in self.exit_syscalls:
            # Strip process history out of memory immediately upon termination
            self.pid_windows.pop(pid, None)

        return event

    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Process a batch of events sequentially.

        Args:
            events: A list of system call events.

        Returns:
            A list of scored and annotated system call events.
        """
        return [self.process_event(event) for event in events]

    def reset(self) -> None:
        """Clear all active PID windows."""
        self.pid_windows.clear()
