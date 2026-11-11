from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from model.interface import BaseModel


class NGramScorer(BaseModel):
    def __init__(self, n: int = 5, k: float = 0.01):
        """
        Initialize the N-Gram Scorer.

        Args:
            n: The n-gram size (default: 5, meaning context is 4, target is 1).
            k: The Add-k smoothing parameter (default: 0.01).
        """
        self.n = n
        self.k = k
        self.vocab = set()

        # Maps context tuple (length n - 1) to count of times context was seen
        self.context_counts = defaultdict(int)

        # Maps context tuple (length n - 1) to dictionary of target counts
        self.transition_counts = defaultdict(lambda: defaultdict(int))

    def train(self, sequence: Sequence[Any]) -> None:
        """
        Incrementally train the model with a new sequence.

        Args:
            sequence: A sequence of syscall IDs of length >= n.
        """
        if len(sequence) < self.n:
            return

        # Slide through sequence and train on all sub-sequences of length n
        for i in range(len(sequence) - self.n + 1):
            sub_seq = sequence[i : i + self.n]
            context = tuple(sub_seq[:-1])
            target = sub_seq[-1]

            # Update vocabulary
            for item in sub_seq:
                self.vocab.add(item)

            # Update counts
            self.context_counts[context] += 1
            self.transition_counts[context][target] += 1

    def score(self, sequence: Sequence[Any]) -> float:
        """
        Evaluate sequence transition probability and return an anomaly score.

        Using Add-k smoothing:
        P(target | context) = (count(context, target) + k) / (count(context) + k * |V|)

        Where |V| is the size of the observed vocabulary.

        The anomaly score is calculated as: 1.0 - P(target | context)

        Args:
            sequence: A sequence of syscall IDs of length >= n.

        Returns:
            A float score between 0.0 and 1.0.
        """
        if len(sequence) < self.n:
            # Not enough context to evaluate; return default non-anomaly
            return 0.0

        # We evaluate the transition at the end of the sequence
        context = tuple(sequence[-(self.n) : -1])
        target = sequence[-1]

        c_count = self.context_counts.get(context, 0)
        t_count = 0
        if context in self.transition_counts:
            t_count = self.transition_counts[context].get(target, 0)

        # Dynamic vocabulary size estimation (at least 1 to avoid DivisionByZero)
        vocab_size = max(1, len(self.vocab))

        # Add-k smoothed probability
        prob = (t_count + self.k) / (c_count + self.k * vocab_size)

        # Ensure floating point bounds
        prob = max(0.0, min(1.0, prob))

        # Return anomaly score
        return 1.0 - prob

    def reset(self) -> None:
        """Clear all learned transition counts and vocabulary."""
        self.vocab.clear()
        self.context_counts.clear()
        self.transition_counts.clear()

    def save(self, filepath: str) -> None:
        """
        Save the model state to a file using pickle.
        Converts defaultdicts to regular dicts to avoid pickling lambda functions.
        """
        import pickle

        state = {
            "n": self.n,
            "k": self.k,
            "vocab": self.vocab,
            "context_counts": dict(self.context_counts),
            "transition_counts": {
                k: dict(v) for k, v in self.transition_counts.items()
            },
        }
        with open(filepath, "wb") as f:
            pickle.dump(state, f)

    def load(self, filepath: str) -> None:
        """
        Load the model state from a file.
        Reconstructs the original defaultdict structures.
        """
        import pickle
        from collections import defaultdict

        with open(filepath, "rb") as f:
            state = pickle.load(f)

        self.n = state.get("n", self.n)
        self.k = state.get("k", self.k)
        self.vocab = set(state.get("vocab", []))
        self.context_counts = defaultdict(int, state.get("context_counts", {}))

        self.transition_counts = defaultdict(lambda: defaultdict(int))
        for k, v in state.get("transition_counts", {}).items():
            self.transition_counts[k] = defaultdict(int, v)
