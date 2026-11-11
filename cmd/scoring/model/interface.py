from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any


class BaseModel(ABC):
    @abstractmethod
    def train(self, sequence: Sequence[Any]) -> None:
        """
        Update the model incrementally with a new sequence (online learning).

        Args:
            sequence: A sequence of syscall IDs (length equal to n-gram size).
        """

    @abstractmethod
    def score(self, sequence: Sequence[Any]) -> float:
        """
        Compute the anomaly score for a given sequence.

        Args:
            sequence: A sequence of syscall IDs (length equal to n-gram size).

        Returns:
            A float score between 0.0 and 1.0, where higher values indicate greater anomaly.
        """

    @abstractmethod
    def reset(self) -> None:
        """
        Reset the internal state of the model.
        """

    @abstractmethod
    def save(self, filepath: str) -> None:
        """
        Save the model state to a file.
        """

    @abstractmethod
    def load(self, filepath: str) -> None:
        """
        Load the model state from a file.
        """
