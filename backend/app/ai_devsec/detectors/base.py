from abc import ABC, abstractmethod
from typing import List
from ..schemas import Finding

class Detector(ABC):
    name: str

    @abstractmethod
    def run(self, code: str) -> List[Finding]:
        """Analyze code and return findings."""
        raise NotImplementedError
