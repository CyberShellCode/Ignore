
from dataclasses import dataclass
from typing import List
from .kb import KnowledgeBase

@dataclass
class LearningLoop:
    kb: KnowledgeBase
    def record_outcome(self, used_titles: List[str], success: bool):
        self.kb.reinforce(used_titles, delta=0.1 if success else -0.05)
