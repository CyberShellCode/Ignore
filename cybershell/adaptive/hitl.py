from dataclasses import dataclass, field
from typing import List
import numpy as np
from .mapper import AdaptiveLearningMapper, FAMILIES
from .signals import SignalEvent
@dataclass
class FeedbackItem:
    event: SignalEvent
    correct_families: List[str]
@dataclass
class HITLLoop:
    mapper: AdaptiveLearningMapper
    buffer: List[FeedbackItem] = field(default_factory=list)
    def submit_feedback(self, item: FeedbackItem):
        self.buffer.append(item)
    def apply(self):
        if not self.buffer: return 0
        texts = [fb.event.as_text() for fb in self.buffer]
        Y = np.zeros((len(self.buffer), len(FAMILIES)), dtype=int)
        for i, fb in enumerate(self.buffer):
            for fam in fb.correct_families:
                if fam in FAMILIES:
                    Y[i, FAMILIES.index(fam)] = 1
        self.mapper.ml.partial_fit(texts, Y)
        n = len(self.buffer); self.buffer.clear(); return n
