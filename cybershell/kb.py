
from dataclasses import dataclass
from typing import List
from .memory import NeuralMemory, MemoryItem

@dataclass
class KBEntry:
    title: str
    content: str
    tags: List[str]

class KnowledgeBase:
    def __init__(self):
        self.memory = NeuralMemory()
    def ingest(self, entries: List[KBEntry]):
        items = [MemoryItem(kind='kb', title=e.title, content=e.content, tags=e.tags) for e in entries]
        self.memory.bulk_add(items)
    def add_entry(self, entry: KBEntry):
        self.memory.add(MemoryItem(kind='kb', title=entry.title, content=entry.content, tags=entry.tags))
    def retrieve(self, query: str, k: int = 8):
        return self.memory.search(query, top_k=k)
    def reinforce(self, titles: List[str], delta: float = 0.1):
        self.memory.reinforce(titles, delta=delta)
