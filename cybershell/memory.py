
from dataclasses import dataclass
from typing import List, Dict, Any
from collections import defaultdict

@dataclass
class MemoryItem:
    kind: str
    title: str
    content: str
    tags: List[str]
    score: float = 0.0

class SimpleVectorizer:
    def __init__(self):
        self.vocab = {}
    def _tok(self, text: str):
        import re
        return [t for t in re.findall(r'[a-z0-9_]+', text.lower()) if len(t) > 2]
    def fit_transform(self, docs: List[str]):
        self.vocab = {}; vecs = []
        for doc in docs:
            counts = defaultdict(int)
            for t in self._tok(doc): counts[t]+=1
            for t in list(counts):
                if t not in self.vocab: self.vocab[t]=len(self.vocab)
            vec = [0.0]*len(self.vocab)
            for t,c in counts.items(): vec[self.vocab[t]] = float(c)
            vecs.append(vec)
        return vecs
    def transform(self, docs: List[str]):
        vecs = []
        for doc in docs:
            counts = defaultdict(int)
            for t in self._tok(doc): counts[t]+=1
            vec = [0.0]*len(self.vocab)
            for t,c in counts.items():
                if t in self.vocab: vec[self.vocab[t]] = float(c)
            vecs.append(vec)
        return vecs
    @staticmethod
    def cosine(a,b):
        dot = sum(x*y for x,y in zip(a,b))
        na = (sum(x*x for x in a) ** 0.5) or 1.0
        nb = (sum(x*x for x in b) ** 0.5) or 1.0
        return dot/(na*nb)

class NeuralMemory:
    def __init__(self):
        self.items: List[MemoryItem] = []
        self.vec = SimpleVectorizer()
        self._matrix: List[List[float]] = []

    def add(self, item: MemoryItem):
        self.items.append(item); self._reindex()

    def bulk_add(self, items: List[MemoryItem]):
        self.items.extend(items); self._reindex()

    def _reindex(self):
        corpus = [f"{i.title} {i.content} {' '.join(i.tags)}" for i in self.items]
        self._matrix = self.vec.fit_transform(corpus) if corpus else []

    def search(self, query: str, top_k: int = 8):
        if not self.items: return []
        qv = self.vec.transform([query])[0]
        scored = [(it, self.vec.cosine(qv, self._matrix[idx])) for idx,it in enumerate(self.items)]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [{'item': it, 'score': sc} for it, sc in scored[:top_k]]

    def reinforce(self, titles: List[str], delta: float = 0.1):
        for it in self.items:
            if it.title in titles:
                it.score = max(0.0, it.score + delta)
