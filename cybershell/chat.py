
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .kb import KnowledgeBase

@dataclass
class ChatMessage:
    role: str
    content: str

@dataclass
class ChatSession:
    kb: KnowledgeBase
    llm: Optional[object] = None   # pluggable LLM connector
    history: List[ChatMessage] = field(default_factory=list)

    def ask(self, text: str) -> Dict[str, Any]:
        self.history.append(ChatMessage('user', text))
        hits = self.kb.retrieve(text, k=5)
        kb_titles = [h['item'].title for h in hits]
        kb_summary = "Top related knowledge: " + ", ".join(kb_titles) if hits else "No related entries yet."
        if self.llm:
            answer = self.llm.answer(text=text, kb_titles=kb_titles)
        else:
            answer = kb_summary
        self.history.append(ChatMessage('assistant', answer))
        return {'answer': answer, 'hits': [{'title': t, 'score': h['score']} for t,h in zip(kb_titles, hits)]}
