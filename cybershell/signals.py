
from dataclasses import dataclass, field
from typing import List, Dict, Any
@dataclass
class SignalEvent:
    status_code: int = 0
    length_delta: float = 0.0
    time_delta_ms: float = 0.0
    error_tokens: List[str] = field(default_factory=list)
    reflections: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    tokens_seen: List[str] = field(default_factory=list)
    url_path: str = ''
    dom_snippets: List[str] = field(default_factory=list)
    notes: str = ''
    def as_text(self) -> str:
        pieces = [
            f"status:{self.status_code}",
            f"len_delta:{self.length_delta:.3f}",
            f"time_delta_ms:{self.time_delta_ms:.1f}",
            "errors:" + " | ".join(self.error_tokens),
            "reflect:" + " | ".join(self.reflections),
            "headers:" + " | ".join([f"{k}:{v}" for k,v in self.headers.items()]),
            "cookies:" + " | ".join(self.cookies.keys()),
            "tokens:" + " | ".join(self.tokens_seen),
            "path:" + self.url_path,
            "dom:" + " | ".join(self.dom_snippets),
            "notes:" + self.notes,
        ]
        return "\n".join(pieces)
