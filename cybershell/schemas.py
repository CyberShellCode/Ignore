
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class Tactic:
    name: str
    description: str
    conditions: Dict[str, Any]
    steps: List[str]

@dataclass
class Evidence:
    kind: str
    summary: str
    artifacts: Dict[str, str]
