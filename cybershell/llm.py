from dataclasses import dataclass
from typing import List, Dict, Any

SYSTEM_PROMPT = (
    "You are CyberShell's planning co-pilot. Suggest non-destructive, lab-safe analysis steps."
)

def build_step_prompt(target: str, recon: Dict[str, Any], kb_titles: List[str], miner_summaries: List[str], mapper_top: List[str]) -> str:
    parts = [
        f"Target: {target}",
        f"Recon: {recon}",
        f"Top families (mapper): {', '.join(mapper_top) if mapper_top else 'n/a'}",
        "KB titles: " + (", ".join(kb_titles) if kb_titles else "(none)"),
        "Doc summaries:\n" + ("\n".join(miner_summaries) if miner_summaries else "(none)"),
        "Output JSON list of steps; each with: plugin, why, params (no network/exploit)."
    ]
    return "\n".join(parts)

@dataclass
class LLMConnector:
    def answer(self, text: str, kb_titles: List[str]) -> str:
        return "LLM disabled. KB: " + (", ".join(kb_titles) if kb_titles else "(none)")
    def suggest_steps(self, target: str, recon: Dict[str, Any], kb_titles: List[str] = None, miner_summaries: List[str] = None, mapper_top: List[str] = None) -> List[Dict[str, Any]]:
        return []
