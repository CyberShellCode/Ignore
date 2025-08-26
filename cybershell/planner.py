
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class PlanStep:
    plugin: str
    rationale: str
    params: Dict[str, Any]

class Planner:
    """Planner that can be guided by an adaptive mapper and optional LLM."""
    def __init__(self, kb, mapper=None, llm=None):
        self.kb = kb
        self.mapper = mapper      # AdaptiveLearningMapper or None
        self.llm = llm            # LLM interface or None

    def make_plan(self, target: str, recon: Dict[str, Any], signals_text: Optional[str] = None) -> List[PlanStep]:
        steps: List[PlanStep] = []

        # Always start with safe discovery steps
        steps.append(PlanStep(plugin='HttpFingerprintPlugin', rationale='Identify headers/banners in lab', params={'target': target}))
        steps.append(PlanStep(plugin='FormDiscoveryPlugin', rationale='Map basic forms/inputs in lab', params={'target': target}))

        # If we have signals + mapper, steer tactic families
        if self.mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = self.mapper.map(evt)
            for fam,score in m.top_families[:3]:
                steps.append(PlanStep(plugin='HeuristicAnalyzerPlugin', rationale=f"Mapper suggests family={fam} score={score:.2f}", params={'target': target, 'hint': fam}))

        # Optionally let an LLM propose additional safe steps based on recon
        if self.llm:
            suggestion = self.llm.suggest_steps(target=target, recon=recon)
            for s in suggestion:
                steps.append(PlanStep(plugin=s['plugin'], rationale=s['why'], params={'target': target, **s.get('params',{})}))

        return steps
