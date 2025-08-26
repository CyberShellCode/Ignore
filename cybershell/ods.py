from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
import time
from .scoring import EvidenceAggregator, BaseScorer
from .strategies import PlanStep

class ExploitationPhase(Enum):
    """Phases of exploitation"""
    DISCOVERY = "discovery"
    TESTING = "testing"
    EXPLOITATION = "exploitation"
    ESCALATION = "escalation"
    CHAINING = "chaining"
    EXFILTRATION = "exfiltration"

@dataclass
class ODSConfig:
    """Configuration for Outcome-Directed Search"""
    window: int = 5                    # Window size for evidence analysis
    patience_steps: int = 3            # Steps before pivoting if no improvement
    stagnation_rounds: int = 2         # Rounds of stagnation before major pivot
    min_improvement: float = 0.05      # Minimum improvement to continue strategy
    stop_threshold: float = 0.85       # Evidence threshold for early stop
    max_iterations: int = 20           # Maximum ODS iterations
    
    # Phase thresholds
    testing_threshold: float = 0.3     # Move from discovery to testing
    exploit_threshold: float = 0.5     # Move from testing to exploitation
    escalation_threshold: float = 0.7  # Move to privilege escalation
    chaining_threshold: float = 0.8    # Attempt vulnerability chaining
    
    # Adaptive parameters
    exploration_rate: float = 0.2      # Chance to explore new strategies
    exploitation_rate: float = 0.8     # Chance to exploit known vulnerabilities
    adapt_thresholds: bool = True      # Dynamically adjust thresholds


class ExploitationState:
    """Tracks the current state of exploitation"""
    
    def __init__(self):
        self.phase = ExploitationPhase.DISCOVERY
        self.discovered_vulns: List[Dict[str, Any]] = []
        self.confirmed_vulns: List[Dict[str, Any]] = []
        self.exploited_vulns: List[Dict[str, Any]] = []
        self.chained_exploits: List[Dict[str, Any]] = []
        self.iteration = 0
        self.stagnation_count = 0
        self.last_improvement_iteration = 0
        self.strategy_performance: Dict[str, float] = {}
    
    def add_vulnerability(self, vuln_type: str, confidence: float, details: Dict):
        """Add a discovered vulnerability"""
        vuln = {
            'type': vuln_type,
            'confidence': confidence,
            'details': details,
            'iteration': self.iteration
        }
        
        if confidence > 0.7:
            self.confirmed_vulns.append(vuln)
        else:
            self.discovered_vulns.append(vuln)
    
    def mark_exploited(self, vuln_type: str, impact: float):
        """Mark a vulnerability as successfully exploited"""
        self.exploited_vulns.append({
            'type': vuln_type,
            'impact': impact,
            'iteration': self.iteration
        })
        
        # Reset stagnation on successful exploit
        self.stagnation_count = 0
        self.last_improvement_iteration = self.iteration
    
    def update_phase(self, new_phase: ExploitationPhase):
        """Update exploitation phase"""
        self.phase = new_phase
    
    def get_unexploited_vulns(self) -> List[Dict[str, Any]]:
        """Get confirmed but unexploited vulnerabilities"""
        exploited_types = {v['type'] for v in self.exploited_vulns}
        return [v for v in self.confirmed_vulns if v['type'] not in exploited_types]


class OutcomeDirectedSearch:
    """
    Manages adaptive exploitation through outcome-directed search
    """
    
    def __init__(self, config: Optional[ODSConfig] = None):
        self.cfg = config or ODSConfig()
        self.state = ExploitationState()
        self.evidence_agg = EvidenceAggregator(window_size=self.cfg.window)
        self.scorer: Optional[BaseScorer] = None
        
        # Strategy selection weights
        self.strategy_weights = {
            'aggressive': 0.3,
            'targeted': 0.4,
            'chaining': 0.2,
            'exfiltration': 0.1
        }
    
    def set_scorer(self, scorer: BaseScorer):
        """Set the evidence scorer"""
        self.scorer = scorer
    
    def should_pivot(self) -> bool:
        """Determine if strategy should pivot"""
        # Check stagnation
        if self.state.stagnation_count >= self.cfg.patience_steps:
            return True
        
        # Check if evidence is declining
        if self.evidence_agg.get_trend() == 'declining':
            return True
        
        # Check if we've been in same phase too long
        phase_duration = self.state.iteration - self.state.last_improvement_iteration
        if phase_duration > self.cfg.patience_steps * 2:
            return True
        
        return False
    
    def select_next_strategy(self) -> str:
        """Select next exploitation strategy based on current state"""
        current_evidence = self.evidence_agg.get_ema()
        
        # Phase-based strategy selection
        if self.state.phase == ExploitationPhase.DISCOVERY:
            if current_evidence < self.cfg.testing_threshold:
                return 'broad_discovery'
            else:
                self.state.update_phase(ExploitationPhase.TESTING)
                return 'targeted_testing'
        
        elif self.state.phase == ExploitationPhase.TESTING:
            if current_evidence < self.cfg.exploit_threshold:
                return 'deep_testing'
            else:
                self.state.update_phase(ExploitationPhase.EXPLOITATION)
                return 'aggressive_exploitation'
        
        elif self.state.phase == ExploitationPhase.EXPLOITATION:
            if current_evidence < self.cfg.escalation_threshold:
                return 'exploit_confirmed'
            else:
                self.state.update_phase(ExploitationPhase.ESCALATION)
                return 'privilege_escalation'
        
        elif self.state.phase == ExploitationPhase.ESCALATION:
            if current_evidence < self.cfg.chaining_threshold:
                return 'lateral_movement'
            else:
                self.state.update_phase(ExploitationPhase.CHAINING)
                return 'chain_vulnerabilities'
        
        elif self.state.phase == ExploitationPhase.CHAINING:
            # Final phase - maximum impact
            self.state.update_phase(ExploitationPhase.EXFILTRATION)
            return 'data_exfiltration'
        
        else:  # EXFILTRATION
            return 'persistence_and_cleanup'
    
    def generate_pivot_plan(self, target: str, current_evidence: float) -> List[PlanStep]:
        """Generate a pivot plan when current strategy is not working"""
        steps = []
        strategy = self.select_next_strategy()
        
        if strategy == 'broad_discovery':
            # Broad vulnerability discovery
            steps.extend([
                PlanStep("SQLiTestPlugin", "Broad SQL injection scan", {"target": target}),
                PlanStep("XSSTestPlugin", "Broad XSS scan", {"target": target}),
                PlanStep("IDORTestPlugin", "Broad IDOR scan", {"target": target}),
                PlanStep("SSRFTestPlugin", "Broad SSRF scan", {"target": target})
            ])
        
        elif strategy == 'targeted_testing':
            # Focus on most promising vulnerabilities
            for vuln in self.state.discovered_vulns[:3]:
                steps.append(
                    PlanStep(f"{vuln['type']}ExploitPlugin",
                           f"Target {vuln['type']} exploitation",
                           {"target": target, "confidence": vuln['confidence']})
                )
        
        elif strategy == 'aggressive_exploitation':
            # Aggressive exploitation of confirmed vulnerabilities
            for vuln in self.state.confirmed_vulns:
                steps.append(
                    PlanStep(f"{vuln['type']}ExploitPlugin",
                           f"Aggressively exploit {vuln['type']}",
                           {"target": target, "aggressive": True, "extract_data": True})
                )
        
        elif strategy == 'privilege_escalation':
            # Attempt privilege escalation
            steps.extend([
                PlanStep("AuthBypassExploitPlugin",
                       "Escalate to admin privileges",
                       {"target": target, "escalate_privileges": True}),
                PlanStep("IDORToPrivEscPlugin",
                       "IDOR-based privilege escalation",
                       {"target": target})
            ])
        
        elif strategy == 'chain_vulnerabilities':
            # Chain multiple vulnerabilities
            if len(self.state.exploited_vulns) >= 2:
                steps.extend([
                    PlanStep("SQLiToRCEChainPlugin",
                           "Chain SQLi to RCE",
                           {"target": target}),
                    PlanStep("XSSToAccountTakeoverPlugin",
                           "Chain XSS to account takeover",
                           {"target": target})
                ])
        
        elif strategy == 'data_exfiltration':
            # Maximum impact - data exfiltration
            steps.append(
                PlanStep("DataExfiltrationPlugin",
                       "Exfiltrate sensitive data for PoC",
                       {"target": target, "limit": 100})  # Limited for responsible disclosure
            )
        
        elif strategy == 'persistence_and_cleanup':
            # Establish persistence (if in scope) and prepare report
            steps.append(
                PlanStep("ReportGenerationPlugin",
                       "Generate comprehensive exploit report",
                       {"target": target, "include_all": True})
            )
        
        return steps
    
    def adapt_thresholds(self, evidence_history: List[float]):
        """Dynamically adapt phase thresholds based on evidence history"""
        if not self.cfg.adapt_thresholds or len(evidence_history) < 5:
            return
        
        # Calculate evidence statistics
        avg_evidence = sum(evidence_history) / len(evidence_history)
        max_evidence = max(evidence_history)
        
        # Adapt thresholds based on actual evidence levels
        if max_evidence < 0.5:
            # Lower thresholds if evidence is consistently low
            self.cfg.testing_threshold *= 0.9
            self.cfg.exploit_threshold *= 0.9
        elif avg_evidence > 0.7:
            # Raise thresholds if evidence is consistently high
            self.cfg.escalation_threshold = min(0.9, self.cfg.escalation_threshold * 1.1)
            self.cfg.chaining_threshold = min(0.95, self.cfg.chaining_threshold * 1.1)
    
    def observe(self, evidence: float, results: List[Any]) -> Optional[PlanStep]:
        """
        Observe evidence and determine next action
        Returns a pivot step if strategy should change
        """
        self.state.iteration += 1
        self.evidence_agg.add(evidence)
        
        # Check for improvement
        if evidence > self.evidence_agg.get_sma():
            self.state.stagnation_count = 0
            self.state.last_improvement_iteration = self.state.iteration
        else:
            self.state.stagnation_count += 1
        
        # Adapt thresholds
        self.adapt_thresholds(self.evidence_agg.scores)
        
        # Check if we should stop (evidence threshold reached)
        if self.evidence_agg.get_max() >= self.cfg.stop_threshold:
            return None
        
        # Check if we should pivot
        if self.should_pivot():
            # Generate pivot action
            pivot_plan = self.generate_pivot_plan("", evidence)
            if pivot_plan:
                return pivot_plan[0]  # Return first step of pivot plan
        
        return None
    
    def update_from_result(self, result: Dict[str, Any]):
        """Update state based on exploitation result"""
        if not result.get('success'):
            return
        
        details = result.get('details') or {}
        
        # Check for discovered vulnerabilities
        if isinstance(details, dict) and (details.get('vulnerable') or details.get('confidence', 0) > 0.5):
            vuln_type = self._identify_vuln_type(result)
            confidence = details.get('confidence', details.get('evidence_score', 0.5))
            
            self.state.add_vulnerability(vuln_type, confidence, details)
        
        # Check for successful exploitation
        if isinstance(details, dict) and (details.get('exploited') or details.get('impact_proof')):
            vuln_type = self._identify_vuln_type(result)
            impact = details.get('evidence_score', 0.7)
            
            self.state.mark_exploited(vuln_type, impact)
    
    def _identify_vuln_type(self, result: Dict[str, Any]) -> str:
        """Identify vulnerability type from result"""
        plugin_name = result.get('name', '').lower()
        
        vuln_types = ['sqli', 'xss', 'rce', 'idor', 'ssrf', 'xxe', 'ssti', 'auth']
        
        for vuln in vuln_types:
            if vuln in plugin_name:
                return vuln
        
        return 'unknown'
    
    def get_exploitation_summary(self) -> Dict[str, Any]:
        """Get summary of exploitation progress"""
        return {
            'phase': self.state.phase.value,
            'iteration': self.state.iteration,
            'discovered_vulns': len(self.state.discovered_vulns),
            'confirmed_vulns': len(self.state.confirmed_vulns),
            'exploited_vulns': len(self.state.exploited_vulns),
            'chained_exploits': len(self.state.chained_exploits),
            'current_evidence': self.evidence_agg.get_ema(),
            'max_evidence': self.evidence_agg.get_max(),
            'trend': self.evidence_agg.get_trend(),
            'stagnation': self.state.stagnation_count
        }
    
    def should_attempt_chaining(self) -> bool:
        """Determine if vulnerability chaining should be attempted"""
        # Need at least 2 exploited vulnerabilities
        if len(self.state.exploited_vulns) < 2:
            return False
        
        # Evidence should be high enough
        if self.evidence_agg.get_ema() < self.cfg.chaining_threshold:
            return False
        
        # Check for chainable combinations
        vuln_types = {v['type'] for v in self.state.exploited_vulns}
        
        chainable_pairs = [
            {'sqli', 'rce'},
            {'xss', 'csrf'},
            {'idor', 'auth'},
            {'ssrf', 'rce'},
            {'xxe', 'ssrf'}
        ]
        
        return any(pair.issubset(vuln_types) for pair in chainable_pairs)
    
    def get_recommended_next_steps(self, target: str) -> List[PlanStep]:
        """Get recommended next steps based on current state"""
        steps = []
        
        # Check unexploited confirmed vulnerabilities
        unexploited = self.state.get_unexploited_vulns()
        if unexploited:
            for vuln in unexploited[:2]:  # Focus on top 2
                steps.append(
                    PlanStep(f"{vuln['type']}ExploitPlugin",
                           f"Exploit confirmed {vuln['type']}",
                           {"target": target, **vuln['details']})
                )
        
        # Check for chaining opportunity
        if self.should_attempt_chaining():
            steps.append(
                PlanStep("VulnerabilityChainPlugin",
                       "Chain exploited vulnerabilities",
                       {"target": target, "auto_detect": True})
            )
        
        # If no specific recommendations, continue with current phase
        if not steps:
            strategy = self.select_next_strategy()
            steps = self.generate_pivot_plan(target, self.evidence_agg.get_ema())
        
        return steps
