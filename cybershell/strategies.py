from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod
from .signals import SignalEvent

# Import your existing PlanStep from planner
from .planner import PlanStep

class BasePlannerStrategy(ABC):
    """Base class for planning strategies"""
    name: str = "base"

    @abstractmethod
    def plan(self,
            target: str,
            recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None,
            llm: Any = None,
            kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None,
            llm_step_budget: int = 3) -> List[PlanStep]:
        """Generate exploitation plan using PlanStep from planner.py"""
        pass

    def _add_exploitation_steps(self, steps: List[PlanStep], target: str,
                               vuln_class: str, confidence: float = 0.7):
        """Add exploitation steps for a vulnerability class"""

        exploit_map = {
            'sqli': [
                ('SQLiTestPlugin', f'Test for SQL injection (confidence: {confidence:.2f})'),
                ('SQLiExploitPlugin', 'Exploit SQL injection for data extraction')
            ],
            'xss': [
                ('XSSTestPlugin', f'Test for XSS vulnerabilities (confidence: {confidence:.2f})'),
                ('XSSExploitPlugin', 'Exploit XSS for session hijacking')
            ],
            'rce': [
                ('RCETestPlugin', f'Test for remote code execution (confidence: {confidence:.2f})'),
                ('RCEExploitPlugin', 'Exploit RCE for system access')
            ],
            'idor': [
                ('IDORTestPlugin', f'Test for IDOR vulnerabilities (confidence: {confidence:.2f})'),
                ('IDORExploitPlugin', 'Exploit IDOR for data access')
            ],
            'ssrf': [
                ('SSRFTestPlugin', f'Test for SSRF (confidence: {confidence:.2f})'),
                ('SSRFExploitPlugin', 'Exploit SSRF for internal access')
            ],
            'ssti': [
                ('SSTITestPlugin', f'Test for template injection (confidence: {confidence:.2f})'),
                ('SSTIExploitPlugin', 'Exploit SSTI for code execution')
            ],
            'auth': [
                ('AuthBypassTestPlugin', f'Test authentication bypass (confidence: {confidence:.2f})'),
                ('AuthBypassExploitPlugin', 'Exploit auth bypass for admin access')
            ]
        }

        if vuln_class in exploit_map:
            for plugin, rationale in exploit_map[vuln_class]:
                steps.append(PlanStep(
                    plugin=plugin,
                    rationale=rationale,
                    params={'target': target, 'confidence': confidence}
                ))


class DepthFirstPlanner(BasePlannerStrategy):
    """
    Depth-first exploitation strategy
    Goes deep into each vulnerability class before moving to next
    """
    name = "depth_first"

    def plan(self,
            target: str,
            recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None,
            llm: Any = None,
            kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None,
            llm_step_budget: int = 3) -> List[PlanStep]:

        steps: List[PlanStep] = []

        # Phase 1: Initial recon (matching your planner.py style)
        steps.append(PlanStep(
            plugin='HttpFingerprintPlugin',
            rationale='Identify headers/banners for depth analysis',
            params={'target': target}
        ))
        steps.append(PlanStep(
            plugin='FormDiscoveryPlugin',
            rationale='Map forms/inputs for deep testing',
            params={'target': target}
        ))

        # Phase 2: Technology-specific deep testing
        if recon:
            tech_stack = recon.get('technologies', [])

            # Deep SQL injection testing if database detected
            if any(db in str(tech_stack).lower() for db in ['mysql', 'postgres', 'mssql', 'oracle']):
                self._add_exploitation_steps(steps, target, 'sqli', confidence=0.9)
                steps.append(PlanStep(
                    plugin='AdvancedSQLiPlugin',
                    rationale='Deep SQLi exploitation with advanced techniques',
                    params={'target': target, 'technique': 'union_based', 'extract_data': True}
                ))

            # Deep form testing
            if recon.get('forms'):
                steps.append(PlanStep(
                    plugin='BusinessLogicPlugin',
                    rationale='Deep business logic testing on forms',
                    params={'target': target, 'forms': recon['forms']}
                ))
                self._add_exploitation_steps(steps, target, 'xss', confidence=0.8)
                self._add_exploitation_steps(steps, target, 'csrf', confidence=0.7)

        # Phase 3: Mapper-informed deep dive (compatible with your mapper)
        if mapper and signals_text:
            from .adaptive.signals import SignalEvent
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)

            # Deep dive into top 2 families
            for fam, score in m.top_families[:2]:
                steps.append(PlanStep(
                    plugin='HeuristicAnalyzerPlugin',
                    rationale=f'Deep analysis for {fam} (mapper score: {score:.2f})',
                    params={'target': target, 'hint': fam, 'depth': 'deep'}
                ))

                # Map to specific exploitation
                if score > 0.7:
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        self._add_exploitation_steps(steps, target, vuln_class, score)

        # Phase 4: LLM-guided deep exploitation
        if llm and llm_step_budget > 0:
            try:
                suggestions = llm.suggest_steps(target=target, recon=recon or {})
                for s in suggestions[:llm_step_budget]:
                    steps.append(PlanStep(
                        plugin=s.get('plugin', 'HeuristicAnalyzerPlugin'),
                        rationale=s.get('why', 'LLM-suggested deep exploitation'),
                        params={'target': target, **s.get('params', {})}
                    ))
            except:
                pass

        # Phase 5: Chaining attempts
        steps.append(PlanStep(
            plugin='ExploitationChainPlugin',
            rationale='Attempt vulnerability chaining for maximum impact',
            params={'target': target, 'auto_detect': True}
        ))

        return steps

    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()

        if 'sql' in family_lower or 'injection' in family_lower:
            return 'sqli'
        elif 'xss' in family_lower or 'script' in family_lower:
            return 'xss'
        elif 'rce' in family_lower or 'command' in family_lower:
            return 'rce'
        elif 'idor' in family_lower or 'authorization' in family_lower:
            return 'idor'
        elif 'ssrf' in family_lower:
            return 'ssrf'
        elif 'ssti' in family_lower or 'template' in family_lower:
            return 'ssti'
        elif 'auth' in family_lower or 'jwt' in family_lower:
            return 'auth'

        return None


class BreadthFirstPlanner(BasePlannerStrategy):
    """
    Breadth-first exploitation strategy
    Tests wide range of vulnerabilities before going deep
    """
    name = "breadth_first"

    def plan(self,
            target: str,
            recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None,
            llm: Any = None,
            kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None,
            llm_step_budget: int = 2) -> List[PlanStep]:

        steps: List[PlanStep] = []

        # Phase 1: Broad reconnaissance
        steps.extend([
            PlanStep('HttpFingerprintPlugin', 'Quick fingerprinting scan', {'target': target}),
            PlanStep('FormDiscoveryPlugin', 'Quick form discovery', {'target': target}),
            PlanStep('APIDiscoveryPlugin', 'API endpoint discovery', {'target': target})
        ])

        # Phase 2: Broad vulnerability testing
        test_plugins = [
            ('SQLiTestPlugin', 'Quick SQL injection test'),
            ('XSSTestPlugin', 'Quick XSS test'),
            ('IDORTestPlugin', 'Quick IDOR test'),
            ('SSRFTestPlugin', 'Quick SSRF test'),
            ('SSTITestPlugin', 'Quick SSTI test'),
            ('AuthBypassTestPlugin', 'Quick auth bypass test'),
            ('RCETestPlugin', 'Quick RCE test'),
            ('CSRFTestPlugin', 'Quick CSRF test')
        ]

        for plugin, rationale in test_plugins:
            steps.append(PlanStep(plugin, rationale, {'target': target, 'quick_scan': True}))

        # Phase 3: Single mapper hint
        if mapper and signals_text:
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)

            if m.top_families:
                fam, score = m.top_families[0]
                steps.append(PlanStep(
                    'HeuristicAnalyzerPlugin',
                    f'Quick test for {fam} (score: {score:.2f})',
                    {'target': target, 'hint': fam, 'quick': True}
                ))

        # Phase 4: Limited LLM suggestions
        if llm and llm_step_budget > 0:
            try:
                suggestions = llm.suggest_steps(target=target, recon=recon or {})
                if suggestions:
                    s = suggestions[0]
                    steps.append(PlanStep(
                        s.get('plugin', 'HeuristicAnalyzerPlugin'),
                        s.get('why', 'LLM breadth test'),
                        {'target': target, **s.get('params', {})}
                    ))
            except:
                pass

        return steps


class AggressivePlanner(BasePlannerStrategy):
    """
    Aggressive exploitation strategy
    Immediately attempts high-impact exploits
    """
    name = "aggressive"

    def plan(self,
            target: str,
            recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None,
            llm: Any = None,
            kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None,
            llm_step_budget: int = 5) -> List[PlanStep]:

        steps: List[PlanStep] = []

        # Skip recon, go straight to exploitation

        # Phase 1: High-impact vulnerability exploitation
        critical_exploits = [
            ('RCEExploitPlugin', 'Immediate RCE exploitation attempt',
             {'establish_shell': True, 'vectors': ['command_injection', 'deserialization', 'file_upload']}),

            ('SQLiExploitPlugin', 'Immediate SQLi data extraction',
             {'technique': 'union_based', 'extract_data': True, 'enumerate_db': True}),

            ('AuthBypassExploitPlugin', 'Immediate authentication bypass',
             {'escalate_privileges': True, 'methods': ['jwt_none', 'session_fixation']}),

            ('SSRFExploitPlugin', 'Immediate SSRF to cloud metadata',
             {'access_metadata': True, 'scan_internal': True}),

            ('SSTIExploitPlugin', 'Immediate template injection RCE',
             {'execute_commands': True, 'identify_engine': True})
        ]

        for plugin, rationale, params in critical_exploits:
            steps.append(PlanStep(plugin, rationale, {'target': target, **params}))

        # Phase 2: Business logic exploitation
        steps.extend([
            PlanStep('BusinessLogicPlugin',
                    'Race condition exploitation for financial impact',
                    {'target': target, 'test_race_conditions': True, 'iterations': 100}),

            PlanStep('IDORExploitPlugin',
                    'Mass IDOR data extraction',
                    {'target': target, 'extract_sensitive': True, 'enumerate_objects': True})
        ])

        # Phase 3: Vulnerability chaining
        steps.extend([
            PlanStep('ExploitationChainPlugin',
                    'Chain SQLi to RCE immediately',
                    {'target': target, 'chain_type': 'sqli_to_rce', 'aggressive': True}),

            PlanStep('ExploitationChainPlugin',
                    'Chain XSS to account takeover',
                    {'target': target, 'chain_type': 'xss_to_takeover', 'target_admin': True})
        ])

        # Phase 4: Mapper-guided aggressive exploitation
        if mapper and signals_text:
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)

            # Aggressively exploit all high-confidence findings
            for fam, score in m.top_families:
                if score > 0.5:
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class.upper()}ExploitPlugin',
                            f'Aggressive {fam} exploitation (confidence: {score:.2f})',
                            {'target': target, 'aggressive': True, 'extract_all': True}
                        ))

        # Phase 5: LLM-guided aggressive exploitation
        if llm and llm_step_budget > 0:
            try:
                # Tell LLM to be aggressive
                aggressive_recon = {
                    **(recon or {}),
                    'mode': 'aggressive',
                    'goal': 'maximum_impact'
                }

                suggestions = llm.suggest_steps(target=target, recon=aggressive_recon)

                for s in suggestions[:llm_step_budget]:
                    if 'Exploit' in s.get('plugin', ''):
                        steps.append(PlanStep(
                            s.get('plugin', 'HeuristicAnalyzerPlugin'),
                            s.get('why', 'Aggressive LLM exploitation'),
                            {'target': target, 'aggressive': True, **s.get('params', {})}
                        ))
            except:
                pass

        return steps

    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()

        mapping = {
            'sqli': 'SQLi',
            'xss': 'XSS',
            'rce': 'RCE',
            'idor': 'IDOR',
            'ssrf': 'SSRF',
            'ssti': 'SSTI',
            'auth': 'AuthBypass',
            'jwt': 'AuthBypass',
            'deserialization': 'Deserialization',
            'xxe': 'XXE'
        }

        for key, value in mapping.items():
            if key in family_lower:
                return value

        return None


class AdaptivePlanner(BasePlannerStrategy):
    """
    Adaptive planning strategy
    Adjusts approach based on signals and evidence
    """
    name = "adaptive"

    def plan(self,
            target: str,
            recon: Optional[Dict[str, Any]] = None,
            mapper: Any = None,
            llm: Any = None,
            kb: Optional[Dict[str, Any]] = None,
            signals_text: Optional[str] = None,
            llm_step_budget: int = 4) -> List[PlanStep]:

        steps: List[PlanStep] = []

        # Analyze confidence level
        confidence_level = 0.0

        if mapper and signals_text:
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)
            if m.top_families:
                confidence_level = m.top_families[0][1] if m.top_families else 0.0

        # Adapt strategy based on confidence
        if confidence_level < 0.3:
            # Low confidence - start with recon
            steps.extend([
                PlanStep('HttpFingerprintPlugin', 'Baseline fingerprint', {'target': target}),
                PlanStep('FormDiscoveryPlugin', 'Discover forms', {'target': target}),
                PlanStep('TechnologyStackPlugin', 'Identify technology stack', {'target': target})
            ])

        # Adaptive testing based on mapper confidence
        if mapper and signals_text:
            evt = SignalEvent(notes=signals_text)
            m = mapper.map(evt)

            for fam, score in m.top_families[:5]:
                if score > 0.7:
                    # High confidence - go straight to exploitation
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class}ExploitPlugin',
                            f'High-confidence {fam} exploitation (score: {score:.2f})',
                            {'target': target, 'confidence': score}
                        ))
                elif score > 0.4:
                    # Medium confidence - test first
                    vuln_class = self._map_family_to_class(fam)
                    if vuln_class:
                        steps.append(PlanStep(
                            f'{vuln_class}TestPlugin',
                            f'Test for {fam} (score: {score:.2f})',
                            {'target': target, 'confidence': score}
                        ))
                else:
                    # Low confidence - just analyze
                    steps.append(PlanStep(
                        'HeuristicAnalyzerPlugin',
                        f'Analyze {fam} signals (score: {score:.2f})',
                        {'target': target, 'hint': fam}
                    ))

        # Adaptive LLM budget
        if llm and llm_step_budget > 0:
            adjusted_budget = max(1, int(llm_step_budget * (1 + confidence_level)))

            try:
                suggestions = llm.suggest_steps(target=target, recon=recon or {})
                for s in suggestions[:adjusted_budget]:
                    steps.append(PlanStep(
                        s.get('plugin', 'HeuristicAnalyzerPlugin'),
                        s.get('why', 'Adaptive LLM suggestion'),
                        {'target': target, **s.get('params', {})}
                    ))
            except:
                pass

        # Add chaining if confidence is high
        if confidence_level > 0.6:
            steps.append(PlanStep(
                'ExploitationChainPlugin',
                'Attempt vulnerability chaining (high confidence)',
                {'target': target, 'auto_detect': True}
            ))

        return steps

    def _map_family_to_class(self, family: str) -> Optional[str]:
        """Map vulnerability family to class"""
        family_lower = family.lower()

        for vuln in ['sqli', 'xss', 'rce', 'idor', 'ssrf', 'ssti', 'auth', 'jwt', 'xxe']:
            if vuln in family_lower:
                return vuln.upper() if len(vuln) <= 4 else vuln.capitalize()

        return None


# Strategy registry
STRATEGY_REGISTRY: Dict[str, BasePlannerStrategy] = {}

def register_strategy(strategy: BasePlannerStrategy):
    """Register a planning strategy"""
    STRATEGY_REGISTRY[strategy.name] = strategy
    return strategy

def get_planner(name: str) -> BasePlannerStrategy:
    """Get planner strategy by name"""
    return STRATEGY_REGISTRY.get(name, STRATEGY_REGISTRY.get("depth_first"))

# Register default strategies
register_strategy(DepthFirstPlanner())
register_strategy(BreadthFirstPlanner())
register_strategy(AggressivePlanner())
register_strategy(AdaptivePlanner())

# Extension point for your existing Planner class
def extend_planner_with_strategy(planner_instance, strategy_name: str = "depth_first"):
    """
    Extend your existing Planner instance with a strategy
    This allows using strategies alongside your existing planner.py
    """
    strategy = get_planner(strategy_name)

    # Monkey-patch or extend the make_plan method
    original_make_plan = planner_instance.make_plan

    def enhanced_make_plan(target: str, recon: Dict[str, Any], signals_text: Optional[str] = None) -> List[PlanStep]:
        # Get base plan from original planner
        base_steps = original_make_plan(target, recon, signals_text)

        # Get strategy-based steps
        strategy_steps = strategy.plan(
            target=target,
            recon=recon,
            mapper=planner_instance.mapper,
            llm=planner_instance.llm,
            kb=planner_instance.kb,
            signals_text=signals_text
        )

        # Merge or replace based on strategy
        if strategy_name == "aggressive":
            # Aggressive replaces cautious steps
            return strategy_steps
        else:
            # Others extend the base plan
            return base_steps + strategy_steps

    planner_instance.make_plan = enhanced_make_plan
    return planner_instance
