from dataclasses import dataclass, field
from typing import Dict, Any, List, Type, Optional, Tuple
import time
import json
from pathlib import Path
from datetime import datetime

# Import unified configuration
from .unified_config import UnifiedConfig, get_config, initialize_config

# Existing imports
from .plugins import PluginBase, PluginResult
from .plugin_loader import load_user_plugins
from .strategies import get_planner
from .scoring import get_scorer
from .ods import OutcomeDirectedSearch, ODSConfig, EvidenceAggregator
from .miner import DocumentMiner
from .mapper import AdaptiveLearningMapper
from .llm import LLMConnector
from .reporting import ReportBuilder
from .agent import AutonomousBountyHunter, BountyConfig

# New enhanced modules
from cybershell.vulnerability_kb import VulnerabilityKBPlugin
from cybershell.bypass_techniques import BypassPlugin
from .continuous_learning_pipeline import ContinuousLearningPipeline, ExploitAttempt
from .business_impact_reporter import BusinessImpactReporter, VulnerabilityFinding
from .benchmarking_framework import BenchmarkingFramework, BenchmarkTarget, BenchmarkResult
from .advanced_ai_orchestrator import AdvancedAIOrchestrator, ModelCapability
from .autonomous_orchestration_engine import (
    AutonomousOrchestrationEngine, 
    AutonomousGoal, 
    ExploitationState,
    DecisionPriority
)
from .validation_framework import (
    RealWorldValidationFramework,
    ValidationResult,
    ValidationEvidence,
    EvidenceType,
    ValidationStrength
)

# NEW: Import fingerprinting and payload management
from .fingerprinter import Fingerprinter, TargetFingerprint
from .payload_manager import PayloadManager, SmartPayloadSelector

@dataclass
class ExploitationMetrics:
    """Metrics for exploitation tracking"""
    total_attempts: int = 0
    successful_exploits: int = 0
    failed_exploits: int = 0
    total_time: float = 0
    vulnerabilities_found: List[str] = field(default_factory=list)
    fingerprints_collected: int = 0  # NEW

class CyberShell:
    """
    Main orchestrator for CyberShell framework
    Now with unified configuration, enhanced modules, and intelligent payload selection
    """
    
    def __init__(self, config: Optional[Dict] = None, args=None):
        """Initialize CyberShell with unified configuration"""
        
        # Initialize unified configuration
        if args:
            self.config = initialize_config(args=args)
        elif config:
            self.config = initialize_config(config_dict=config)
        else:
            self.config = initialize_config()
        
        # Validate configuration
        issues = self.config.validate()
        if issues:
            print(f"[WARNING] Configuration issues: {issues}")
        
        # Core configuration shortcuts
        self.safety_config = self.config.safety
        self.bounty_config = self.config.bounty
        self.exploitation_config = self.config.exploitation
        self.llm_config = self.config.llm
        
        # Initialize core components
        self.plugins = self._load_plugins()
        self.planner = get_planner(self.config.exploitation.max_parallel_exploits)
        self.scorer = get_scorer('default')
        self.metrics = ExploitationMetrics()
        
        # NEW: Initialize fingerprinting and payload management
        self.fingerprinter = Fingerprinter({
            'timeout': self.config.exploitation.request_timeout,
            'aggressive': self.config.exploitation.aggressive_mode,
            'use_external_tools': False  # Can be configured
        })
        
        self.vuln_kb = VulnerabilityKBPlugin(self.config)
        self.payload_selector = SmartPayloadSelector()
        self.payload_manager = PayloadManager(self.vuln_kb.kb)
        
        # Cache for fingerprints
        self.fingerprint_cache = {}
        
        # Initialize enhanced modules
        self._initialize_enhanced_modules()
        
        # Initialize ODS if configured
        if self.config.autonomy.enable_autonomy:
            self.ods = OutcomeDirectedSearch(ODSConfig())
            self.evidence_aggregator = EvidenceAggregator()
        
        # Initialize LLM if configured
        if self.config.llm.provider != 'none':
            self.llm_connector = LLMConnector(
                provider=self.config.llm.provider,
                model=self.config.llm.model,
                base_url=self.config.llm.base_url,
                api_key=self.config.llm.api_key
            )
        else:
            self.llm_connector = None
        
        # Initialize reporting
        self.report_builder = ReportBuilder(self.config.reporting)
        
        # Initialize agent if in autonomous mode
        if self.config.autonomy.enable_autonomy:
            self.agent = AutonomousBountyHunter(
                self.config.bounty,
                self.safety_config
            )
            # Wire in payload manager to agent
            self.agent.payload_manager = self.payload_manager
            self.agent.fingerprinter = self.fingerprinter
    
    def _initialize_enhanced_modules(self):
        """Initialize all enhanced modules with unified config"""
        
        # Machine Learning Pipeline
        self.learning_pipeline = ContinuousLearningPipeline(
            model_dir=self.config.learning.model_dir
        )
        
        # Business Impact Reporter
        self.impact_reporter = BusinessImpactReporter(
            company_profile=self.config.reporting.company_profile
        )
        
        # Benchmarking Framework
        if self.config.benchmarking.enable_benchmarking:
            self.benchmark_framework = BenchmarkingFramework(
                config_file=self.config.config_file
            )
        else:
            self.benchmark_framework = None
        
        # Advanced AI Orchestrator
        self.ai_orchestrator = AdvancedAIOrchestrator(
            config={
                'max_parallel_models': self.config.exploitation.max_parallel_exploits,
                'exploration_rate': self.config.learning.exploration_rate
            }
        )
        
        # Autonomous Orchestration Engine
        self.autonomous_engine = AutonomousOrchestrationEngine(
            config={
                'max_autonomous_actions': self.config.autonomy.max_autonomous_actions,
                'decision_timeout': self.config.autonomy.decision_timeout,
                'learning_rate': self.config.learning.learning_rate
            }
        )
        
        # Set scope for autonomous engine
        self.autonomous_engine.set_scope(
            allowed=self.config.safety.scope_hosts,
            excluded=self.config.safety.out_of_scope_patterns
        )
        
        # Validation Framework
        self.validation_framework = RealWorldValidationFramework(
            config={
                'min_confidence_threshold': self.config.validation.min_confidence_threshold,
                'require_multiple_evidence': self.config.validation.require_multiple_evidence,
                'max_validation_attempts': self.config.validation.max_validation_attempts
            }
        )
        
        # Wire up scope checking
        self.validation_framework.scope_checker = self.safety_config.is_in_scope
    
    def _load_plugins(self) -> Dict[str, PluginBase]:
        """Load plugins from user directory"""
        if self.config.plugin.enable_user_plugins:
            plugins = load_user_plugins(self.config.plugin.plugins_dir)
            
            # Apply whitelist/blacklist
            if self.config.plugin.plugin_whitelist:
                plugins = {k: v for k, v in plugins.items() 
                          if k in self.config.plugin.plugin_whitelist}
            
            if self.config.plugin.plugin_blacklist:
                plugins = {k: v for k, v in plugins.items() 
                          if k not in self.config.plugin.plugin_blacklist}
            
            return plugins
        return {}
    
    def check_scope(self, target: str) -> bool:
        """Check if target is in scope using unified config"""
        return self.safety_config.is_in_scope(target)
    
    def fingerprint_target(self, target: str, use_cache: bool = True) -> TargetFingerprint:
        """
        Fingerprint target and cache results
        
        Args:
            target: Target URL
            use_cache: Whether to use cached fingerprint if available
            
        Returns:
            TargetFingerprint object
        """
        # Check cache
        if use_cache and target in self.fingerprint_cache:
            cached = self.fingerprint_cache[target]
            # Check if cache is still fresh (5 minutes)
            if (datetime.now() - datetime.fromisoformat(cached.timestamp)).seconds < 300:
                print(f"[FINGERPRINT] Using cached fingerprint for {target}")
                return cached
        
        # Perform fingerprinting
        print(f"[FINGERPRINT] Fingerprinting {target}...")
        fingerprint = self.fingerprinter.fingerprint(
            target,
            aggressive=self.config.exploitation.aggressive_mode
        )
        
        # Cache result
        self.fingerprint_cache[target] = fingerprint
        self.metrics.fingerprints_collected += 1
        
        # Log summary
        print(f"[FINGERPRINT] Detected: {fingerprint.product} {fingerprint.version or 'unknown version'}")
        if fingerprint.technologies:
            print(f"[FINGERPRINT] Technologies: {', '.join(fingerprint.technologies)}")
        if fingerprint.waf:
            print(f"[FINGERPRINT] WAF detected: {fingerprint.waf}")
        
        return fingerprint
    
    async def run_exploitation(self, target: str) -> Dict:
        """Run exploitation with all enhanced features including fingerprinting"""
        
        # Check scope
        if not self.check_scope(target):
            print(f"[SCOPE] Target {target} is out of scope!")
            return {'error': 'out_of_scope'}
        
        print(f"[*] Starting exploitation of {target}")
        start_time = time.time()
        
        # NEW: Fingerprint target first
        fingerprint = self.fingerprint_target(target)
        
        # Create enriched context with fingerprint
        context = {
            'config': self.config.to_dict(),
            'target_info': {
                'product': fingerprint.product,
                'version': fingerprint.version,
                'technologies': fingerprint.technologies,
                'frameworks': fingerprint.frameworks,
                'cms': fingerprint.cms,
                'server': fingerprint.server,
                'waf': fingerprint.waf,
                'raw_signals': fingerprint.raw_signals
            }
        }
        
        # Pass fingerprint to mapper if available
        if hasattr(self, 'mapper'):
            self.mapper.integrate_with_orchestrator(self)
            enhanced_recon = self.mapper.perform_enhanced_recon(target)
            context['mapper_recon'] = enhanced_recon
        
        # Use AI orchestrator for intelligent exploitation with fingerprint context
        if self.config.llm.provider != 'none':
            ai_result = await self.ai_orchestrator.orchestrate_exploitation(
                target=target,
                vulnerability_type='AUTO',
                context=context
            )
            
            # Validate results
            validation = await self.validation_framework.validate_exploitation(
                target=target,
                vulnerability_type=ai_result.get('vulnerability_type', 'UNKNOWN'),
                exploitation_result=ai_result
            )
            
            # Record for learning
            if self.config.learning.enable_continuous_learning:
                attempt = ExploitAttempt(
                    timestamp=datetime.now(),
                    target=target,
                    vulnerability_type=ai_result.get('vulnerability_type', 'UNKNOWN'),
                    plugin_used='AI_Orchestrator',
                    success=validation.validated,
                    confidence_score=validation.confidence_score,
                    evidence_score=validation.confidence_score,
                    execution_time=time.time() - start_time,
                    error_details=None,
                    environmental_factors={'fingerprint': fingerprint.product},
                    payload_characteristics={}
                )
                self.learning_pipeline.record_exploitation_attempt(attempt)
        
        # Run autonomous exploitation if enabled with fingerprint context
        if self.config.autonomy.enable_autonomy:
            # Pass fingerprint to autonomous engine
            self.autonomous_engine.context = context
            
            autonomous_result = await self.autonomous_engine.run_autonomous_exploitation(
                target=target,
                objectives=['Find all vulnerabilities', 'Demonstrate impact'],
                constraints={'max_time': self.config.exploitation.exploitation_timeout}
            )
            
            # Generate business impact report
            if autonomous_result.get('findings'):
                report = self.impact_reporter.generate_executive_report(
                    findings=autonomous_result['findings'],
                    scan_metadata={
                        'target': target,
                        'duration': time.time() - start_time,
                        'fingerprint': {
                            'product': fingerprint.product,
                            'version': fingerprint.version,
                            'technologies': fingerprint.technologies
                        }
                    }
                )
                
                # Save report
                report_path = Path(self.config.reporting.output_dir) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                
                print(f"[+] Report saved to {report_path}")
        
        # Update metrics
        self.metrics.total_attempts += 1
        self.metrics.total_time += time.time() - start_time
        
        return {
            'target': target,
            'duration': time.time() - start_time,
            'fingerprint': {
                'product': fingerprint.product,
                'version': fingerprint.version,
                'confidence': fingerprint.confidence.get('overall', 0)
            },
            'metrics': self.metrics,
            'config_used': self.config.version
        }
    
    def select_payloads_for_target(self, 
                                  target: str,
                                  vulnerability_type: str,
                                  context: Optional[Dict] = None) -> List[Dict]:
        """
        Select optimal payloads for a target based on fingerprint
        
        Args:
            target: Target URL
            vulnerability_type: Type of vulnerability to test
            context: Additional context for selection
            
        Returns:
            List of selected payloads with ranking
        """
        # Get fingerprint
        fingerprint = self.fingerprint_target(target)
        
        # Use smart selector
        payloads = self.payload_selector.select_for_target(
            target=target,
            vulnerability=vulnerability_type,
            aggressive=self.config.exploitation.aggressive_mode,
            context=context
        )
        
        return payloads
    
    def get_status(self) -> Dict:
        """Get current status with all module information"""
        return {
            'config_version': self.config.version,
            'target': self.config.bounty.target_domain,
            'scope': self.config.safety.scope_hosts,
            'metrics': self.metrics,
            'fingerprints_cached': len(self.fingerprint_cache),
            'learning_insights': self.learning_pipeline.get_learning_insights(),
            'modules_loaded': {
                'learning': True,
                'impact_reporting': True,
                'benchmarking': self.benchmark_framework is not None,
                'ai_orchestration': True,
                'autonomous': self.config.autonomy.enable_autonomy,
                'validation': True,
                'fingerprinting': True,  # NEW
                'payload_management': True  # NEW
            }
        }
    
    def export_fingerprint_cache(self) -> Dict:
        """Export all collected fingerprints"""
        return {
            target: {
                'product': fp.product,
                'version': fp.version,
                'technologies': fp.technologies,
                'frameworks': fp.frameworks,
                'cms': fp.cms,
                'server': fp.server,
                'waf': fp.waf,
                'timestamp': fp.timestamp
            }
            for target, fp in self.fingerprint_cache.items()
        }
