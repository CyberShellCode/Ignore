import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# BASE CONFIGURATION CLASSES
# ============================================================================

@dataclass
class SafetyConfig:
    """Safety and scope configuration"""
    allow_localhost: bool = False
    allow_private_ranges: bool = False
    allow_production: bool = False
    scope_hosts: List[str] = field(default_factory=list)
    out_of_scope_patterns: List[str] = field(default_factory=list)
    additional_scope_hosts: List[str] = field(default_factory=list)
    require_explicit_authorization: bool = True
    safe_mode: bool = False
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        from urllib.parse import urlparse
        
        parsed = urlparse(target if '://' in target else f'http://{target}')
        domain = parsed.netloc or parsed.path
        
        # Check localhost
        if not self.allow_localhost and domain in ['localhost', '127.0.0.1', '::1']:
            return False
        
        # Check private ranges
        if not self.allow_private_ranges:
            import ipaddress
            try:
                ip = ipaddress.ip_address(domain.split(':')[0])
                if ip.is_private:
                    return False
            except ValueError:
                pass
        
        # Check out-of-scope patterns
        for pattern in self.out_of_scope_patterns:
            if pattern in domain:
                return False
        
        # Check explicit scope
        all_scope = self.scope_hosts + self.additional_scope_hosts
        if not all_scope:
            return False  # No scope = no testing (fail-safe)
        
        for allowed in all_scope:
            if allowed.startswith('*.'):
                if domain.endswith(allowed[2:]) or domain == allowed[2:]:
                    return True
            elif domain == allowed:
                return True
        
        return False

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    enabled: bool = True
    requests_per_second: float = 5.0  # Default 5 RPS as requested
    burst_size: int = 10
    adaptive_mode: bool = True  # Automatically adjust based on server response
    
    # Per-host custom limits (domain -> RPS)
    per_host_limits: Dict[str, float] = field(default_factory=lambda: {
        'github.com': 3.0,  # GitHub is strict
        'localhost': 100.0,  # Local testing can be faster
        '127.0.0.1': 100.0,
        'bugcrowd.com': 2.0,  # Bug bounty platforms
        'hackerone.com': 2.0,
    })
    
    # Tool-specific limits
    nmap_packets_per_second: int = 50
    sqlmap_delay_seconds: float = 0.2  # 5 RPS = 0.2s delay
    
    # Advanced settings
    respect_retry_after: bool = True  # Honor Retry-After headers
    backoff_multiplier: float = 2.0  # Exponential backoff on 429
    max_retries: int = 3
    
    # Monitoring
    log_stats_interval: int = 60  # Log stats every 60 seconds
    alert_on_block: bool = True  # Alert when requests are blocked

@dataclass
class VulnerabilityKBConfig:
    """Vulnerability Knowledge Base configuration"""
    kb_path: str = "knowledge_base"
    auto_load_custom_payloads: bool = True
    custom_payloads_dir: str = "knowledge_base/custom_payloads"
    
    # Payload management
    min_confidence_threshold: float = 0.5
    max_payloads_per_category: int = 1000
    auto_update_confidence: bool = True
    confidence_update_weight: float = 0.3  # Weight for new results vs historical
    
    # Categories to enable
    enabled_categories: List[str] = field(default_factory=lambda: [
        "XSS", "SQLI", "SSRF", "RCE", "IDOR", "XXE", 
        "LFI", "RFI", "CSRF", "AUTH_BYPASS", "BUSINESS_LOGIC",
        "REQUEST_SMUGGLING", "RACE_CONDITION", "INFO_DISCLOSURE"
    ])
    
    # Payload priorities (higher = test first)
    category_priorities: Dict[str, int] = field(default_factory=lambda: {
        'RCE': 10,
        'SQLI': 9,
        'XXE': 8,
        'SSRF': 7,
        'LFI': 6,
        'XSS': 5,
        'IDOR': 4,
        'BUSINESS_LOGIC': 3,
        'INFO_DISCLOSURE': 2,
        'CSRF': 1
    })
    
    # Auto-save settings
    auto_save_interval: int = 100  # Save KB after N updates
    backup_on_save: bool = True
    max_backups: int = 5

@dataclass
class BypassConfig:
    """Bypass techniques configuration"""
    enable_403_bypass: bool = True
    enable_waf_bypass: bool = True
    
    # Bypass technique selection
    bypass_categories: List[str] = field(default_factory=lambda: [
        "PATH_MANIPULATION", "ENCODING", "HEADER_INJECTION",
        "METHOD_OVERRIDE", "PROTOCOL_ABUSE", "PARSER_DIFFERENTIAL",
        "UNICODE", "CASE_VARIATION"
    ])
    
    # Learning settings
    remember_successful_bypasses: bool = True
    max_bypass_history: int = 1000
    
    # Attempt configuration
    max_bypass_attempts_per_target: int = 50
    stop_on_first_success: bool = False
    
    # Server-specific settings
    target_server_detection: bool = True  # Auto-detect nginx/apache/iis
    server_specific_techniques: Dict[str, List[str]] = field(default_factory=lambda: {
        'nginx': ['PATH_MANIPULATION', 'UNICODE', 'HEADER_INJECTION'],
        'apache': ['ENCODING', 'PATH_MANIPULATION', 'METHOD_OVERRIDE'],
        'iis': ['UNICODE', 'CASE_VARIATION', 'ENCODING'],
        'cloudflare': ['HEADER_INJECTION', 'ENCODING']
    })
    
    # WAF evasion
    encoding_chains_max_depth: int = 3
    enable_chunking: bool = True
    enable_case_variation: bool = True
    enable_comment_injection: bool = True

@dataclass
class BountyConfig:
    """Bug bounty specific configuration"""
    target_domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    aggressive_mode: bool = False
    chain_vulnerabilities: bool = False
    extract_data_samples: bool = False
    auto_generate_reports: bool = True
    max_parallel_exploits: int = 5
    min_cvss_for_exploit: float = 4.0
    confidence_threshold: float = 0.75
    bounty_values: Dict[str, float] = field(default_factory=lambda: {
        'Critical': 10000,
        'High': 5000,
        'Medium': 1000,
        'Low': 100
    })

@dataclass
class ExploitationConfig:
    """Exploitation behavior configuration"""
    max_parallel_exploits: int = 10
    min_cvss_for_exploit: float = 7.0
    confidence_threshold: float = 0.8
    chain_vulnerabilities: bool = True
    extract_data_samples: bool = True
    exploitation_timeout: int = 300  # seconds
    max_exploitation_attempts: int = 3
    delay_between_attempts: float = 1.0
    prioritize_critical: bool = True
    skip_low_severity: bool = False
    
    # Integration with new modules
    use_kb_payloads: bool = True  # Use vulnerability KB payloads
    use_bypass_techniques: bool = True  # Use bypass techniques on 403/401
    smart_payload_selection: bool = True  # AI-driven payload selection

@dataclass
class LLMConfig:
    """LLM integration configuration"""
    provider: str = "ollama"  # ollama, openai, anthropic, none
    model: str = "dolphin-mixtral:8x7b"
    base_url: str = "http://localhost:11434"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30
    max_retries: int = 3
    context_window: int = 32768
    enable_caching: bool = True
    cache_ttl: int = 3600
    
    # AI-enhanced features
    generate_custom_payloads: bool = True
    analyze_responses: bool = True
    suggest_exploit_chains: bool = True

@dataclass
class LearningConfig:
    """Machine learning and adaptive learning configuration"""
    enable_continuous_learning: bool = True
    model_update_threshold: int = 100
    experience_buffer_size: int = 10000
    learning_rate: float = 0.01
    exploration_rate: float = 0.2
    model_save_interval: int = 1000
    model_dir: str = "models/adaptive"
    enable_online_learning: bool = True
    batch_size: int = 32
    validation_split: float = 0.2
    
    # Knowledge base learning
    update_payload_confidence: bool = True
    update_bypass_success_rates: bool = True
    track_exploitation_patterns: bool = True

@dataclass
class ReportingConfig:
    """Reporting and output configuration"""
    output_format: str = "json"  # json, markdown, html, pdf
    output_dir: str = "reports"
    include_screenshots: bool = True
    include_poc_code: bool = True
    include_remediation: bool = True
    include_business_impact: bool = True
    include_compliance_mapping: bool = True
    executive_summary: bool = True
    technical_details: bool = True
    generate_charts: bool = True
    
    # New reporting features
    include_bypass_techniques_used: bool = True
    include_payload_confidence_scores: bool = True
    include_rate_limit_stats: bool = True
    
    company_profile: Dict[str, Any] = field(default_factory=lambda: {
        'name': 'Target Organization',
        'industry': 'Technology',
        'compliance_requirements': ['GDPR', 'SOC2', 'PCI-DSS']
    })

@dataclass
class BenchmarkingConfig:
    """Benchmarking and performance testing configuration"""
    enable_benchmarking: bool = False
    benchmark_suite: str = "basic"  # basic, advanced, comprehensive
    max_parallel_benchmarks: int = 10
    benchmark_timeout: int = 300
    collect_metrics_interval: float = 1.0
    performance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'max_cpu': 80.0,
        'max_memory': 4096.0,
        'min_success_rate': 0.7,
        'max_false_positive_rate': 0.2
    })
    compare_tools: List[str] = field(default_factory=lambda: [
        'Burp Suite', 'OWASP ZAP', 'Nuclei'
    ])

@dataclass
class ValidationConfig:
    """Validation and verification configuration"""
    min_confidence_threshold: float = 0.7
    require_multiple_evidence: bool = True
    max_validation_attempts: int = 5
    validation_timeout: int = 30
    differential_threshold: float = 0.3
    timing_deviation_threshold: float = 2.0
    check_false_positives: bool = True
    verify_remediation: bool = False
    evidence_correlation: bool = True

@dataclass
class AutonomyConfig:
    """Autonomous operation configuration"""
    enable_autonomy: bool = True
    max_autonomous_actions: int = 1000
    decision_timeout: int = 30
    goal_reassessment_interval: int = 60
    learning_enabled: bool = True
    exploration_vs_exploitation: float = 0.2
    allow_destructive_actions: bool = False
    require_human_confirmation: bool = False
    pause_on_critical_finding: bool = True

@dataclass
class PluginConfig:
    """Plugin system configuration"""
    plugins_dir: str = "plugins_user"
    enable_user_plugins: bool = True
    plugin_timeout: int = 60
    max_plugin_retries: int = 3
    plugin_whitelist: List[str] = field(default_factory=list)
    plugin_blacklist: List[str] = field(default_factory=list)
    auto_reload_plugins: bool = False

@dataclass
class NetworkConfig:
    """Network and proxy configuration"""
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    no_proxy: List[str] = field(default_factory=lambda: ['localhost', '127.0.0.1'])
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    user_agent: str = "CyberShell/2.0"
    follow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = True

@dataclass
class DebugConfig:
    """Debug and logging configuration"""
    debug: bool = False
    verbose: bool = False
    log_level: str = "INFO"
    log_file: Optional[str] = "cybershell.log"
    log_to_console: bool = True
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    save_responses: bool = False
    save_payloads: bool = False
    trace_execution: bool = False

@dataclass
class IntegrationConfig:
    """External tool integration configuration"""
    enable_nmap: bool = True
    nmap_path: str = "nmap"
    nmap_default_args: str = "-sV -sC"
    
    enable_sqlmap: bool = True
    sqlmap_path: str = "sqlmap"
    sqlmap_default_args: str = "--batch --random-agent"
    
    enable_nuclei: bool = False
    nuclei_path: str = "nuclei"
    nuclei_templates: str = "nuclei-templates"
    
    # Tool coordination
    tool_timeout: int = 600  # 10 minutes
    max_concurrent_tools: int = 2

# ============================================================================
# MAIN UNIFIED CONFIGURATION
# ============================================================================

@dataclass
class UnifiedConfig:
    """
    Unified configuration for all CyberShell components
    Single source of truth for all settings
    """
    
    # Core configurations
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    vulnerability_kb: VulnerabilityKBConfig = field(default_factory=VulnerabilityKBConfig)
    bypass: BypassConfig = field(default_factory=BypassConfig)
    bounty: BountyConfig = field(default_factory=lambda: BountyConfig(target_domain=""))
    exploitation: ExploitationConfig = field(default_factory=ExploitationConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    learning: LearningConfig = field(default_factory=LearningConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    benchmarking: BenchmarkingConfig = field(default_factory=BenchmarkingConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    integration: IntegrationConfig = field(default_factory=IntegrationConfig)
    
    # Metadata
    version: str = "2.0.0"
    config_file: Optional[str] = None
    
    def get_rate_limiter(self):
        """Get configured rate limiter instance"""
        from cybershell.rate_limiter import RateLimiter
        
        if not hasattr(self, '_rate_limiter'):
            self._rate_limiter = RateLimiter(
                requests_per_second=self.rate_limit.requests_per_second,
                burst_size=self.rate_limit.burst_size,
                per_host_limits=self.rate_limit.per_host_limits
            )
            self._rate_limiter.adaptive_mode = self.rate_limit.adaptive_mode
        
        return self._rate_limiter
    
    def apply_rate_limiting(self) -> None:
        """Apply rate limiting configuration globally"""
        from cybershell.rate_limiter import configure_rate_limiting
        
        config = {
            'requests_per_second': self.rate_limit.requests_per_second,
            'burst_size': self.rate_limit.burst_size,
            'per_host_limits': self.rate_limit.per_host_limits,
            'adaptive_mode': self.rate_limit.adaptive_mode
        }
        
        configure_rate_limiting(config)
    
    @classmethod
    def from_file(cls, config_file: str = "config.yaml") -> 'UnifiedConfig':
        """Load configuration from YAML file"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.warning("Config file %s not found, using defaults", config_file)
            return cls()
        
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        
        return cls.from_dict(data, config_file=config_file)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], config_file: Optional[str] = None) -> 'UnifiedConfig':
        """Create configuration from dictionary"""
        config = cls()
        config.config_file = config_file
        
        # Update each sub-configuration
        if 'safety' in data:
            config.safety = SafetyConfig(**data['safety'])
        if 'rate_limit' in data:
            config.rate_limit = RateLimitConfig(**data['rate_limit'])
        if 'vulnerability_kb' in data:
            config.vulnerability_kb = VulnerabilityKBConfig(**data['vulnerability_kb'])
        if 'bypass' in data:
            config.bypass = BypassConfig(**data['bypass'])
        if 'bounty' in data:
            config.bounty = BountyConfig(**data['bounty'])
        if 'exploitation' in data:
            config.exploitation = ExploitationConfig(**data['exploitation'])
        if 'llm' in data:
            config.llm = LLMConfig(**data['llm'])
        if 'learning' in data:
            config.learning = LearningConfig(**data['learning'])
        if 'reporting' in data:
            config.reporting = ReportingConfig(**data['reporting'])
        if 'benchmarking' in data:
            config.benchmarking = BenchmarkingConfig(**data['benchmarking'])
        if 'validation' in data:
            config.validation = ValidationConfig(**data['validation'])
        if 'autonomy' in data:
            config.autonomy = AutonomyConfig(**data['autonomy'])
        if 'plugin' in data:
            config.plugin = PluginConfig(**data['plugin'])
        if 'network' in data:
            config.network = NetworkConfig(**data['network'])
        if 'debug' in data:
            config.debug = DebugConfig(**data['debug'])
        if 'integration' in data:
            config.integration = IntegrationConfig(**data['integration'])
        
        return config
    
    @classmethod
    def from_args(cls, args) -> 'UnifiedConfig':
        """Create configuration from command-line arguments"""
        config = cls()
        
        # Map command-line arguments to configuration
        if hasattr(args, 'target'):
            config.bounty.target_domain = args.target
        
        if hasattr(args, 'scope') and args.scope:
            config.safety.scope_hosts = args.scope.split(',')
            config.bounty.scope = args.scope.split(',')
        
        if hasattr(args, 'out_of_scope') and args.out_of_scope:
            config.safety.out_of_scope_patterns = args.out_of_scope.split(',')
            config.bounty.out_of_scope = args.out_of_scope.split(',')
        
        if hasattr(args, 'safe_mode'):
            config.safety.safe_mode = args.safe_mode
            config.bounty.aggressive_mode = not args.safe_mode
        
        if hasattr(args, 'production'):
            config.safety.allow_production = args.production
            config.safety.allow_localhost = not args.production
            config.safety.allow_private_ranges = not args.production
        
        if hasattr(args, 'rate_limit'):
            config.rate_limit.requests_per_second = args.rate_limit
        
        if hasattr(args, 'no_rate_limit'):
            config.rate_limit.enabled = not args.no_rate_limit
        
        if hasattr(args, 'adaptive'):
            config.rate_limit.adaptive_mode = args.adaptive
        
        if hasattr(args, 'burst'):
            config.rate_limit.burst_size = args.burst
        
        if hasattr(args, 'bypass_403'):
            config.bypass.enable_403_bypass = args.bypass_403
        
        if hasattr(args, 'bypass_waf'):
            config.bypass.enable_waf_bypass = args.bypass_waf
        
        if hasattr(args, 'chain_exploits'):
            config.exploitation.chain_vulnerabilities = args.chain_exploits
            config.bounty.chain_vulnerabilities = args.chain_exploits
        
        if hasattr(args, 'extract_data'):
            config.exploitation.extract_data_samples = args.extract_data
            config.bounty.extract_data_samples = args.extract_data
        
        if hasattr(args, 'parallel'):
            config.exploitation.max_parallel_exploits = args.parallel
            config.bounty.max_parallel_exploits = args.parallel
        
        if hasattr(args, 'min_cvss'):
            config.exploitation.min_cvss_for_exploit = args.min_cvss
            config.bounty.min_cvss_for_exploit = args.min_cvss
        
        if hasattr(args, 'confidence'):
            config.exploitation.confidence_threshold = args.confidence
            config.bounty.confidence_threshold = args.confidence
        
        if hasattr(args, 'llm'):
            config.llm.provider = args.llm
        
        if hasattr(args, 'verbose'):
            config.debug.verbose = args.verbose
            config.debug.debug = args.verbose
        
        if hasattr(args, 'output'):
            config.reporting.output_dir = os.path.dirname(args.output) or 'reports'
        
        if hasattr(args, 'format'):
            config.reporting.output_format = args.format
        
        return config
    
    def merge_with_env(self) -> 'UnifiedConfig':
        """Merge configuration with environment variables"""
        
        # LLM settings from environment
        if os.getenv('OLLAMA_MODEL'):
            self.llm.model = os.getenv('OLLAMA_MODEL')
        if os.getenv('OLLAMA_BASE_URL'):
            self.llm.base_url = os.getenv('OLLAMA_BASE_URL')
        if os.getenv('OPENAI_API_KEY'):
            self.llm.api_key = os.getenv('OPENAI_API_KEY')
            if not self.llm.provider:
                self.llm.provider = 'openai'
        if os.getenv('ANTHROPIC_API_KEY'):
            self.llm.api_key = os.getenv('ANTHROPIC_API_KEY')
            if not self.llm.provider:
                self.llm.provider = 'anthropic'
        
        # Network settings
        if os.getenv('HTTP_PROXY'):
            self.network.http_proxy = os.getenv('HTTP_PROXY')
        if os.getenv('HTTPS_PROXY'):
            self.network.https_proxy = os.getenv('HTTPS_PROXY')
        
        # Debug settings
        if os.getenv('DEBUG'):
            self.debug.debug = os.getenv('DEBUG').lower() in ('true', '1', 'yes')
        if os.getenv('VERBOSE'):
            self.debug.verbose = os.getenv('VERBOSE').lower() in ('true', '1', 'yes')
        
        # Rate limiting
        if os.getenv('RATE_LIMIT'):
            try:
                self.rate_limit.requests_per_second = float(os.getenv('RATE_LIMIT'))
            except ValueError:
                pass
        
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)
    
    def save(self, config_file: Optional[str] = None) -> None:
        """Save configuration to YAML file"""
        config_file = config_file or self.config_file or "config.yaml"
        Path(config_file).parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
        
        logger.info("Configuration saved to %s", config_file)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Check required fields
        if not self.bounty.target_domain and not self.safety.scope_hosts:
            issues.append("No target or scope defined")
        
        # Check conflicting settings
        if self.safety.safe_mode and self.bounty.aggressive_mode:
            issues.append("Both safe_mode and aggressive_mode are enabled")
        
        if self.safety.allow_production and not self.safety.scope_hosts:
            issues.append("Production mode enabled without explicit scope")
        
        # Check thresholds
        if self.exploitation.confidence_threshold > 1.0 or self.exploitation.confidence_threshold < 0:
            issues.append("Confidence threshold must be between 0 and 1")
        
        if self.exploitation.min_cvss_for_exploit > 10.0 or self.exploitation.min_cvss_for_exploit < 0:
            issues.append("CVSS threshold must be between 0 and 10")
        
        # Check rate limiting
        if self.rate_limit.requests_per_second <= 0:
            issues.append("Rate limit must be positive")
        
        if self.rate_limit.burst_size < 1:
            issues.append("Burst size must be at least 1")
        
        # Check paths
        if not Path(self.plugin.plugins_dir).exists():
            issues.append(f"Plugin directory {self.plugin.plugins_dir} does not exist")
        
        # Create knowledge base directory if it doesn't exist
        kb_path = Path(self.vulnerability_kb.kb_path)
        if not kb_path.exists():
            kb_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created knowledge base directory: {kb_path}")
        
        return issues
    
    def get_module_config(self, module_name: str) -> Any:
        """Get configuration for specific module"""
        return getattr(self, module_name, None)
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return f"UnifiedConfig(version={self.version}, target={self.bounty.target_domain}, rate_limit={self.rate_limit.requests_per_second}rps)"

# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigurationManager:
    """
    Singleton configuration manager for CyberShell
    Ensures single source of truth for all configuration
    """
    
    _instance = None
    _config: Optional[UnifiedConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def initialize(self, 
                  config_file: Optional[str] = None,
                  args: Optional[Any] = None,
                  config_dict: Optional[Dict] = None) -> UnifiedConfig:
        """Initialize configuration from various sources"""
        
        # Priority: args > config_dict > config_file > defaults
        if args:
            self._config = UnifiedConfig.from_args(args)
        elif config_dict:
            self._config = UnifiedConfig.from_dict(config_dict)
        elif config_file:
            self._config = UnifiedConfig.from_file(config_file)
        else:
            self._config = UnifiedConfig()
        
        # Merge with environment variables
        self._config.merge_with_env()
        
        # Apply rate limiting if enabled
        if self._config.rate_limit.enabled:
            self._config.apply_rate_limiting()
            logger.info("Rate limiting enabled: %s RPS", self._config.rate_limit.requests_per_second)
        
        # Validate configuration
        issues = self._config.validate()
        if issues:
            logger.warning("Configuration issues: %s", issues)
        
        return self._config
    
    @property
    def config(self) -> UnifiedConfig:
        """Get current configuration"""
        if self._config is None:
            self._config = UnifiedConfig()
        return self._config
    
    def reload(self) -> None:
        """Reload configuration from file"""
        if self._config and self._config.config_file:
            self._config = UnifiedConfig.from_file(self._config.config_file)
            self._config.merge_with_env()
            
            # Re-apply rate limiting
            if self._config.rate_limit.enabled:
                self._config.apply_rate_limiting()
    
    def update(self, **kwargs) -> None:
        """Update specific configuration values"""
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def get_config() -> UnifiedConfig:
    """Get current configuration instance"""
    return ConfigurationManager().config

def initialize_config(config_file: Optional[str] = None,
                     args: Optional[Any] = None,
                     config_dict: Optional[Dict] = None) -> UnifiedConfig:
    """Initialize and return configuration"""
    return ConfigurationManager().initialize(config_file, args, config_dict)

def update_config(**kwargs) -> None:
    """Update configuration values"""
    ConfigurationManager().update(**kwargs)

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example: Create configuration from command-line arguments
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--scope', help='Scope')
    parser.add_argument('--safe-mode', action='store_true')
    parser.add_argument('--production', action='store_true')
    parser.add_argument('--rate-limit', type=float, default=5.0)
    parser.add_argument('--no-rate-limit', action='store_true')
    parser.add_argument('--bypass-403', action='store_true')
    parser.add_argument('--bypass-waf', action='store_true')
    
    args = parser.parse_args(['http://example.com', '--scope', '*.example.com', '--rate-limit', '10'])
    
    # Initialize configuration
    config = initialize_config(args=args)
    
    # Access configuration
    print(f"Target: {config.bounty.target_domain}")
    print(f"Scope: {config.safety.scope_hosts}")
    print(f"Safe mode: {config.safety.safe_mode}")
    print(f"Rate limit: {config.rate_limit.requests_per_second} RPS")
    print(f"403 Bypass: {config.bypass.enable_403_bypass}")
    print(f"WAF Bypass: {config.bypass.enable_waf_bypass}")
    
    # Check if target is in scope
    print(f"In scope: {config.safety.is_in_scope('http://example.com')}")
    
    # Save configuration
    config.save("my_config.yaml")
