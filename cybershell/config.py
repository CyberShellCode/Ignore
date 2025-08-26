import warnings
from typing import Dict, List, Optional, Any

# Import everything from unified configuration
from .unified_config import (
    UnifiedConfig,
    SafetyConfig,
    BountyConfig,
    ExploitationConfig,
    LLMConfig,
    LearningConfig,
    ReportingConfig,
    BenchmarkingConfig,
    ValidationConfig,
    AutonomyConfig,
    PluginConfig,
    NetworkConfig,
    DebugConfig,
    ConfigurationManager,
    get_config,
    initialize_config,
    update_config
)

# Re-export for backward compatibility
__all__ = [
    'SafetyConfig',
    'BountyConfig',
    'ExploitationConfig',
    'LLMConfig',
    'LearningConfig',
    'ReportingConfig',
    'BenchmarkingConfig',
    'ValidationConfig',
    'AutonomyConfig',
    'PluginConfig',
    'NetworkConfig',
    'DebugConfig',
    'UnifiedConfig',
    'get_config',
    'initialize_config',
    'update_config',
    'Config',  # Legacy class name
    'load_config',  # Legacy function
    'save_config'   # Legacy function
]

# Legacy Config class for backward compatibility
class Config(UnifiedConfig):
    """
    Legacy Config class - redirects to UnifiedConfig
    Deprecated: Use UnifiedConfig instead
    """
    
    def __init__(self, *args, **kwargs):
        warnings.warn(
            "Config class is deprecated. Use UnifiedConfig instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)

# Legacy functions for backward compatibility
def load_config(config_file: str = "config.yaml") -> UnifiedConfig:
    """
    Legacy config loader - redirects to unified system
    Deprecated: Use initialize_config() instead
    """
    warnings.warn(
        "load_config() is deprecated. Use initialize_config() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    return initialize_config(config_file=config_file)

def save_config(config: UnifiedConfig, config_file: str = "config.yaml"):
    """
    Legacy config saver - uses unified system
    Deprecated: Use config.save() instead
    """
    warnings.warn(
        "save_config() is deprecated. Use config.save() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    config.save(config_file)

# Convenience function for getting specific module configs
def get_safety_config() -> SafetyConfig:
    """Get current safety configuration"""
    return get_config().safety

def get_bounty_config() -> BountyConfig:
    """Get current bounty configuration"""
    return get_config().bounty

def get_exploitation_config() -> ExploitationConfig:
    """Get current exploitation configuration"""
    return get_config().exploitation

def get_llm_config() -> LLMConfig:
    """Get current LLM configuration"""
    return get_config().llm

def get_learning_config() -> LearningConfig:
    """Get current learning configuration"""
    return get_config().learning

# Default configuration factory
def create_default_config(target: str = None) -> UnifiedConfig:
    """Create a default configuration with optional target"""
    config = UnifiedConfig()
    
    if target:
        config.bounty.target_domain = target
        # Extract domain for scope
        from urllib.parse import urlparse
        parsed = urlparse(target if '://' in target else f'http://{target}')
        domain = parsed.netloc or parsed.path
        config.safety.scope_hosts = [domain]
        config.bounty.scope = [domain]
    
    return config

# Configuration validation helper
def validate_and_fix_config(config: UnifiedConfig) -> UnifiedConfig:
    """Validate and fix common configuration issues"""
    
    # Ensure scope is set if target is set
    if config.bounty.target_domain and not config.safety.scope_hosts:
        from urllib.parse import urlparse
        parsed = urlparse(config.bounty.target_domain if '://' in config.bounty.target_domain 
                         else f'http://{config.bounty.target_domain}')
        domain = parsed.netloc or parsed.path
        config.safety.scope_hosts = [domain]
        config.bounty.scope = [domain]
    
    # Ensure paths exist
    from pathlib import Path
    
    Path(config.learning.model_dir).mkdir(parents=True, exist_ok=True)
    Path(config.reporting.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.plugin.plugins_dir).mkdir(parents=True, exist_ok=True)
    
    # Fix conflicting settings
    if config.safety.safe_mode:
        config.bounty.aggressive_mode = False
        config.exploitation.max_parallel_exploits = min(config.exploitation.max_parallel_exploits, 3)
    
    if config.safety.allow_production:
        config.safety.require_explicit_authorization = True
    
    return config
