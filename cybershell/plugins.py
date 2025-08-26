from dataclasses import dataclass
from typing import Dict, Any
from .config import SafetyConfig

@dataclass
class PluginResult:
    name: str
    success: bool
    details: Dict[str, Any]

class PluginBase:
    name = 'PluginBase'
    def __init__(self, config: SafetyConfig):
        self.config = config
    def in_scope(self, target: str) -> bool:
        return self.config.in_scope(target)
    def run(self, **kwargs) -> PluginResult:
        raise NotImplementedError

class HttpFingerprintPlugin(PluginBase):
    name = 'HttpFingerprintPlugin'
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target','')
        if not self.in_scope(target):
            return PluginResult(self.name, False, {'reason':'out_of_scope'})
        # Simulated fingerprint output (safe, no network)
        return PluginResult(self.name, True, {
            'target': target,
            'headers': {'server': 'lab-stub'},
            'notes': 'fingerprint simulated',
            'error_tokens': [],
            'length_delta': 0.0,
        })

class FormDiscoveryPlugin(PluginBase):
    name = 'FormDiscoveryPlugin'
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target','')
        if not self.in_scope(target):
            return PluginResult(self.name, False, {'reason':'out_of_scope'})
        forms = [{'action': '/login', 'method': 'POST', 'inputs': ['username','password']}]
        return PluginResult(self.name, True, {'target': target, 'forms': forms, 'notes': 'discovery simulated'})

class HeuristicAnalyzerPlugin(PluginBase):
    name = 'HeuristicAnalyzerPlugin'
    def run(self, **kwargs) -> PluginResult:
        target = kwargs.get('target','')
        if not self.in_scope(target):
            return PluginResult(self.name, False, {'reason':'out_of_scope'})
        hint = kwargs.get('hint','')
        # Deliberately non-invasive; a placeholder for your lab analyzers
        return PluginResult(self.name, True, {'target': target, 'hint_used': hint, 'safety': 'lab-only'})
