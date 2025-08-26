import asyncio
import json
import time
import logging
import traceback
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from collections import deque
import hashlib
import re
from enum import Enum
import numpy as np

# Import payload management
from .payload_manager import PayloadManager
from .vulnerability_kb import VulnerabilityKnowledgeBase, VulnCategory
from .fingerprinter import TargetFingerprint

# Set up module logger
logger = logging.getLogger(__name__)


class ModelCapability(Enum):
    """Capabilities of different AI models"""
    CODE_GENERATION = "code_generation"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    PAYLOAD_CRAFTING = "payload_crafting"
    PATTERN_RECOGNITION = "pattern_recognition"
    STRATEGIC_PLANNING = "strategic_planning"
    REPORT_WRITING = "report_writing"
    REVERSE_ENGINEERING = "reverse_engineering"


@dataclass
class AIModel:
    """Represents an AI model with its capabilities"""
    name: str
    provider: str  # ollama, openai, anthropic, local
    capabilities: List[ModelCapability]
    context_window: int
    cost_per_token: float
    latency_ms: float
    accuracy_score: float
    specializations: List[str]
    connection_params: Dict[str, Any]


@dataclass
class ContextWindow:
    """Manages context for AI interactions"""
    max_tokens: int
    current_tokens: int
    messages: deque
    key_facts: List[Dict]
    vulnerability_context: Dict
    target_profile: Dict
    exploitation_history: List[Dict]
    fingerprint_data: Optional[Dict] = None


class AdvancedAIOrchestrator:
    """
    Orchestrates multiple AI models for optimal exploitation strategies
    Now with fingerprint-aware payload generation
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.models = self._initialize_models()
        self.context_manager = ContextManager()
        self.prompt_optimizer = PromptOptimizer()
        self.model_selector = ModelSelector(self.models)
        self.response_cache = {}
        self.performance_tracker = PerformanceTracker()
        
        # Initialize payload management
        self.kb = VulnerabilityKnowledgeBase()
        self.payload_manager = PayloadManager(self.kb)
        
    def _default_config(self) -> Dict:
        """Default configuration for AI orchestration"""
        return {
            'max_parallel_models': 3,
            'context_compression_ratio': 0.7,
            'cache_ttl_seconds': 3600,
            'fallback_enabled': True,
            'ensemble_voting': True,
            'prompt_optimization': True,
            'max_retries': 3,
            'temperature_range': (0.1, 0.9),
            'use_fingerprint_context': True
        }
    
    def _initialize_models(self) -> Dict[str, AIModel]:
        """Initialize available AI models"""
        return {
            'dolphin-mixtral': AIModel(
                name='dolphin-mixtral:8x7b',
                provider='ollama',
                capabilities=[
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.VULNERABILITY_ANALYSIS,
                    ModelCapability.PAYLOAD_CRAFTING
                ],
                context_window=32768,
                cost_per_token=0.0,
                latency_ms=500,
                accuracy_score=0.85,
                specializations=['web_exploitation', 'code_analysis'],
                connection_params={'base_url': 'http://localhost:11434'}
            ),
            'gpt-4': AIModel(
                name='gpt-4',
                provider='openai',
                capabilities=[
                    ModelCapability.STRATEGIC_PLANNING,
                    ModelCapability.PATTERN_RECOGNITION,
                    ModelCapability.REPORT_WRITING
                ],
                context_window=8192,
                cost_per_token=0.03,
                latency_ms=2000,
                accuracy_score=0.92,
                specializations=['reasoning', 'analysis'],
                connection_params={'api_key': 'env:OPENAI_API_KEY'}
            ),
            'claude-3': AIModel(
                name='claude-3-opus',
                provider='anthropic',
                capabilities=[
                    ModelCapability.VULNERABILITY_ANALYSIS,
                    ModelCapability.REVERSE_ENGINEERING,
                    ModelCapability.REPORT_WRITING
                ],
                context_window=200000,
                cost_per_token=0.015,
                latency_ms=1500,
                accuracy_score=0.94,
                specializations=['detailed_analysis', 'security'],
                connection_params={'api_key': 'env:ANTHROPIC_API_KEY'}
            ),
            'local-llama': AIModel(
                name='llama-2-70b',
                provider='local',
                capabilities=[
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.PAYLOAD_CRAFTING
                ],
                context_window=4096,
                cost_per_token=0.0,
                latency_ms=300,
                accuracy_score=0.78,
                specializations=['fast_inference', 'code'],
                connection_params={'model_path': '/models/llama-2-70b'}
            )
        }
    
    def _map_vulnerability_to_specialization(self, vulnerability_type: str) -> str:
        """Map vulnerability type to model specialization"""
        mapping = {
            'XSS': 'web_exploitation',
            'SQLI': 'web_exploitation', 
            'RCE': 'code_analysis',
            'SSRF': 'web_exploitation',
            'XXE': 'detailed_analysis',
            'IDOR': 'analysis',
            'AUTH_BYPASS': 'security',
            'BUSINESS_LOGIC': 'reasoning',
            'AUTO': 'analysis'
        }
        return mapping.get(vulnerability_type.upper(), 'analysis')
    
    async def orchestrate_exploitation(self, 
                                      target: str,
                                      vulnerability_type: str,
                                      context: Dict) -> Dict:
        """Orchestrate multiple models for exploitation with fingerprint awareness"""
        
        # Extract fingerprint data if available
        target_info = context.get('target_info', {})
        fingerprint_data = {
            'product': target_info.get('product'),
            'version': target_info.get('version'),
            'technologies': target_info.get('technologies', []),
            'waf': target_info.get('waf'),
            'server': target_info.get('server')
        }
        
        # Map vulnerability type to specialization for better model selection
        specialization = self._map_vulnerability_to_specialization(vulnerability_type)
        
        # Select best models for the task with proper specialization
        selected_models = self.model_selector.select_models(
            task_type=specialization,
            capabilities_needed=[
                ModelCapability.VULNERABILITY_ANALYSIS,
                ModelCapability.PAYLOAD_CRAFTING
            ],
            max_models=self.config['max_parallel_models']
        )
        
        # Prepare context with fingerprint
        enriched_context = self.context_manager.prepare_context(
            target=target,
            vulnerability_type=vulnerability_type,
            base_context=context,
            fingerprint=fingerprint_data
        )
        
        # Get version-specific payloads from knowledge base
        if vulnerability_type != 'AUTO':
            try:
                vuln_category = VulnCategory[vulnerability_type.upper()]
                kb_payloads = self._get_fingerprint_matched_payloads(
                    vuln_category,
                    fingerprint_data
                )
                enriched_context['suggested_payloads'] = kb_payloads
            except KeyError as e:
                logger.error(f"Invalid vulnerability category: {vulnerability_type}. Error: {e}")
                enriched_context['suggested_payloads'] = []
            except Exception as e:
                logger.error(f"Failed to get KB payloads: {e}", exc_info=True)
                enriched_context['suggested_payloads'] = []
        
        # Generate optimized prompts for each model
        prompts = {}
        for model_name, model in selected_models.items():
            prompts[model_name] = self.prompt_optimizer.optimize_prompt(
                model=model,
                task=vulnerability_type,
                context=enriched_context,
                fingerprint=fingerprint_data
            )
        
        # Execute parallel model queries
        results = await self._parallel_model_execution(selected_models, prompts)
        
        # Ensemble and synthesize results
        final_result = self._ensemble_results(results, vulnerability_type, fingerprint_data)
        
        # Update context manager with result for learning
        self.context_manager.update_with_result(target, vulnerability_type, final_result)
        
        # Update performance tracking
        self.performance_tracker.record_execution(
            models=list(selected_models.keys()),
            task=vulnerability_type,
            success=final_result['success'],
            latency=final_result['latency']
        )
        
        return final_result
    
    def _get_fingerprint_matched_payloads(self, 
                                         vuln_category: VulnCategory,
                                         fingerprint: Dict) -> List[str]:
        """Get payloads matching the target fingerprint"""
        mock_fp = TargetFingerprint(
            url="",
            product=fingerprint.get('product'),
            version=fingerprint.get('version'),
            technologies=fingerprint.get('technologies', []),
            server=fingerprint.get('server')
        )
        
        # Get ranked payloads
        ranked = self.payload_manager.select_payloads(
            fingerprint=mock_fp,
            vulnerability=vuln_category,
            context=None,
            top_n=5
        )
        
        return [rp.payload.payload for rp in ranked]
    
    async def _parallel_model_execution(self, 
                                       models: Dict[str, AIModel],
                                       prompts: Dict[str, str]) -> Dict:
        """Execute multiple models in parallel"""
        
        tasks = []
        for model_name, model in models.items():
            task = self._execute_model(model, prompts[model_name])
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        model_results = {}
        for i, (model_name, _) in enumerate(models.items()):
            if isinstance(results[i], Exception):
                logger.error(f"Model {model_name} failed with error: {results[i]}", exc_info=results[i])
                model_results[model_name] = None
            else:
                model_results[model_name] = results[i]
        
        return model_results
    
    async def _execute_model(self, model: AIModel, prompt: str) -> Dict:
        """Execute a single model with retry logic"""
        
        # Check cache first
        cache_key = self._generate_cache_key(model.name, prompt)
        if cache_key in self.response_cache:
            cached = self.response_cache[cache_key]
            if time.time() - cached['timestamp'] < self.config['cache_ttl_seconds']:
                return cached['response']
        
        # Execute with retries
        for attempt in range(self.config['max_retries']):
            try:
                start_time = time.time()
                
                # Route to appropriate provider
                if model.provider == 'ollama':
                    response = await self._execute_ollama(model, prompt)
                elif model.provider == 'openai':
                    response = await self._execute_openai(model, prompt)
                elif model.provider == 'anthropic':
                    response = await self._execute_anthropic(model, prompt)
                elif model.provider == 'local':
                    response = await self._execute_local(model, prompt)
                else:
                    raise ValueError(f"Unknown provider: {model.provider}")
                
                latency = (time.time() - start_time) * 1000
                
                result = {
                    'model': model.name,
                    'response': response,
                    'latency_ms': latency,
                    'confidence': self._calculate_confidence(response),
                    'timestamp': time.time()
                }
                
                # Cache successful response
                self.response_cache[cache_key] = {'response': result, 'timestamp': time.time()}
                return result
                
            except Exception as e:
                if attempt == self.config['max_retries'] - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # Should not be reached; defensive safeguard
        raise RuntimeError("Model execution retries exhausted without raising.")

    async def _execute_ollama(self, model: AIModel, prompt: str) -> str:
        """Execute Ollama model"""
        # Simulate Ollama API call
        await asyncio.sleep(model.latency_ms / 1000)
        
        # In reality, would use ollama library
        return f"Ollama response for: {prompt[:50]}..."
    
    async def _execute_openai(self, model: AIModel, prompt: str) -> str:
        """Execute OpenAI model"""
        # Simulate OpenAI API call
        await asyncio.sleep(model.latency_ms / 1000)
        
        # In reality, would use openai library
        return f"OpenAI response for: {prompt[:50]}..."
    
    async def _execute_anthropic(self, model: AIModel, prompt: str) -> str:
        """Execute Anthropic model"""
        # Simulate Anthropic API call
        await asyncio.sleep(model.latency_ms / 1000)
        
        # In reality, would use anthropic library
        return f"Anthropic response for: {prompt[:50]}..."
    
    async def _execute_local(self, model: AIModel, prompt: str) -> str:
        """Execute local model"""
        # Simulate local model execution
        await asyncio.sleep(model.latency_ms / 1000)
        
        # In reality, would load and run local model
        return f"Local model response for: {prompt[:50]}..."
    
    def _ensemble_results(self, results: Dict, task: str, fingerprint: Dict) -> Dict:
        """Ensemble results from multiple models with fingerprint consideration"""
        
        valid_results = [r for r in results.values() if r is not None]
        
        if not valid_results:
            return {
                'success': False,
                'error': 'All models failed',
                'latency': 0
            }
        
        if self.config['ensemble_voting']:
            # Voting-based ensemble
            synthesized = self._voting_ensemble(valid_results, task, fingerprint)
        else:
            # Confidence-weighted ensemble
            synthesized = self._weighted_ensemble(valid_results)
        
        return {
            'success': True,
            'exploitation_strategy': synthesized['strategy'],
            'payload': synthesized['payload'],
            'confidence': synthesized['confidence'],
            'model_consensus': synthesized['consensus'],
            'latency': max([r['latency_ms'] for r in valid_results]),
            'models_used': [r['model'] for r in valid_results],
            'fingerprint_match': synthesized.get('fingerprint_match', False)
        }
    
    def _voting_ensemble(self, results: List[Dict], task: str, fingerprint: Dict) -> Dict:
        """Voting-based ensemble strategy with fingerprint awareness"""
        
        # Extract strategies from each model
        strategies = []
        for result in results:
            # Parse strategy from response (simplified)
            strategy = self._extract_strategy(result['response'])
            strategies.append({
                'strategy': strategy,
                'confidence': result['confidence'],
                'model': result['model']
            })
        
        # Find consensus
        strategy_votes = {}
        for s in strategies:
            key = s['strategy']
            if key not in strategy_votes:
                strategy_votes[key] = []
            strategy_votes[key].append(s)
        
        # Select strategy with most votes
        best_strategy = max(strategy_votes.items(), key=lambda x: len(x[1]))
        
        # Generate payload considering fingerprint
        payload = self._generate_fingerprint_aware_payload(
            best_strategy[0], 
            task, 
            fingerprint
        )
        
        return {
            'strategy': best_strategy[0],
            'payload': payload,
            'confidence': np.mean([s['confidence'] for s in best_strategy[1]]),
            'consensus': len(best_strategy[1]) / len(results),
            'fingerprint_match': fingerprint.get('product') is not None
        }
    
    def _weighted_ensemble(self, results: List[Dict]) -> Dict:
        """Confidence-weighted ensemble strategy"""
        
        # Weight by confidence and model accuracy
        weighted_strategies = []
        total_weight = 0
        
        for result in results:
            model_name = result['model']
            model = self.models.get(model_name)
            if model:
                weight = result['confidence'] * model.accuracy_score
                weighted_strategies.append({
                    'strategy': self._extract_strategy(result['response']),
                    'weight': weight
                })
                total_weight += weight
        
        # Normalize weights and select best
        if total_weight > 0:
            for ws in weighted_strategies:
                ws['normalized_weight'] = ws['weight'] / total_weight
        
        best = max(weighted_strategies, key=lambda x: x.get('normalized_weight', 0))
        
        return {
            'strategy': best['strategy'],
            'payload': self._generate_payload(best['strategy'], 'weighted'),
            'confidence': best['normalized_weight'],
            'consensus': best['normalized_weight']
        }
    
    def _generate_fingerprint_aware_payload(self, strategy: str, task: str, fingerprint: Dict) -> str:
        """Generate payload considering target fingerprint"""
        
        # If we have product/version, get specific payload
        if fingerprint.get('product'):
            try:
                product_payloads = self.kb.get_payloads_by_product(
                    fingerprint['product'],
                    fingerprint.get('version')
                )
                
                if product_payloads:
                    # Return highest confidence payload
                    best = max(product_payloads, key=lambda p: p.confidence_score)
                    return best.payload
            except Exception as e:
                logger.warning(f"Product-specific payload selection failed: {e}", exc_info=True)
        
        # Fallback to generic payload
        return self._generate_payload(strategy, task)
    
    def _extract_strategy(self, response: str) -> str:
        """Extract exploitation strategy from model response"""
        # Simplified extraction - in reality would parse structured response
        return response[:100]
    
    def _generate_payload(self, strategy: str, task: str) -> str:
        """Generate payload based on strategy"""
        # Simplified payload generation
        return f"PAYLOAD[{task}]: {strategy[:50]}"
    
    def _calculate_confidence(self, response: str) -> float:
        """Calculate confidence score for a response"""
        # Simplified confidence calculation
        # In reality, would analyze response structure and content
        
        confidence_indicators = ['definitely', 'certain', 'high confidence', 'confirmed']
        uncertainty_indicators = ['might', 'possibly', 'uncertain', 'unclear']
        
        confidence = 0.5
        response_lower = response.lower()
        
        for indicator in confidence_indicators:
            if indicator in response_lower:
                confidence += 0.1
        
        for indicator in uncertainty_indicators:
            if indicator in response_lower:
                confidence -= 0.1
        
        return max(0.1, min(1.0, confidence))
    
    def _generate_cache_key(self, model_name: str, prompt: str) -> str:
        """Generate cache key for model responses"""
        content = f"{model_name}:{prompt}"
        return hashlib.md5(content.encode()).hexdigest()
    
    async def generate_adaptive_payload(self, 
                                       vulnerability: str,
                                       target_response: str,
                                       previous_attempts: List[Dict],
                                       target_info: Optional[Dict] = None) -> Dict:
        """Generate adaptive payload based on previous attempts and fingerprint"""
        
        # Analyze previous attempts
        analysis = self._analyze_attempts(previous_attempts)
        
        # Select specialized model for payload crafting
        model = self.model_selector.select_best_model(
            ModelCapability.PAYLOAD_CRAFTING,
            context={'vulnerability': vulnerability, 'attempts': len(previous_attempts)}
        )
        
        # Get alternative payloads from KB if we have fingerprint
        kb_alternatives = []
        if target_info and target_info.get('product'):
            try:
                mock_fp = TargetFingerprint(
                    url="",
                    product=target_info.get('product'),
                    version=target_info.get('version')
                )
                
                vuln_category = VulnCategory[vulnerability.upper()]
                
                # Get failed payloads
                failed_payloads = [
                    self.kb.search_payloads(att['payload'])[0] 
                    for att in previous_attempts 
                    if not att.get('success', False)
                ]
                
                # Get adaptive payloads
                adaptive = self.payload_manager.get_adaptive_payloads(
                    fingerprint=mock_fp,
                    failed_payloads=failed_payloads,
                    vulnerability=vuln_category
                )
                
                kb_alternatives = [rp.payload.payload for rp in adaptive[:3]]
            except KeyError as e:
                logger.error(f"Invalid vulnerability category for adaptive payload: {vulnerability}. Error: {e}")
            except Exception as e:
                logger.error(f"Failed to get adaptive KB payloads: {e}", exc_info=True)
        
        # Generate context-aware prompt
        prompt = self.prompt_optimizer.create_adaptive_prompt(
            vulnerability=vulnerability,
            target_response=target_response,
            failure_patterns=analysis['failure_patterns'],
            successful_patterns=analysis['successful_patterns'],
            target_info=target_info,
            kb_alternatives=kb_alternatives
        )
        
        # Execute model
        result = await self._execute_model(model, prompt)
        
        # Parse and return payload
        payload = self._extract_payload(result['response'])
        
        # If AI didn't generate good payload, use KB alternative
        if not payload and kb_alternatives:
            payload = kb_alternatives[0]
        
        return {
            'payload': payload,
            'technique': analysis['recommended_technique'],
            'confidence': result['confidence'],
            'model_used': model.name,
            'fingerprint_aware': target_info is not None
        }
    
    def _analyze_attempts(self, attempts: List[Dict]) -> Dict:
        """Analyze previous exploitation attempts"""
        
        successful = [a for a in attempts if a.get('success', False)]
        failed = [a for a in attempts if not a.get('success', False)]
        
        return {
            'success_rate': len(successful) / len(attempts) if attempts else 0,
            'failure_patterns': self._identify_patterns(failed),
            'successful_patterns': self._identify_patterns(successful),
            'recommended_technique': self._recommend_technique(attempts)
        }
    
    def _identify_patterns(self, attempts: List[Dict]) -> List[str]:
        """Identify patterns in attempts"""
        patterns = []
        
        # Analyze payload characteristics
        if attempts:
            # Length patterns
            lengths = [len(a.get('payload', '')) for a in attempts]
            if lengths:
                avg_length = np.mean(lengths)
                patterns.append(f"avg_length:{avg_length:.0f}")
            
            # Encoding patterns
            encodings = [a.get('encoding', 'none') for a in attempts]
            most_common = max(set(encodings), key=encodings.count)
            patterns.append(f"common_encoding:{most_common}")
        
        return patterns
    
    def _recommend_technique(self, attempts: List[Dict]) -> str:
        """Recommend exploitation technique based on history"""
        
        if not attempts:
            return "standard"
        
        success_rate = sum(1 for a in attempts if a.get('success', False)) / len(attempts)
        
        if success_rate < 0.2:
            return "advanced_evasion"
        elif success_rate < 0.5:
            return "moderate_obfuscation"
        else:
            return "standard_optimization"
    
    def _extract_payload(self, response: str) -> str:
        """Extract payload from model response"""
        # Look for payload markers in response
        payload_match = re.search(r'PAYLOAD:(.*?)(?:END|$)', response, re.DOTALL)
        if payload_match:
            return payload_match.group(1).strip()
        return response[:200]  # Fallback to first part of response


class ContextManager:
    """Manages context across AI interactions with fingerprint support"""
    
    def __init__(self, max_context_size: int = 32000):
        self.max_context_size = max_context_size
        self.context_windows = {}
        self.global_facts = []
        
    def prepare_context(self, target: str, vulnerability_type: str, 
                       base_context: Dict, fingerprint: Optional[Dict] = None) -> Dict:
        """Prepare enriched context for AI models"""
        
        # Initialize or retrieve context window
        context_key = f"{target}:{vulnerability_type}"
        if context_key not in self.context_windows:
            self.context_windows[context_key] = ContextWindow(
                max_tokens=self.max_context_size,
                current_tokens=0,
                messages=deque(maxlen=100),
                key_facts=[],
                vulnerability_context={},
                target_profile={},
                exploitation_history=[],
                fingerprint_data=fingerprint
            )
        
        window = self.context_windows[context_key]
        
        # Update context with new information
        window.vulnerability_context.update({
            'type': vulnerability_type,
            'target': target,
            'timestamp': datetime.now().isoformat()
        })
        
        # Add fingerprint data to context
        if fingerprint:
            window.fingerprint_data = fingerprint
            window.key_facts.append({
                'fact': f"Target is {fingerprint.get('product', 'unknown')} {fingerprint.get('version', '')}",
                'confidence': 0.9
            })
            if fingerprint.get('waf'):
                window.key_facts.append({
                    'fact': f"WAF detected: {fingerprint['waf']}",
                    'confidence': 0.85
                })
        
        # Add base context
        window.target_profile.update(base_context)
        
        # Compress if needed
        if window.current_tokens > window.max_tokens * 0.8:
            self._compress_context(window)
        
        return {
            'vulnerability': window.vulnerability_context,
            'target': window.target_profile,
            'key_facts': window.key_facts + self.global_facts,
            'history': window.exploitation_history[-10:],  # Last 10 attempts
            'fingerprint': window.fingerprint_data
        }
    
    def _compress_context(self, window: ContextWindow):
        """Compress context to fit within token limits"""
        
        # Remove old messages
        while len(window.messages) > 50:
            window.messages.popleft()
        
        # Summarize exploitation history
        if len(window.exploitation_history) > 20:
            window.exploitation_history = window.exploitation_history[-20:]
        
        # Recalculate tokens (simplified)
        window.current_tokens = len(json.dumps({
            'messages': list(window.messages),
            'facts': window.key_facts,
            'context': window.vulnerability_context,
            'profile': window.target_profile,
            'history': window.exploitation_history,
            'fingerprint': window.fingerprint_data
        })) // 4  # Rough token estimate
    
    def update_with_result(self, target: str, vulnerability_type: str, result: Dict):
        """Update context with exploitation result"""
        
        context_key = f"{target}:{vulnerability_type}"
        if context_key in self.context_windows:
            window = self.context_windows[context_key]
            
            # Add to history
            window.exploitation_history.append({
                'timestamp': datetime.now().isoformat(),
                'success': result.get('success', False),
                'technique': result.get('technique', 'unknown'),
                'fingerprint_match': result.get('fingerprint_match', False)
            })
            
            # Extract key facts from successful attempts
            if result.get('success'):
                window.key_facts.append({
                    'fact': f"Successful {vulnerability_type} exploitation",
                    'confidence': result.get('confidence', 0.5)
                })


class PromptOptimizer:
    """Optimizes prompts for different AI models with fingerprint context"""
    
    def __init__(self):
        self.prompt_templates = self._load_templates()
        self.optimization_history = []
        
    def _load_templates(self) -> Dict:
        """Load prompt templates for different tasks"""
        return {
            'vulnerability_analysis': """
                Analyze the following target for {vulnerability_type} vulnerabilities:
                Target: {target}
                Product: {product}
                Version: {version}
                Context: {context}
                
                Provide detailed analysis including:
                1. Vulnerability indicators
                2. Exploitation vectors
                3. Recommended payloads (consider the product/version)
                4. Success probability
            """,
            'payload_crafting': """
                Create an optimized payload for {vulnerability_type}:
                Target Product: {product} {version}
                Target characteristics: {target_profile}
                Previous attempts: {attempts}
                KB suggestions: {kb_alternatives}
                
                Generate a payload that:
                1. Is specific to {product} {version}
                2. Evades common filters
                3. Maximizes success probability
                4. Minimizes detection
            """,
            'strategic_planning': """
                Develop exploitation strategy for:
                Target: {target}
                Fingerprint: {fingerprint}
                Vulnerabilities found: {vulnerabilities}
                
                Provide:
                1. Prioritized exploitation order
                2. Product-specific techniques
                3. Chaining opportunities
                4. Risk assessment
                5. Expected outcomes
            """
        }
    
    def optimize_prompt(self, model: AIModel, task: str, context: Dict,
                        fingerprint: Optional[Dict] = None) -> str:
        """Optimize prompt for specific model and task with fingerprint"""
        # Get base template (default to vulnerability_analysis)
        template = self.prompt_templates.get(task, self.prompt_templates['vulnerability_analysis'])

        # Build a non-mutating formatting context
        format_ctx = {
            # Always present fields expected by templates
            'vulnerability_type': task,
            'target': context.get('target', {}),
            'context': context,
            'target_profile': context.get('target', {}),
            'attempts': context.get('history', []),
            'kb_alternatives': context.get('suggested_payloads', []),
            'fingerprint': json.dumps(context.get('fingerprint', {})),
            'product': 'unknown',
            'version': 'unknown',
            'vulnerabilities': context.get('vulnerability', {}),
        }
        if fingerprint:
            format_ctx['product'] = fingerprint.get('product', 'unknown')
            format_ctx['version'] = fingerprint.get('version', 'unknown')
            format_ctx['fingerprint'] = json.dumps(fingerprint)

        # Apply model-specific optimizations
        if model.provider == 'ollama':
            prompt = self._optimize_for_ollama(template, format_ctx)
        elif model.provider == 'openai':
            prompt = self._optimize_for_openai(template, format_ctx)
        elif model.provider == 'anthropic':
            prompt = self._optimize_for_anthropic(template, format_ctx)
        else:
            prompt = template.format(**format_ctx)
        
        # Apply general optimizations
        prompt = self._apply_general_optimizations(prompt, model)
        
        return prompt
    
    def _optimize_for_ollama(self, template: str, context: Dict) -> str:
        """Optimize prompt for Ollama models"""
        # Ollama prefers direct, technical prompts
        prompt = template.format(**context)
        prompt = f"### TECHNICAL ANALYSIS ###\n{prompt}\n### END ###"
        return prompt
    
    def _optimize_for_openai(self, template: str, context: Dict) -> str:
        """Optimize prompt for OpenAI models"""
        # OpenAI responds well to structured prompts
        prompt = template.format(**context)
        prompt = f"You are a security expert. {prompt}\nProvide response in JSON format."
        return prompt
    
    def _optimize_for_anthropic(self, template: str, context: Dict) -> str:
        """Optimize prompt for Anthropic models"""
        # Anthropic models prefer detailed context
        prompt = template.format(**context)
        prompt = f"Context: You are analyzing security vulnerabilities.\n\n{prompt}\n\nBe thorough and precise."
        return prompt
    
    def _apply_general_optimizations(self, prompt: str, model: AIModel) -> str:
        """Apply general prompt optimizations"""
        
        # Trim to fit context window
        max_prompt_tokens = model.context_window * 0.7  # Leave room for response
        
        # Simple token estimation (4 chars per token)
        if len(prompt) / 4 > max_prompt_tokens:
            prompt = prompt[:int(max_prompt_tokens * 4)]
        
        # Add few-shot examples if beneficial
        if 'code_generation' in [c.value for c in model.capabilities]:
            prompt += "\n\nExample payload: ' OR '1'='1"
        
        return prompt
    
    def create_adaptive_prompt(self, **kwargs) -> str:
        """Create adaptive prompt based on context with fingerprint"""
        
        base_prompt = "Generate an adaptive exploitation strategy.\n"
        
        if 'vulnerability' in kwargs:
            base_prompt += f"Vulnerability: {kwargs['vulnerability']}\n"
        
        if 'target_info' in kwargs and kwargs['target_info']:
            info = kwargs['target_info']
            base_prompt += f"Target: {info.get('product', 'unknown')} {info.get('version', '')}\n"
            if info.get('technologies'):
                base_prompt += f"Technologies: {', '.join(info['technologies'])}\n"
        
        if 'kb_alternatives' in kwargs and kwargs['kb_alternatives']:
            base_prompt += f"Consider these KB payloads: {kwargs['kb_alternatives'][:3]}\n"
        
        if 'failure_patterns' in kwargs:
            base_prompt += f"Avoid patterns: {kwargs['failure_patterns']}\n"
        
        if 'successful_patterns' in kwargs:
            base_prompt += f"Successful patterns: {kwargs['successful_patterns']}\n"
        
        base_prompt += "\nProvide optimized payload with explanation."
        
        return base_prompt


class ModelSelector:
    """Selects optimal models for tasks"""
    
    def __init__(self, models: Dict[str, AIModel]):
        self.models = models
        self.performance_history = {}
        
    def select_models(self, 
                     task_type: str,
                     capabilities_needed: List[ModelCapability],
                     max_models: int = 3) -> Dict[str, AIModel]:
        """Select best models for a task"""
        
        suitable_models = {}
        
        for model_name, model in self.models.items():
            # Check if model has required capabilities
            model_caps = set(model.capabilities)
            needed_caps = set(capabilities_needed)
            
            if needed_caps.intersection(model_caps):
                score = self._calculate_model_score(model, task_type, capabilities_needed)
                suitable_models[model_name] = (model, score)
        
        # Sort by score and select top models
        sorted_models = sorted(suitable_models.items(), key=lambda x: x[1][1], reverse=True)
        selected = {}
        
        for model_name, (model, score) in sorted_models[:max_models]:
            selected[model_name] = model
        
        return selected
    
    def select_best_model(self, 
                         capability: ModelCapability,
                         context: Optional[Dict] = None) -> AIModel:
        """Select single best model for a capability"""
        
        best_model = None
        best_score = -1
        
        for model_name, model in self.models.items():
            if capability in model.capabilities:
                score = self._calculate_model_score(model, capability.value, [capability])
                
                # Adjust score based on context
                if context:
                    if context.get('require_large_context') and model.context_window > 100000:
                        score *= 1.5
                    if context.get('cost_sensitive') and model.cost_per_token == 0:
                        score *= 1.3
                
                if score > best_score:
                    best_score = score
                    best_model = model
        
        return best_model or list(self.models.values())[0]  # Fallback to first model
    
    def _calculate_model_score(self, 
                              model: AIModel,
                              task_type: str,
                              capabilities: List[ModelCapability]) -> float:
        """Calculate model suitability score"""
        
        score = 0
        
        # Base accuracy score
        score += model.accuracy_score * 10
        
        # Capability match
        model_caps = set(model.capabilities)
        needed_caps = set(capabilities)
        overlap = len(model_caps.intersection(needed_caps))
        score += overlap * 5
        
        # Specialization bonus
        if task_type.lower() in [s.lower() for s in model.specializations]:
            score += 10
        
        # Cost penalty (if not free)
        if model.cost_per_token > 0:
            score -= model.cost_per_token * 100
        
        # Latency penalty
        score -= model.latency_ms / 1000
        
        # Historical performance bonus
        if model.name in self.performance_history:
            historical_success = self.performance_history[model.name].get('success_rate', 0.5)
            score += historical_success * 10
        
        return score
    
    def update_performance(self, model_name: str, success: bool, task_type: str):
        """Update model performance history"""
        
        if model_name not in self.performance_history:
            self.performance_history[model_name] = {
                'total_tasks': 0,
                'successful_tasks': 0,
                'success_rate': 0,
                'task_types': {}
            }
        
        history = self.performance_history[model_name]
        history['total_tasks'] += 1
        if success:
            history['successful_tasks'] += 1
        history['success_rate'] = history['successful_tasks'] / history['total_tasks']
        
        # Track per task type
        if task_type not in history['task_types']:
            history['task_types'][task_type] = {'total': 0, 'successful': 0}
        
        history['task_types'][task_type]['total'] += 1
        if success:
            history['task_types'][task_type]['successful'] += 1


class PerformanceTracker:
    """Tracks AI orchestration performance"""
    
    def __init__(self):
        self.executions = []
        self.model_stats = {}
        
    def record_execution(self, models: List[str], task: str, success: bool, latency: float):
        """Record execution metrics"""
        
        execution = {
            'timestamp': datetime.now(),
            'models': models,
            'task': task,
            'success': success,
            'latency': latency
        }
        
        self.executions.append(execution)
        
        # Update model statistics
        for model in models:
            if model not in self.model_stats:
                self.model_stats[model] = {
                    'executions': 0,
                    'successes': 0,
                    'total_latency': 0
                }
            
            stats = self.model_stats[model]
            stats['executions'] += 1
            if success:
                stats['successes'] += 1
            stats['total_latency'] += latency
    
    def get_performance_report(self) -> Dict:
        """Generate performance report"""
        
        if not self.executions:
            return {'message': 'No executions recorded'}
        
        recent_executions = self.executions[-100:]  # Last 100
        
        return {
            'total_executions': len(self.executions),
            'success_rate': sum(1 for e in self.executions if e['success']) / len(self.executions),
            'average_latency': np.mean([e['latency'] for e in self.executions]),
            'model_performance': {
                model: {
                    'success_rate': stats['successes'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'avg_latency': stats['total_latency'] / stats['executions'] if stats['executions'] > 0 else 0,
                    'usage_count': stats['executions']
                }
                for model, stats in self.model_stats.items()
            },
            'recent_trend': {
                'success_rate': sum(1 for e in recent_executions if e['success']) / len(recent_executions),
                'avg_latency': np.mean([e['latency'] for e in recent_executions])
            }
        }
