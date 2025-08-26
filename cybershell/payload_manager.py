"""
Payload Manager Module
======================
Intelligently selects and ranks payloads based on target fingerprint
"""

import re
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from packaging import version
from packaging.specifiers import SpecifierSet
import numpy as np
from datetime import datetime

from .vulnerability_kb import (
    VulnerabilityKnowledgeBase,
    VulnPayload,
    VulnCategory
)
from .fingerprinter import TargetFingerprint

@dataclass
class PayloadScore:
    """Scoring components for payload ranking"""
    version_match: float = 0.0  # Product/version compatibility
    pattern_match: float = 0.0  # Detection pattern match
    confidence_base: float = 0.0  # Base confidence from KB
    tag_match: float = 0.0  # Tag relevance
    context_match: float = 0.0  # Context appropriateness
    historical_success: float = 0.0  # Past success rate
    total: float = 0.0  # Weighted total
    
    def calculate_total(self, weights: Dict[str, float]) -> float:
        """Calculate weighted total score"""
        self.total = (
            self.version_match * weights.get('version', 0.3) +
            self.pattern_match * weights.get('pattern', 0.2) +
            self.confidence_base * weights.get('confidence', 0.2) +
            self.tag_match * weights.get('tag', 0.1) +
            self.context_match * weights.get('context', 0.1) +
            self.historical_success * weights.get('history', 0.1)
        )
        return self.total

@dataclass
class RankedPayload:
    """Payload with ranking information"""
    payload: VulnPayload
    score: PayloadScore
    rank: int
    reasoning: List[str] = field(default_factory=list)
    
class PayloadManager:
    """Manages payload selection and ranking"""
    
    def __init__(self, kb: Optional[VulnerabilityKnowledgeBase] = None,
                 config: Optional[Dict] = None):
        self.kb = kb or VulnerabilityKnowledgeBase()
        self.config = config or self._default_config()
        self.history = {}  # Track success rates
        self.cache = {}  # Cache selection results
        
    def _default_config(self) -> Dict:
        """Default configuration for payload selection"""
        return {
            'weights': {
                'version': 0.35,  # Product/version match weight
                'pattern': 0.25,  # Detection pattern weight
                'confidence': 0.20,  # Base confidence weight
                'tag': 0.10,  # Tag match weight
                'context': 0.05,  # Context match weight
                'history': 0.05  # Historical success weight
            },
            'min_score': 0.3,  # Minimum score to include payload
            'prefer_version_specific': True,  # Prioritize version-specific payloads
            'enable_caching': True,
            'cache_ttl': 300  # 5 minutes
        }
    
    def select_payloads(self,
                       fingerprint: TargetFingerprint,
                       vulnerability: VulnCategory,
                       context: Optional[Dict] = None,
                       top_n: int = 5) -> List[RankedPayload]:
        """
        Select and rank payloads based on fingerprint and context
        
        Args:
            fingerprint: Target fingerprint with product/version info
            vulnerability: Vulnerability category to test
            context: Additional context (endpoint type, parameters, etc.)
            top_n: Number of top payloads to return
            
        Returns:
            List of ranked payloads
        """
        # Check cache
        cache_key = self._get_cache_key(fingerprint, vulnerability, context)
        if self.config['enable_caching'] and cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['timestamp']).seconds < self.config['cache_ttl']:
                return cached['payloads'][:top_n]
        
        # Get all payloads for vulnerability category
        all_payloads = self.kb.get_payloads_by_category(vulnerability)
        
        # Score and rank payloads
        ranked_payloads = []
        for payload in all_payloads:
            score = self._score_payload(payload, fingerprint, context)
            
            # Skip low-scoring payloads
            if score.total < self.config['min_score']:
                continue
            
            reasoning = self._generate_reasoning(payload, score, fingerprint)
            
            ranked_payloads.append(RankedPayload(
                payload=payload,
                score=score,
                rank=0,  # Will be set after sorting
                reasoning=reasoning
            ))
        
        # Sort by score
        ranked_payloads.sort(key=lambda x: x.score.total, reverse=True)
        
        # Assign ranks
        for i, rp in enumerate(ranked_payloads):
            rp.rank = i + 1
        
        # Cache results
        if self.config['enable_caching']:
            self.cache[cache_key] = {
                'timestamp': datetime.now(),
                'payloads': ranked_payloads
            }
        
        return ranked_payloads[:top_n]
    
    def _score_payload(self,
                      payload: VulnPayload,
                      fingerprint: TargetFingerprint,
                      context: Optional[Dict]) -> PayloadScore:
        """Score a payload based on various factors"""
        score = PayloadScore()
        
        # 1. Version match scoring
        score.version_match = self._score_version_match(payload, fingerprint)
        
        # 2. Pattern match scoring (against previous responses if available)
        score.pattern_match = self._score_pattern_match(payload, context)
        
        # 3. Base confidence from KB
        score.confidence_base = payload.confidence_score
        
        # 4. Tag match scoring
        score.tag_match = self._score_tag_match(payload, fingerprint, context)
        
        # 5. Context match scoring
        score.context_match = self._score_context_match(payload, context)
        
        # 6. Historical success rate
        score.historical_success = self._get_historical_success(payload)
        
        # Calculate weighted total
        score.calculate_total(self.config['weights'])
        
        return score
    
    def _score_version_match(self,
                            payload: VulnPayload,
                            fingerprint: TargetFingerprint) -> float:
        """Score how well payload matches target version"""
        # No product/version requirements - universal payload
        if not payload.product and not payload.version_spec:
            return 0.5  # Neutral score for universal payloads
        
        # Product mismatch
        if payload.product and fingerprint.product:
            if payload.product.lower() != fingerprint.product.lower():
                # Check if product is in technologies list
                tech_match = any(
                    payload.product.lower() in tech.lower()
                    for tech in fingerprint.technologies
                )
                if not tech_match:
                    return 0.0  # Complete mismatch
        
        # Product matches, check version
        if payload.version_spec and fingerprint.version:
            try:
                if payload.matches_version(fingerprint.version):
                    return 1.0  # Perfect version match
                else:
                    return 0.2  # Product matches but version doesn't
            except:
                return 0.5  # Can't determine version match
        
        # Product matches but no version info
        if payload.product and fingerprint.product:
            if payload.product.lower() == fingerprint.product.lower():
                return 0.8  # Good product match
        
        return 0.5  # Default neutral score
    
    def _score_pattern_match(self,
                            payload: VulnPayload,
                            context: Optional[Dict]) -> float:
        """Score based on detection pattern relevance"""
        if not payload.detection_pattern or not context:
            return 0.5
        
        # Check if we have previous response data
        prev_responses = context.get('previous_responses', [])
        if not prev_responses:
            return 0.5
        
        # Check if pattern would match previous responses
        pattern_score = 0.0
        for response in prev_responses:
            response_text = response.get('text', '')
            if response_text:
                try:
                    if re.search(payload.detection_pattern, response_text):
                        pattern_score = 1.0
                        break
                except:
                    pass
        
        return pattern_score
    
    def _score_tag_match(self,
                        payload: VulnPayload,
                        fingerprint: TargetFingerprint,
                        context: Optional[Dict]) -> float:
        """Score based on tag relevance"""
        if not payload.tags:
            return 0.5
        
        score = 0.0
        matches = 0
        
        # Check tags against fingerprint
        fingerprint_terms = []
        if fingerprint.product:
            fingerprint_terms.append(fingerprint.product.lower())
        fingerprint_terms.extend([t.lower() for t in fingerprint.technologies])
        fingerprint_terms.extend([f.lower() for f in fingerprint.frameworks])
        if fingerprint.cms:
            fingerprint_terms.append(fingerprint.cms.lower())
        
        for tag in payload.tags:
            tag_lower = tag.lower()
            if any(term in tag_lower for term in fingerprint_terms):
                matches += 1
        
        if matches > 0:
            score = min(1.0, matches / len(payload.tags))
        
        # Check tags against context
        if context:
            context_tags = context.get('tags', [])
            for tag in payload.tags:
                if tag in context_tags:
                    score = min(1.0, score + 0.2)
        
        return score
    
    def _score_context_match(self,
                            payload: VulnPayload,
                            context: Optional[Dict]) -> float:
        """Score based on context appropriateness"""
        if not context:
            return 0.5
        
        score = 0.5
        
        # Check injection context
        inj_context = context.get('injection_context', '')
        if inj_context and payload.context:
            if inj_context == payload.context:
                score = 1.0
            elif inj_context in ['any', 'unknown']:
                score = 0.7
            else:
                score = 0.3
        
        # Check endpoint type
        endpoint_type = context.get('endpoint_type', '')
        if endpoint_type:
            if endpoint_type == 'api' and 'json' in payload.context:
                score = min(1.0, score + 0.2)
            elif endpoint_type == 'form' and 'parameter' in payload.context:
                score = min(1.0, score + 0.2)
        
        return score
    
    def _get_historical_success(self, payload: VulnPayload) -> float:
        """Get historical success rate for payload"""
        payload_id = f"{payload.category.value}_{payload.name}"
        
        if payload_id in self.history:
            stats = self.history[payload_id]
            if stats['attempts'] > 0:
                return stats['successes'] / stats['attempts']
        
        return 0.5  # No history, neutral score
    
    def _generate_reasoning(self,
                           payload: VulnPayload,
                           score: PayloadScore,
                           fingerprint: TargetFingerprint) -> List[str]:
        """Generate reasoning for payload selection"""
        reasons = []
        
        if score.version_match >= 0.8:
            if payload.product and payload.version_spec:
                reasons.append(f"Specifically designed for {payload.product} {payload.version_spec}")
            elif payload.product:
                reasons.append(f"Matches target product: {payload.product}")
        
        if score.confidence_base >= 0.8:
            reasons.append(f"High confidence payload ({score.confidence_base:.0%})")
        
        if score.pattern_match >= 0.8:
            reasons.append("Detection pattern matches previous responses")
        
        if score.tag_match >= 0.7:
            reasons.append("Tags match target technologies")
        
        if score.historical_success >= 0.7:
            success_rate = score.historical_success * 100
            reasons.append(f"Historical success rate: {success_rate:.0f}%")
        
        if not reasons:
            reasons.append("General purpose payload")
        
        return reasons
    
    def _get_cache_key(self,
                      fingerprint: TargetFingerprint,
                      vulnerability: VulnCategory,
                      context: Optional[Dict]) -> str:
        """Generate cache key for selection results"""
        key_parts = [
            vulnerability.value,
            fingerprint.product or 'unknown',
            fingerprint.version or 'unknown'
        ]
        
        if context:
            key_parts.append(json.dumps(sorted(context.items()), sort_keys=True))
        
        return "|".join(key_parts)
    
    def update_history(self,
                      payload: VulnPayload,
                      success: bool):
        """Update historical success data for payload"""
        payload_id = f"{payload.category.value}_{payload.name}"
        
        if payload_id not in self.history:
            self.history[payload_id] = {
                'attempts': 0,
                'successes': 0
            }
        
        self.history[payload_id]['attempts'] += 1
        if success:
            self.history[payload_id]['successes'] += 1
    
    def get_adaptive_payloads(self,
                             fingerprint: TargetFingerprint,
                             failed_payloads: List[VulnPayload],
                             vulnerability: VulnCategory,
                             context: Optional[Dict] = None) -> List[RankedPayload]:
        """
        Get adaptive payloads after initial failures
        
        Args:
            fingerprint: Target fingerprint
            failed_payloads: List of payloads that have failed
            vulnerability: Vulnerability category
            context: Additional context
            
        Returns:
            List of alternative payloads to try
        """
        # Get all payloads
        all_payloads = self.kb.get_payloads_by_category(vulnerability)
        
        # Filter out failed payloads
        failed_names = {p.name for p in failed_payloads}
        remaining = [p for p in all_payloads if p.name not in failed_names]
        
        # Analyze failure patterns
        failure_analysis = self._analyze_failures(failed_payloads)
        
        # Adjust scoring weights based on failures
        adapted_weights = self._adapt_weights(failure_analysis)
        
        # Score remaining payloads with adapted weights
        ranked_payloads = []
        for payload in remaining:
            score = self._score_payload(payload, fingerprint, context)
            score.calculate_total(adapted_weights)
            
            # Boost score if payload is different from failed patterns
            if self._is_different_approach(payload, failed_payloads):
                score.total *= 1.2
            
            reasoning = self._generate_reasoning(payload, score, fingerprint)
            reasoning.append("Selected as alternative approach after failures")
            
            ranked_payloads.append(RankedPayload(
                payload=payload,
                score=score,
                rank=0,
                reasoning=reasoning
            ))
        
        # Sort and rank
        ranked_payloads.sort(key=lambda x: x.score.total, reverse=True)
        for i, rp in enumerate(ranked_payloads):
            rp.rank = i + 1
        
        return ranked_payloads[:5]
    
    def _analyze_failures(self, failed_payloads: List[VulnPayload]) -> Dict:
        """Analyze patterns in failed payloads"""
        analysis = {
            'common_contexts': {},
            'common_techniques': {},
            'avg_length': 0,
            'encoding_used': False
        }
        
        # Analyze contexts
        for p in failed_payloads:
            context = p.context or 'unknown'
            analysis['common_contexts'][context] = \
                analysis['common_contexts'].get(context, 0) + 1
        
        # Analyze payload characteristics
        lengths = [len(p.payload) for p in failed_payloads]
        if lengths:
            analysis['avg_length'] = np.mean(lengths)
        
        # Check for encoding
        for p in failed_payloads:
            if any(enc in p.payload for enc in ['%', '&#', '\\x', '\\u']):
                analysis['encoding_used'] = True
                break
        
        return analysis
    
    def _adapt_weights(self, failure_analysis: Dict) -> Dict[str, float]:
        """Adapt scoring weights based on failure analysis"""
        weights = self.config['weights'].copy()
        
        # If many failures, reduce confidence weight and increase version weight
        if len(failure_analysis['common_contexts']) > 2:
            weights['confidence'] *= 0.7
            weights['version'] *= 1.3
        
        # Normalize weights
        total = sum(weights.values())
        for key in weights:
            weights[key] /= total
        
        return weights
    
    def _is_different_approach(self,
                               payload: VulnPayload,
                               failed_payloads: List[VulnPayload]) -> bool:
        """Check if payload uses different approach than failed ones"""
        # Check if context is different
        failed_contexts = {p.context for p in failed_payloads}
        if payload.context and payload.context not in failed_contexts:
            return True
        
        # Check if length is significantly different
        failed_lengths = [len(p.payload) for p in failed_payloads]
        if failed_lengths:
            avg_failed_length = np.mean(failed_lengths)
            if abs(len(payload.payload) - avg_failed_length) > avg_failed_length * 0.5:
                return True
        
        # Check for different encoding/technique
        failed_patterns = set()
        for p in failed_payloads:
            if '<' in p.payload:
                failed_patterns.add('html')
            if 'script' in p.payload.lower():
                failed_patterns.add('script')
            if '%' in p.payload:
                failed_patterns.add('urlencoded')
        
        payload_patterns = set()
        if '<' in payload.payload:
            payload_patterns.add('html')
        if 'script' in payload.payload.lower():
            payload_patterns.add('script')
        if '%' in payload.payload:
            payload_patterns.add('urlencoded')
        
        # Different if it doesn't share patterns with failed ones
        return not payload_patterns.intersection(failed_patterns)
    
    def export_selection_report(self,
                               ranked_payloads: List[RankedPayload],
                               fingerprint: TargetFingerprint) -> Dict:
        """Export detailed selection report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'target': {
                'url': fingerprint.url,
                'product': fingerprint.product,
                'version': fingerprint.version,
                'technologies': fingerprint.technologies
            },
            'payloads': [
                {
                    'rank': rp.rank,
                    'name': rp.payload.name,
                    'category': rp.payload.category.value,
                    'payload': rp.payload.payload,
                    'score': {
                        'total': rp.score.total,
                        'version_match': rp.score.version_match,
                        'confidence': rp.score.confidence_base,
                        'pattern_match': rp.score.pattern_match
                    },
                    'reasoning': rp.reasoning,
                    'product_specific': rp.payload.product is not None,
                    'version_specific': rp.payload.version_spec is not None
                }
                for rp in ranked_payloads
            ],
            'config': self.config
        }


# Integration helper class
class SmartPayloadSelector:
    """High-level interface for payload selection"""
    
    def __init__(self, kb_path: Optional[str] = None):
        self.kb = VulnerabilityKnowledgeBase(kb_path) if kb_path else VulnerabilityKnowledgeBase()
        self.manager = PayloadManager(self.kb)
        self.fingerprints = {}  # Cache fingerprints
    
    def select_for_target(self,
                         target: str,
                         vulnerability: str,
                         aggressive: bool = False,
                         context: Optional[Dict] = None) -> List[Dict]:
        """
        Select payloads for a target URL and vulnerability type
        
        Args:
            target: Target URL
            vulnerability: Vulnerability type (e.g., 'XSS', 'SQLI')
            aggressive: Use aggressive fingerprinting
            context: Additional context
            
        Returns:
            List of payload dictionaries with ranking info
        """
        # Get or create fingerprint
        if target not in self.fingerprints:
            from .fingerprinter import Fingerprinter
            fp = Fingerprinter()
            self.fingerprints[target] = fp.fingerprint(target, aggressive=aggressive)
        
        fingerprint = self.fingerprints[target]
        
        # Get vulnerability category
        try:
            vuln_category = VulnCategory[vulnerability.upper()]
        except KeyError:
            return []
        
        # Select payloads
        ranked_payloads = self.manager.select_payloads(
            fingerprint=fingerprint,
            vulnerability=vuln_category,
            context=context,
            top_n=10
        )
        
        # Convert to simple dictionaries
        return [
            {
                'payload': rp.payload.payload,
                'name': rp.payload.name,
                'rank': rp.rank,
                'score': rp.score.total,
                'reasoning': rp.reasoning,
                'confidence': rp.payload.confidence_score
            }
            for rp in ranked_payloads
        ]
    
    def update_results(self, payload_name: str, success: bool):
        """Update historical data based on exploitation results"""
        # Find payload in KB
        for category_payloads in self.kb.payloads.values():
            for payload in category_payloads:
                if payload.name == payload_name:
                    self.manager.update_history(payload, success)
                    return
