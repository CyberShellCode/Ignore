import hashlib
import json
import re
import time
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from pathlib import Path
import difflib
import requests
from urllib.parse import urlparse, parse_qs

class EvidenceType(Enum):
    """Types of evidence for validation"""
    RESPONSE_DIFFERENCE = "response_difference"
    TIME_BASED = "time_based"
    ERROR_MESSAGE = "error_message"
    DATA_EXTRACTION = "data_extraction"
    BEHAVIORAL_CHANGE = "behavioral_change"
    SIDE_CHANNEL = "side_channel"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    COMMAND_EXECUTION = "command_execution"

class ValidationStrength(Enum):
    """Strength of validation evidence"""
    CONCLUSIVE = 1.0
    STRONG = 0.8
    MODERATE = 0.6
    WEAK = 0.4
    MINIMAL = 0.2

@dataclass
class ValidationEvidence:
    """Evidence collected during validation"""
    evidence_type: EvidenceType
    strength: ValidationStrength
    data: Dict[str, Any]
    timestamp: datetime
    confidence: float
    reproducible: bool
    artifacts: List[Dict] = field(default_factory=list)

@dataclass 
class ValidationResult:
    """Result of validation process"""
    vulnerability_type: str
    validated: bool
    confidence_score: float
    evidence: List[ValidationEvidence]
    false_positive_indicators: List[str]
    exploitation_proof: Dict
    impact_assessment: Dict
    remediation_verified: bool
    
class RealWorldValidationFramework:
    """
    Comprehensive validation framework for real-world exploitation verification
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        
        # Core validators
        self.response_validator = ResponseDifferenceValidator()
        self.timing_validator = TimingValidator()
        self.behavior_validator = BehaviorValidator()
        self.evidence_correlator = EvidenceCorrelator()
        self.false_positive_detector = FalsePositiveDetector()
        self.impact_analyzer = ImpactAnalyzer()
        
        # Validation cache
        self.validation_cache = {}
        self.baseline_responses = {}
        
    def _default_config(self) -> Dict:
        """Default configuration for validation"""
        return {
            'min_confidence_threshold': 0.7,
            'require_multiple_evidence': True,
            'max_validation_attempts': 5,
            'validation_timeout': 30,
            'differential_threshold': 0.3,
            'timing_deviation_threshold': 2.0,  # Standard deviations
            'false_positive_patterns': [
                'generic_error',
                'rate_limit',
                'maintenance_mode',
                'honeypot_response'
            ]
        }
    
    async def validate_exploitation(self,
                                   target: str,
                                   vulnerability_type: str,
                                   exploitation_result: Dict,
                                   original_response: Optional[str] = None) -> ValidationResult:
        """Validate exploitation with comprehensive evidence gathering"""
        
        print(f"[VALIDATION] Starting validation for {vulnerability_type} on {target}")
        
        # Collect baseline if not provided
        if not original_response:
            original_response = await self._get_baseline_response(target)
        
        # Initialize evidence collection
        evidence = []
        
        # 1. Response Difference Validation
        response_evidence = await self.response_validator.validate(
            target,
            exploitation_result,
            original_response
        )
        if response_evidence:
            evidence.append(response_evidence)
        
        # 2. Timing-based Validation
        timing_evidence = await self.timing_validator.validate(
            target,
            vulnerability_type,
            exploitation_result
        )
        if timing_evidence:
            evidence.append(timing_evidence)
        
        # 3. Behavioral Validation
        behavior_evidence = await self.behavior_validator.validate(
            target,
            vulnerability_type,
            exploitation_result
        )
        if behavior_evidence:
            evidence.append(behavior_evidence)
        
        # 4. Correlate all evidence
        correlation_result = self.evidence_correlator.correlate(evidence)
        
        # 5. Check for false positives
        false_positive_indicators = self.false_positive_detector.detect(
            evidence,
            exploitation_result
        )
        
        # 6. Calculate final confidence
        confidence = self._calculate_confidence(
            evidence,
            correlation_result,
            false_positive_indicators
        )
        
        # 7. Assess real-world impact
        impact = self.impact_analyzer.analyze(
            vulnerability_type,
            exploitation_result,
            evidence
        )
        
        # 8. Generate exploitation proof
        proof = self._generate_proof(
            vulnerability_type,
            evidence,
            exploitation_result
        )
        
        # 9. Verify remediation (if applicable)
        remediation_verified = await self._verify_remediation(
            target,
            vulnerability_type,
            exploitation_result
        )
        
        # Determine if validated
        validated = (
            confidence >= self.config['min_confidence_threshold'] and
            len(false_positive_indicators) == 0 and
            (not self.config['require_multiple_evidence'] or len(evidence) >= 2)
        )
        
        result = ValidationResult(
            vulnerability_type=vulnerability_type,
            validated=validated,
            confidence_score=confidence,
            evidence=evidence,
            false_positive_indicators=false_positive_indicators,
            exploitation_proof=proof,
            impact_assessment=impact,
            remediation_verified=remediation_verified
        )
        
        # Cache result
        cache_key = f"{target}:{vulnerability_type}:{hashlib.md5(str(exploitation_result).encode()).hexdigest()}"
        self.validation_cache[cache_key] = result
        
        return result
    
    async def _get_baseline_response(self, target: str) -> str:
        """Get baseline response for comparison"""
        
        if target in self.baseline_responses:
            return self.baseline_responses[target]
        
        try:
            # Simulate getting baseline response
            # In reality, would make actual request
            baseline = f"Baseline response for {target}"
            self.baseline_responses[target] = baseline
            return baseline
        except Exception as e:
            print(f"[VALIDATION] Error getting baseline: {e}")
            return ""
    
    def _calculate_confidence(self,
                            evidence: List[ValidationEvidence],
                            correlation: Dict,
                            false_positives: List[str]) -> float:
        """Calculate overall confidence score"""
        
        if not evidence:
            return 0.0
        
        # Weight evidence by strength
        weighted_sum = sum(e.confidence * e.strength.value for e in evidence)
        total_weight = sum(e.strength.value for e in evidence)
        
        base_confidence = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Apply correlation bonus
        if correlation.get('correlation_strength', 0) > 0.7:
            base_confidence *= 1.2
        
        # Apply false positive penalty
        fp_penalty = len(false_positives) * 0.1
        base_confidence *= (1 - fp_penalty)
        
        # Apply reproducibility bonus
        reproducible_count = sum(1 for e in evidence if e.reproducible)
        if reproducible_count == len(evidence):
            base_confidence *= 1.1
        
        return min(1.0, max(0.0, base_confidence))
    
    def _generate_proof(self,
                       vulnerability_type: str,
                       evidence: List[ValidationEvidence],
                       exploitation_result: Dict) -> Dict:
        """Generate proof of exploitation"""
        
        proof = {
            'vulnerability_type': vulnerability_type,
            'timestamp': datetime.now().isoformat(),
            'evidence_count': len(evidence),
            'evidence_types': list(set(e.evidence_type.value for e in evidence)),
            'strongest_evidence': max(evidence, key=lambda e: e.strength.value).data if evidence else {},
            'exploitation_details': exploitation_result,
            'reproducible': all(e.reproducible for e in evidence) if evidence else False
        }
        
        # Add specific proof elements based on vulnerability type
        if vulnerability_type == 'SQLI':
            proof['database_accessed'] = any(
                'database' in e.data.get('extracted_data', '') 
                for e in evidence
            )
        elif vulnerability_type == 'RCE':
            proof['command_executed'] = any(
                e.evidence_type == EvidenceType.COMMAND_EXECUTION 
                for e in evidence
            )
        elif vulnerability_type == 'XSS':
            proof['payload_reflected'] = any(
                'payload_reflected' in e.data 
                for e in evidence
            )
        
        return proof
    
    async def _verify_remediation(self,
                                 target: str,
                                 vulnerability_type: str,
                                 exploitation_result: Dict) -> bool:
        """Verify if remediation blocks exploitation"""
        
        # Simulate remediation verification
        # In reality, would re-test after potential fix
        
        # For now, return False (not remediated)
        return False
    
    async def validate_chain(self,
                            target: str,
                            chain: List[Dict]) -> Dict:
        """Validate exploitation chain"""
        
        print(f"[VALIDATION] Validating exploitation chain with {len(chain)} steps")
        
        chain_valid = True
        chain_confidence = 1.0
        step_results = []
        
        for i, step in enumerate(chain):
            print(f"[VALIDATION] Validating chain step {i+1}/{len(chain)}")
            
            # Validate individual step
            step_result = await self.validate_exploitation(
                target,
                step['vulnerability_type'],
                step['exploitation_result']
            )
            
            step_results.append(step_result)
            
            # Update chain validity
            if not step_result.validated:
                chain_valid = False
                print(f"[VALIDATION] Chain broken at step {i+1}")
                break
            
            # Update chain confidence (multiplicative)
            chain_confidence *= step_result.confidence_score
        
        return {
            'chain_valid': chain_valid,
            'chain_confidence': chain_confidence,
            'total_steps': len(chain),
            'validated_steps': sum(1 for r in step_results if r.validated),
            'step_results': step_results,
            'weakest_link': min(step_results, key=lambda r: r.confidence_score) if step_results else None
        }


class ResponseDifferenceValidator:
    """Validates exploitation through response differences"""
    
    async def validate(self,
                      target: str,
                      exploitation_result: Dict,
                      baseline: str) -> Optional[ValidationEvidence]:
        """Validate based on response differences"""
        
        exploited_response = exploitation_result.get('response', '')
        
        if not exploited_response or not baseline:
            return None
        
        # Calculate similarity
        similarity = difflib.SequenceMatcher(None, baseline, exploited_response).ratio()
        
        # Significant difference indicates potential vulnerability
        if similarity < 0.9:  # More than 10% different
            
            # Analyze differences
            differences = self._analyze_differences(baseline, exploited_response)
            
            # Determine strength based on difference characteristics
            strength = self._determine_strength(differences)
            
            return ValidationEvidence(
                evidence_type=EvidenceType.RESPONSE_DIFFERENCE,
                strength=strength,
                data={
                    'similarity': similarity,
                    'differences': differences,
                    'baseline_length': len(baseline),
                    'exploited_length': len(exploited_response)
                },
                timestamp=datetime.now(),
                confidence=1 - similarity,
                reproducible=True
            )
        
        return None
    
    def _analyze_differences(self, baseline: str, exploited: str) -> Dict:
        """Analyze specific differences between responses"""
        
        differences = {
            'added_content': [],
            'removed_content': [],
            'modified_patterns': []
        }
        
        # Find added/removed lines
        baseline_lines = baseline.split('\n')
        exploited_lines = exploited.split('\n')
        
        differ = difflib.unified_diff(baseline_lines, exploited_lines)
        
        for line in differ:
            if line.startswith('+') and not line.startswith('+++'):
                differences['added_content'].append(line[1:])
            elif line.startswith('-') and not line.startswith('---'):
                differences['removed_content'].append(line[1:])
        
        # Check for specific patterns
        patterns = {
            'error_messages': r'(error|exception|warning|fatal)',
            'database_content': r'(SELECT|INSERT|UPDATE|DELETE|table|column)',
            'file_content': r'(/etc/passwd|/etc/shadow|C:\\Windows)',
            'code_execution': r'(uid=|gid=|whoami|id\s)'
        }
        
        for pattern_name, pattern_regex in patterns.items():
            if re.search(pattern_regex, exploited, re.IGNORECASE):
                differences['modified_patterns'].append(pattern_name)
        
        return differences
    
    def _determine_strength(self, differences: Dict) -> ValidationStrength:
        """Determine validation strength based on differences"""
        
        # Strong indicators
        if 'database_content' in differences['modified_patterns']:
            return ValidationStrength.STRONG
        if 'code_execution' in differences['modified_patterns']:
            return ValidationStrength.CONCLUSIVE
        if 'file_content' in differences['modified_patterns']:
            return ValidationStrength.STRONG
        
        # Moderate indicators
        if len(differences['added_content']) > 5:
            return ValidationStrength.MODERATE
        if 'error_messages' in differences['modified_patterns']:
            return ValidationStrength.MODERATE
        
        # Weak indicators
        if differences['added_content'] or differences['removed_content']:
            return ValidationStrength.WEAK
        
        return ValidationStrength.MINIMAL


class TimingValidator:
    """Validates exploitation through timing analysis"""
    
    def __init__(self):
        self.timing_baselines = {}
        
    async def validate(self,
                      target: str,
                      vulnerability_type: str,
                      exploitation_result: Dict) -> Optional[ValidationEvidence]:
        """Validate based on timing differences"""
        
        if vulnerability_type not in ['SQLI', 'TIME_BASED', 'BLIND']:
            return None
        
        timing_data = exploitation_result.get('timing', {})
        
        if not timing_data:
            return None
        
        # Get baseline timing
        baseline_timing = await self._get_baseline_timing(target)
        
        # Analyze timing anomalies
        anomaly_detected, confidence = self._detect_timing_anomaly(
            baseline_timing,
            timing_data
        )
        
        if anomaly_detected:
            return ValidationEvidence(
                evidence_type=EvidenceType.TIME_BASED,
                strength=ValidationStrength.STRONG if confidence > 0.8 else ValidationStrength.MODERATE,
                data={
                    'baseline_ms': baseline_timing,
                    'exploit_ms': timing_data.get('response_time', 0),
                    'delay_injected': timing_data.get('delay_injected', 0),
                    'deviation': abs(timing_data.get('response_time', 0) - baseline_timing)
                },
                timestamp=datetime.now(),
                confidence=confidence,
                reproducible=timing_data.get('consistent', False)
            )
        
        return None
    
    async def _get_baseline_timing(self, target: str) -> float:
        """Get baseline response timing"""
        
        if target in self.timing_baselines:
            return self.timing_baselines[target]
        
        # Simulate baseline timing measurement
        # In reality, would make multiple requests and calculate average
        baseline = np.random.uniform(100, 500)  # milliseconds
        self.timing_baselines[target] = baseline
        
        return baseline
    
    def _detect_timing_anomaly(self,
                              baseline: float,
                              timing_data: Dict) -> Tuple[bool, float]:
        """Detect timing anomalies"""
        
        exploit_time = timing_data.get('response_time', baseline)
        delay_injected = timing_data.get('delay_injected', 0)
        
        # Calculate expected time with delay
        expected_time = baseline + delay_injected
        
        # Check if actual time matches expected (within threshold)
        deviation = abs(exploit_time - expected_time)
        relative_deviation = deviation / baseline if baseline > 0 else 0
        
        # Anomaly if deviation is small (timing attack worked)
        if delay_injected > 0:
            if relative_deviation < 0.3:  # Within 30% of expected
                confidence = 1 - relative_deviation
                return True, confidence
        
        # Or if response is significantly slower without injection
        elif exploit_time > baseline * 2:
            confidence = min(1.0, (exploit_time / baseline - 1) / 3)
            return True, confidence
        
        return False, 0.0


class BehaviorValidator:
    """Validates exploitation through behavioral changes"""
    
    async def validate(self,
                      target: str,
                      vulnerability_type: str,
                      exploitation_result: Dict) -> Optional[ValidationEvidence]:
        """Validate based on behavioral changes"""
        
        behavioral_changes = []
        
        # Check for authentication bypass
        if exploitation_result.get('authenticated', False):
            behavioral_changes.append('authentication_bypass')
        
        # Check for privilege escalation
        if exploitation_result.get('privileges_changed', False):
            behavioral_changes.append('privilege_escalation')
        
        # Check for data access
        if exploitation_result.get('data_accessed', False):
            behavioral_changes.append('unauthorized_data_access')
        
        # Check for state changes
        if exploitation_result.get('state_modified', False):
            behavioral_changes.append('state_modification')
        
        if behavioral_changes:
            strength = self._determine_behavior_strength(behavioral_changes)
            
            return ValidationEvidence(
                evidence_type=EvidenceType.BEHAVIORAL_CHANGE,
                strength=strength,
                data={
                    'changes_detected': behavioral_changes,
                    'original_state': exploitation_result.get('original_state', {}),
                    'modified_state': exploitation_result.get('modified_state', {})
                },
                timestamp=datetime.now(),
                confidence=len(behavioral_changes) / 4,  # Normalized by max possible
                reproducible=exploitation_result.get('reproducible', True)
            )
        
        return None
    
    def _determine_behavior_strength(self, changes: List[str]) -> ValidationStrength:
        """Determine strength based on behavioral changes"""
        
        if 'authentication_bypass' in changes:
            return ValidationStrength.CONCLUSIVE
        if 'privilege_escalation' in changes:
            return ValidationStrength.STRONG
        if 'unauthorized_data_access' in changes:
            return ValidationStrength.STRONG
        if 'state_modification' in changes:
            return ValidationStrength.MODERATE
        
        return ValidationStrength.WEAK


class EvidenceCorrelator:
    """Correlates multiple evidence sources"""
    
    def correlate(self, evidence: List[ValidationEvidence]) -> Dict:
        """Correlate evidence from multiple sources"""
        
        if not evidence:
            return {'correlation_strength': 0, 'correlated_evidence': []}
        
        correlation_matrix = self._build_correlation_matrix(evidence)
        
        # Find strongly correlated evidence
        correlated_pairs = []
        for i in range(len(evidence)):
            for j in range(i + 1, len(evidence)):
                if correlation_matrix[i][j] > 0.7:
                    correlated_pairs.append((i, j, correlation_matrix[i][j]))
        
        # Calculate overall correlation strength
        if correlated_pairs:
            avg_correlation = np.mean([score for _, _, score in correlated_pairs])
        else:
            avg_correlation = 0
        
        return {
            'correlation_strength': avg_correlation,
            'correlated_evidence': correlated_pairs,
            'evidence_diversity': len(set(e.evidence_type for e in evidence)) / len(EvidenceType),
            'temporal_consistency': self._check_temporal_consistency(evidence)
        }
    
    def _build_correlation_matrix(self, evidence: List[ValidationEvidence]) -> np.ndarray:
        """Build correlation matrix for evidence"""
        
        n = len(evidence)
        matrix = np.zeros((n, n))
        
        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i][j] = 1.0
                else:
                    matrix[i][j] = self._calculate_correlation(evidence[i], evidence[j])
        
        return matrix
    
    def _calculate_correlation(self, e1: ValidationEvidence, e2: ValidationEvidence) -> float:
        """Calculate correlation between two pieces of evidence"""
        
        correlation = 0.0
        
        # Same evidence type increases correlation
        if e1.evidence_type == e2.evidence_type:
            correlation += 0.3
        
        # Similar confidence increases correlation
        conf_diff = abs(e1.confidence - e2.confidence)
        correlation += (1 - conf_diff) * 0.3
        
        # Temporal proximity increases correlation
        time_diff = abs((e1.timestamp - e2.timestamp).total_seconds())
        if time_diff < 10:
            correlation += 0.2
        
        # Both reproducible increases correlation
        if e1.reproducible and e2.reproducible:
            correlation += 0.2
        
        return min(1.0, correlation)
    
    def _check_temporal_consistency(self, evidence: List[ValidationEvidence]) -> float:
        """Check temporal consistency of evidence"""
        
        if len(evidence) < 2:
            return 1.0
        
        timestamps = [e.timestamp for e in evidence]
        time_diffs = [
            (timestamps[i+1] - timestamps[i]).total_seconds() 
            for i in range(len(timestamps)-1)
        ]
        
        # Check if evidence was collected in reasonable timeframe
        if max(time_diffs) < 60:  # All within 1 minute
            return 1.0
        elif max(time_diffs) < 300:  # All within 5 minutes
            return 0.8
        else:
            return 0.5


class FalsePositiveDetector:
    """Detects false positive indicators"""
    
    def __init__(self):
        self.false_positive_patterns = [
            {'pattern': r'rate limit', 'indicator': 'rate_limiting'},
            {'pattern': r'maintenance mode', 'indicator': 'maintenance'},
            {'pattern': r'honeypot', 'indicator': 'honeypot'},
            {'pattern': r'blocked by WAF', 'indicator': 'waf_block'},
            {'pattern': r'403 Forbidden', 'indicator': 'access_denied'},
            {'pattern': r'service unavailable', 'indicator': 'service_down'}
        ]
        
    def detect(self, 
              evidence: List[ValidationEvidence],
              exploitation_result: Dict) -> List[str]:
        """Detect false positive indicators"""
        
        indicators = []
        
        # Check evidence for false positive patterns
        for e in evidence:
            # Check for generic errors
            if e.evidence_type == EvidenceType.ERROR_MESSAGE:
                if self._is_generic_error(e.data):
                    indicators.append('generic_error_response')
            
            # Check for WAF/protection responses
            response_text = str(e.data.get('response', ''))
            for fp_pattern in self.false_positive_patterns:
                if re.search(fp_pattern['pattern'], response_text, re.IGNORECASE):
                    indicators.append(fp_pattern['indicator'])
        
        # Check for inconsistent results
        if self._check_inconsistency(evidence):
            indicators.append('inconsistent_results')
        
        # Check for honeypot characteristics
        if self._detect_honeypot(exploitation_result):
            indicators.append('potential_honeypot')
        
        return list(set(indicators))  # Remove duplicates
    
    def _is_generic_error(self, data: Dict) -> bool:
        """Check if error is generic (not vulnerability-specific)"""
        
        generic_errors = [
            '404 not found',
            '500 internal server error',
            'an error occurred',
            'something went wrong',
            'please try again later'
        ]
        
        error_text = str(data.get('error', '')).lower()
        
        return any(generic in error_text for generic in generic_errors)
    
    def _check_inconsistency(self, evidence: List[ValidationEvidence]) -> bool:
        """Check for inconsistent evidence"""
        
        if len(evidence) < 2:
            return False
        
        # Check if evidence conflicts
        confidences = [e.confidence for e in evidence]
        
        # High variance in confidence indicates inconsistency
        if np.std(confidences) > 0.3:
            return True
        
        # Check reproducibility inconsistency
        reproducible_count = sum(1 for e in evidence if e.reproducible)
        if 0 < reproducible_count < len(evidence):
            return True
        
        return False
    
    def _detect_honeypot(self, exploitation_result: Dict) -> bool:
        """Detect honeypot characteristics"""
        
        honeypot_indicators = [
            exploitation_result.get('response_time', 1000) < 10,  # Too fast
            'honey' in str(exploitation_result).lower(),
            exploitation_result.get('success_rate', 0) == 1.0,  # Too easy
            len(exploitation_result.get('vulnerabilities', [])) > 10  # Too many vulns
        ]
        
        return sum(honeypot_indicators) >= 2


class ImpactAnalyzer:
    """Analyzes real-world impact of vulnerabilities"""
    
    def analyze(self,
               vulnerability_type: str,
               exploitation_result: Dict,
               evidence: List[ValidationEvidence]) -> Dict:
        """Analyze real-world impact"""
        
        impact = {
            'severity': self._calculate_severity(vulnerability_type, evidence),
            'business_impact': self._assess_business_impact(vulnerability_type, exploitation_result),
            'data_exposure': self._assess_data_exposure(evidence),
            'system_compromise': self._assess_system_compromise(exploitation_result),
            'lateral_movement': self._assess_lateral_movement(exploitation_result),
            'persistence': self._assess_persistence(exploitation_result),
            'cvss_score': self._calculate_cvss(vulnerability_type, evidence)
        }
        
        # Calculate overall impact score
        impact['overall_score'] = self._calculate_overall_impact(impact)
        
        return impact
    
    def _calculate_severity(self, 
                          vulnerability_type: str,
                          evidence: List[ValidationEvidence]) -> str:
        """Calculate vulnerability severity"""
        
        # Base severity by type
        severity_map = {
            'RCE': 'Critical',
            'SQLI': 'High',
            'XXE': 'High',
            'SSRF': 'High',
            'XSS': 'Medium',
            'CSRF': 'Medium',
            'IDOR': 'Medium',
            'INFO': 'Low'
        }
        
        base_severity = severity_map.get(vulnerability_type, 'Medium')
        
        # Adjust based on evidence strength
        if evidence:
            avg_strength = np.mean([e.strength.value for e in evidence])
            if avg_strength >= 0.8 and base_severity == 'High':
                return 'Critical'
            elif avg_strength <= 0.4 and base_severity == 'Medium':
                return 'Low'
        
        return base_severity
    
    def _assess_business_impact(self, vulnerability_type: str, exploitation_result: Dict) -> Dict:
        """Assess business impact"""
        
        return {
            'confidentiality': 'High' if vulnerability_type in ['SQLI', 'IDOR', 'XXE'] else 'Medium',
            'integrity': 'High' if vulnerability_type in ['RCE', 'SQLI', 'XSS'] else 'Low',
            'availability': 'High' if vulnerability_type in ['RCE', 'DOS'] else 'Low',
            'financial': self._estimate_financial_impact(vulnerability_type),
            'reputation': self._estimate_reputation_impact(vulnerability_type),
            'compliance': self._check_compliance_impact(vulnerability_type)
        }
    
    def _assess_data_exposure(self, evidence: List[ValidationEvidence]) -> Dict:
        """Assess data exposure risk"""
        
        exposed_data = {
            'sensitive_data': False,
            'personal_data': False,
            'credentials': False,
            'business_data': False
        }
        
        for e in evidence:
            if e.evidence_type == EvidenceType.DATA_EXTRACTION:
                data = str(e.data)
                if re.search(r'(password|passwd|pwd)', data, re.IGNORECASE):
                    exposed_data['credentials'] = True
                if re.search(r'(email|phone|address|ssn)', data, re.IGNORECASE):
                    exposed_data['personal_data'] = True
                if re.search(r'(revenue|profit|financial)', data, re.IGNORECASE):
                    exposed_data['business_data'] = True
        
        exposed_data['sensitive_data'] = any(exposed_data.values())
        
        return exposed_data
    
    def _assess_system_compromise(self, exploitation_result: Dict) -> str:
        """Assess level of system compromise"""
        
        if exploitation_result.get('root_access', False):
            return 'Complete'
        elif exploitation_result.get('user_access', False):
            return 'Partial'
        elif exploitation_result.get('authenticated', False):
            return 'Limited'
        else:
            return 'None'
    
    def _assess_lateral_movement(self, exploitation_result: Dict) -> bool:
        """Assess lateral movement possibility"""
        
        return (
            exploitation_result.get('network_access', False) or
            exploitation_result.get('pivot_possible', False) or
            exploitation_result.get('internal_access', False)
        )
    
    def _assess_persistence(self, exploitation_result: Dict) -> bool:
        """Assess persistence possibility"""
        
        return (
            exploitation_result.get('backdoor_possible', False) or
            exploitation_result.get('persistent_access', False) or
            exploitation_result.get('webshell_uploaded', False)
        )
    
    def _calculate_cvss(self, vulnerability_type: str, evidence: List[ValidationEvidence]) -> float:
        """Calculate CVSS score"""
        
        # Simplified CVSS calculation
        base_scores = {
            'RCE': 9.8,
            'SQLI': 8.5,
            'XXE': 8.2,
            'SSRF': 7.5,
            'XSS': 6.5,
            'CSRF': 6.0,
            'IDOR': 5.5,
            'INFO': 3.0
        }
        
        score = base_scores.get(vulnerability_type, 5.0)
        
        # Adjust based on evidence
        if evidence:
            confidence_avg = np.mean([e.confidence for e in evidence])
            score *= (0.8 + 0.2 * confidence_avg)  # ±20% based on confidence
        
        return min(10.0, max(0.0, score))
    
    def _estimate_financial_impact(self, vulnerability_type: str) -> str:
        """Estimate financial impact"""
        
        if vulnerability_type in ['RCE', 'SQLI']:
            return 'Critical (>$1M)'
        elif vulnerability_type in ['XXE', 'SSRF', 'IDOR']:
            return 'High ($100K-$1M)'
        elif vulnerability_type in ['XSS', 'CSRF']:
            return 'Medium ($10K-$100K)'
        else:
            return 'Low (<$10K)'
    
    def _estimate_reputation_impact(self, vulnerability_type: str) -> str:
        """Estimate reputation impact"""
        
        if vulnerability_type in ['RCE', 'SQLI', 'IDOR']:
            return 'Severe'
        elif vulnerability_type in ['XXE', 'SSRF', 'XSS']:
            return 'Moderate'
        else:
            return 'Minor'
    
    def _check_compliance_impact(self, vulnerability_type: str) -> List[str]:
        """Check compliance impact"""
        
        impacts = []
        
        if vulnerability_type in ['SQLI', 'IDOR', 'XXE']:
            impacts.append('GDPR violation risk')
            impacts.append('PCI-DSS non-compliance')
        
        if vulnerability_type in ['RCE', 'SQLI']:
            impacts.append('SOC2 audit failure')
        
        if vulnerability_type in ['XSS', 'CSRF']:
            impacts.append('OWASP Top 10 violation')
        
        return impacts
    
    def _calculate_overall_impact(self, impact: Dict) -> float:
        """Calculate overall impact score"""
        
        severity_scores = {
            'Critical': 1.0,
            'High': 0.75,
            'Medium': 0.5,
            'Low': 0.25
        }
        
        score = severity_scores.get(impact['severity'], 0.5)
        
        # Add modifiers
        if impact['data_exposure']['sensitive_data']:
            score += 0.2
        
        if impact['system_compromise'] == 'Complete':
            score += 0.3
        elif impact['system_compromise'] == 'Partial':
            score += 0.15
        
        if impact['lateral_movement']:
            score += 0.1
        
        if impact['persistence']:
            score += 0.1
        
        return min(1.0, score)
