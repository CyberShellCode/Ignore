from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
import numpy as np
from .plugins import PluginResult

class BaseScorer(ABC):
    """Base class for evidence scoring strategies"""
    name: str = "base"

    @abstractmethod
    def score(self, result: PluginResult) -> float:
        """Calculate evidence score from plugin result (0.0 to 1.0)"""
        pass

    def calculate_severity_weight(self, severity: str) -> float:
        """Weight based on vulnerability severity"""
        weights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.2,
            'Info': 0.1,
            'None': 0.0
        }
        return weights.get(severity, 0.0)


class DefaultScorer(BaseScorer):
    """Default scoring strategy - balanced approach"""
    name = "default"

    def score(self, result: PluginResult) -> float:
        """Simple scoring based on success and evidence_score field"""
        if not result.success:
            return 0.0

        details = result.details or {}

        # First check if plugin provided its own score
        if 'evidence_score' in details:
            return max(0.0, min(1.0, float(details['evidence_score'])))

        # Otherwise calculate based on available evidence
        score = 0.5  # Base score for successful result

        # Adjust based on evidence
        if details.get('vulnerable'):
            score += 0.2

        if details.get('exploited'):
            score += 0.3

        if details.get('data_extracted') or details.get('data'):
            score += 0.2

        # Apply severity weight
        severity = details.get('severity', 'None')
        score *= self.calculate_severity_weight(severity)

        return min(score, 1.0)


class WeightedSignalScorer(BaseScorer):
    """Weighted scoring based on multiple signals"""
    name = "weighted_signal"

    def __init__(self):
        # Define signal weights for different evidence types
        self.weights = {
            'error_tokens': 0.15,
            'reflections': 0.12,
            'length_delta': 0.08,
            'time_delta': 0.10,
            'status_code': 0.05,
            'headers': 0.08,
            'data_access': 0.20,
            'code_execution': 0.25,
            'auth_bypass': 0.22,
            'privilege_escalation': 0.20,
            'chain_exploit': 0.15
        }

    def score(self, result: PluginResult) -> float:
        """Calculate weighted score from multiple signals"""
        if not result.success:
            return 0.0

        details = result.details or {}

        # Check for explicit evidence score
        if 'evidence_score' in details:
            base_score = float(details['evidence_score'])
        else:
            base_score = 0.0

        # Calculate signal-based score
        signal_score = 0.0

        # Error tokens (SQL errors, etc.)
        if details.get('error_tokens'):
            signal_score += self.weights['error_tokens'] * min(len(details['error_tokens']) / 3, 1.0)

        # Reflections (XSS)
        if details.get('reflections'):
            signal_score += self.weights['reflections'] * min(len(details['reflections']) / 2, 1.0)

        # Response differences
        if details.get('length_delta'):
            delta = abs(float(details['length_delta']))
            if delta > 100:
                signal_score += self.weights['length_delta']

        # Time-based detection
        if details.get('time_delta'):
            time_delta = float(details.get('time_delta', 0))
            if time_delta > 5000:  # 5 seconds
                signal_score += self.weights['time_delta']

        # Headers
        if details.get('headers'):
            interesting_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-Debug']
            found = sum(1 for h in interesting_headers if h in details['headers'])
            signal_score += self.weights['headers'] * (found / len(interesting_headers))

        # High-value findings
        if details.get('data') or details.get('data_accessed'):
            signal_score += self.weights['data_access']

        if details.get('commands_executed') or details.get('rce'):
            signal_score += self.weights['code_execution']

        if details.get('auth_bypassed') or details.get('admin'):
            signal_score += self.weights['auth_bypass']

        if details.get('chain') or details.get('chained'):
            signal_score += self.weights['chain_exploit']

        # Severity multiplier
        severity = details.get('severity', 'None')
        severity_weight = self.calculate_severity_weight(severity)

        # Combine base and signal scores
        final_score = max(base_score, signal_score) * severity_weight

        # Boost for verified/reproducible findings
        if details.get('verified') or details.get('reproducible'):
            final_score *= 1.2

        return min(final_score, 1.0)


class HighConfidenceScorer(BaseScorer):
    """Conservative scoring - requires strong evidence"""
    name = "high_confidence"

    def score(self, result: PluginResult) -> float:
        """Only high scores for verified, high-impact findings"""
        if not result.success:
            return 0.0

        details = result.details or {}

        # Start with explicit score if provided
        base_score = float(details.get('evidence_score', 0.0))

        # Apply strict criteria
        criteria_met = 0
        total_criteria = 5

        # Must have severity of High or Critical
        severity = details.get('severity', 'None')
        if severity in ['Critical', 'High']:
            criteria_met += 1
        else:
            base_score *= 0.3

        # Must have actual evidence
        if details.get('evidence') or details.get('data'):
            criteria_met += 1

        # Must be reproducible
        if details.get('reproducible') or details.get('verified'):
            criteria_met += 1

        # Must have impact demonstration
        if details.get('impact_proof') or details.get('impact_demonstrated'):
            criteria_met += 1

        # Must have high CVSS score
        cvss = details.get('cvss_score', 0)
        if cvss >= 7.0:
            criteria_met += 1

        # Calculate confidence factor
        confidence_factor = criteria_met / total_criteria

        # Final score
        final_score = base_score * confidence_factor

        # Only give high scores to findings that meet most criteria
        if criteria_met < 3:
            final_score = min(final_score, 0.5)

        return final_score


class BountyValueScorer(BaseScorer):
    """Score based on estimated bug bounty value"""
    name = "bounty_value"

    def __init__(self):
        # Estimated bounty values by vulnerability type
        self.bounty_values = {
            'rce': 10000,
            'sqli': 5000,
            'auth_bypass': 3000,
            'ssrf': 2000,
            'xxe': 2000,
            'ssti': 2000,
            'idor': 1500,
            'xss_stored': 1500,
            'xss_reflected': 500,
            'csrf': 500,
            'open_redirect': 250,
            'information_disclosure': 100
        }

        self.max_bounty = 10000

    def score(self, result: PluginResult) -> float:
        """Score based on potential bounty value"""
        if not result.success:
            return 0.0

        details = result.details or {}

        # Identify vulnerability type
        vuln_type = self._identify_vuln_type(result.name, details)

        # Get base bounty value
        base_value = self.bounty_values.get(vuln_type, 100)

        # Apply multipliers
        multipliers = 1.0

        # Data exposure multiplier
        if details.get('data') or details.get('pii_exposed'):
            multipliers *= 1.5

        # Admin access multiplier
        if details.get('admin') or details.get('admin_access'):
            multipliers *= 2.0

        # Chained exploit multiplier
        if details.get('chain') or details.get('impact_multiplier'):
            multipliers *= float(details.get('impact_multiplier', 1.5))

        # Calculate final value
        estimated_value = base_value * multipliers

        # Convert to 0-1 score
        score = min(estimated_value / self.max_bounty, 1.0)

        # Ensure minimum score for valid findings
        if score < 0.1 and result.success:
            score = 0.1

        return score

    def _identify_vuln_type(self, plugin_name: str, details: Dict) -> str:
        """Identify vulnerability type from plugin name and details"""
        plugin_lower = plugin_name.lower()

        if 'rce' in plugin_lower or details.get('commands_executed'):
            return 'rce'
        elif 'sqli' in plugin_lower or details.get('database'):
            return 'sqli'
        elif 'auth' in plugin_lower and 'bypass' in plugin_lower:
            return 'auth_bypass'
        elif 'ssrf' in plugin_lower:
            return 'ssrf'
        elif 'xxe' in plugin_lower:
            return 'xxe'
        elif 'ssti' in plugin_lower:
            return 'ssti'
        elif 'idor' in plugin_lower:
            return 'idor'
        elif 'xss' in plugin_lower:
            if details.get('stored') or 'stored' in plugin_lower:
                return 'xss_stored'
            return 'xss_reflected'
        elif 'csrf' in plugin_lower:
            return 'csrf'

        return 'unknown'

    def get_estimated_bounty(self, result: PluginResult) -> int:
        """Get estimated bounty value in dollars"""
        score = self.score(result)
        return int(score * self.max_bounty)


class CombinedScorer(BaseScorer):
    """Combines multiple scoring strategies"""
    name = "combined"

    def __init__(self):
        self.scorers = [
            WeightedSignalScorer(),
            HighConfidenceScorer(),
            BountyValueScorer()
        ]
        self.weights = [0.4, 0.3, 0.3]  # Weights for each scorer

    def score(self, result: PluginResult) -> float:
        """Calculate weighted average of multiple scorers"""
        if not result.success:
            return 0.0

        scores = []
        for scorer, weight in zip(self.scorers, self.weights):
            score = scorer.score(result)
            scores.append(score * weight)

        return sum(scores)


# Scorer registry
SCORER_REGISTRY: Dict[str, BaseScorer] = {
    'default': DefaultScorer(),
    'weighted_signal': WeightedSignalScorer(),
    'high_confidence': HighConfidenceScorer(),
    'bounty_value': BountyValueScorer(),
    'combined': CombinedScorer()
}

def get_scorer(name: str) -> BaseScorer:
    """Get scorer by name"""
    return SCORER_REGISTRY.get(name, SCORER_REGISTRY['default'])

def register_scorer(name: str, scorer: BaseScorer):
    """Register a custom scorer"""
    SCORER_REGISTRY[name] = scorer


class EvidenceAggregator:
    """Aggregates evidence scores over time for ODS decisions"""

    def __init__(self, window_size: int = 10, ema_alpha: float = 0.3):
        self.scores: List[float] = []
        self.window_size = window_size
        self.ema_alpha = ema_alpha
        self._ema = 0.0
        self._metadata: List[Dict[str, Any]] = []

    def add(self, score: float, metadata: Optional[Dict[str, Any]] = None):
        """Add a new evidence score with optional metadata"""
        self.scores.append(score)

        if metadata:
            self._metadata.append(metadata)

        # Update EMA
        if len(self.scores) == 1:
            self._ema = score
        else:
            self._ema = self.ema_alpha * score + (1 - self.ema_alpha) * self._ema

        # Keep window size
        if len(self.scores) > self.window_size * 2:
            self.scores = self.scores[-self.window_size:]
            self._metadata = self._metadata[-self.window_size:]

    def get_ema(self) -> float:
        """Get exponential moving average of scores"""
        return self._ema

    def get_sma(self) -> float:
        """Get simple moving average of recent scores"""
        if not self.scores:
            return 0.0

        recent = self.scores[-self.window_size:]
        return sum(recent) / len(recent)

    def get_max(self) -> float:
        """Get maximum score seen"""
        return max(self.scores) if self.scores else 0.0

    def get_min(self) -> float:
        """Get minimum score seen"""
        return min(self.scores) if self.scores else 0.0

    def get_trend(self) -> str:
        """Get trend direction (improving/declining/stable)"""
        if len(self.scores) < 3:
            return 'stable'

        recent = self.scores[-3:]
        older = self.scores[-6:-3] if len(self.scores) >= 6 else self.scores[:-3]

        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older) if older else recent_avg

        diff = recent_avg - older_avg

        if diff > 0.1:
            return 'improving'
        elif diff < -0.1:
            return 'declining'
        else:
            return 'stable'

    def get_variance(self) -> float:
        """Get variance of recent scores"""
        if len(self.scores) < 2:
            return 0.0

        recent = self.scores[-self.window_size:]
        mean = sum(recent) / len(recent)
        variance = sum((x - mean) ** 2 for x in recent) / len(recent)
        return variance

    def should_pivot(self, patience: int = 3, min_improvement: float = 0.05) -> bool:
        """Determine if ODS should pivot strategy"""
        if len(self.scores) < patience:
            return False

        # Check if scores are stagnating
        recent = self.scores[-patience:]
        variance = max(recent) - min(recent)

        # Pivot if variance is too low (stagnating)
        if variance < min_improvement:
            return True

        # Pivot if trend is declining
        if self.get_trend() == 'declining':
            return True

        # Pivot if we've been stuck below a threshold
        if self.get_sma() < 0.3 and len(self.scores) > patience * 2:
            return True

        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        if not self.scores:
            return {
                'count': 0,
                'mean': 0.0,
                'max': 0.0,
                'min': 0.0,
                'ema': 0.0,
                'trend': 'stable'
            }

        return {
            'count': len(self.scores),
            'mean': sum(self.scores) / len(self.scores),
            'max': max(self.scores),
            'min': min(self.scores),
            'ema': self._ema,
            'sma': self.get_sma(),
            'variance': self.get_variance(),
            'trend': self.get_trend(),
            'should_pivot': self.should_pivot()
        }

    def get_high_scoring_plugins(self, threshold: float = 0.7) -> List[str]:
        """Get plugins that achieved high scores"""
        high_scoring = []

        for i, score in enumerate(self.scores):
            if score >= threshold and i < len(self._metadata):
                plugin_name = self._metadata[i].get('plugin_name')
                if plugin_name and plugin_name not in high_scoring:
                    high_scoring.append(plugin_name)

        return high_scoring