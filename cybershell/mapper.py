import asyncio
import json
import re
import time
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin
import hashlib
from collections import defaultdict
import networkx as nx
from mitmproxy import http

# HTTP interception
try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

# Browser automation
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.proxy import Proxy, ProxyType
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

@dataclass
class Endpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str = "GET"
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    content_type: str = ""
    auth_required: bool = False
    user_role: str = "anonymous"
    forms: List[Dict] = field(default_factory=list)
    javascript_events: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    potential_vulns: List[str] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    discovered_at: float = field(default_factory=time.time)

@dataclass
class WebAppMap:
    """Complete map of the web application"""
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    technologies: Set[str] = field(default_factory=set)
    authentication_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    file_upload_endpoints: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    vulnerability_map: Dict[str, List[Endpoint]] = field(default_factory=dict)

class AdaptiveLearningMapper:
    """
    Advanced web application mapper with HTTP interception and analysis
    """
    def __init__(
        self,
        target: str = "",
        proxy_port: int = 8080,
        alpha: float | None = None,      # legacy compat
        model_path: str | None = None,   # legacy compat
        **kwargs,
    ):
        self.target = target
        self.proxy_port = proxy_port
        self.webapp_map = WebAppMap()
        self.session_tokens = {}
        self.discovered_urls = set()
        self.request_history = []
        self.proxy_master = None
        
        # Vulnerability patterns
        self.vuln_patterns = self._init_vuln_patterns()
        
    def _init_vuln_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize vulnerability detection patterns"""
        return {
            'sqli': [
                {'param_pattern': r'(id|user|account|number|order)', 'weight': 0.7},
                {'param_pattern': r'(select|search|filter|sort)', 'weight': 0.6},
                {'endpoint_pattern': r'/api/.*/(users|products|orders)', 'weight': 0.8}
            ],
            'xss': [
                {'param_pattern': r'(q|query|search|message|comment|name)', 'weight': 0.7},
                {'param_pattern': r'(input|text|data|content)', 'weight': 0.5},
                {'content_type': 'text/html', 'weight': 0.8}
            ],
            'idor': [
                {'param_pattern': r'(id|uid|userid|doc|file)=\d+', 'weight': 0.9},
                {'endpoint_pattern': r'/api/.*/\d+', 'weight': 0.8},
                {'endpoint_pattern': r'/(profile|account|user)/\d+', 'weight': 0.9}
            ],
            'lfi': [
                {'param_pattern': r'(file|path|template|page|include)', 'weight': 0.8},
                {'param_pattern': r'(load|read|download)', 'weight': 0.7}
            ],
            'rce': [
                {'param_pattern': r'(cmd|exec|command|run|ping)', 'weight': 0.9},
                {'endpoint_pattern': r'/(admin|debug|test)', 'weight': 0.6}
            ],
            'xxe': [
                {'content_type': 'application/xml', 'weight': 0.9},
                {'content_type': 'text/xml', 'weight': 0.9},
                {'param_pattern': r'(xml|data|import)', 'weight': 0.5}
            ],
            'ssrf': [
                {'param_pattern': r'(url|uri|target|host|proxy)', 'weight': 0.8},
                {'param_pattern': r'(callback|webhook|fetch)', 'weight': 0.7}
            ],
            'upload': [
                {'endpoint_pattern': r'/(upload|import|file)', 'weight': 0.9},
                {'param_pattern': r'(file|upload|attachment)', 'weight': 0.8}
            ]
        }
    
    async def start_mapping(self, duration: int = 300, use_browser: bool = True) -> WebAppMap:
        """
        Start the mapping process
        
        Args:
            duration: Mapping duration in seconds
            use_browser: Whether to use browser automation for JS rendering
        """
        tasks = []
        
        # Start HTTP proxy
        if MITMPROXY_AVAILABLE:
            tasks.append(self._start_proxy())
        
        # Start browser-based crawling
        if use_browser and PLAYWRIGHT_AVAILABLE:
            tasks.append(self._browser_crawl_playwright())
        elif use_browser and SELENIUM_AVAILABLE:
            tasks.append(self._browser_crawl_selenium())
        
        # Start API discovery
        tasks.append(self._discover_apis())
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)
        
        # Analyze collected data
        self._analyze_relationships()
        self._categorize_endpoints()
        self._identify_attack_surface()
        
        return self.webapp_map
    
    async def _start_proxy(self):
        """Start mitmproxy for HTTP interception"""
        if not MITMPROXY_AVAILABLE:
            print("[!] mitmproxy not available, skipping HTTP interception")
            return
        
        class InterceptAddon:
            def __init__(self, mapper):
                self.mapper = mapper
            
            def request(self, flow: http.HTTPFlow):
                self.mapper._process_request(flow)
            
            def response(self, flow: http.HTTPFlow):
                self.mapper._process_response(flow)
        
        opts = options.Options(listen_port=self.proxy_port)
        self.proxy_master = DumpMaster(opts)
        self.proxy_master.addons.add(InterceptAddon(self))
        
        try:
            await self.proxy_master.run()
        except KeyboardInterrupt:
            self.proxy_master.shutdown()
    
    def _process_request(self, flow: http.HTTPFlow):
        """Process intercepted HTTP request"""
        request = flow.request
        url = request.pretty_url
        
        # Create endpoint entry
        endpoint = Endpoint(
            url=url,
            method=request.method,
            headers=dict(request.headers),
            cookies=dict(request.cookies)
        )
        
        # Extract parameters
        if request.method == "GET":
            parsed = urlparse(url)
            endpoint.parameters = parse_qs(parsed.query)
        elif request.method == "POST":
            if request.content:
                try:
                    # Try to parse as form data
                    endpoint.parameters = parse_qs(request.content.decode())
                except:
                    # Try as JSON
                    try:
                        endpoint.parameters = json.loads(request.content)
                    except:
                        pass
        
        # Detect potential vulnerabilities
        endpoint.potential_vulns = self._detect_vulnerabilities(endpoint)
        
        # Store endpoint
        endpoint_key = f"{request.method}:{urlparse(url).path}"
        self.webapp_map.endpoints[endpoint_key] = endpoint
        self.discovered_urls.add(url)
    
    def _process_response(self, flow: http.HTTPFlow):
        """Process intercepted HTTP response"""
        request = flow.request
        response = flow.response
        
        endpoint_key = f"{request.method}:{urlparse(request.pretty_url).path}"
        
        if endpoint_key in self.webapp_map.endpoints:
            endpoint = self.webapp_map.endpoints[endpoint_key]
            endpoint.response_code = response.status_code
            endpoint.content_type = response.headers.get("Content-Type", "")
            
            # Check for authentication
            if response.status_code == 401 or response.status_code == 403:
                endpoint.auth_required = True
            
            # Extract forms from HTML responses
            if "text/html" in endpoint.content_type:
                endpoint.forms = self._extract_forms(response.content)
            
            # Extract API calls from JavaScript
            if "javascript" in endpoint.content_type:
                endpoint.api_calls = self._extract_api_calls(response.content)
    
    async def _browser_crawl_playwright(self):
        """Use Playwright for JavaScript-aware crawling"""
        if not PLAYWRIGHT_AVAILABLE:
            return
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": f"http://localhost:{self.proxy_port}"} if MITMPROXY_AVAILABLE else None
            )
            
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            
            # Set up request interception
            await page.route("**/*", self._playwright_intercept)
            
            # Start crawling
            await self._crawl_page(page, self.target)
            
            await browser.close()
    
    async def _playwright_intercept(self, route):
        """Intercept requests in Playwright"""
        request = route.request
        
        # Log the request
        self.discovered_urls.add(request.url)
        
        # Continue request
        await route.continue_()
    
    async def _crawl_page(self, page, url: str, depth: int = 0, max_depth: int = 3):
        """Recursively crawl pages"""
        if depth > max_depth:
            return
        
        try:
            await page.goto(url, wait_until="networkidle")
            
            # Extract all links
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href.startsWith('http'))
            """)
            
            # Extract forms
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                        name: input.name,
                        type: input.type,
                        value: input.value
                    }))
                }))
            """)
            
            # Extract AJAX endpoints
            ajax_endpoints = await page.evaluate("""
                () => {
                    const endpoints = [];
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach(script => {
                        const matches = script.textContent.match(/['"](\/api\/[^'"]+)['"]/g);
                        if (matches) endpoints.push(...matches);
                    });
                    return [...new Set(endpoints)];
                }
            """)
            
            # Store discovered data
            for form in forms:
                self._process_form(url, form)
            
            for endpoint in ajax_endpoints:
                self.webapp_map.api_endpoints.append(endpoint)
            
            # Crawl discovered links
            for link in links:
                if link not in self.discovered_urls and self._is_same_origin(link, self.target):
                    await self._crawl_page(page, link, depth + 1, max_depth)
                    
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")
    
    def _detect_vulnerabilities(self, endpoint: Endpoint) -> List[str]:
        """Detect potential vulnerabilities in an endpoint"""
        potential_vulns = []
        
        for vuln_type, patterns in self.vuln_patterns.items():
            total_weight = 0.0
            
            for pattern in patterns:
                # Check parameter patterns
                if 'param_pattern' in pattern:
                    param_regex = re.compile(pattern['param_pattern'], re.I)
                    for param_name in endpoint.parameters.keys():
                        if param_regex.search(param_name):
                            total_weight += pattern['weight']
                
                # Check endpoint patterns
                if 'endpoint_pattern' in pattern:
                    endpoint_regex = re.compile(pattern['endpoint_pattern'], re.I)
                    if endpoint_regex.search(endpoint.url):
                        total_weight += pattern['weight']
                
                # Check content type
                if 'content_type' in pattern:
                    if pattern['content_type'] in endpoint.content_type:
                        total_weight += pattern['weight']
            
            # If weight exceeds threshold, mark as potential vulnerability
            if total_weight >= 0.6:
                potential_vulns.append(vuln_type)
                
                # Add to vulnerability map
                if vuln_type not in self.webapp_map.vulnerability_map:
                    self.webapp_map.vulnerability_map[vuln_type] = []
                self.webapp_map.vulnerability_map[vuln_type].append(endpoint)
        
        return potential_vulns
    
    def _analyze_relationships(self):
        """Analyze relationships between endpoints"""
        # Build graph of endpoint relationships
        for endpoint_key, endpoint in self.webapp_map.endpoints.items():
            self.webapp_map.graph.add_node(endpoint_key, endpoint=endpoint)
            
            # Find relationships based on parameters
            for other_key, other_endpoint in self.webapp_map.endpoints.items():
                if endpoint_key != other_key:
                    # Check if endpoints share parameters
                    shared_params = set(endpoint.parameters.keys()) & set(other_endpoint.parameters.keys())
                    if shared_params:
                        self.webapp_map.graph.add_edge(
                            endpoint_key, 
                            other_key,
                            shared_params=list(shared_params)
                        )
                    
                    # Check if one endpoint references another
                    if other_endpoint.url in str(endpoint.parameters.values()):
                        self.webapp_map.graph.add_edge(
                            endpoint_key,
                            other_key,
                            relationship="references"
                        )
    
    def _categorize_endpoints(self):
        """Categorize endpoints by functionality"""
        for endpoint_key, endpoint in self.webapp_map.endpoints.items():
            url_lower = endpoint.url.lower()
            
            # Authentication endpoints
            if any(auth in url_lower for auth in ['login', 'signin', 'auth', 'oauth']):
                self.webapp_map.authentication_endpoints.append(endpoint.url)
            
            # Admin endpoints
            if any(admin in url_lower for admin in ['admin', 'manage', 'dashboard']):
                self.webapp_map.admin_endpoints.append(endpoint.url)
            
            # API endpoints
            if '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower:
                self.webapp_map.api_endpoints.append(endpoint.url)
            
            # File upload endpoints
            if any(upload in url_lower for upload in ['upload', 'import', 'file']):
                self.webapp_map.file_upload_endpoints.append(endpoint.url)
    
    def _identify_attack_surface(self):
        """Identify the attack surface and prioritize targets"""
        attack_surface = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for endpoint_key, endpoint in self.webapp_map.endpoints.items():
            priority_score = 0
            
            # High value targets
            if endpoint.url in self.webapp_map.authentication_endpoints:
                priority_score += 30
            if endpoint.url in self.webapp_map.admin_endpoints:
                priority_score += 40
            if endpoint.url in self.webapp_map.file_upload_endpoints:
                priority_score += 35
            
            # Vulnerability potential
            priority_score += len(endpoint.potential_vulns) * 20
            
            # Parameter complexity
            priority_score += len(endpoint.parameters) * 5
            
            # Categorize by priority
            if priority_score >= 60:
                attack_surface['critical'].append(endpoint)
            elif priority_score >= 40:
                attack_surface['high'].append(endpoint)
            elif priority_score >= 20:
                attack_surface['medium'].append(endpoint)
            else:
                attack_surface['low'].append(endpoint)
        
        return attack_surface
    
    def get_exploitation_targets(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get prioritized exploitation targets for a specific vulnerability type"""
        targets = []
        
        if vuln_type in self.webapp_map.vulnerability_map:
            for endpoint in self.webapp_map.vulnerability_map[vuln_type]:
                target = {
                    'url': endpoint.url,
                    'method': endpoint.method,
                    'parameters': endpoint.parameters,
                    'priority': 'high' if endpoint.url in self.webapp_map.admin_endpoints else 'medium',
                    'auth_required': endpoint.auth_required,
                    'additional_context': {
                        'forms': endpoint.forms,
                        'cookies': endpoint.cookies,
                        'headers': endpoint.headers
                    }
                }
                targets.append(target)
        
        # Sort by priority
        targets.sort(key=lambda x: x['priority'] == 'high', reverse=True)
        
        return targets
    
    def export_map(self, filename: str = "webapp_map.json"):
        """Export the web application map to JSON"""
        export_data = {
            'target': self.target,
            'endpoints': [
                {
                    'url': e.url,
                    'method': e.method,
                    'parameters': e.parameters,
                    'potential_vulns': e.potential_vulns,
                    'auth_required': e.auth_required
                }
                for e in self.webapp_map.endpoints.values()
            ],
            'vulnerability_map': {
                vuln: [e.url for e in endpoints]
                for vuln, endpoints in self.webapp_map.vulnerability_map.items()
            },
            'statistics': {
                'total_endpoints': len(self.webapp_map.endpoints),
                'total_parameters': sum(len(e.parameters) for e in self.webapp_map.endpoints.values()),
                'authentication_endpoints': len(self.webapp_map.authentication_endpoints),
                'admin_endpoints': len(self.webapp_map.admin_endpoints),
                'api_endpoints': len(self.webapp_map.api_endpoints)
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return export_data
    
    def _is_same_origin(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same origin"""
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        return parsed1.netloc == parsed2.netloc
    
    def _extract_forms(self, content: bytes) -> List[Dict]:
        """Extract forms from HTML content"""
        forms = []
        try:
            content_str = content.decode('utf-8', errors='ignore')
            # Simple regex-based form extraction
            form_pattern = r'<form[^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            
            for form_match in re.finditer(form_pattern, content_str, re.DOTALL | re.IGNORECASE):
                form_html = form_match.group(0)
                inputs = re.findall(input_pattern, form_html)
                if inputs:
                    forms.append({
                        'inputs': inputs,
                        'html': form_html[:500]  # Store first 500 chars
                    })
        except:
            pass
        
        return forms
    
    def _extract_api_calls(self, content: bytes) -> List[str]:
        """Extract API calls from JavaScript"""
        api_calls = []
        try:
            content_str = content.decode('utf-8', errors='ignore')
            # Look for API patterns
            patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[get|post|put|delete]\(["\']([^"\']+)["\']',
                r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content_str)
                api_calls.extend(matches)
        except:
            pass
        
        return list(set(api_calls))
    
    def _process_form(self, url: str, form: Dict):
        """Process discovered form"""
        endpoint = Endpoint(
            url=form.get('action', url),
            method=form.get('method', 'POST').upper(),
            forms=[form]
        )
        
        # Extract parameters from form inputs
        for input_field in form.get('inputs', []):
            param_name = input_field.get('name')
            if param_name:
                if param_name not in endpoint.parameters:
                    endpoint.parameters[param_name] = []
                endpoint.parameters[param_name].append(input_field.get('value', ''))
        
        # Detect potential vulnerabilities
        endpoint.potential_vulns = self._detect_vulnerabilities(endpoint)
        
        # Store endpoint
        endpoint_key = f"{endpoint.method}:{urlparse(endpoint.url).path}"
        self.webapp_map.endpoints[endpoint_key] = endpoint

# Async wrapper for synchronous code
async def map_target(target: str, duration: int = 60) -> Dict[str, Any]:
    """
    Main function to map a target web application
    """
    mapper = EnhancedWebMapper(target)
    webapp_map = await mapper.start_mapping(duration=duration, use_browser=True)
    return mapper.export_map()

# Integration with existing CyberShell
def integrate_with_orchestrator():
    """
    Integrate the enhanced mapper with CyberShell orchestrator
    """
    # This would be called from orchestrator.py
    import asyncio
    
    def enhanced_recon(target: str) -> Dict[str, Any]:
        """Enhanced reconnaissance using web mapper"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run mapping for 60 seconds
            mapping_result = loop.run_until_complete(
                map_target(target, duration=60)
            )
            
            return {
                'endpoints': mapping_result.get('endpoints', []),
                'vulnerabilities': mapping_result.get('vulnerability_map', {}),
                'statistics': mapping_result.get('statistics', {}),
                'technologies': list(mapping_result.get('technologies', set())),
                'parameters': list(set(
                    param
                    for endpoint in mapping_result.get('endpoints', [])
                    for param in endpoint.get('parameters', {}).keys()
                ))
            }
        finally:
            loop.close()
    
    return enhanced_recon
