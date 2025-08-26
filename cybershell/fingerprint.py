"""
Target Fingerprinting Module
============================
Identifies target technology stack, versions, and configurations
"""

import re
import json
import socket
import ssl
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import concurrent.futures
from datetime import datetime

@dataclass
class TargetFingerprint:
    """Structured fingerprint of target system"""
    url: str
    product: Optional[str] = None  # Primary product (nginx, apache, wordpress)
    version: Optional[str] = None  # Version string (1.14.0, 2.4.41)
    technologies: List[str] = field(default_factory=list)  # All detected techs
    server: Optional[str] = None  # Server header value
    os: Optional[str] = None  # Operating system if detected
    frameworks: List[str] = field(default_factory=list)  # Web frameworks
    cms: Optional[str] = None  # Content Management System
    cdn: Optional[str] = None  # CDN provider
    waf: Optional[str] = None  # Web Application Firewall
    cloud_provider: Optional[str] = None  # AWS, GCP, Azure
    
    # Raw signals for analysis
    raw_signals: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    
    # Confidence scores
    confidence: Dict[str, float] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class Fingerprinter:
    """Main fingerprinting engine"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.aggressive = self.config.get('aggressive', False)
        self.use_external_tools = self.config.get('use_external_tools', False)
        
        # Initialize signature database
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> Dict:
        """Load fingerprinting signatures"""
        return {
            'servers': {
                'nginx': {
                    'headers': [r'nginx/?([\d\.]+)?', r'openresty/?([\d\.]+)?'],
                    'error_pages': ['nginx', '301 Moved Permanently'],
                    'confidence': 0.9
                },
                'apache': {
                    'headers': [r'Apache/?([\d\.]+)?', r'Apache-Coyote/?([\d\.]+)?'],
                    'error_pages': ['Apache Server', 'Apache/'],
                    'confidence': 0.9
                },
                'iis': {
                    'headers': [r'Microsoft-IIS/?([\d\.]+)?'],
                    'error_pages': ['IIS Windows Server'],
                    'confidence': 0.9
                },
                'cloudflare': {
                    'headers': [r'cloudflare'],
                    'cookies': ['__cfduid', 'cf_clearance'],
                    'confidence': 0.95
                }
            },
            'frameworks': {
                'django': {
                    'cookies': ['csrftoken', 'sessionid'],
                    'headers': ['WSGIServer'],
                    'patterns': ['django', 'csrfmiddlewaretoken'],
                    'confidence': 0.8
                },
                'flask': {
                    'cookies': ['session'],
                    'headers': ['Werkzeug'],
                    'confidence': 0.7
                },
                'rails': {
                    'headers': ['X-Runtime', 'X-Rack-Cache'],
                    'cookies': ['_session_id'],
                    'patterns': ['authenticity_token'],
                    'confidence': 0.8
                },
                'laravel': {
                    'cookies': ['laravel_session', 'XSRF-TOKEN'],
                    'patterns': ['laravel', '_token'],
                    'confidence': 0.85
                },
                'express': {
                    'headers': ['X-Powered-By: Express'],
                    'confidence': 0.9
                },
                'aspnet': {
                    'headers': ['X-AspNet-Version', 'X-AspNetMvc-Version'],
                    'cookies': ['ASP.NET_SessionId'],
                    'patterns': ['__VIEWSTATE', '__EVENTVALIDATION'],
                    'confidence': 0.9
                }
            },
            'cms': {
                'wordpress': {
                    'patterns': ['/wp-content/', '/wp-includes/', 'wp-json'],
                    'meta': ['generator.*WordPress'],
                    'endpoints': ['/wp-login.php', '/wp-admin/'],
                    'version_endpoint': '/feed/',  # Contains version in generator tag
                    'confidence': 0.95
                },
                'drupal': {
                    'patterns': ['/sites/default/', 'Drupal.settings'],
                    'meta': ['generator.*Drupal'],
                    'headers': ['X-Drupal-Cache'],
                    'endpoints': ['/user/login', '/admin'],
                    'confidence': 0.9
                },
                'joomla': {
                    'patterns': ['/components/', '/modules/', 'Joomla'],
                    'meta': ['generator.*Joomla'],
                    'endpoints': ['/administrator/'],
                    'confidence': 0.9
                }
            },
            'technologies': {
                'jquery': {
                    'patterns': ['jquery', 'jQuery'],
                    'confidence': 0.8
                },
                'react': {
                    'patterns': ['react', 'React', '_react', '__react'],
                    'confidence': 0.85
                },
                'angular': {
                    'patterns': ['ng-', 'angular', 'Angular'],
                    'confidence': 0.85
                },
                'vue': {
                    'patterns': ['Vue', 'v-', '__vue'],
                    'confidence': 0.8
                }
            },
            'databases': {
                'mysql': {
                    'error_patterns': ['MySQL', 'mysql_', 'mysqli'],
                    'ports': [3306],
                    'confidence': 0.7
                },
                'postgresql': {
                    'error_patterns': ['PostgreSQL', 'pg_', 'psql'],
                    'ports': [5432],
                    'confidence': 0.7
                },
                'mongodb': {
                    'error_patterns': ['MongoDB', 'mongo'],
                    'ports': [27017],
                    'confidence': 0.7
                }
            }
        }
    
    def fingerprint(self, target: str, aggressive: bool = False) -> TargetFingerprint:
        """
        Perform fingerprinting on target
        
        Args:
            target: Target URL
            aggressive: Enable aggressive fingerprinting (more requests)
            
        Returns:
            TargetFingerprint object with identified technologies
        """
        fingerprint = TargetFingerprint(url=target)
        
        # Parse URL
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Passive fingerprinting first
        self._passive_fingerprint(fingerprint, target)
        
        # Light active fingerprinting
        if aggressive or self.aggressive:
            self._active_fingerprint(fingerprint, base_url)
        
        # Analyze and consolidate results
        self._analyze_fingerprint(fingerprint)
        
        # External tools if configured
        if self.use_external_tools:
            self._external_fingerprint(fingerprint, target)
        
        return fingerprint
    
    def _passive_fingerprint(self, fingerprint: TargetFingerprint, target: str):
        """Passive fingerprinting using single request"""
        try:
            # Make initial request
            response = requests.get(
                target,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'},
                verify=False,
                allow_redirects=True
            )
            
            # Extract headers
            fingerprint.headers = dict(response.headers)
            fingerprint.raw_signals['status_code'] = response.status_code
            fingerprint.raw_signals['response_size'] = len(response.content)
            
            # Extract cookies
            for cookie in response.cookies:
                fingerprint.cookies.append({
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly')
                })
            
            # Parse HTML content
            if 'text/html' in response.headers.get('Content-Type', ''):
                self._parse_html(fingerprint, response.text)
            
            # Server header analysis
            server_header = response.headers.get('Server', '')
            if server_header:
                fingerprint.server = server_header
                self._parse_server_header(fingerprint, server_header)
            
            # Powered-By header
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                fingerprint.raw_signals['powered_by'] = powered_by
                self._parse_powered_by(fingerprint, powered_by)
            
            # SSL/TLS information
            self._get_ssl_info(fingerprint, target)
            
        except Exception as e:
            fingerprint.raw_signals['error'] = str(e)
    
    def _parse_html(self, fingerprint: TargetFingerprint, html: str):
        """Parse HTML for technology indicators"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '') or meta.get('property', '')
                content = meta.get('content', '')
                if name and content:
                    fingerprint.meta_tags[name] = content
                    
                    # Check for generator tag (CMS indicator)
                    if name.lower() == 'generator':
                        self._parse_generator_tag(fingerprint, content)
            
            # Look for technology patterns in HTML
            html_lower = html.lower()
            
            # Check CMS patterns
            for cms_name, cms_data in self.signatures['cms'].items():
                for pattern in cms_data.get('patterns', []):
                    if pattern.lower() in html_lower:
                        fingerprint.cms = cms_name
                        fingerprint.confidence[f'cms_{cms_name}'] = cms_data['confidence']
                        break
            
            # Check framework patterns
            for fw_name, fw_data in self.signatures['frameworks'].items():
                for pattern in fw_data.get('patterns', []):
                    if pattern.lower() in html_lower:
                        if fw_name not in fingerprint.frameworks:
                            fingerprint.frameworks.append(fw_name)
                            fingerprint.confidence[f'framework_{fw_name}'] = fw_data['confidence']
            
            # Check JavaScript libraries
            for tech_name, tech_data in self.signatures['technologies'].items():
                for pattern in tech_data.get('patterns', []):
                    if pattern.lower() in html_lower:
                        if tech_name not in fingerprint.technologies:
                            fingerprint.technologies.append(tech_name)
                            fingerprint.confidence[f'tech_{tech_name}'] = tech_data['confidence']
            
            # Extract all script sources
            scripts = soup.find_all('script', src=True)
            fingerprint.raw_signals['scripts'] = [s['src'] for s in scripts]
            
            # Extract all link hrefs
            links = soup.find_all('link', href=True)
            fingerprint.raw_signals['stylesheets'] = [l['href'] for l in links if 'stylesheet' in l.get('rel', [])]
            
        except Exception as e:
            fingerprint.raw_signals['html_parse_error'] = str(e)
    
    def _parse_server_header(self, fingerprint: TargetFingerprint, server_header: str):
        """Parse server header for product and version"""
        for server_name, server_data in self.signatures['servers'].items():
            for pattern in server_data.get('headers', []):
                match = re.search(pattern, server_header, re.IGNORECASE)
                if match:
                    fingerprint.product = server_name
                    if match.groups():
                        fingerprint.version = match.group(1)
                    fingerprint.confidence[f'server_{server_name}'] = server_data['confidence']
                    return
    
    def _parse_powered_by(self, fingerprint: TargetFingerprint, powered_by: str):
        """Parse X-Powered-By header"""
        # PHP version
        php_match = re.search(r'PHP/?([\d\.]+)?', powered_by, re.IGNORECASE)
        if php_match:
            fingerprint.technologies.append('PHP')
            if php_match.group(1):
                fingerprint.raw_signals['php_version'] = php_match.group(1)
        
        # ASP.NET
        if 'ASP.NET' in powered_by:
            fingerprint.technologies.append('ASP.NET')
            fingerprint.frameworks.append('aspnet')
        
        # Express
        if 'Express' in powered_by:
            fingerprint.frameworks.append('express')
            fingerprint.technologies.append('Node.js')
    
    def _parse_generator_tag(self, fingerprint: TargetFingerprint, content: str):
        """Parse generator meta tag for CMS and version"""
        # WordPress
        wp_match = re.search(r'WordPress\s*([\d\.]+)?', content, re.IGNORECASE)
        if wp_match:
            fingerprint.cms = 'wordpress'
            if wp_match.group(1):
                fingerprint.raw_signals['wordpress_version'] = wp_match.group(1)
        
        # Drupal
        drupal_match = re.search(r'Drupal\s*([\d\.]+)?', content, re.IGNORECASE)
        if drupal_match:
            fingerprint.cms = 'drupal'
            if drupal_match.group(1):
                fingerprint.raw_signals['drupal_version'] = drupal_match.group(1)
        
        # Joomla
        joomla_match = re.search(r'Joomla!\s*([\d\.]+)?', content, re.IGNORECASE)
        if joomla_match:
            fingerprint.cms = 'joomla'
            if joomla_match.group(1):
                fingerprint.raw_signals['joomla_version'] = joomla_match.group(1)
    
    def _get_ssl_info(self, fingerprint: TargetFingerprint, target: str):
        """Extract SSL/TLS certificate information"""
        try:
            parsed = urlparse(target)
            if parsed.scheme != 'https':
                return
            
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        fingerprint.ssl_info = {
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'san': cert.get('subjectAltName', [])
                        }
                        
                        # Check for CDN/Cloud providers
                        issuer_org = fingerprint.ssl_info['issuer'].get('organizationName', '')
                        if 'CloudFlare' in issuer_org:
                            fingerprint.cdn = 'cloudflare'
                        elif 'Amazon' in issuer_org:
                            fingerprint.cloud_provider = 'aws'
                        elif 'Google' in issuer_org:
                            fingerprint.cloud_provider = 'gcp'
                        elif 'Microsoft' in issuer_org:
                            fingerprint.cloud_provider = 'azure'
                    
                    # Get TLS version and cipher
                    fingerprint.ssl_info['tls_version'] = ssock.version()
                    fingerprint.ssl_info['cipher'] = ssock.cipher()
                    
        except Exception as e:
            fingerprint.ssl_info['error'] = str(e)
    
    def _active_fingerprint(self, fingerprint: TargetFingerprint, base_url: str):
        """Active fingerprinting with additional requests"""
        # Test common endpoints
        endpoints = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/README.md',
            '/package.json',
            '/composer.json',
            '/.env',
            '/wp-login.php',  # WordPress
            '/admin',  # Generic admin
            '/api',  # API endpoint
            '/graphql',  # GraphQL
            '/.well-known/security.txt'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for endpoint in endpoints:
                future = executor.submit(self._check_endpoint, base_url + endpoint)
                futures.append((endpoint, future))
            
            for endpoint, future in futures:
                try:
                    result = future.result(timeout=5)
                    if result:
                        fingerprint.raw_signals[f'endpoint_{endpoint}'] = result
                        self._analyze_endpoint_result(fingerprint, endpoint, result)
                except:
                    pass
    
    def _check_endpoint(self, url: str) -> Optional[Dict]:
        """Check if endpoint exists and return info"""
        try:
            response = requests.get(
                url,
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0'},
                verify=False,
                allow_redirects=False
            )
            
            if response.status_code in [200, 301, 302, 401, 403]:
                return {
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_sample': response.text[:500] if response.status_code == 200 else None
                }
        except:
            pass
        return None
    
    def _analyze_endpoint_result(self, fingerprint: TargetFingerprint, endpoint: str, result: Dict):
        """Analyze endpoint check results"""
        if endpoint == '/wp-login.php' and result['status'] == 200:
            fingerprint.cms = 'wordpress'
            fingerprint.confidence['cms_wordpress'] = 0.99
        
        elif endpoint == '/package.json' and result['status'] == 200:
            try:
                package = json.loads(result.get('content_sample', '{}'))
                fingerprint.technologies.append('Node.js')
                if 'dependencies' in package:
                    for dep in package['dependencies']:
                        if 'react' in dep:
                            fingerprint.technologies.append('React')
                        elif 'vue' in dep:
                            fingerprint.technologies.append('Vue')
                        elif 'angular' in dep:
                            fingerprint.technologies.append('Angular')
            except:
                pass
        
        elif endpoint == '/composer.json' and result['status'] == 200:
            fingerprint.technologies.append('PHP')
            try:
                composer = json.loads(result.get('content_sample', '{}'))
                if 'require' in composer:
                    for req in composer['require']:
                        if 'laravel' in req:
                            fingerprint.frameworks.append('laravel')
                        elif 'symfony' in req:
                            fingerprint.frameworks.append('symfony')
            except:
                pass
    
    def _analyze_fingerprint(self, fingerprint: TargetFingerprint):
        """Analyze and consolidate fingerprint data"""
        # Set primary product if not already set
        if not fingerprint.product and fingerprint.cms:
            fingerprint.product = fingerprint.cms
            
        # Extract version from various sources
        if not fingerprint.version:
            # Try CMS versions
            if fingerprint.cms == 'wordpress':
                fingerprint.version = fingerprint.raw_signals.get('wordpress_version')
            elif fingerprint.cms == 'drupal':
                fingerprint.version = fingerprint.raw_signals.get('drupal_version')
            elif fingerprint.cms == 'joomla':
                fingerprint.version = fingerprint.raw_signals.get('joomla_version')
        
        # Detect WAF
        self._detect_waf(fingerprint)
        
        # Detect cloud provider from headers
        self._detect_cloud_provider(fingerprint)
        
        # Calculate overall confidence
        if fingerprint.confidence:
            fingerprint.confidence['overall'] = sum(fingerprint.confidence.values()) / len(fingerprint.confidence)
        else:
            fingerprint.confidence['overall'] = 0.5
    
    def _detect_waf(self, fingerprint: TargetFingerprint):
        """Detect Web Application Firewall"""
        waf_signatures = {
            'cloudflare': ['CF-RAY', '__cfduid', 'cloudflare'],
            'akamai': ['AkamaiGHost', 'akamai'],
            'aws_waf': ['AWSALB', 'AWSALBCORS', 'x-amzn-RequestId'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['x-sucuri-id', 'sucuri'],
            'barracuda': ['barra'],
            'f5_bigip': ['x-wa-info', 'BigIP', 'F5'],
            'modsecurity': ['mod_security', 'Mod_Security'],
            'nginx_modsecurity': ['nginx.*modsecurity']
        }
        
        # Check headers
        headers_str = ' '.join(fingerprint.headers.keys()).lower()
        headers_values = ' '.join(fingerprint.headers.values()).lower()
        
        # Check cookies
        cookies_str = ' '.join([c['name'] for c in fingerprint.cookies]).lower()
        
        combined = f"{headers_str} {headers_values} {cookies_str}"
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in combined:
                    fingerprint.waf = waf_name
                    fingerprint.confidence[f'waf_{waf_name}'] = 0.85
                    break
    
    def _detect_cloud_provider(self, fingerprint: TargetFingerprint):
        """Detect cloud provider from various signals"""
        # Already detected from SSL?
        if fingerprint.cloud_provider:
            return
        
        # Check headers
        headers = fingerprint.headers
        
        # AWS
        if any(h.startswith('x-amz-') for h in headers):
            fingerprint.cloud_provider = 'aws'
        # Azure
        elif any('azure' in h.lower() for h in headers):
            fingerprint.cloud_provider = 'azure'
        # GCP
        elif any('google' in h.lower() for h in headers.values()):
            fingerprint.cloud_provider = 'gcp'
        # DigitalOcean
        elif 'do-loadbalancer' in headers.get('server', '').lower():
            fingerprint.cloud_provider = 'digitalocean'
    
    def _external_fingerprint(self, fingerprint: TargetFingerprint, target: str):
        """Use external tools if available (placeholder for integration)"""
        # This would integrate with tools like:
        # - WhatWeb
        # - Wappalyzer CLI
        # - Nmap service detection
        # For now, just add a flag
        fingerprint.raw_signals['external_tools_used'] = False
    
    def get_summary(self, fingerprint: TargetFingerprint) -> str:
        """Get human-readable summary of fingerprint"""
        lines = []
        lines.append(f"Target: {fingerprint.url}")
        lines.append(f"Timestamp: {fingerprint.timestamp}")
        
        if fingerprint.product:
            version = f" {fingerprint.version}" if fingerprint.version else ""
            lines.append(f"Primary Product: {fingerprint.product}{version}")
        
        if fingerprint.server:
            lines.append(f"Server: {fingerprint.server}")
        
        if fingerprint.cms:
            lines.append(f"CMS: {fingerprint.cms}")
        
        if fingerprint.frameworks:
            lines.append(f"Frameworks: {', '.join(fingerprint.frameworks)}")
        
        if fingerprint.technologies:
            lines.append(f"Technologies: {', '.join(fingerprint.technologies)}")
        
        if fingerprint.waf:
            lines.append(f"WAF: {fingerprint.waf}")
        
        if fingerprint.cdn:
            lines.append(f"CDN: {fingerprint.cdn}")
        
        if fingerprint.cloud_provider:
            lines.append(f"Cloud Provider: {fingerprint.cloud_provider}")
        
        lines.append(f"Overall Confidence: {fingerprint.confidence.get('overall', 0):.2%}")
        
        return "\n".join(lines)


# Utility functions for external use
def quick_fingerprint(target: str) -> Dict[str, Any]:
    """Quick fingerprint for simple integration"""
    fp = Fingerprinter()
    result = fp.fingerprint(target, aggressive=False)
    
    return {
        'product': result.product,
        'version': result.version,
        'technologies': result.technologies,
        'frameworks': result.frameworks,
        'cms': result.cms,
        'server': result.server,
        'waf': result.waf,
        'confidence': result.confidence.get('overall', 0)
    }


def detailed_fingerprint(target: str) -> TargetFingerprint:
    """Detailed fingerprint with aggressive scanning"""
    fp = Fingerprinter({'aggressive': True, 'use_external_tools': False})
    return fp.fingerprint(target, aggressive=True)
