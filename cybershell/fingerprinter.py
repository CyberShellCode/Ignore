"""
Target Fingerprinting Module
============================
Identifies technologies, versions, and characteristics of target systems
"""

import re
import requests
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import hashlib
import json
from packaging import version

@dataclass
class TargetFingerprint:
    """Comprehensive fingerprint of a target system"""
    url: str
    product: Optional[str] = None
    version: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    cms: Optional[str] = None
    server: Optional[str] = None
    waf: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cloud_provider: Optional[str] = None
    raw_signals: Dict[str, Any] = field(default_factory=dict)
    
    def matches_version(self, version_spec: str) -> bool:
        """Check if fingerprint version matches specification"""
        if not self.version or not version_spec:
            return False
        try:
            from packaging.specifiers import SpecifierSet
            spec = SpecifierSet(version_spec)
            return version.parse(self.version) in spec
        except:
            # Fallback to simple string matching
            return self.version.startswith(version_spec)

class Fingerprinter:
    """Advanced target fingerprinting system"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.signatures = self._load_signatures()
        self.timeout = self.config.get('timeout', 10)
        self.user_agent = self.config.get('user_agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    
    def _load_signatures(self) -> Dict:
        """Load technology signatures"""
        return {
            'cms': {
                'wordpress': {
                    'patterns': ['/wp-content/', '/wp-includes/', 'wp-json'],
                    'headers': {'X-Powered-By': 'WordPress'},
                    'meta': ['generator.*WordPress']
                },
                'drupal': {
                    'patterns': ['/sites/default/', '/modules/', 'Drupal'],
                    'headers': {'X-Drupal-Cache': '.*'},
                    'meta': ['generator.*Drupal']
                },
                'joomla': {
                    'patterns': ['/components/', '/modules/', 'Joomla'],
                    'headers': {},
                    'meta': ['generator.*Joomla']
                }
            },
            'servers': {
                'nginx': {
                    'headers': {'Server': 'nginx'},
                    'errors': ['nginx/']
                },
                'apache': {
                    'headers': {'Server': 'Apache'},
                    'errors': ['Apache/']
                },
                'iis': {
                    'headers': {'Server': 'Microsoft-IIS'},
                    'errors': ['Microsoft-IIS/']
                }
            },
            'technologies': {
                'php': {
                    'headers': {'X-Powered-By': 'PHP'},
                    'extensions': ['.php', '.phtml'],
                    'cookies': ['PHPSESSID']
                },
                'asp.net': {
                    'headers': {'X-AspNet-Version': '.*'},
                    'extensions': ['.aspx', '.asp'],
                    'cookies': ['ASP.NET_SessionId']
                },
                'python': {
                    'headers': {'X-Powered-By': 'Python'},
                    'frameworks': ['Django', 'Flask']
                },
                'node.js': {
                    'headers': {'X-Powered-By': 'Express'},
                    'patterns': ['node', 'express']
                }
            },
            'waf': {
                'cloudflare': {
                    'headers': {'Server': 'cloudflare', 'CF-RAY': '.*'},
                    'cookies': ['__cfduid', 'cf_clearance']
                },
                'aws': {
                    'headers': {'Server': 'AmazonS3', 'x-amz-request-id': '.*'}
                },
                'incapsula': {
                    'headers': {'X-Iinfo': '.*'},
                    'cookies': ['incap_ses_', 'visid_incap_']
                },
                'akamai': {
                    'headers': {'X-Akamai': '.*'}
                }
            },
            'databases': {
                'mysql': {
                    'errors': ['MySQL', 'mysql_', 'mysqli_'],
                    'ports': [3306]
                },
                'postgresql': {
                    'errors': ['PostgreSQL', 'pg_', 'psql'],
                    'ports': [5432]
                },
                'mssql': {
                    'errors': ['Microsoft SQL Server', 'mssql_', 'sqlsrv_'],
                    'ports': [1433]
                },
                'oracle': {
                    'errors': ['Oracle', 'ORA-'],
                    'ports': [1521]
                },
                'mongodb': {
                    'errors': ['MongoDB', 'mongo'],
                    'ports': [27017]
                }
            },
            'frameworks': {
                'laravel': {
                    'cookies': ['laravel_session'],
                    'headers': {'X-Powered-By': 'Laravel'}
                },
                'django': {
                    'cookies': ['csrftoken', 'sessionid'],
                    'patterns': ['/admin/', '__debug__']
                },
                'flask': {
                    'cookies': ['session'],
                    'patterns': []
                },
                'spring': {
                    'headers': {'X-Application-Context': '.*'},
                    'patterns': ['/actuator/']
                },
                'rails': {
                    'headers': {'X-Powered-By': 'Rails'},
                    'cookies': ['_session_id']
                }
            }
        }
    
    def fingerprint(self, target: str, aggressive: bool = False) -> TargetFingerprint:
        """
        Fingerprint a target to identify technologies and versions
        
        Args:
            target: Target URL
            aggressive: Use aggressive fingerprinting (more requests)
            
        Returns:
            TargetFingerprint object with detected information
        """
        fingerprint = TargetFingerprint(url=target)
        
        try:
            # Basic HTTP fingerprinting
            response = self._make_request(target)
            if response:
                self._analyze_response(response, fingerprint)
            
            # Aggressive fingerprinting if enabled
            if aggressive:
                self._aggressive_fingerprint(target, fingerprint)
            
            # Detect cloud provider
            self._detect_cloud_provider(fingerprint)
            
            # Determine product and version
            self._determine_product_version(fingerprint)
            
        except Exception as e:
            fingerprint.raw_signals['error'] = str(e)
        
        return fingerprint
    
    def _make_request(self, url: str, method: str = 'GET', 
                     headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            req_headers = {'User-Agent': self.user_agent}
            if headers:
                req_headers.update(headers)
            
            response = requests.request(
                method=method,
                url=url,
                headers=req_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return response
        except requests.RequestException:
            return None
    
    def _analyze_response(self, response: requests.Response, 
                         fingerprint: TargetFingerprint):
        """Analyze HTTP response for fingerprinting"""
        
        # Store headers
        fingerprint.headers = dict(response.headers)
        
        # Analyze headers
        for header, value in response.headers.items():
            header_lower = header.lower()
            
            # Server detection
            if header_lower == 'server':
                fingerprint.server = value
                self._detect_server_version(value, fingerprint)
            
            # Technology detection
            elif header_lower == 'x-powered-by':
                self._detect_technology(value, fingerprint)
            
            # WAF detection
            for waf_name, waf_sig in self.signatures['waf'].items():
                if any(h in header for h in waf_sig.get('headers', {})):
                    fingerprint.waf = waf_name
                    break
        
        # Analyze response body
        if response.text:
            self._analyze_content(response.text, fingerprint)
        
        # Analyze cookies
        self._analyze_cookies(response.cookies, fingerprint)
        
        # Store raw response info
        fingerprint.raw_signals['status_code'] = response.status_code
        fingerprint.raw_signals['response_size'] = len(response.content)
        fingerprint.raw_signals['response_time'] = response.elapsed.total_seconds()
    
    def _analyze_content(self, content: str, fingerprint: TargetFingerprint):
        """Analyze response content for fingerprinting"""
        
        # CMS detection
        for cms_name, cms_sig in self.signatures['cms'].items():
            for pattern in cms_sig.get('patterns', []):
                if pattern in content:
                    fingerprint.cms = cms_name
                    break
            
            # Meta tag detection
            for meta_pattern in cms_sig.get('meta', []):
                if re.search(meta_pattern, content, re.IGNORECASE):
                    fingerprint.cms = cms_name
                    break
        
        # Framework detection
        for framework_name, framework_sig in self.signatures['frameworks'].items():
            for pattern in framework_sig.get('patterns', []):
                if pattern in content:
                    if framework_name not in fingerprint.frameworks:
                        fingerprint.frameworks.append(framework_name)
        
        # Technology detection from content
        tech_indicators = {
            'jQuery': [r'jquery[\.-][\d\.]+', r'jQuery\s*\('],
            'React': [r'react[\.-][\d\.]+', r'React\.'],
            'Angular': [r'angular[\.-][\d\.]+', r'ng-app'],
            'Vue.js': [r'vue[\.-][\d\.]+', r'Vue\.'],
            'Bootstrap': [r'bootstrap[\.-][\d\.]+', r'class=".*bootstrap'],
        }
        
        for tech, patterns in tech_indicators.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if tech not in fingerprint.technologies:
                        fingerprint.technologies.append(tech)
                    break
        
        # Extract version information
        version_patterns = {
            'wordpress': r'WordPress\s+([\d\.]+)',
            'drupal': r'Drupal\s+([\d\.]+)',
            'joomla': r'Joomla!\s+([\d\.]+)',
            'apache': r'Apache/([\d\.]+)',
            'nginx': r'nginx/([\d\.]+)',
            'php': r'PHP/([\d\.]+)',
        }
        
        for product, pattern in version_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                if not fingerprint.product:
                    fingerprint.product = product
                if not fingerprint.version:
                    fingerprint.version = match.group(1)
    
    def _analyze_cookies(self, cookies: Any, fingerprint: TargetFingerprint):
        """Analyze cookies for technology detection"""
        
        cookie_names = [cookie.name for cookie in cookies]
        
        # Technology detection from cookies
        for tech_name, tech_sig in self.signatures['technologies'].items():
            for cookie_pattern in tech_sig.get('cookies', []):
                if any(cookie_pattern in name for name in cookie_names):
                    if tech_name not in fingerprint.technologies:
                        fingerprint.technologies.append(tech_name)
        
        # Framework detection from cookies
        for fw_name, fw_sig in self.signatures['frameworks'].items():
            for cookie_pattern in fw_sig.get('cookies', []):
                if any(cookie_pattern in name for name in cookie_names):
                    if fw_name not in fingerprint.frameworks:
                        fingerprint.frameworks.append(fw_name)
    
    def _detect_server_version(self, server_header: str, 
                              fingerprint: TargetFingerprint):
        """Extract server version from header"""
        
        # Common server version patterns
        patterns = {
            'apache': r'Apache/([\d\.]+)',
            'nginx': r'nginx/([\d\.]+)',
            'iis': r'Microsoft-IIS/([\d\.]+)',
            'lighttpd': r'lighttpd/([\d\.]+)',
        }
        
        for server_name, pattern in patterns.items():
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                if not fingerprint.product:
                    fingerprint.product = server_name
                if not fingerprint.version:
                    fingerprint.version = match.group(1)
                break
    
    def _detect_technology(self, powered_by: str, fingerprint: TargetFingerprint):
        """Detect technology from X-Powered-By header"""
        
        tech_patterns = {
            'PHP': r'PHP/([\d\.]+)',
            'ASP.NET': r'ASP\.NET\s+([\d\.]+)',
            'Express': r'Express',
            'Django': r'Django',
            'Rails': r'Rails\s+([\d\.]+)',
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, powered_by, re.IGNORECASE):
                if tech not in fingerprint.technologies:
                    fingerprint.technologies.append(tech)
                
                # Extract version if present
                match = re.search(pattern, powered_by)
                if match and len(match.groups()) > 0:
                    if not fingerprint.version:
                        fingerprint.version = match.group(1)
    
    def _detect_cloud_provider(self, fingerprint: TargetFingerprint):
        """Detect cloud provider from various signals"""
        
        # Check headers
        headers_lower = {k.lower(): v for k, v in fingerprint.headers.items()}
        
        if 'x-amz-request-id' in headers_lower or 'x-amz-id-2' in headers_lower:
            fingerprint.cloud_provider = 'aws'
        elif 'x-ms-request-id' in headers_lower:
            fingerprint.cloud_provider = 'azure'
        elif 'x-goog-' in str(headers_lower):
            fingerprint.cloud_provider = 'gcp'
        elif fingerprint.waf == 'cloudflare':
            fingerprint.cloud_provider = 'cloudflare'
    
    def _aggressive_fingerprint(self, target: str, fingerprint: TargetFingerprint):
        """Perform aggressive fingerprinting with additional requests"""
        
        # Test common paths
        test_paths = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/HEAD',
            '/admin/',
            '/api/',
            '/wp-admin/',
            '/.env',
            '/package.json',
            '/composer.json',
        ]
        
        for path in test_paths:
            url = target.rstrip('/') + path
            response = self._make_request(url)
            
            if response and response.status_code != 404:
                fingerprint.raw_signals[f'path_{path}'] = response.status_code
                
                # Analyze specific files
                if path == '/robots.txt' and response.text:
                    self._analyze_robots(response.text, fingerprint)
                elif path == '/package.json' and response.text:
                    self._analyze_package_json(response.text, fingerprint)
                elif path == '/composer.json' and response.text:
                    self._analyze_composer_json(response.text, fingerprint)
        
        # Test HTTP methods
        for method in ['OPTIONS', 'TRACE', 'PUT', 'DELETE']:
            response = self._make_request(target, method=method)
            if response:
                fingerprint.raw_signals[f'method_{method}'] = response.status_code
    
    def _analyze_robots(self, content: str, fingerprint: TargetFingerprint):
        """Analyze robots.txt for technology hints"""
        
        # Common CMS patterns in robots.txt
        cms_patterns = {
            'wordpress': ['/wp-admin/', '/wp-includes/'],
            'drupal': ['/admin/', '/core/', '/modules/'],
            'joomla': ['/administrator/', '/components/'],
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in content for pattern in patterns):
                if not fingerprint.cms:
                    fingerprint.cms = cms
    
    def _analyze_package_json(self, content: str, fingerprint: TargetFingerprint):
        """Analyze package.json for Node.js dependencies"""
        try:
            data = json.loads(content)
            
            # Add Node.js to technologies
            if 'node.js' not in fingerprint.technologies:
                fingerprint.technologies.append('node.js')
            
            # Check dependencies
            deps = data.get('dependencies', {})
            if 'express' in deps:
                fingerprint.frameworks.append('express')
            if 'react' in deps:
                fingerprint.technologies.append('React')
            if 'vue' in deps:
                fingerprint.technologies.append('Vue.js')
            if 'angular' in deps:
                fingerprint.technologies.append('Angular')
        except json.JSONDecodeError:
            pass
    
    def _analyze_composer_json(self, content: str, fingerprint: TargetFingerprint):
        """Analyze composer.json for PHP dependencies"""
        try:
            data = json.loads(content)
            
            # Add PHP to technologies
            if 'PHP' not in fingerprint.technologies:
                fingerprint.technologies.append('PHP')
            
            # Check requirements
            reqs = data.get('require', {})
            if 'laravel/framework' in reqs:
                fingerprint.frameworks.append('laravel')
            if 'symfony/symfony' in reqs:
                fingerprint.frameworks.append('symfony')
            if 'drupal/core' in reqs:
                fingerprint.cms = 'drupal'
        except json.JSONDecodeError:
            pass
    
    def _determine_product_version(self, fingerprint: TargetFingerprint):
        """Determine primary product and version from all signals"""
        
        # Priority order for product determination
        if fingerprint.cms:
            if not fingerprint.product:
                fingerprint.product = fingerprint.cms
        elif fingerprint.server:
            if not fingerprint.product:
                fingerprint.product = fingerprint.server.split('/')[0].lower()
        elif fingerprint.frameworks:
            if not fingerprint.product:
                fingerprint.product = fingerprint.frameworks[0].lower()
        elif fingerprint.technologies:
            if not fingerprint.product:
                fingerprint.product = fingerprint.technologies[0].lower()
