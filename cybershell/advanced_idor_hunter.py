"""
Advanced IDOR/BOLA Hunting System
=================================
Comprehensive IDOR hunting with credential management, endpoint discovery,
GraphQL awareness, and JWT-focused authorization testing.
"""

import jwt
import json
import re
import asyncio
import random
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin
import requests
from bs4 import BeautifulSoup
import hashlib
from datetime import datetime, timedelta

from .rate_limiter import RateLimiter
from .fingerprinter import TargetFingerprint

@dataclass
class Credential:
    """User credential pair"""
    username: str
    password: str
    realm: Optional[str] = None
    source: str = "manual"  # manual, default, weak, fingerprint

@dataclass
class AuthSession:
    """Authenticated session information"""
    session_id: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    jwt_token: Optional[str] = None
    jwt_claims: Dict[str, Any] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None
    authenticated: bool = False

@dataclass
class APIEndpoint:
    """API endpoint information"""
    path: str
    method: str
    parameters: List[str]
    auth_required: bool
    response_status: int
    response_size: int
    content_type: str
    requires_csrf: bool = False
    object_references: List[str] = field(default_factory=list)

@dataclass
class IDOREvidence:
    """Evidence of IDOR vulnerability"""
    endpoint: str
    method: str
    original_request: Dict[str, Any]
    modified_request: Dict[str, Any]
    original_response: Dict[str, Any]
    modified_response: Dict[str, Any]
    evidence_type: str  # "data_exposure", "privilege_escalation", "object_access"
    severity: str  # "Critical", "High", "Medium", "Low"
    confidence: float
    unauthorized_data: Dict[str, Any] = field(default_factory=dict)

class CredentialManager:
    """Manages authentication credentials and sessions"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.default_credentials = self._load_default_credentials()
        self.weak_credentials = self._load_weak_credentials()
        self.active_sessions: Dict[str, AuthSession] = {}
        self.lockout_tracker: Dict[str, Dict] = {}
    
    def _load_default_credentials(self) -> Dict[str, List[Credential]]:
        """Load default credentials by product"""
        return {
            'apache': [
                Credential('admin', 'admin', 'Apache'),
                Credential('admin', 'password', 'Apache'),
                Credential('root', 'root', 'Apache'),
            ],
            'nginx': [
                Credential('admin', 'admin', 'Nginx'),
                Credential('nginx', 'nginx', 'Nginx'),
            ],
            'mysql': [
                Credential('root', '', 'MySQL'),
                Credential('root', 'root', 'MySQL'),
                Credential('admin', 'admin', 'MySQL'),
            ],
            'postgresql': [
                Credential('postgres', 'postgres', 'PostgreSQL'),
                Credential('admin', 'admin', 'PostgreSQL'),
            ],
            'wordpress': [
                Credential('admin', 'admin', 'WordPress'),
                Credential('admin', 'password', 'WordPress'),
                Credential('user', 'user', 'WordPress'),
            ],
            'drupal': [
                Credential('admin', 'admin', 'Drupal'),
                Credential('admin', 'password', 'Drupal'),
            ],
            'joomla': [
                Credential('admin', 'admin', 'Joomla'),
                Credential('admin', 'password', 'Joomla'),
            ]
        }
    
    def _load_weak_credentials(self) -> List[Credential]:
        """Load common weak credential pairs"""
        weak_pairs = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('user', 'user'), ('user', 'password'), ('guest', 'guest'),
            ('test', 'test'), ('demo', 'demo'), ('root', 'root'),
            ('administrator', 'administrator'), ('sa', 'sa'),
            ('admin', ''), ('root', ''), ('', ''),
            ('admin', 'admin123'), ('user', '123456'),
            ('api', 'api'), ('service', 'service')
        ]
        
        return [Credential(u, p, source="weak") for u, p in weak_pairs]
    
    def get_credential_candidates(self, fingerprint: Optional[TargetFingerprint] = None) -> List[Credential]:
        """Get credential candidates based on fingerprint"""
        candidates = []
        
        # Add fingerprint-specific defaults
        if fingerprint and fingerprint.product:
            product_creds = self.default_credentials.get(fingerprint.product.lower(), [])
            candidates.extend(product_creds)
            
            # Add CMS-specific credentials
            if fingerprint.cms:
                cms_creds = self.default_credentials.get(fingerprint.cms.lower(), [])
                candidates.extend(cms_creds)
        
        # Add common weak credentials
        candidates.extend(self.weak_credentials[:10])  # Limit to avoid lockouts
        
        return candidates
    
    def is_locked_out(self, target: str, username: str) -> bool:
        """Check if username is locked out for target"""
        key = f"{target}:{username}"
        if key not in self.lockout_tracker:
            return False
        
        tracker = self.lockout_tracker[key]
        
        # Check if still in lockout period
        if tracker.get('locked_until'):
            if datetime.now() < tracker['locked_until']:
                return True
            else:
                # Lockout expired
                del self.lockout_tracker[key]
                return False
        
        # Check failure count
        return tracker.get('failure_count', 0) >= 3
    
    def record_auth_attempt(self, target: str, username: str, success: bool):
        """Record authentication attempt result"""
        key = f"{target}:{username}"
        
        if key not in self.lockout_tracker:
            self.lockout_tracker[key] = {'failure_count': 0, 'last_attempt': datetime.now()}
        
        tracker = self.lockout_tracker[key]
        tracker['last_attempt'] = datetime.now()
        
        if success:
            # Reset on success
            tracker['failure_count'] = 0
            if 'locked_until' in tracker:
                del tracker['locked_until']
        else:
            tracker['failure_count'] += 1
            
            # Implement progressive lockout
            if tracker['failure_count'] >= 3:
                lockout_duration = min(300, tracker['failure_count'] * 60)  # Max 5 minutes
                tracker['locked_until'] = datetime.now() + timedelta(seconds=lockout_duration)

class EndpointMapper:
    """Maps and discovers API endpoints"""
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.discovered_endpoints: Dict[str, APIEndpoint] = {}
        self.graphql_endpoints: List[str] = []
    
    async def discover_endpoints(self, base_url: str, session: Optional[AuthSession] = None) -> List[APIEndpoint]:
        """Discover API endpoints through crawling and analysis"""
        endpoints = []
        
        # Phase 1: Traditional crawling
        crawled_endpoints = await self._crawl_endpoints(base_url, session)
        endpoints.extend(crawled_endpoints)
        
        # Phase 2: JavaScript analysis
        js_endpoints = await self._analyze_javascript(base_url, session)
        endpoints.extend(js_endpoints)
        
        # Phase 3: GraphQL discovery
        graphql_endpoints = await self._discover_graphql(base_url, session)
        endpoints.extend(graphql_endpoints)
        
        # Phase 4: Common API patterns
        pattern_endpoints = await self._test_api_patterns(base_url, session)
        endpoints.extend(pattern_endpoints)
        
        return endpoints
    
    async def _crawl_endpoints(self, base_url: str, session: Optional[AuthSession]) -> List[APIEndpoint]:
        """Crawl for endpoints using authenticated session if available"""
        endpoints = []
        visited_urls = set()
        to_visit = [base_url]
        
        headers = {}
        if session and session.authenticated:
            headers.update(session.headers)
        
        while to_visit and len(visited_urls) < 50:  # Limit crawling
            await self.rate_limiter.acquire()
            
            url = to_visit.pop(0)
            if url in visited_urls:
                continue
            
            visited_urls.add(url)
            
            try:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                # Extract API endpoints from HTML
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Look for forms
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'GET').upper()
                        
                        if action:
                            full_url = urljoin(url, action)
                            endpoint = APIEndpoint(
                                path=full_url,
                                method=method,
                                parameters=self._extract_form_parameters(form),
                                auth_required=session is not None,
                                response_status=response.status_code,
                                response_size=len(response.content),
                                content_type=response.headers.get('Content-Type', ''),
                                requires_csrf=bool(soup.find('input', {'name': re.compile(r'csrf|_token', re.I)}))
                            )
                            endpoints.append(endpoint)
                    
                    # Look for AJAX endpoints in onclick handlers
                    for element in soup.find_all(attrs={'onclick': True}):
                        onclick = element['onclick']
                        ajax_matches = re.findall(r'["\']([^"\']*(?:api|ajax)[^"\']*)["\']', onclick)
                        for match in ajax_matches:
                            full_url = urljoin(url, match)
                            to_visit.append(full_url)
                
                # Extract links for further crawling
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.content, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('/') or base_url in href:
                            full_url = urljoin(base_url, href)
                            if len(to_visit) < 20:  # Limit queue size
                                to_visit.append(full_url)
                
            except Exception as e:
                continue
        
        return endpoints
    
    def _extract_form_parameters(self, form) -> List[str]:
        """Extract parameter names from form"""
        parameters = []
        for input_elem in form.find_all(['input', 'select', 'textarea']):
            name = input_elem.get('name')
            if name and name not in ['csrf_token', '_token']:
                parameters.append(name)
        return parameters
    
    async def _analyze_javascript(self, base_url: str, session: Optional[AuthSession]) -> List[APIEndpoint]:
        """Analyze JavaScript for API endpoints"""
        endpoints = []
        
        await self.rate_limiter.acquire()
        
        try:
            headers = {}
            if session and session.authenticated:
                headers.update(session.headers)
            
            response = requests.get(base_url, headers=headers, timeout=10, verify=False)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract inline JavaScript
                js_content = ""
                for script in soup.find_all('script'):
                    if script.string:
                        js_content += script.string + "\n"
                
                # Extract external JavaScript
                for script in soup.find_all('script', src=True):
                    try:
                        js_url = urljoin(base_url, script['src'])
                        await self.rate_limiter.acquire()
                        js_response = requests.get(js_url, headers=headers, timeout=10, verify=False)
                        js_content += js_response.text + "\n"
                    except:
                        continue
                
                # Extract API patterns from JavaScript
                api_patterns = [
                    r'["\']([^"\']*(?:api|endpoint)[^"\']*)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'fetch\(\s*["\']([^"\']+)["\']',
                    r'axios\.\w+\(\s*["\']([^"\']+)["\']',
                    r'\$\.(?:get|post|put|delete)\(\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        if match.startswith('/') or base_url in match:
                            full_url = urljoin(base_url, match)
                            endpoint = APIEndpoint(
                                path=full_url,
                                method='GET',  # Will be tested with multiple methods
                                parameters=[],
                                auth_required=session is not None,
                                response_status=0,
                                response_size=0,
                                content_type='application/json'
                            )
                            endpoints.append(endpoint)
                
                # Look for GraphQL endpoints
                graphql_patterns = [
                    r'["\']([^"\']*graphql[^"\']*)["\']',
                    r'query\s*:\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in graphql_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        full_url = urljoin(base_url, match)
                        self.graphql_endpoints.append(full_url)
        
        except Exception as e:
            pass
        
        return endpoints
    
    async def _discover_graphql(self, base_url: str, session: Optional[AuthSession]) -> List[APIEndpoint]:
        """Discover and analyze GraphQL endpoints"""
        endpoints = []
        common_graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graph']
        
        headers = {'Content-Type': 'application/json'}
        if session and session.authenticated:
            headers.update(session.headers)
        
        # Test common GraphQL paths
        for path in common_graphql_paths + self.graphql_endpoints:
            await self.rate_limiter.acquire()
            
            full_url = urljoin(base_url, path)
            
            # Try introspection query
            introspection_query = {
                "query": """
                {
                    __schema {
                        types {
                            name
                            fields {
                                name
                                type {
                                    name
                                }
                            }
                        }
                    }
                }
                """
            }
            
            try:
                response = requests.post(
                    full_url, 
                    json=introspection_query,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            # Successfully found GraphQL endpoint
                            endpoint = APIEndpoint(
                                path=full_url,
                                method='POST',
                                parameters=['query', 'variables'],
                                auth_required=session is not None,
                                response_status=response.status_code,
                                response_size=len(response.content),
                                content_type='application/json'
                            )
                            
                            # Extract object references from schema
                            object_refs = self._extract_graphql_objects(data)
                            endpoint.object_references = object_refs
                            
                            endpoints.append(endpoint)
                    except:
                        continue
            except:
                continue
        
        return endpoints
    
    def _extract_graphql_objects(self, schema_data: Dict) -> List[str]:
        """Extract object types and fields from GraphQL schema"""
        objects = []
        
        try:
            types = schema_data.get('data', {}).get('__schema', {}).get('types', [])
            
            for type_info in types:
                type_name = type_info.get('name', '')
                if not type_name.startswith('__'):  # Skip introspection types
                    objects.append(type_name)
                    
                    fields = type_info.get('fields', [])
                    for field in fields:
                        field_name = field.get('name', '')
                        if field_name and 'id' in field_name.lower():
                            objects.append(f"{type_name}.{field_name}")
        except:
            pass
        
        return objects
    
    async def _test_api_patterns(self, base_url: str, session: Optional[AuthSession]) -> List[APIEndpoint]:
        """Test common API path patterns"""
        endpoints = []
        
        # Common API patterns that might contain object references
        api_patterns = [
            '/api/v1/users', '/api/users', '/users',
            '/api/v1/orders', '/api/orders', '/orders', 
            '/api/v1/accounts', '/api/accounts', '/accounts',
            '/api/v1/prescriptions', '/api/prescriptions', '/prescriptions',
            '/api/v1/documents', '/api/documents', '/documents',
            '/api/v1/files', '/api/files', '/files',
            '/api/v1/profile', '/api/profile', '/profile',
            '/api/v1/settings', '/api/settings', '/settings'
        ]
        
        headers = {}
        if session and session.authenticated:
            headers.update(session.headers)
        
        for pattern in api_patterns:
            await self.rate_limiter.acquire()
            
            full_url = urljoin(base_url, pattern)
            
            try:
                response = requests.get(full_url, headers=headers, timeout=10, verify=False)
                
                if response.status_code in [200, 201, 401, 403]:  # Interesting responses
                    endpoint = APIEndpoint(
                        path=full_url,
                        method='GET',
                        parameters=['id', 'user_id', 'account_id'],  # Common IDOR parameters
                        auth_required=response.status_code in [401, 403],
                        response_status=response.status_code,
                        response_size=len(response.content),
                        content_type=response.headers.get('Content-Type', '')
                    )
                    endpoints.append(endpoint)
            except:
                continue
        
        return endpoints

class JWTAnalyzer:
    """Analyzes and manipulates JWT tokens"""
    
    @staticmethod
    def decode_jwt_safe(token: str) -> Optional[Dict[str, Any]]:
        """Safely decode JWT without verification"""
        try:
            # Decode without verification to inspect claims
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except:
            return None
    
    @staticmethod
    def extract_user_claims(token: str) -> Dict[str, Any]:
        """Extract user-related claims from JWT"""
        decoded = JWTAnalyzer.decode_jwt_safe(token)
        if not decoded:
            return {}
        
        user_claims = {}
        
        # Common user identifier fields
        user_fields = ['sub', 'uid', 'user_id', 'id', 'username', 'email']
        for field in user_fields:
            if field in decoded:
                user_claims[field] = decoded[field]
        
        # Role/permission fields
        role_fields = ['role', 'roles', 'permissions', 'scope', 'groups']
        for field in role_fields:
            if field in decoded:
                user_claims[field] = decoded[field]
        
        # Tenant/organization fields
        tenant_fields = ['tenant', 'tenant_id', 'org', 'organization', 'account_id']
        for field in tenant_fields:
            if field in decoded:
                user_claims[field] = decoded[field]
        
        return user_claims
    
    @staticmethod
    def is_expired(token: str) -> bool:
        """Check if JWT is expired"""
        decoded = JWTAnalyzer.decode_jwt_safe(token)
        if not decoded:
            return True
        
        exp = decoded.get('exp')
        if exp:
            return datetime.fromtimestamp(exp) < datetime.now()
        
        return False

class IDORHunter:
    """Main IDOR hunting orchestrator"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('requests_per_second', 5),
            burst_size=self.config.get('burst_size', 10)
        )
        
        self.credential_manager = CredentialManager(config)
        self.endpoint_mapper = EndpointMapper(self.rate_limiter)
        self.evidence_found: List[IDOREvidence] = []
    
    async def hunt_idor(self, target: str, fingerprint: Optional[TargetFingerprint] = None,
                       provided_credentials: Optional[List[Credential]] = None) -> Dict[str, Any]:
        """
        Comprehensive IDOR hunting process
        
        Args:
            target: Target URL to test
            fingerprint: Optional target fingerprint
            provided_credentials: Optional user-provided credentials
            
        Returns:
            Comprehensive IDOR hunting results
        """
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'authentication': {},
            'endpoints_discovered': [],
            'idor_evidence': [],
            'jwt_analysis': {},
            'summary': {}
        }
        
        # Phase 1: Authentication attempt
        session = None
        if provided_credentials:
            session = await self._authenticate_with_provided_creds(target, provided_credentials[0])
        else:
            session = await self._attempt_default_authentication(target, fingerprint)
        
        results['authentication'] = {
            'successful': session.authenticated if session else False,
            'session_type': 'jwt' if session and session.jwt_token else 'cookie',
            'user_claims': session.jwt_claims if session else {}
        }
        
        # Phase 2: Endpoint discovery
        endpoints = await self.endpoint_mapper.discover_endpoints(target, session)
        results['endpoints_discovered'] = [
            {
                'path': ep.path,
                'method': ep.method,
                'auth_required': ep.auth_required,
                'object_references': ep.object_references
            }
            for ep in endpoints
        ]
        
        # Phase 3: JWT analysis if present
        if session and session.jwt_token:
            jwt_analysis = self._analyze_jwt_token(session.jwt_token)
            results['jwt_analysis'] = jwt_analysis
        
        # Phase 4: IDOR testing
        idor_evidence = await self._test_idor_vulnerabilities(endpoints, session)
        results['idor_evidence'] = [
            {
                'endpoint': ev.endpoint,
                'method': ev.method,
                'evidence_type': ev.evidence_type,
                'severity': ev.severity,
                'confidence': ev.confidence,
                'unauthorized_data_keys': list(ev.unauthorized_data.keys())
            }
            for ev in idor_evidence
        ]
        
        # Generate summary
        results['summary'] = {
            'total_endpoints': len(endpoints),
            'idor_vulnerabilities_found': len(idor_evidence),
            'high_severity_issues': len([ev for ev in idor_evidence if ev.severity == 'High']),
            'authentication_successful': session.authenticated if session else False,
            'jwt_token_present': bool(session and session.jwt_token)
        }
        
        return results
    
    async def _authenticate_with_provided_creds(self, target: str, credential: Credential) -> Optional[AuthSession]:
        """Authenticate with provided credentials"""
        await self.rate_limiter.acquire()
        
        # Try to find login endpoint
        login_endpoints = ['/login', '/api/login', '/auth/login', '/signin', '/api/auth']
        
        for login_path in login_endpoints:
            login_url = urljoin(target, login_path)
            
            try:
                # Try POST with JSON
                response = requests.post(
                    login_url,
                    json={'username': credential.username, 'password': credential.password},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    session = self._create_session_from_response(response)
                    if session.authenticated:
                        return session
                
                # Try POST with form data
                response = requests.post(
                    login_url,
                    data={'username': credential.username, 'password': credential.password},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    session = self._create_session_from_response(response)
                    if session.authenticated:
                        return session
                        
            except:
                continue
        
        return None
    
    async def _attempt_default_authentication(self, target: str, fingerprint: Optional[TargetFingerprint]) -> Optional[AuthSession]:
        """Attempt authentication with default/weak credentials"""
        candidates = self.credential_manager.get_credential_candidates(fingerprint)
        
        for credential in candidates[:5]:  # Limit attempts
            if self.credential_manager.is_locked_out(target, credential.username):
                continue
            
            # Add jitter to avoid triggering rate limits
            await asyncio.sleep(random.uniform(1, 3))
            
            session = await self._authenticate_with_provided_creds(target, credential)
            
            success = session and session.authenticated
            self.credential_manager.record_auth_attempt(target, credential.username, success)
            
            if success:
                return session
        
        return None
    
    def _create_session_from_response(self, response: requests.Response) -> AuthSession:
        """Create session object from authentication response"""
        session = AuthSession(
            session_id=hashlib.md5(f"{response.url}{time.time()}".encode()).hexdigest(),
            cookies=dict(response.cookies),
            headers={}
        )
        
        # Extract JWT from response
        try:
            json_data = response.json()
            
            # Common JWT fields
            jwt_fields = ['token', 'access_token', 'jwt', 'authToken', 'bearerToken']
            for field in jwt_fields:
                if field in json_data:
                    session.jwt_token = json_data[field]
                    session.headers['Authorization'] = f'Bearer {session.jwt_token}'
                    break
            
            # Extract user info
            if 'user' in json_data:
                user_info = json_data['user']
                session.user_id = user_info.get('id') or user_info.get('user_id')
                session.role = user_info.get('role')
                
        except:
            pass
        
        # Check for session cookies
        if any(cookie_name in session.cookies for cookie_name in ['JSESSIONID', 'PHPSESSID', 'session']):
            session.authenticated = True
        
        # Analyze JWT if present
        if session.jwt_token:
            session.jwt_claims = JWTAnalyzer.extract_user_claims(session.jwt_token)
            session.user_id = session.jwt_claims.get('sub') or session.jwt_claims.get('uid')
            session.role = session.jwt_claims.get('role')
            session.authenticated = True
        
        return session
    
    def _analyze_jwt_token(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token for security issues"""
        analysis = {
            'claims': {},
            'security_issues': [],
            'expired': False,
            'algorithm': 'unknown'
        }
        
        try:
            # Decode header to check algorithm
            header = jwt.get_unverified_header(token)
            analysis['algorithm'] = header.get('alg', 'unknown')
            
            # Check for weak algorithms
            if analysis['algorithm'] in ['none', 'HS256']:
                analysis['security_issues'].append('weak_algorithm')
            
            # Extract claims
            analysis['claims'] = JWTAnalyzer.extract_user_claims(token)
            
            # Check if expired
            analysis['expired'] = JWTAnalyzer.is_expired(token)
            
        except Exception as e:
            analysis['security_issues'].append('decode_error')
        
        return analysis
    
    async def _test_idor_vulnerabilities(self, endpoints: List[APIEndpoint], 
                                       session: Optional[AuthSession]) -> List[IDOREvidence]:
        """Test endpoints for IDOR vulnerabilities"""
        evidence_list = []
        
        if not session or not session.authenticated:
            return evidence_list
        
        # Extract user context from session
        current_user_id = session.user_id or '1'
        current_role = session.role or 'user'
        
        # Test each endpoint
        for endpoint in endpoints:
            if not endpoint.auth_required:
                continue
            
            # Generate test object IDs
            test_ids = self._generate_test_object_ids(current_user_id)
            
            for test_id in test_ids:
                await self.rate_limiter.acquire()
                
                evidence = await self._test_single_endpoint(
                    endpoint, 
                    session, 
                    test_id,
                    current_user_id
                )
                
                if evidence:
                    evidence_list.append(evidence)
        
        return evidence_list
    
    def _generate_test_object_ids(self, current_user_id: str) -> List[str]:
        """Generate test object IDs for IDOR testing"""
        test_ids = []
        
        try:
            # If current ID is numeric, generate nearby numbers
            current_int = int(current_user_id)
            test_ids.extend([
                str(current_int - 1),
                str(current_int + 1),
                str(current_int - 10),
                str(current_int + 10),
                '1', '2', '100', '999'
            ])
        except ValueError:
            # Non-numeric ID, try common patterns
            test_ids.extend([
                'admin', 'administrator', 'user1', 'user2',
                'test', '1', '2', '100'
            ])
        
        return list(set(test_ids))  # Remove duplicates
    
    async def _test_single_endpoint(self, endpoint: APIEndpoint, session: AuthSession,
                                  test_id: str, current_user_id: str) -> Optional[IDOREvidence]:
        """Test single endpoint for IDOR vulnerability"""
        headers = session.headers.copy()
        
        # Build test URL with object ID
        test_url = endpoint.path
        if '{id}' in test_url:
            test_url = test_url.replace('{id}', test_id)
        elif endpoint.path.endswith('/'):
            test_url = f"{endpoint.path}{test_id}"
        else:
            test_url = f"{endpoint.path}/{test_id}"
        
        try:
            # Make request to original object (user's own)
            original_url = test_url.replace(test_id, current_user_id)
            original_response = requests.get(original_url, headers=headers, timeout=10, verify=False)
            
            # Make request to test object (potentially unauthorized)
            test_response = requests.get(test_url, headers=headers, timeout=10, verify=False)
            
            # Analyze responses for IDOR
            if self._analyze_idor_responses(original_response, test_response):
                evidence = IDOREvidence(
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    original_request={
                        'url': original_url,
                        'headers': dict(headers),
                        'user_id': current_user_id
                    },
                    modified_request={
                        'url': test_url,
                        'headers': dict(headers),
                        'test_id': test_id
                    },
                    original_response={
                        'status_code': original_response.status_code,
                        'size': len(original_response.content),
                        'content_type': original_response.headers.get('Content-Type', '')
                    },
                    modified_response={
                        'status_code': test_response.status_code,
                        'size': len(test_response.content),
                        'content_type': test_response.headers.get('Content-Type', '')
                    },
                    evidence_type=self._classify_evidence_type(test_response),
                    severity=self._calculate_severity(test_response),
                    confidence=self._calculate_confidence(original_response, test_response),
                    unauthorized_data=self._extract_unauthorized_data(test_response)
                )
                
                return evidence
                
        except Exception as e:
            pass
        
        return None
    
    def _analyze_idor_responses(self, original_response: requests.Response, 
                              test_response: requests.Response) -> bool:
        """Analyze responses to detect IDOR vulnerability"""
        
        # Check if test response succeeded when it shouldn't
        if test_response.status_code == 200 and original_response.status_code == 200:
            
            # Compare response sizes (simple heuristic)
            size_diff = abs(len(test_response.content) - len(original_response.content))
            if size_diff < 100:  # Similar sizes might indicate success
                return True
            
            # Check for JSON data
            try:
                test_data = test_response.json()
                orig_data = original_response.json()
                
                # Look for different user data in responses
                if self._contains_different_user_data(orig_data, test_data):
                    return True
                    
            except:
                pass
            
            # Check for sensitive data patterns
            if self._contains_sensitive_data(test_response.text):
                return True
        
        return False
    
    def _contains_different_user_data(self, orig_data: Any, test_data: Any) -> bool:
        """Check if responses contain different user data"""
        if isinstance(orig_data, dict) and isinstance(test_data, dict):
            # Look for user identifier fields
            user_fields = ['id', 'user_id', 'username', 'email', 'name']
            
            for field in user_fields:
                orig_val = orig_data.get(field)
                test_val = test_data.get(field)
                
                if orig_val and test_val and orig_val != test_val:
                    return True
        
        return False
    
    def _contains_sensitive_data(self, response_text: str) -> bool:
        """Check if response contains sensitive data patterns"""
        sensitive_patterns = [
            r'flag\{[^}]+\}',  # CTF flags
            r'"password":\s*"[^"]+',  # Password fields
            r'"email":\s*"[^"@]+@[^"]+',  # Email addresses
            r'"ssn":\s*"\d{3}-\d{2}-\d{4}',  # SSN
            r'"credit_card":\s*"\d{4}',  # Credit card
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _classify_evidence_type(self, response: requests.Response) -> str:
        """Classify the type of IDOR evidence"""
        if 'admin' in response.text.lower():
            return 'privilege_escalation'
        elif any(pattern in response.text.lower() for pattern in ['password', 'email', 'ssn']):
            return 'data_exposure'
        else:
            return 'object_access'
    
    def _calculate_severity(self, response: requests.Response) -> str:
        """Calculate severity based on response content"""
        content = response.text.lower()
        
        # Critical indicators
        if any(indicator in content for indicator in ['flag{', 'password', 'ssn', 'credit_card']):
            return 'Critical'
        
        # High indicators
        if any(indicator in content for indicator in ['admin', 'email', 'phone', 'address']):
            return 'High'
        
        # Medium indicators
        if response.status_code == 200:
            return 'Medium'
        
        return 'Low'
    
    def _calculate_confidence(self, original_response: requests.Response,
                            test_response: requests.Response) -> float:
        """Calculate confidence score for IDOR finding"""
        confidence = 0.5
        
        # Boost confidence for successful unauthorized access
        if test_response.status_code == 200:
            confidence += 0.3
        
        # Boost for different response content
        if len(test_response.content) != len(original_response.content):
            confidence += 0.2
        
        # Boost for sensitive data
        if self._contains_sensitive_data(test_response.text):
            confidence += 0.3
        
        return min(1.0, confidence)
    
    def _extract_unauthorized_data(self, response: requests.Response) -> Dict[str, Any]:
        """Extract unauthorized data from response"""
        unauthorized_data = {}
        
        try:
            if 'application/json' in response.headers.get('Content-Type', ''):
                data = response.json()
                
                # Extract sensitive fields
                sensitive_fields = ['password', 'email', 'phone', 'ssn', 'flag']
                for field in sensitive_fields:
                    if field in str(data).lower():
                        unauthorized_data[field] = 'REDACTED'
                
        except:
            # Look for patterns in text
            if re.search(r'flag\{[^}]+\}', response.text):
                unauthorized_data['flag'] = 'FOUND'
        
        return unauthorized_data
