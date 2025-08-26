"""
State Manager Plugin for CyberShell
Handles authentication, session management, and state persistence across exploitation attempts
"""

import json
import time
import pickle
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import requests
from urllib.parse import urlparse
import jwt
import re

class StateManagerPlugin:
    """
    Manages authentication state, sessions, and context across multiple exploitation attempts
    """
    
    def __init__(self):
        self.sessions = {}
        self.credentials_store = {}
        self.tokens = {}
        self.cookies = {}
        self.csrf_tokens = {}
        self.api_keys = {}
        self.state_file = './sessions/state.pkl'
        self.session_timeout = 3600  # 1 hour default
        
    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for state management
        """
        action = kwargs.get('action', 'get_session')
        target = kwargs.get('target', '')
        
        if action == 'login':
            return self.handle_login(target, kwargs.get('credentials', {}))
        elif action == 'get_session':
            return self.get_active_session(target)
        elif action == 'refresh':
            return self.refresh_session(target)
        elif action == 'save_state':
            return self.save_state()
        elif action == 'load_state':
            return self.load_state()
        elif action == 'multi_step_auth':
            return self.handle_multi_step_auth(target, kwargs)
            
    def handle_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle various types of login mechanisms
        """
        # Detect login type
        login_type = self.detect_login_type(target)
        
        if login_type == 'form':
            return self.form_login(target, credentials)
        elif login_type == 'json':
            return self.json_login(target, credentials)
        elif login_type == 'oauth':
            return self.oauth_login(target, credentials)
        elif login_type == 'jwt':
            return self.jwt_login(target, credentials)
        elif login_type == 'graphql':
            return self.graphql_login(target, credentials)
        else:
            return self.generic_login(target, credentials)
            
    def detect_login_type(self, target: str) -> str:
        """
        Detect the type of authentication mechanism
        """
        try:
            response = requests.get(target, timeout=5)
            content = response.text.lower()
            
            if 'graphql' in content or '/graphql' in content:
                return 'graphql'
            elif 'oauth' in content or 'authorize' in content:
                return 'oauth'
            elif 'application/json' in response.headers.get('Content-Type', ''):
                return 'json'
            elif '<form' in content and 'password' in content:
                return 'form'
            elif 'jwt' in content or 'bearer' in content:
                return 'jwt'
            else:
                return 'unknown'
        except:
            return 'unknown'
            
    def form_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle form-based login
        """
        session = requests.Session()
        
        # Get login page to extract CSRF token
        login_page = session.get(target)
        csrf_token = self.extract_csrf_token(login_page.text)
        
        # Common credential combinations if not provided
        if not credentials:
            credentials = self.try_common_credentials()
            
        login_data = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin'),
            'csrf_token': csrf_token,
            'submit': 'Login'
        }
        
        # Try different parameter names
        param_variations = [
            {'username': 'user', 'password': 'pass'},
            {'username': 'email', 'password': 'password'},
            {'username': 'login', 'password': 'pwd'},
            {'username': 'uname', 'password': 'passwd'}
        ]
        
        for variation in param_variations:
            test_data = {}
            for key, alt_key in variation.items():
                test_data[alt_key] = login_data[key]
            test_data['csrf_token'] = csrf_token
            
            response = session.post(target, data=test_data, allow_redirects=True)
            
            if self.check_login_success(response):
                self.sessions[target] = session
                self.cookies[target] = session.cookies.get_dict()
                return {
                    'success': True,
                    'session': session,
                    'cookies': self.cookies[target],
                    'message': 'Login successful'
                }
                
        return {'success': False, 'message': 'Login failed'}
        
    def json_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle JSON-based API login
        """
        session = requests.Session()
        
        if not credentials:
            credentials = self.try_common_credentials()
            
        login_data = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin')
        }
        
        headers = {'Content-Type': 'application/json'}
        
        # Try different endpoints
        endpoints = ['/login', '/api/login', '/auth/login', '/api/auth/login', '/authenticate']
        
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        
        for endpoint in endpoints:
            try:
                response = session.post(
                    f"{base_url}{endpoint}",
                    json=login_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract token
                    token = data.get('token') or data.get('access_token') or data.get('auth_token')
                    if token:
                        self.tokens[target] = token
                        session.headers['Authorization'] = f'Bearer {token}'
                        
                    # Extract user info
                    user_id = data.get('userId') or data.get('user_id') or data.get('id')
                    
                    self.sessions[target] = session
                    return {
                        'success': True,
                        'session': session,
                        'token': token,
                        'user_id': user_id,
                        'message': 'JSON login successful'
                    }
            except:
                continue
                
        return {'success': False, 'message': 'JSON login failed'}
        
    def graphql_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle GraphQL-based login
        """
        session = requests.Session()
        
        if not credentials:
            credentials = self.try_common_credentials()
            
        # GraphQL login mutation
        login_mutation = """
        mutation Login($username: String!, $password: String!) {
            login(username: $username, password: $password) {
                token
                user {
                    id
                    username
                    role
                }
            }
        }
        """
        
        variables = {
            'username': credentials.get('username', 'admin'),
            'password': credentials.get('password', 'admin')
        }
        
        # Try different GraphQL endpoints
        endpoints = ['/graphql', '/api/graphql', '/query', '/gql']
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        
        for endpoint in endpoints:
            try:
                response = session.post(
                    f"{base_url}{endpoint}",
                    json={'query': login_mutation, 'variables': variables},
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and 'login' in data['data']:
                        login_data = data['data']['login']
                        token = login_data.get('token')
                        
                        if token:
                            self.tokens[target] = token
                            session.headers['Authorization'] = f'Bearer {token}'
                            
                        self.sessions[target] = session
                        return {
                            'success': True,
                            'session': session,
                            'token': token,
                            'user_data': login_data.get('user'),
                            'message': 'GraphQL login successful'
                        }
            except:
                continue
                
        return {'success': False, 'message': 'GraphQL login failed'}
        
    def oauth_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle OAuth authentication flow
        """
        session = requests.Session()
        
        # OAuth flow typically requires:
        # 1. Get authorization code
        # 2. Exchange code for token
        # 3. Use token for API access
        
        # This is a simplified implementation
        oauth_params = {
            'client_id': credentials.get('client_id', 'test_client'),
            'redirect_uri': 'http://localhost/callback',
            'response_type': 'code',
            'scope': 'read write'
        }
        
        # Would need actual OAuth implementation here
        # For now, return a placeholder
        return {
            'success': False,
            'message': 'OAuth implementation needed',
            'flow_type': 'oauth2'
        }
        
    def jwt_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Handle JWT-based authentication
        """
        session = requests.Session()
        
        # First try standard login to get JWT
        result = self.json_login(target, credentials)
        
        if result['success'] and result.get('token'):
            # Decode JWT to get expiration
            try:
                decoded = jwt.decode(result['token'], options={"verify_signature": False})
                exp = decoded.get('exp')
                if exp:
                    self.token_expiry[target] = datetime.fromtimestamp(exp)
            except:
                pass
                
        return result
        
    def generic_login(self, target: str, credentials: Dict) -> Dict[str, Any]:
        """
        Generic login attempt for unknown authentication types
        """
        # Try various methods in sequence
        methods = [
            self.form_login,
            self.json_login,
            self.graphql_login,
            self.jwt_login
        ]
        
        for method in methods:
            result = method(target, credentials)
            if result['success']:
                return result
                
        return {'success': False, 'message': 'All login methods failed'}
        
    def handle_multi_step_auth(self, target: str, kwargs: Dict) -> Dict[str, Any]:
        """
        Handle multi-step authentication (MFA, OTP, etc.)
        """
        step = kwargs.get('step', 1)
        
        if step == 1:
            # Initial login
            return self.handle_login(target, kwargs.get('credentials', {}))
        elif step == 2:
            # Handle MFA/OTP
            otp = kwargs.get('otp', '')
            session = self.sessions.get(target)
            
            if session and otp:
                response = session.post(
                    f"{target}/verify-otp",
                    json={'otp': otp}
                )
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'session': session,
                        'message': 'Multi-factor authentication successful'
                    }
                    
        return {'success': False, 'message': 'Multi-step authentication failed'}
        
    def get_active_session(self, target: str) -> Dict[str, Any]:
        """
        Get an active session for the target
        """
        if target in self.sessions:
            session = self.sessions[target]
            
            # Check if session is still valid
            if self.validate_session(target, session):
                return {
                    'success': True,
                    'session': session,
                    'cookies': self.cookies.get(target),
                    'token': self.tokens.get(target),
                    'csrf_token': self.csrf_tokens.get(target)
                }
            else:
                # Try to refresh
                return self.refresh_session(target)
                
        return {'success': False, 'message': 'No active session found'}
        
    def validate_session(self, target: str, session: requests.Session) -> bool:
        """
        Validate if a session is still active
        """
        try:
            # Try to access a protected endpoint
            response = session.get(f"{target}/api/user", timeout=5)
            return response.status_code != 401
        except:
            return False
            
    def refresh_session(self, target: str) -> Dict[str, Any]:
        """
        Refresh an expired session
        """
        if target in self.tokens:
            # Try token refresh
            refresh_token = self.tokens.get(f"{target}_refresh")
            if refresh_token:
                return self.refresh_token(target, refresh_token)
                
        # Try to re-login with stored credentials
        if target in self.credentials_store:
            return self.handle_login(target, self.credentials_store[target])
            
        return {'success': False, 'message': 'Unable to refresh session'}
        
    def refresh_token(self, target: str, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token
        """
        try:
            response = requests.post(
                f"{target}/refresh",
                json={'refresh_token': refresh_token}
            )
            
            if response.status_code == 200:
                data = response.json()
                new_token = data.get('access_token')
                
                if new_token:
                    self.tokens[target] = new_token
                    if target in self.sessions:
                        self.sessions[target].headers['Authorization'] = f'Bearer {new_token}'
                        
                    return {
                        'success': True,
                        'token': new_token,
                        'message': 'Token refreshed successfully'
                    }
        except:
            pass
            
        return {'success': False, 'message': 'Token refresh failed'}
        
    def extract_csrf_token(self, html: str) -> Optional[str]:
        """
        Extract CSRF token from HTML
        """
        patterns = [
            r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'name=["\']csrf[_-]?token["\'].*?value=["\']([^"\']+)',
            r'<meta name=["\']csrf-token["\'] content=["\']([^"\']+)',
            r'X-CSRF-Token["\']:\s*["\']([^"\']+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
        
    def check_login_success(self, response: requests.Response) -> bool:
        """
        Check if login was successful
        """
        # Check status code
        if response.status_code in [200, 302]:
            # Check for success indicators
            success_indicators = [
                'dashboard', 'welcome', 'profile', 'logout',
                'success', 'authenticated'
            ]
            
            for indicator in success_indicators:
                if indicator in response.url.lower() or indicator in response.text.lower():
                    return True
                    
            # Check for failure indicators
            failure_indicators = [
                'invalid', 'failed', 'error', 'incorrect',
                'wrong', 'denied'
            ]
            
            for indicator in failure_indicators:
                if indicator in response.text.lower():
                    return False
                    
            # If redirected away from login page, probably successful
            if 'login' not in response.url.lower():
                return True
                
        return False
        
    def try_common_credentials(self) -> Dict[str, str]:
        """
        Try common default credentials
        """
        common_creds = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'user', 'password': 'user'},
            {'username': 'test', 'password': 'test'},
            {'username': 'demo', 'password': 'demo'},
            {'username': 'guest', 'password': 'guest'},
            {'username': 'root', 'password': 'root'},
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'administrator', 'password': 'password'}
        ]
        
        # Return first set for now
        # Could iterate through all in actual implementation
        return common_creds[0]
        
    def save_state(self) -> Dict[str, Any]:
        """
        Save current state to disk
        """
        state = {
            'sessions': self.sessions,
            'tokens': self.tokens,
            'cookies': self.cookies,
            'csrf_tokens': self.csrf_tokens,
            'credentials': self.credentials_store
        }
        
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump(state, f)
            return {'success': True, 'message': 'State saved'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to save state: {e}'}
            
    def load_state(self) -> Dict[str, Any]:
        """
        Load state from disk
        """
        try:
            with open(self.state_file, 'rb') as f:
                state = pickle.load(f)
                
            self.sessions = state.get('sessions', {})
            self.tokens = state.get('tokens', {})
            self.cookies = state.get('cookies', {})
            self.csrf_tokens = state.get('csrf_tokens', {})
            self.credentials_store = state.get('credentials', {})
            
            return {'success': True, 'message': 'State loaded'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to load state: {e}'}
