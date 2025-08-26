"""
Business Logic Plugin for CyberShell
Detects and exploits business logic vulnerabilities like IDOR, race conditions, price manipulation
"""

import requests
import threading
import time
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import hashlib
from decimal import Decimal
import itertools

class BusinessLogicPlugin:
    """
    Detects and exploits complex business logic vulnerabilities
    """
    
    def __init__(self):
        self.session = None
        self.found_vulnerabilities = []
        self.test_results = []
        self.baseline_responses = {}
        
    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for business logic testing
        """
        target = kwargs.get('target', '')
        session = kwargs.get('session')
        test_type = kwargs.get('test_type', 'all')
        
        self.session = session or requests.Session()
        
        if test_type == 'all':
            return self.run_all_tests(target)
        elif test_type == 'idor':
            return self.test_idor(target)
        elif test_type == 'race_condition':
            return self.test_race_conditions(target)
        elif test_type == 'price_manipulation':
            return self.test_price_manipulation(target)
        elif test_type == 'workflow':
            return self.test_workflow_bypass(target)
        elif test_type == 'authorization':
            return self.test_authorization_flaws(target)
        elif test_type == 'graphql':
            return self.test_graphql_vulnerabilities(target)
            
    def run_all_tests(self, target: str) -> Dict[str, Any]:
        """
        Run all business logic tests
        """
        results = {
            'vulnerabilities': [],
            'test_results': {},
            'risk_score': 0
        }
        
        # IDOR Testing
        idor_result = self.test_idor(target)
        if idor_result['vulnerable']:
            results['vulnerabilities'].append(idor_result)
            results['risk_score'] += idor_result['severity_score']
            
        # Race Condition Testing
        race_result = self.test_race_conditions(target)
        if race_result['vulnerable']:
            results['vulnerabilities'].append(race_result)
            results['risk_score'] += race_result['severity_score']
            
        # Price Manipulation Testing
        price_result = self.test_price_manipulation(target)
        if price_result['vulnerable']:
            results['vulnerabilities'].append(price_result)
            results['risk_score'] += price_result['severity_score']
            
        # Workflow Bypass Testing
        workflow_result = self.test_workflow_bypass(target)
        if workflow_result['vulnerable']:
            results['vulnerabilities'].append(workflow_result)
            results['risk_score'] += workflow_result['severity_score']
            
        # Authorization Testing
        auth_result = self.test_authorization_flaws(target)
        if auth_result['vulnerable']:
            results['vulnerabilities'].append(auth_result)
            results['risk_score'] += auth_result['severity_score']
            
        # GraphQL Testing
        graphql_result = self.test_graphql_vulnerabilities(target)
        if graphql_result['vulnerable']:
            results['vulnerabilities'].append(graphql_result)
            results['risk_score'] += graphql_result['severity_score']
            
        return results
        
    def test_idor(self, target: str) -> Dict[str, Any]:
        """
        Test for Insecure Direct Object References
        """
        vulnerable_endpoints = []
        
        # Find endpoints with IDs
        endpoints = self.discover_id_endpoints(target)
        
        for endpoint in endpoints:
            # Get baseline response for valid ID
            baseline = self.get_baseline_response(endpoint['url'], endpoint['id'])
            
            # Test adjacent IDs
            for test_id in self.generate_test_ids(endpoint['id']):
                test_url = endpoint['url'].replace(str(endpoint['id']), str(test_id))
                
                try:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if we got data for different ID
                    if response.status_code == 200:
                        if self.is_different_object(baseline, response):
                            vulnerable_endpoints.append({
                                'endpoint': endpoint['url'],
                                'original_id': endpoint['id'],
                                'accessed_id': test_id,
                                'response': response.text[:500]
                            })
                            
                except:
                    continue
                    
        # Test for IDOR in GraphQL
        graphql_idor = self.test_graphql_idor(target)
        if graphql_idor:
            vulnerable_endpoints.extend(graphql_idor)
            
        return {
            'vulnerable': len(vulnerable_endpoints) > 0,
            'type': 'IDOR',
            'endpoints': vulnerable_endpoints,
            'severity_score': 8 if vulnerable_endpoints else 0,
            'description': 'Insecure Direct Object Reference allows accessing other users\' data'
        }
        
    def test_race_conditions(self, target: str) -> Dict[str, Any]:
        """
        Test for race condition vulnerabilities
        """
        vulnerable_operations = []
        
        # Test common race condition scenarios
        scenarios = [
            {'endpoint': '/api/transfer', 'action': 'money_transfer'},
            {'endpoint': '/api/coupon/apply', 'action': 'coupon_application'},
            {'endpoint': '/api/vote', 'action': 'voting'},
            {'endpoint': '/api/withdraw', 'action': 'withdrawal'},
            {'endpoint': '/api/purchase', 'action': 'purchase'}
        ]
        
        for scenario in scenarios:
            endpoint = f"{target}{scenario['endpoint']}"
            
            if self.endpoint_exists(endpoint):
                # Perform race condition test
                result = self.execute_race_condition_test(endpoint, scenario['action'])
                
                if result['vulnerable']:
                    vulnerable_operations.append(result)
                    
        return {
            'vulnerable': len(vulnerable_operations) > 0,
            'type': 'Race Condition',
            'operations': vulnerable_operations,
            'severity_score': 9 if vulnerable_operations else 0,
            'description': 'Race conditions allow exploiting timing vulnerabilities'
        }
        
    def execute_race_condition_test(self, endpoint: str, action: str) -> Dict[str, Any]:
        """
        Execute race condition test with parallel requests
        """
        num_threads = 20
        results = []
        
        def send_request():
            try:
                if action == 'money_transfer':
                    data = {'amount': 100, 'to_account': 'test123'}
                elif action == 'coupon_application':
                    data = {'coupon_code': 'DISCOUNT50'}
                elif action == 'voting':
                    data = {'vote_id': 1}
                elif action == 'withdrawal':
                    data = {'amount': 1000}
                else:
                    data = {'quantity': 1}
                    
                response = self.session.post(endpoint, json=data, timeout=5)
                return response.status_code, response.text
            except:
                return None, None
                
        # Send parallel requests
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(send_request) for _ in range(num_threads)]
            
            for future in as_completed(futures):
                status, response = future.result()
                if status and response:
                    results.append({'status': status, 'response': response})
                    
        # Analyze results for race condition indicators
        success_count = sum(1 for r in results if r['status'] == 200)
        
        if success_count > 1:
            # Multiple successes indicate race condition
            return {
                'vulnerable': True,
                'endpoint': endpoint,
                'action': action,
                'success_count': success_count,
                'total_requests': num_threads
            }
            
        return {'vulnerable': False}
        
    def test_price_manipulation(self, target: str) -> Dict[str, Any]:
        """
        Test for price manipulation vulnerabilities
        """
        vulnerable_endpoints = []
        
        # Find shopping/payment endpoints
        endpoints = [
            '/api/cart/update',
            '/api/checkout',
            '/api/order/create',
            '/api/payment/process',
            '/api/product/price'
        ]
        
        for endpoint_path in endpoints:
            endpoint = f"{target}{endpoint_path}"
            
            if self.endpoint_exists(endpoint):
                # Test various price manipulation techniques
                manipulations = [
                    {'price': -100, 'technique': 'negative_price'},
                    {'price': 0.001, 'technique': 'decimal_bypass'},
                    {'price': '0', 'technique': 'string_zero'},
                    {'price': None, 'technique': 'null_price'},
                    {'quantity': -1, 'technique': 'negative_quantity'},
                    {'discount': 200, 'technique': 'excessive_discount'},
                    {'currency': 'XXX', 'technique': 'invalid_currency'}
                ]
                
                for manipulation in manipulations:
                    try:
                        response = self.session.post(
                            endpoint,
                            json=manipulation,
                            timeout=5
                        )
                        
                        # Check if manipulation was accepted
                        if response.status_code == 200:
                            if self.check_price_accepted(response.text, manipulation):
                                vulnerable_endpoints.append({
                                    'endpoint': endpoint,
                                    'manipulation': manipulation,
                                    'response': response.text[:500]
                                })
                    except:
                        continue
                        
        return {
            'vulnerable': len(vulnerable_endpoints) > 0,
            'type': 'Price Manipulation',
            'endpoints': vulnerable_endpoints,
            'severity_score': 10 if vulnerable_endpoints else 0,
            'description': 'Price manipulation allows altering transaction amounts'
        }
        
    def test_workflow_bypass(self, target: str) -> Dict[str, Any]:
        """
        Test for workflow bypass vulnerabilities
        """
        vulnerable_workflows = []
        
        # Test skipping steps in multi-step processes
        workflows = [
            {
                'name': 'registration',
                'steps': ['/register/step1', '/register/step2', '/register/complete']
            },
            {
                'name': 'checkout',
                'steps': ['/checkout/cart', '/checkout/shipping', '/checkout/payment', '/checkout/confirm']
            },
            {
                'name': 'verification',
                'steps': ['/verify/email', '/verify/phone', '/verify/identity']
            }
        ]
        
        for workflow in workflows:
            # Try to access final step directly
            final_step = f"{target}{workflow['steps'][-1]}"
            
            try:
                response = self.session.get(final_step, timeout=5)
                
                if response.status_code == 200:
                    # Check if we bypassed previous steps
                    if self.is_workflow_bypassed(response.text):
                        vulnerable_workflows.append({
                            'workflow': workflow['name'],
                            'bypassed_steps': workflow['steps'][:-1],
                            'accessed_directly': final_step
                        })
            except:
                continue
                
        # Test state manipulation
        state_vulns = self.test_state_manipulation(target)
        if state_vulns:
            vulnerable_workflows.extend(state_vulns)
            
        return {
            'vulnerable': len(vulnerable_workflows) > 0,
            'type': 'Workflow Bypass',
            'workflows': vulnerable_workflows,
            'severity_score': 7 if vulnerable_workflows else 0,
            'description': 'Workflow bypass allows skipping required steps'
        }
        
    def test_authorization_flaws(self, target: str) -> Dict[str, Any]:
        """
        Test for authorization vulnerabilities
        """
        vulnerable_endpoints = []
        
        # Test horizontal privilege escalation
        horizontal_vulns = self.test_horizontal_privilege_escalation(target)
        if horizontal_vulns:
            vulnerable_endpoints.extend(horizontal_vulns)
            
        # Test vertical privilege escalation
        vertical_vulns = self.test_vertical_privilege_escalation(target)
        if vertical_vulns:
            vulnerable_endpoints.extend(vertical_vulns)
            
        # Test missing function level access control
        function_vulns = self.test_function_level_access(target)
        if function_vulns:
            vulnerable_endpoints.extend(function_vulns)
            
        return {
            'vulnerable': len(vulnerable_endpoints) > 0,
            'type': 'Authorization Flaws',
            'endpoints': vulnerable_endpoints,
            'severity_score': 9 if vulnerable_endpoints else 0,
            'description': 'Authorization flaws allow unauthorized access to resources'
        }
        
    def test_graphql_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """
        Test for GraphQL-specific vulnerabilities
        """
        vulnerabilities = []
        
        # Find GraphQL endpoint
        graphql_endpoint = self.find_graphql_endpoint(target)
        
        if graphql_endpoint:
            # Test introspection
            introspection_result = self.test_graphql_introspection(graphql_endpoint)
            if introspection_result['vulnerable']:
                vulnerabilities.append(introspection_result)
                
            # Test for IDOR in GraphQL
            idor_result = self.test_graphql_idor_detailed(graphql_endpoint)
            if idor_result['vulnerable']:
                vulnerabilities.append(idor_result)
                
            # Test for batching attacks
            batching_result = self.test_graphql_batching(graphql_endpoint)
            if batching_result['vulnerable']:
                vulnerabilities.append(batching_result)
                
            # Test for deep nesting
            nesting_result = self.test_graphql_deep_nesting(graphql_endpoint)
            if nesting_result['vulnerable']:
                vulnerabilities.append(nesting_result)
                
        return {
            'vulnerable': len(vulnerabilities) > 0,
            'type': 'GraphQL Vulnerabilities',
            'vulnerabilities': vulnerabilities,
            'severity_score': 8 if vulnerabilities else 0,
            'description': 'GraphQL API vulnerabilities'
        }
        
    def test_graphql_introspection(self, endpoint: str) -> Dict[str, Any]:
        """
        Test if GraphQL introspection is enabled
        """
        introspection_query = """
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
        
        try:
            response = self.session.post(
                endpoint,
                json={'query': introspection_query},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if '__schema' in data.get('data', {}):
                    return {
                        'vulnerable': True,
                        'type': 'GraphQL Introspection Enabled',
                        'schema': data['data']['__schema']
                    }
        except:
            pass
            
        return {'vulnerable': False}
        
    def test_graphql_idor_detailed(self, endpoint: str) -> Dict[str, Any]:
        """
        Test for IDOR in GraphQL queries
        """
        vulnerable_queries = []
        
        # Common GraphQL queries that might have IDOR
        queries = [
            {
                'name': 'user',
                'query': 'query { user(id: %s) { id username email } }',
                'id_field': 'id'
            },
            {
                'name': 'order',
                'query': 'query { order(orderId: %s) { id amount status } }',
                'id_field': 'orderId'
            },
            {
                'name': 'document',
                'query': 'query { document(docId: %s) { id title content } }',
                'id_field': 'docId'
            }
        ]
        
        for query_template in queries:
            # Test with different IDs
            for test_id in [1, 2, 100, 1000]:
                query = query_template['query'] % test_id
                
                try:
                    response = self.session.post(
                        endpoint,
                        json={'query': query},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if 'data' in data and data['data']:
                            vulnerable_queries.append({
                                'query_type': query_template['name'],
                                'accessed_id': test_id,
                                'data': data['data']
                            })
                except:
                    continue
                    
        return {
            'vulnerable': len(vulnerable_queries) > 0,
            'type': 'GraphQL IDOR',
            'queries': vulnerable_queries
        }
        
    def test_graphql_batching(self, endpoint: str) -> Dict[str, Any]:
        """
        Test for GraphQL batching attacks
        """
        # Send multiple queries in one request
        batch_query = """
        query {
            user1: user(id: 1) { id username }
            user2: user(id: 2) { id username }
            user3: user(id: 3) { id username }
            user4: user(id: 4) { id username }
            user5: user(id: 5) { id username }
        }
        """
        
        try:
            response = self.session.post(
                endpoint,
                json={'query': batch_query},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    users_found = sum(1 for k in data['data'] if data['data'][k])
                    if users_found > 1:
                        return {
                            'vulnerable': True,
                            'type': 'GraphQL Batching Attack',
                            'users_accessed': users_found
                        }
        except:
            pass
            
        return {'vulnerable': False}
        
    def test_graphql_deep_nesting(self, endpoint: str) -> Dict[str, Any]:
        """
        Test for deep nesting DoS in GraphQL
        """
        # Create deeply nested query
        nested_query = """
        query {
            user(id: 1) {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                text
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            start_time = time.time()
            response = self.session.post(
                endpoint,
                json={'query': nested_query},
                timeout=10
            )
            response_time = time.time() - start_time
            
            # If response takes too long, might be vulnerable
            if response_time > 5:
                return {
                    'vulnerable': True,
                    'type': 'GraphQL Deep Nesting DoS',
                    'response_time': response_time
                }
        except:
            pass
            
        return {'vulnerable': False}
        
    # Helper methods
    def discover_id_endpoints(self, target: str) -> List[Dict]:
        """
        Discover endpoints that use IDs
        """
        endpoints = []
        
        # Common patterns
        patterns = [
            r'/api/user/(\d+)',
            r'/api/order/(\d+)',
            r'/api/document/(\d+)',
            r'/api/product/(\d+)',
            r'/profile/(\d+)',
            r'/post/(\d+)',
            r'/item/(\d+)'
        ]
        
        # Would need actual endpoint discovery here
        # Using placeholders for now
        test_endpoints = [
            {'url': f'{target}/api/user/1', 'id': 1},
            {'url': f'{target}/api/order/1', 'id': 1},
            {'url': f'{target}/api/document/1', 'id': 1}
        ]
        
        for endpoint in test_endpoints:
            if self.endpoint_exists(endpoint['url']):
                endpoints.append(endpoint)
                
        return endpoints
        
    def generate_test_ids(self, original_id: int) -> List[int]:
        """
        Generate test IDs for IDOR testing
        """
        test_ids = []
        
        # Adjacent IDs
        test_ids.extend([original_id - 1, original_id + 1])
        
        # Common IDs
        test_ids.extend([0, 1, 2, 100, 1000])
        
        # Random IDs
        test_ids.extend([random.randint(1, 10000) for _ in range(5)])
        
        return list(set(test_ids))
        
    def endpoint_exists(self, endpoint: str) -> bool:
        """
        Check if endpoint exists
        """
        try:
            response = self.session.head(endpoint, timeout=2)
            return response.status_code != 404
        except:
            return False
            
    def find_graphql_endpoint(self, target: str) -> Optional[str]:
        """
        Find GraphQL endpoint
        """
        common_paths = ['/graphql', '/api/graphql', '/query', '/api', '/gql']
        
        for path in common_paths:
            endpoint = f"{target}{path}"
            try:
                response = self.session.post(
                    endpoint,
                    json={'query': '{ __typename }'},
                    timeout=2
                )
                if response.status_code == 200:
                    return endpoint
            except:
                continue
                
        return None
        
    def get_baseline_response(self, url: str, obj_id: int) -> Dict:
        """
        Get baseline response for comparison
        """
        try:
            response = self.session.get(url, timeout=5)
            return {
                'status': response.status_code,
                'content': response.text,
                'headers': dict(response.headers)
            }
        except:
            return {}
            
    def is_different_object(self, baseline: Dict, response: requests.Response) -> bool:
        """
        Check if response contains different object
        """
        if not baseline:
            return False
            
        # Compare response content
        if response.text != baseline.get('content', ''):
            # Check if it's actually different data, not just an error
            if 'error' not in response.text.lower() and 'denied' not in response.text.lower():
                return True
                
        return False
        
    def check_price_accepted(self, response_text: str, manipulation: Dict) -> bool:
        """
        Check if price manipulation was accepted
        """
        # Look for indicators that the manipulated price was accepted
        if 'success' in response_text.lower():
            return True
        if 'total' in response_text.lower() and str(manipulation.get('price', '')) in response_text:
            return True
        return False
        
    def is_workflow_bypassed(self, response_text: str) -> bool:
        """
        Check if workflow was bypassed
        """
        # Look for success indicators without completing previous steps
        success_indicators = ['success', 'complete', 'confirmed', 'thank you']
        error_indicators = ['error', 'required', 'missing', 'invalid']
        
        for indicator in success_indicators:
            if indicator in response_text.lower():
                for error in error_indicators:
                    if error in response_text.lower():
                        return False
                return True
        return False
        
    def test_horizontal_privilege_escalation(self, target: str) -> List[Dict]:
        """
        Test for horizontal privilege escalation
        """
        vulnerabilities = []
        
        # Test accessing other users' resources
        endpoints = [
            '/api/user/{id}/profile',
            '/api/account/{id}/settings',
            '/api/order/{id}/details'
        ]
        
        for endpoint_template in endpoints:
            # Test with different user IDs
            for user_id in [1, 2, 100]:
                endpoint = f"{target}{endpoint_template.format(id=user_id)}"
                
                try:
                    response = self.session.get(endpoint, timeout=5)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Horizontal Privilege Escalation',
                            'endpoint': endpoint,
                            'accessed_user_id': user_id
                        })
                except:
                    continue
                    
        return vulnerabilities
        
    def test_vertical_privilege_escalation(self, target: str) -> List[Dict]:
        """
        Test for vertical privilege escalation
        """
        vulnerabilities = []
        
        # Test accessing admin endpoints
        admin_endpoints = [
            '/admin',
            '/api/admin/users',
            '/api/admin/settings',
            '/dashboard/admin'
        ]
        
        for endpoint_path in admin_endpoints:
            endpoint = f"{target}{endpoint_path}"
            
            try:
                response = self.session.get(endpoint, timeout=5)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Vertical Privilege Escalation',
                        'endpoint': endpoint,
                        'accessed_as': 'regular_user'
                    })
            except:
                continue
                
        return vulnerabilities
        
    def test_function_level_access(self, target: str) -> List[Dict]:
        """
        Test for missing function level access control
        """
        vulnerabilities = []
        
        # Test sensitive functions
        sensitive_functions = [
            {'method': 'DELETE', 'path': '/api/user/{id}'},
            {'method': 'PUT', 'path': '/api/user/{id}/role'},
            {'method': 'POST', 'path': '/api/admin/action'}
        ]
        
        for function in sensitive_functions:
            endpoint = f"{target}{function['path'].format(id=1)}"
            
            try:
                if function['method'] == 'DELETE':
                    response = self.session.delete(endpoint, timeout=5)
                elif function['method'] == 'PUT':
                    response = self.session.put(endpoint, json={'role': 'admin'}, timeout=5)
                else:
                    response = self.session.post(endpoint, json={'action': 'test'}, timeout=5)
                    
                if response.status_code in [200, 204]:
                    vulnerabilities.append({
                        'type': 'Missing Function Level Access Control',
                        'endpoint': endpoint,
                        'method': function['method']
                    })
            except:
                continue
                
        return vulnerabilities
        
    def test_state_manipulation(self, target: str) -> List[Dict]:
        """
        Test for state manipulation vulnerabilities
        """
        vulnerabilities = []
        
        # Test manipulating hidden fields, cookies, etc.
        # This would require more complex implementation
        
        return vulnerabilities
        
    def test_graphql_idor(self, target: str) -> List[Dict]:
        """
        Test for IDOR in GraphQL
        """
        vulnerabilities = []
        
        graphql_endpoint = self.find_graphql_endpoint(target)
        if graphql_endpoint:
            result = self.test_graphql_idor_detailed(graphql_endpoint)
            if result['vulnerable']:
                vulnerabilities.append(result)
                
        return vulnerabilities
