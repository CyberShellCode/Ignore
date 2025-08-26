import os
import json
import time
import hashlib
import base64
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests
from urllib.parse import urlparse
import subprocess
import shutil
import zipfile
from pathlib import Path
from markdown import markdown as md_render

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class ArtifactHandlingPlugin:
    """
    Comprehensive evidence collection and management
    """
    
    def __init__(self):
        self.artifacts_dir = './artifacts'
        self.screenshots_dir = f'{self.artifacts_dir}/screenshots'
        self.requests_dir = f'{self.artifacts_dir}/requests'
        self.responses_dir = f'{self.artifacts_dir}/responses'
        self.reports_dir = f'{self.artifacts_dir}/reports'
        self.videos_dir = f'{self.artifacts_dir}/videos'
        
        self.setup_directories()
        self.artifact_registry = []
        
    def setup_directories(self):
        """
        Create necessary directories
        """
        dirs = [
            self.artifacts_dir,
            self.screenshots_dir,
            self.requests_dir,
            self.responses_dir,
            self.reports_dir,
            self.videos_dir
        ]
        
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
            
    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for artifact handling
        """
        action = kwargs.get('action', 'collect')
        vulnerability = kwargs.get('vulnerability', {})
        target = kwargs.get('target', '')
        
        if action == 'collect':
            return self.collect_artifacts(vulnerability, target)
        elif action == 'screenshot':
            return self.capture_screenshot(target, kwargs.get('element'))
        elif action == 'record_video':
            return self.record_exploitation(target, kwargs.get('steps'))
        elif action == 'generate_report':
            return self.generate_report(vulnerability)
        elif action == 'create_poc':
            return self.create_poc(vulnerability)
        elif action == 'package':
            return self.package_artifacts(kwargs.get('finding_id'))
            
    def collect_artifacts(self, vulnerability: Dict, target: str) -> Dict[str, Any]:
        """
        Collect all artifacts for a vulnerability
        """
        finding_id = self.generate_finding_id(vulnerability)
        artifacts = {
            'finding_id': finding_id,
            'timestamp': datetime.now().isoformat(),
            'vulnerability': vulnerability,
            'evidence': []
        }
        
        # Capture screenshot
        screenshot_result = self.capture_screenshot(target, vulnerability.get('element'))
        if screenshot_result['success']:
            artifacts['evidence'].append({
                'type': 'screenshot',
                'path': screenshot_result['path']
            })
            
        # Save request/response
        request_result = self.save_request_response(vulnerability)
        if request_result['success']:
            artifacts['evidence'].append({
                'type': 'request_response',
                'request_path': request_result['request_path'],
                'response_path': request_result['response_path']
            })
            
        # Generate HAR file
        har_result = self.generate_har_file(vulnerability)
        if har_result['success']:
            artifacts['evidence'].append({
                'type': 'har_file',
                'path': har_result['path']
            })
            
        # Create proof of concept
        poc_result = self.create_poc(vulnerability)
        if poc_result['success']:
            artifacts['evidence'].append({
                'type': 'poc',
                'path': poc_result['path']
            })
            
        # Generate report
        report_result = self.generate_report(vulnerability)
        if report_result['success']:
            artifacts['evidence'].append({
                'type': 'report',
                'path': report_result['path']
            })
            
        # Save to registry
        self.artifact_registry.append(artifacts)
        self.save_registry()
        
        # Package everything
        package_result = self.package_artifacts(finding_id)
        artifacts['package'] = package_result.get('path')
        
        return {
            'success': True,
            'finding_id': finding_id,
            'artifacts': artifacts,
            'package': package_result.get('path')
        }
        
    def capture_screenshot(self, target: str, element: Optional[str] = None) -> Dict[str, Any]:
        """
        Capture screenshot of vulnerability
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'screenshot_{timestamp}.png'
        filepath = os.path.join(self.screenshots_dir, filename)
        
        # Try Playwright first
        if PLAYWRIGHT_AVAILABLE:
            return self.capture_with_playwright(target, filepath, element)
        
        # Fall back to Selenium
        elif SELENIUM_AVAILABLE:
            return self.capture_with_selenium(target, filepath, element)
        
        # Fall back to basic curl + wkhtmltoimage
        else:
            return self.capture_with_wkhtmltoimage(target, filepath)
            
    def capture_with_playwright(self, url: str, filepath: str, element: Optional[str] = None) -> Dict[str, Any]:
        """
        Capture screenshot using Playwright
        """
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    ignore_https_errors=True
                )
                page = context.new_page()
                
                # Navigate to URL
                page.goto(url, wait_until='networkidle')
                
                # Wait for any dynamic content
                page.wait_for_timeout(2000)
                
                # Capture screenshot
                if element:
                    # Screenshot specific element
                    elem = page.locator(element)
                    if elem.count() > 0:
                        elem.first.screenshot(path=filepath)
                    else:
                        page.screenshot(path=filepath)
                else:
                    # Full page screenshot
                    page.screenshot(path=filepath, full_page=True)
                    
                browser.close()
                
                return {
                    'success': True,
                    'path': filepath,
                    'method': 'playwright'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def capture_with_selenium(self, url: str, filepath: str, element: Optional[str] = None) -> Dict[str, Any]:
        """
        Capture screenshot using Selenium
        """
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Capture screenshot
            if element:
                try:
                    elem = driver.find_element(By.CSS_SELECTOR, element)
                    elem.screenshot(filepath)
                except:
                    driver.save_screenshot(filepath)
            else:
                driver.save_screenshot(filepath)
                
            driver.quit()
            
            return {
                'success': True,
                'path': filepath,
                'method': 'selenium'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def capture_with_wkhtmltoimage(self, url: str, filepath: str) -> Dict[str, Any]:
        """
        Capture screenshot using wkhtmltoimage
        """
        try:
            subprocess.run([
                'wkhtmltoimage',
                '--width', '1920',
                '--height', '1080',
                url,
                filepath
            ], capture_output=True, timeout=30)
            
            if os.path.exists(filepath):
                return {
                    'success': True,
                    'path': filepath,
                    'method': 'wkhtmltoimage'
                }
        except:
            pass
            
        return {
            'success': False,
            'error': 'No screenshot method available'
        }
        
    def save_request_response(self, vulnerability: Dict) -> Dict[str, Any]:
        """
        Save HTTP request and response
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Save request
            request_data = vulnerability.get('request', {})
            request_filename = f'request_{timestamp}.txt'
            request_path = os.path.join(self.requests_dir, request_filename)
            
            with open(request_path, 'w') as f:
                f.write(f"Method: {request_data.get('method', 'GET')}\n")
                f.write(f"URL: {request_data.get('url', '')}\n")
                f.write(f"Headers:\n")
                for header, value in request_data.get('headers', {}).items():
                    f.write(f"  {header}: {value}\n")
                f.write(f"\nBody:\n{request_data.get('body', '')}\n")
                
            # Save response
            response_data = vulnerability.get('response', {})
            response_filename = f'response_{timestamp}.txt'
            response_path = os.path.join(self.responses_dir, response_filename)
            
            with open(response_path, 'w') as f:
                f.write(f"Status Code: {response_data.get('status_code', '')}\n")
                f.write(f"Headers:\n")
                for header, value in response_data.get('headers', {}).items():
                    f.write(f"  {header}: {value}\n")
                f.write(f"\nBody:\n{response_data.get('body', '')}\n")
                
            return {
                'success': True,
                'request_path': request_path,
                'response_path': response_path
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def generate_har_file(self, vulnerability: Dict) -> Dict[str, Any]:
        """
        Generate HAR (HTTP Archive) file
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'capture_{timestamp}.har'
            filepath = os.path.join(self.artifacts_dir, filename)
            
            har_data = {
                'log': {
                    'version': '1.2',
                    'creator': {
                        'name': 'CyberShell',
                        'version': '1.0'
                    },
                    'entries': []
                }
            }
            
            # Add entry for the vulnerability request
            request_data = vulnerability.get('request', {})
            response_data = vulnerability.get('response', {})
            
            entry = {
                'startedDateTime': datetime.now().isoformat(),
                'time': response_data.get('time', 0),
                'request': {
                    'method': request_data.get('method', 'GET'),
                    'url': request_data.get('url', ''),
                    'httpVersion': 'HTTP/1.1',
                    'headers': [
                        {'name': k, 'value': v}
                        for k, v in request_data.get('headers', {}).items()
                    ],
                    'queryString': [],
                    'postData': {
                        'mimeType': 'application/x-www-form-urlencoded',
                        'text': request_data.get('body', '')
                    } if request_data.get('body') else None
                },
                'response': {
                    'status': response_data.get('status_code', 200),
                    'statusText': 'OK',
                    'httpVersion': 'HTTP/1.1',
                    'headers': [
                        {'name': k, 'value': v}
                        for k, v in response_data.get('headers', {}).items()
                    ],
                    'content': {
                        'size': len(response_data.get('body', '')),
                        'mimeType': 'text/html',
                        'text': response_data.get('body', '')
                    }
                },
                'cache': {},
                'timings': {
                    'send': 0,
                    'wait': response_data.get('time', 0),
                    'receive': 0
                }
            }
            
            har_data['log']['entries'].append(entry)
            
            with open(filepath, 'w') as f:
                json.dump(har_data, f, indent=2)
                
            return {
                'success': True,
                'path': filepath
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def create_poc(self, vulnerability: Dict) -> Dict[str, Any]:
        """
        Create proof of concept script
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            vuln_type = vulnerability.get('type', 'unknown').replace(' ', '_')
            filename = f'poc_{vuln_type}_{timestamp}.py'
            filepath = os.path.join(self.artifacts_dir, filename)
            
            # Generate PoC script
            poc_script = self.generate_poc_script(vulnerability)
            
            with open(filepath, 'w') as f:
                f.write(poc_script)
                
            return {
                'success': True,
                'path': filepath
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def generate_poc_script(self, vulnerability: Dict) -> str:
        """
        Generate PoC script based on vulnerability type
        """
        vuln_type = vulnerability.get('type', '').lower()
        request_data = vulnerability.get('request', {})
        
        poc_template = '''#!/usr/bin/env python3
"""
Proof of Concept for {vuln_type}
Generated by CyberShell
Date: {date}
"""

import requests
import sys

def exploit():
    """
    Exploit {vuln_type} vulnerability
    """
    target = "{url}"
    
    headers = {headers}
    
    payload = {payload}
    
    try:
        if "{method}" == "GET":
            response = requests.get(target, params=payload, headers=headers, verify=False)
        else:
            response = requests.post(target, data=payload, headers=headers, verify=False)
            
        print(f"Status Code: {{response.status_code}}")
        print(f"Response: {{response.text[:500]}}")
        
        if response.status_code == 200:
            print("\\n[+] Vulnerability confirmed!")
            return True
        else:
            print("\\n[-] Vulnerability not confirmed")
            return False
            
    except Exception as e:
        print(f"Error: {{e}}")
        return False

if __name__ == "__main__":
    print("Starting PoC...")
    exploit()
'''
        
        return poc_template.format(
            vuln_type=vulnerability.get('type', 'Unknown'),
            date=datetime.now().isoformat(),
            url=request_data.get('url', 'http://target.com'),
            method=request_data.get('method', 'GET'),
            headers=json.dumps(request_data.get('headers', {}), indent=8),
            payload=json.dumps(request_data.get('payload', {}), indent=8)
        )
        
    def generate_report(self, vulnerability: Dict) -> Dict[str, Any]:
        """
        Generate vulnerability report
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'report_{timestamp}.md'
            filepath = os.path.join(self.reports_dir, filename)
            
            report = self.generate_markdown_report(vulnerability)
            
            with open(filepath, 'w') as f:
                f.write(report)
                
            # Also generate HTML version
            html_filepath = filepath.replace('.md', '.html')
            html_report = self.markdown_to_html(report)
            
            with open(html_filepath, 'w') as f:
                f.write(html_report)
                
            return {
                'success': True,
                'path': filepath,
                'html_path': html_filepath
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def generate_markdown_report(self, vulnerability: Dict) -> str:
        """
        Generate markdown report
        """
        severity = vulnerability.get('severity', 'Medium')
        severity_score = vulnerability.get('severity_score', 5)
        
        report = f"""# Vulnerability Report

## Summary
**Type:** {vulnerability.get('type', 'Unknown')}  
**Severity:** {severity} ({severity_score}/10)  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target:** {vulnerability.get('target', 'Unknown')}

## Description
{vulnerability.get('description', 'No description provided')}

## Technical Details

### Affected Endpoint
```
{vulnerability.get('endpoint', 'Unknown')}
```

### Request
```http
{self.format_request(vulnerability.get('request', {}))}
```

### Response
```http
Status: {vulnerability.get('response', {}).get('status_code', 'Unknown')}
{vulnerability.get('response', {}).get('body', '')[:500]}
```

## Impact
{self.generate_impact_section(vulnerability)}

## Steps to Reproduce
{self.generate_reproduction_steps(vulnerability)}

## Remediation
{self.generate_remediation(vulnerability)}

## Evidence
{self.generate_evidence_section(vulnerability)}

---
*Report generated by CyberShell*
"""
        return report
        
    def format_request(self, request_data: Dict) -> str:
        """
        Format HTTP request for report
        """
        formatted = f"{request_data.get('method', 'GET')} {request_data.get('url', '/')} HTTP/1.1\\n"
        
        for header, value in request_data.get('headers', {}).items():
            formatted += f"{header}: {value}\\n"
            
        if request_data.get('body'):
            formatted += f"\\n{request_data.get('body')}"
            
        return formatted
        
    def generate_impact_section(self, vulnerability: Dict) -> str:
        """
        Generate impact assessment
        """
        vuln_type = vulnerability.get('type', '').lower()
        
        impacts = {
            'sqli': 'Database compromise, data theft, authentication bypass',
            'xss': 'Session hijacking, phishing, malware distribution',
            'idor': 'Unauthorized access to sensitive data',
            'rce': 'Complete system compromise',
            'xxe': 'File disclosure, SSRF, DoS',
            'race condition': 'Financial loss, data corruption',
            'csrf': 'Unauthorized actions on behalf of users'
        }
        
        for key, impact in impacts.items():
            if key in vuln_type:
                return impact
                
        return 'Potential security impact on application and users'
        
    def generate_reproduction_steps(self, vulnerability: Dict) -> str:
        """
        Generate reproduction steps
        """
        steps = [
            "1. Navigate to the target application",
            f"2. Access the endpoint: {vulnerability.get('endpoint', 'Unknown')}",
            f"3. Send the following payload: `{vulnerability.get('payload', 'N/A')}`",
            "4. Observe the response indicating successful exploitation"
        ]
        
        return '\\n'.join(steps)
        
    def generate_remediation(self, vulnerability: Dict) -> str:
        """
        Generate remediation recommendations
        """
        vuln_type = vulnerability.get('type', '').lower()
        
        remediations = {
            'sqli': 'Use parameterized queries, input validation, and least privilege database access',
            'xss': 'Implement output encoding, Content Security Policy, and input validation',
            'idor': 'Implement proper access controls and authorization checks',
            'rce': 'Sanitize user input, use sandboxing, and principle of least privilege',
            'xxe': 'Disable external entity processing in XML parsers',
            'race condition': 'Implement proper locking mechanisms and atomic operations',
            'csrf': 'Implement CSRF tokens and SameSite cookies'
        }
        
        for key, remediation in remediations.items():
            if key in vuln_type:
                return remediation
                
        return 'Implement appropriate security controls based on the vulnerability type'
        
    def generate_evidence_section(self, vulnerability: Dict) -> str:
        """
        Generate evidence section
        """
        evidence = vulnerability.get('evidence', [])
        
        if not evidence:
            return 'No additional evidence available'
            
        section = 'The following evidence has been collected:\\n\\n'
        
        for item in evidence:
            if item['type'] == 'screenshot':
                section += f"- Screenshot: `{item['path']}`\\n"
            elif item['type'] == 'request_response':
                section += f"- Request: `{item['request_path']}`\\n"
                section += f"- Response: `{item['response_path']}`\\n"
            elif item['type'] == 'video':
                section += f"- Video: `{item['path']}`\\n"
                
        return section
        
    def markdown_to_html(self, markdown_text: str) -> str:
        body_html = md_render(
        markdown_text,
        extensions=['fenced_code', 'tables', 'codehilite']
        )
        html_doc = f"""<!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #d32f2f; }}
            h2 {{ color: #1976d2; }}
            pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
            code {{ background: #f5f5f5; padding: 2px 4px; }}
        </style>
    </head>
    <body>
    {body_html}
    </body>
    </html>"""
        return html_doc
  
    def package_artifacts(self, finding_id: str) -> Dict[str, Any]:
        """
        Package all artifacts into a zip file
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'artifacts_{finding_id}_{timestamp}.zip'
            filepath = os.path.join(self.artifacts_dir, filename)
            
            with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add all artifacts for this finding
                for root, dirs, files in os.walk(self.artifacts_dir):
                    for file in files:
                        if finding_id in file or timestamp in file:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.artifacts_dir)
                            zipf.write(file_path, arcname)
                            
            return {
                'success': True,
                'path': filepath,
                'size': os.path.getsize(filepath)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
            
    def record_exploitation(self, target: str, steps: List[Dict]) -> Dict[str, Any]:
        """
        Record video of exploitation steps
        """
        # This would require screen recording capability
        # Placeholder implementation
        return {
            'success': False,
            'message': 'Video recording not implemented'
        }
        
    def generate_finding_id(self, vulnerability: Dict) -> str:
        """
        Generate unique finding ID
        """
        data = f"{vulnerability.get('type')}_{vulnerability.get('endpoint')}_{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
        
    def save_registry(self):
        """
        Save artifact registry to disk
        """
        registry_path = os.path.join(self.artifacts_dir, 'registry.json')
        with open(registry_path, 'w') as f:
            json.dump(self.artifact_registry, f, indent=2)