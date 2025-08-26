"""
External Tools Integration with Rate Limiting
=============================================
Integrates Nmap and SQLMap with proper rate limiting for bug bounty programs
"""

import subprocess
import json
import time
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import tempfile
import asyncio
from urllib.parse import urlparse
import logging

from .rate_limiter import RateLimiter
from .fingerprinter import TargetFingerprint

logger = logging.getLogger(__name__)

@dataclass
class NmapResult:
    """Structured Nmap scan results"""
    host: str
    ports: List[Dict[str, Any]]
    os_info: Optional[Dict[str, str]] = None
    services: List[Dict[str, Any]] = None
    scripts: Dict[str, Any] = None
    scan_time: float = 0.0

@dataclass
class SQLMapResult:
    """Structured SQLMap results"""
    target: str
    vulnerable: bool
    database_type: Optional[str] = None
    injection_points: List[Dict[str, Any]] = None
    extracted_data: Dict[str, Any] = None
    scan_time: float = 0.0
    risk_level: str = "Unknown"

class ExternalToolsManager:
    """Manager for external security tools with rate limiting"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize rate limiter - be conservative for bug bounty
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('requests_per_second', 2),  # Very conservative
            burst_size=self.config.get('burst_size', 5),
            respect_headers=True
        )
        
        # Tool configurations
        self.nmap_path = self.config.get('nmap_path', 'nmap')
        self.sqlmap_path = self.config.get('sqlmap_path', 'sqlmap')
        
        # Output directories
        self.output_dir = Path(self.config.get('output_dir', './tool_output'))
        self.output_dir.mkdir(exist_ok=True)
        
        # Verify tools are installed
        self._verify_tools()
    
    def _verify_tools(self):
        """Verify external tools are available"""
        tools = {
            'nmap': self.nmap_path,
            'sqlmap': self.sqlmap_path
        }
        
        for tool_name, tool_path in tools.items():
            try:
                result = subprocess.run(
                    [tool_path, '--version'], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode != 0:
                    logger.warning(f"{tool_name} not found at {tool_path}")
                else:
                    logger.info(f"{tool_name} verified: {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.warning(f"{tool_name} not available or not responding")

class NmapIntegration:
    """Nmap integration with rate-limited scanning"""
    
    def __init__(self, tools_manager: ExternalToolsManager):
        self.manager = tools_manager
        self.rate_limiter = tools_manager.rate_limiter
        self.nmap_path = tools_manager.nmap_path
        self.output_dir = tools_manager.output_dir / 'nmap'
        self.output_dir.mkdir(exist_ok=True)
    
    async def scan_target(self, target: str, scan_type: str = "light") -> Optional[NmapResult]:
        """
        Perform rate-limited Nmap scan
        
        Args:
            target: Target to scan
            scan_type: light, full, or service_detection
            
        Returns:
            NmapResult or None if failed
        """
        start_time = time.time()
        
        # Apply rate limiting
        await self.rate_limiter.acquire()
        
        try:
            # Build Nmap command based on scan type
            cmd = self._build_nmap_command(target, scan_type)
            
            logger.info(f"Starting Nmap {scan_type} scan on {target}")
            
            # Execute scan with timeout
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return None
            
            # Parse results
            scan_result = self._parse_nmap_output(stdout.decode(), target)
            scan_result.scan_time = time.time() - start_time
            
            # Save results
            self._save_nmap_results(scan_result, target)
            
            return scan_result
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out for {target}")
            return None
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return None
    
    def _build_nmap_command(self, target: str, scan_type: str) -> List[str]:
        """Build Nmap command based on scan type"""
        
        # Parse target to get just the host
        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or target
        
        base_cmd = [
            self.nmap_path,
            '--host-timeout', '120s',  # 2 minute host timeout
            '--max-retries', '1',      # Minimal retries
            '-T2',                     # Polite timing (bug bounty appropriate)
            '-oX', '-'                 # XML output to stdout
        ]
        
        if scan_type == "light":
            # Light scan - just top ports and basic service detection
            cmd = base_cmd + [
                '--top-ports', '100',
                '-sV',                 # Version detection
                '--version-intensity', '2',  # Light version detection
                host
            ]
        elif scan_type == "service_detection":
            # Service detection focus
            cmd = base_cmd + [
                '-sV',
                '--version-intensity', '5',
                '-sC',                 # Default scripts
                '--script-timeout', '30s',
                host
            ]
        elif scan_type == "full":
            # More comprehensive but still respectful
            cmd = base_cmd + [
                '-sV',
                '-sC',
                '--script-timeout', '45s',
                '-O',                  # OS detection
                host
            ]
        else:
            # Default to light
            cmd = base_cmd + ['--top-ports', '100', '-sV', host]
        
        return cmd
    
    def _parse_nmap_output(self, xml_output: str, target: str) -> NmapResult:
        """Parse Nmap XML output into structured results"""
        
        try:
            root = ET.fromstring(xml_output)
            
            # Find the host element
            host_elem = root.find('.//host')
            if host_elem is None:
                return NmapResult(host=target, ports=[])
            
            # Extract ports
            ports = []
            for port_elem in host_elem.findall('.//port'):
                port_info = {
                    'port': port_elem.get('portid'),
                    'protocol': port_elem.get('protocol'),
                    'state': port_elem.find('state').get('state') if port_elem.find('state') is not None else 'unknown'
                }
                
                # Service information
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    port_info.update({
                        'service': service_elem.get('name', ''),
                        'product': service_elem.get('product', ''),
                        'version': service_elem.get('version', ''),
                        'extrainfo': service_elem.get('extrainfo', '')
                    })
                
                ports.append(port_info)
            
            # Extract OS information
            os_info = {}
            os_elem = host_elem.find('.//os')
            if os_elem is not None:
                osmatch_elem = os_elem.find('osmatch')
                if osmatch_elem is not None:
                    os_info = {
                        'name': osmatch_elem.get('name', ''),
                        'accuracy': osmatch_elem.get('accuracy', ''),
                        'line': osmatch_elem.get('line', '')
                    }
            
            # Extract script results
            scripts = {}
            for script_elem in host_elem.findall('.//script'):
                script_id = script_elem.get('id')
                script_output = script_elem.get('output', '')
                scripts[script_id] = script_output
            
            return NmapResult(
                host=target,
                ports=ports,
                os_info=os_info if os_info else None,
                services=[p for p in ports if p.get('service')],
                scripts=scripts if scripts else None
            )
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
            return NmapResult(host=target, ports=[])
    
    def _save_nmap_results(self, result: NmapResult, target: str):
        """Save Nmap results to file"""
        timestamp = int(time.time())
        filename = f"nmap_{target.replace(':', '_')}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            # Convert dataclass to dict for JSON serialization
            result_dict = {
                'host': result.host,
                'ports': result.ports,
                'os_info': result.os_info,
                'services': result.services,
                'scripts': result.scripts,
                'scan_time': result.scan_time
            }
            json.dump(result_dict, f, indent=2)
        
        logger.info(f"Nmap results saved to {filepath}")

class SQLMapIntegration:
    """SQLMap integration with rate-limited testing"""
    
    def __init__(self, tools_manager: ExternalToolsManager):
        self.manager = tools_manager
        self.rate_limiter = tools_manager.rate_limiter
        self.sqlmap_path = tools_manager.sqlmap_path
        self.output_dir = tools_manager.output_dir / 'sqlmap'
        self.output_dir.mkdir(exist_ok=True)
    
    async def test_sql_injection(self, target: str, parameters: Dict[str, str] = None,
                               scan_level: int = 1, risk_level: int = 1) -> Optional[SQLMapResult]:
        """
        Perform rate-limited SQL injection testing
        
        Args:
            target: Target URL to test
            parameters: Optional parameters to test
            scan_level: SQLMap scan level (1-5, default 1 for bug bounty)
            risk_level: SQLMap risk level (1-3, default 1 for bug bounty)
            
        Returns:
            SQLMapResult or None if failed
        """
        start_time = time.time()
        
        # Apply rate limiting - SQLMap can be aggressive
        await self.rate_limiter.acquire()
        
        try:
            # Build SQLMap command
            cmd = self._build_sqlmap_command(target, parameters, scan_level, risk_level)
            
            logger.info(f"Starting SQLMap test on {target}")
            
            # Execute with timeout
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=600  # 10 minute timeout for SQLMap
            )
            
            # Parse results
            scan_result = self._parse_sqlmap_output(stdout.decode(), target)
            scan_result.scan_time = time.time() - start_time
            
            # Save results
            self._save_sqlmap_results(scan_result, target)
            
            return scan_result
            
        except asyncio.TimeoutError:
            logger.error(f"SQLMap scan timed out for {target}")
            return None
        except Exception as e:
            logger.error(f"SQLMap scan error: {e}")
            return None
    
    def _build_sqlmap_command(self, target: str, parameters: Optional[Dict[str, str]],
                            scan_level: int, risk_level: int) -> List[str]:
        """Build SQLMap command with conservative settings"""
        
        cmd = [
            self.sqlmap_path,
            '-u', target,
            '--level', str(scan_level),
            '--risk', str(risk_level),
            '--timeout', '30',           # 30 second timeout per request
            '--retries', '1',            # Minimal retries
            '--delay', '2',              # 2 second delay between requests
            '--randomize', '2',          # Randomize parameter values
            '--batch',                   # Non-interactive mode
            '--flush-session',           # Don't reuse sessions
            '--output-dir', str(self.output_dir),
            '--threads', '1'             # Single threaded for politeness
        ]
        
        # Add specific parameters if provided
        if parameters:
            param_string = '&'.join(f"{k}={v}" for k, v in parameters.items())
            cmd.extend(['--data', param_string])
        
        # Safe enumeration options (minimal data extraction)
        cmd.extend([
            '--current-db',              # Just get DB name
            '--no-cast',                 # Don't cast to retrieve data
            '--no-escape'                # Don't escape special chars
        ])
        
        return cmd
    
    def _parse_sqlmap_output(self, output: str, target: str) -> SQLMapResult:
        """Parse SQLMap output into structured results"""
        
        vulnerable = False
        database_type = None
        injection_points = []
        risk_level = "Unknown"
        
        # Check for vulnerability indicators
        if 'Parameter:' in output and 'is vulnerable' in output:
            vulnerable = True
        
        # Extract database type
        db_patterns = {
            'MySQL': r'MySQL',
            'PostgreSQL': r'PostgreSQL',
            'Microsoft SQL Server': r'Microsoft SQL Server',
            'Oracle': r'Oracle',
            'SQLite': r'SQLite'
        }
        
        for db_name, pattern in db_patterns.items():
            if re.search(pattern, output, re.IGNORECASE):
                database_type = db_name
                break
        
        # Extract injection points
        injection_matches = re.findall(
            r'Parameter: ([^\s]+).*?Type: ([^\n]+).*?Payload: ([^\n]+)',
            output,
            re.DOTALL
        )
        
        for match in injection_matches:
            injection_points.append({
                'parameter': match[0],
                'injection_type': match[1],
                'payload': match[2]
            })
        
        # Determine risk level
        if vulnerable:
            if 'time-based' in output.lower():
                risk_level = "Medium"
            elif 'union' in output.lower() or 'error-based' in output.lower():
                risk_level = "High"
            else:
                risk_level = "Low"
        
        return SQLMapResult(
            target=target,
            vulnerable=vulnerable,
            database_type=database_type,
            injection_points=injection_points,
            risk_level=risk_level
        )
    
    def _save_sqlmap_results(self, result: SQLMapResult, target: str):
        """Save SQLMap results to file"""
        timestamp = int(time.time())
        filename = f"sqlmap_{target.replace('/', '_').replace(':', '_')}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            result_dict = {
                'target': result.target,
                'vulnerable': result.vulnerable,
                'database_type': result.database_type,
                'injection_points': result.injection_points,
                'extracted_data': result.extracted_data,
                'scan_time': result.scan_time,
                'risk_level': result.risk_level
            }
            json.dump(result_dict, f, indent=2)
        
        logger.info(f"SQLMap results saved to {filepath}")

class ToolOrchestrator:
    """Orchestrates external tools for comprehensive scanning"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.manager = ExternalToolsManager(config)
        self.nmap = NmapIntegration(self.manager)
        self.sqlmap = SQLMapIntegration(self.manager)
    
    async def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform comprehensive scan using multiple tools
        
        Args:
            target: Target to scan
            
        Returns:
            Combined results from all tools
        """
        results = {
            'target': target,
            'timestamp': time.time(),
            'nmap_results': None,
            'sqlmap_results': None,
            'summary': {}
        }
        
        # Phase 1: Nmap reconnaissance
        logger.info(f"Starting comprehensive scan on {target}")
        
        nmap_result = await self.nmap.scan_target(target, scan_type="service_detection")
        if nmap_result:
            results['nmap_results'] = {
                'host': nmap_result.host,
                'ports': nmap_result.ports,
                'services': nmap_result.services,
                'scan_time': nmap_result.scan_time
            }
            
            # Update fingerprint based on Nmap results
            results['fingerprint_updates'] = self._extract_fingerprint_from_nmap(nmap_result)
        
        # Phase 2: Web application testing if web services found
        web_ports = []
        if nmap_result and nmap_result.ports:
            web_ports = [p for p in nmap_result.ports 
                        if p.get('service') in ['http', 'https', 'http-alt'] 
                        and p.get('state') == 'open']
        
        if web_ports:
            # Test for SQL injection on web services
            for port_info in web_ports[:2]:  # Limit to 2 ports to avoid being too aggressive
                port = port_info['port']
                scheme = 'https' if port_info.get('service') == 'https' else 'http'
                web_target = f"{scheme}://{target}:{port}/"
                
                sqlmap_result = await self.sqlmap.test_sql_injection(
                    web_target, 
                    scan_level=1,  # Conservative for bug bounty
                    risk_level=1
                )
                
                if sqlmap_result:
                    if results['sqlmap_results'] is None:
                        results['sqlmap_results'] = []
                    results['sqlmap_results'].append({
                        'target': sqlmap_result.target,
                        'vulnerable': sqlmap_result.vulnerable,
                        'database_type': sqlmap_result.database_type,
                        'injection_points': sqlmap_result.injection_points,
                        'risk_level': sqlmap_result.risk_level,
                        'scan_time': sqlmap_result.scan_time
                    })
        
        # Generate summary
        results['summary'] = self._generate_scan_summary(results)
        
        return results
    
    def _extract_fingerprint_from_nmap(self, nmap_result: NmapResult) -> Dict[str, Any]:
        """Extract fingerprint information from Nmap results"""
        fingerprint_updates = {}
        
        # Extract server information from services
        for service in nmap_result.services or []:
            if service.get('service') in ['http', 'https']:
                if service.get('product'):
                    fingerprint_updates['server_product'] = service['product']
                if service.get('version'):
                    fingerprint_updates['server_version'] = service['version']
        
        # Extract OS information
        if nmap_result.os_info:
            fingerprint_updates['os_info'] = nmap_result.os_info
        
        # Extract technologies from scripts
        if nmap_result.scripts:
            technologies = []
            for script_name, script_output in nmap_result.scripts.items():
                if 'http-server-header' in script_name:
                    fingerprint_updates['server_header'] = script_output
                elif 'http-title' in script_name:
                    fingerprint_updates['page_title'] = script_output
                elif 'ssl-cert' in script_name:
                    fingerprint_updates['ssl_certificate'] = script_output
        
        return fingerprint_updates
    
    def _generate_scan_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of scan results"""
        summary = {
            'open_ports': 0,
            'services_identified': 0,
            'web_services': 0,
            'sql_injection_found': False,
            'risk_level': 'Low'
        }
        
        # Analyze Nmap results
        if results.get('nmap_results'):
            nmap = results['nmap_results']
            summary['open_ports'] = len([p for p in nmap['ports'] if p.get('state') == 'open'])
            summary['services_identified'] = len(nmap.get('services', []))
            summary['web_services'] = len([s for s in nmap.get('services', []) 
                                         if s.get('service') in ['http', 'https']])
        
        # Analyze SQLMap results
        if results.get('sqlmap_results'):
            for sqlmap in results['sqlmap_results']:
                if sqlmap.get('vulnerable'):
                    summary['sql_injection_found'] = True
                    if sqlmap.get('risk_level') == 'High':
                        summary['risk_level'] = 'High'
                    elif sqlmap.get('risk_level') == 'Medium' and summary['risk_level'] != 'High':
                        summary['risk_level'] = 'Medium'
        
        return summary
