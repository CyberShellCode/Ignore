import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Template
import pandas as pd
import numpy as np
from pathlib import Path
import base64
from io import BytesIO

@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding with business context"""
    vulnerability_type: str
    severity: str  # Critical, High, Medium, Low
    cvss_score: float
    evidence_score: float
    confidence_score: float
    affected_assets: List[str]
    exploitation_proof: Dict
    remediation_cost: float
    potential_loss: float
    compliance_implications: List[str]
    business_functions_affected: List[str]
    time_to_exploit: float
    fix_complexity: str  # Simple, Moderate, Complex

class BusinessImpactReporter:
    """
    Generates comprehensive business impact reports with financial analysis
    """
    
    # Industry average costs (in USD)
    BREACH_COSTS = {
        'Critical': 4_450_000,  # Average cost of a critical data breach
        'High': 1_500_000,
        'Medium': 500_000,
        'Low': 100_000
    }
    
    # Remediation time estimates (in hours)
    REMEDIATION_TIME = {
        'Simple': 4,
        'Moderate': 16,
        'Complex': 40
    }
    
    # Average hourly rate for security remediation
    HOURLY_RATE = 150
    
    def __init__(self, company_profile: Optional[Dict] = None):
        self.company_profile = company_profile or self._default_company_profile()
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        
    def _default_company_profile(self) -> Dict:
        """Default company profile for calculations"""
        return {
            'name': 'Target Organization',
            'industry': 'Technology',
            'annual_revenue': 100_000_000,
            'employee_count': 500,
            'data_sensitivity': 'High',
            'compliance_requirements': ['GDPR', 'SOC2', 'ISO27001'],
            'average_customer_value': 10000,
            'reputation_multiplier': 2.5  # Reputation damage multiplier
        }
    
    def generate_executive_report(self, 
                                 findings: List[VulnerabilityFinding],
                                 scan_metadata: Dict) -> Dict:
        """Generate comprehensive executive report"""
        
        report = {
            'metadata': self._generate_metadata(scan_metadata),
            'executive_summary': self._generate_executive_summary(findings),
            'risk_assessment': self._calculate_risk_assessment(findings),
            'financial_impact': self._calculate_financial_impact(findings),
            'compliance_impact': self._assess_compliance_impact(findings),
            'remediation_roadmap': self._generate_remediation_roadmap(findings),
            'roi_analysis': self._calculate_roi_analysis(findings),
            'visualizations': self._generate_visualizations(findings),
            'recommendations': self._generate_recommendations(findings),
            'appendix': self._generate_technical_appendix(findings)
        }
        
        # Generate multiple format outputs
        self._save_json_report(report)
        self._save_html_report(report)
        self._save_pdf_report(report)
        
        return report
    
    def _generate_metadata(self, scan_metadata: Dict) -> Dict:
        """Generate report metadata"""
        return {
            'report_id': f"CS-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'scan_duration': scan_metadata.get('duration', 0),
            'target': scan_metadata.get('target', 'Unknown'),
            'scan_type': scan_metadata.get('scan_type', 'Comprehensive'),
            'company': self.company_profile['name'],
            'industry': self.company_profile['industry']
        }
    
    def _generate_executive_summary(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate executive summary with key metrics"""
        
        critical_count = sum(1 for f in findings if f.severity == 'Critical')
        high_count = sum(1 for f in findings if f.severity == 'High')
        
        total_risk_score = sum(f.cvss_score * f.confidence_score for f in findings)
        avg_confidence = np.mean([f.confidence_score for f in findings]) if findings else 0
        
        return {
            'total_vulnerabilities': len(findings),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'overall_risk_level': self._calculate_risk_level(total_risk_score),
            'average_confidence': round(avg_confidence, 2),
            'key_risks': self._identify_key_risks(findings),
            'immediate_actions_required': critical_count > 0 or high_count > 2,
            'executive_recommendation': self._generate_executive_recommendation(findings)
        }
    
    def _calculate_risk_assessment(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate comprehensive risk assessment"""
        
        risk_matrix = {
            'technical_risk': self._calculate_technical_risk(findings),
            'business_risk': self._calculate_business_risk(findings),
            'compliance_risk': self._calculate_compliance_risk(findings),
            'reputation_risk': self._calculate_reputation_risk(findings),
            'operational_risk': self._calculate_operational_risk(findings)
        }
        
        # Calculate weighted overall risk
        weights = {
            'technical_risk': 0.25,
            'business_risk': 0.30,
            'compliance_risk': 0.20,
            'reputation_risk': 0.15,
            'operational_risk': 0.10
        }
        
        overall_risk = sum(risk_matrix[k] * weights[k] for k in weights)
        
        return {
            'risk_matrix': risk_matrix,
            'overall_risk_score': round(overall_risk, 2),
            'risk_level': self._score_to_level(overall_risk),
            'risk_trend': self._calculate_risk_trend(),
            'risk_appetite_exceeded': overall_risk > 7.0,
            'mitigation_priority': self._prioritize_mitigations(findings)
        }
    
    def _calculate_financial_impact(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate financial impact of vulnerabilities"""
        
        # Direct costs
        potential_breach_cost = sum(
            self.BREACH_COSTS.get(f.severity, 0) * f.confidence_score 
            for f in findings
        )
        
        # Remediation costs
        total_remediation_cost = sum(
            self.REMEDIATION_TIME[f.fix_complexity] * self.HOURLY_RATE
            for f in findings
        )
        
        # Compliance fines
        compliance_fines = self._calculate_compliance_fines(findings)
        
        # Business disruption costs
        disruption_cost = self._calculate_disruption_cost(findings)
        
        # Reputation damage (using multiplier)
        reputation_damage = potential_breach_cost * (
            self.company_profile['reputation_multiplier'] - 1
        )
        
        total_potential_loss = (
            potential_breach_cost + 
            compliance_fines + 
            disruption_cost + 
            reputation_damage
        )
        
        return {
            'potential_breach_cost': round(potential_breach_cost, 2),
            'remediation_cost': round(total_remediation_cost, 2),
            'compliance_fines': round(compliance_fines, 2),
            'disruption_cost': round(disruption_cost, 2),
            'reputation_damage': round(reputation_damage, 2),
            'total_potential_loss': round(total_potential_loss, 2),
            'cost_per_vulnerability': round(total_potential_loss / len(findings), 2) if findings else 0,
            'insurance_impact': self._calculate_insurance_impact(total_potential_loss),
            'budget_allocation_recommendation': round(total_remediation_cost * 1.5, 2)
        }
    
    def _calculate_roi_analysis(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Calculate ROI of security investment"""
        
        financial_impact = self._calculate_financial_impact(findings)
        
        # Investment required
        investment = financial_impact['remediation_cost']
        
        # Potential savings (avoided losses)
        potential_savings = financial_impact['total_potential_loss']
        
        # ROI calculation
        roi = ((potential_savings - investment) / investment * 100) if investment > 0 else 0
        
        # Payback period (in months)
        monthly_risk = potential_savings / 12  # Annualized risk
        payback_period = (investment / monthly_risk) if monthly_risk > 0 else 0
        
        return {
            'investment_required': round(investment, 2),
            'potential_savings': round(potential_savings, 2),
            'roi_percentage': round(roi, 2),
            'payback_period_months': round(payback_period, 1),
            'risk_reduction_percentage': self._calculate_risk_reduction(),
            'cost_benefit_ratio': round(potential_savings / investment, 2) if investment > 0 else 0,
            'recommendation': 'Immediate action recommended' if roi > 200 else 'Scheduled remediation'
        }
    
    def _assess_compliance_impact(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Assess compliance impact of vulnerabilities"""
        
        compliance_violations = {}
        for req in self.company_profile['compliance_requirements']:
            violations = self._check_compliance_violations(findings, req)
            compliance_violations[req] = violations
        
        return {
            'compliance_frameworks': self.company_profile['compliance_requirements'],
            'violations_by_framework': compliance_violations,
            'total_violations': sum(len(v) for v in compliance_violations.values()),
            'audit_risk': 'High' if any(compliance_violations.values()) else 'Low',
            'certification_at_risk': self._check_certification_risk(compliance_violations),
            'remediation_deadline': self._calculate_compliance_deadline(compliance_violations)
        }
    
    def _generate_remediation_roadmap(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate prioritized remediation roadmap"""
        
        # Group by priority
        immediate = [f for f in findings if f.severity in ['Critical', 'High']]
        short_term = [f for f in findings if f.severity == 'Medium']
        long_term = [f for f in findings if f.severity == 'Low']
        
        roadmap = {
            'immediate_actions': {
                'timeframe': '0-7 days',
                'vulnerabilities': len(immediate),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in immediate),
                'items': self._format_remediation_items(immediate)
            },
            'short_term_actions': {
                'timeframe': '7-30 days',
                'vulnerabilities': len(short_term),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in short_term),
                'items': self._format_remediation_items(short_term)
            },
            'long_term_actions': {
                'timeframe': '30-90 days',
                'vulnerabilities': len(long_term),
                'estimated_effort': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in long_term),
                'items': self._format_remediation_items(long_term)
            },
            'total_effort_hours': sum(self.REMEDIATION_TIME[f.fix_complexity] for f in findings),
            'recommended_team_size': self._calculate_team_size(findings),
            'milestones': self._generate_milestones(findings)
        }
        
        return roadmap
    
    def _generate_visualizations(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate data visualizations"""
        
        visualizations = {}
        
        # Risk heatmap
        visualizations['risk_heatmap'] = self._create_risk_heatmap(findings)
        
        # Severity distribution
        visualizations['severity_distribution'] = self._create_severity_chart(findings)
        
        # Financial impact breakdown
        visualizations['financial_breakdown'] = self._create_financial_chart(findings)
        
        # Remediation timeline
        visualizations['remediation_timeline'] = self._create_timeline_chart(findings)
        
        # Compliance dashboard
        visualizations['compliance_dashboard'] = self._create_compliance_chart(findings)
        
        return visualizations
    
    def _create_risk_heatmap(self, findings: List[VulnerabilityFinding]) -> str:
        """Create risk heatmap visualization"""
        
        # Create matrix data
        risk_matrix = np.zeros((4, 4))
        severity_map = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0}
        
        for f in findings:
            sev_idx = severity_map.get(f.severity, 0)
            conf_idx = min(int(f.confidence_score * 4), 3)
            risk_matrix[sev_idx][conf_idx] += 1
        
        # Create heatmap
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(risk_matrix, annot=True, fmt='g', cmap='YlOrRd',
                   xticklabels=['Low', 'Medium', 'High', 'Critical'],
                   yticklabels=['Low', 'Medium', 'High', 'Critical'])
        ax.set_xlabel('Confidence')
        ax.set_ylabel('Severity')
        ax.set_title('Risk Heatmap')
        
        # Convert to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_severity_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create severity distribution chart"""
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        fig, ax = plt.subplots(figsize=(8, 6))
        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']
        ax.bar(severity_counts.keys(), severity_counts.values(), color=colors)
        ax.set_ylabel('Count')
        ax.set_title('Vulnerability Severity Distribution')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_financial_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create financial impact breakdown chart"""
        
        financial = self._calculate_financial_impact(findings)
        
        labels = ['Breach Cost', 'Remediation', 'Compliance', 'Disruption', 'Reputation']
        values = [
            financial['potential_breach_cost'],
            financial['remediation_cost'],
            financial['compliance_fines'],
            financial['disruption_cost'],
            financial['reputation_damage']
        ]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.set_title('Financial Impact Breakdown')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_timeline_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create remediation timeline chart"""
        
        # Group by complexity
        complexity_hours = {'Simple': 0, 'Moderate': 0, 'Complex': 0}
        for f in findings:
            complexity_hours[f.fix_complexity] += self.REMEDIATION_TIME[f.fix_complexity]
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Create Gantt-like chart
        y_pos = 0
        colors = {'Simple': '#4caf50', 'Moderate': '#ff9800', 'Complex': '#f44336'}
        
        for complexity, hours in complexity_hours.items():
            if hours > 0:
                ax.barh(y_pos, hours, left=0, height=0.5, 
                       label=complexity, color=colors[complexity])
                y_pos += 1
        
        ax.set_xlabel('Hours')
        ax.set_title('Remediation Timeline by Complexity')
        ax.legend()
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _create_compliance_chart(self, findings: List[VulnerabilityFinding]) -> str:
        """Create compliance impact chart"""
        
        compliance_impact = self._assess_compliance_impact(findings)
        
        frameworks = list(compliance_impact['violations_by_framework'].keys())
        violations = [len(v) for v in compliance_impact['violations_by_framework'].values()]
        
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.bar(frameworks, violations, color='#1976d2')
        ax.set_ylabel('Violations')
        ax.set_title('Compliance Violations by Framework')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        """Generate prioritized recommendations"""
        
        recommendations = []
        
        # Critical recommendations
        critical_findings = [f for f in findings if f.severity == 'Critical']
        if critical_findings:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Immediately remediate {len(critical_findings)} critical vulnerabilities',
                'impact': 'Prevent potential data breach and regulatory violations',
                'effort': 'High',
                'timeline': '0-48 hours'
            })
        
        # Strategic recommendations
        if len(findings) > 10:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Implement Continuous Security Testing',
                'description': 'Deploy automated security testing in CI/CD pipeline',
                'impact': 'Reduce vulnerability introduction by 70%',
                'effort': 'Medium',
                'timeline': '2-4 weeks'
            })
        
        # Process recommendations
        if any(f.fix_complexity == 'Complex' for f in findings):
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Security Architecture Review',
                'description': 'Conduct comprehensive security architecture review',
                'impact': 'Identify and fix systemic security issues',
                'effort': 'High',
                'timeline': '1-2 months'
            })
        
        return sorted(recommendations, key=lambda x: {'IMMEDIATE': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['priority'], 3))
    
    def _save_html_report(self, report: Dict):
        """Save report as HTML"""
        
        html_template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {{ metadata.report_id }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #1976d2; }
                h2 { color: #424242; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
                .critical { color: #d32f2f; font-weight: bold; }
                .high { color: #f57c00; font-weight: bold; }
                .metric { display: inline-block; margin: 10px; padding: 15px; background: #f5f5f5; border-radius: 5px; }
                .chart { margin: 20px 0; }
                table { border-collapse: collapse; width: 100%; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #1976d2; color: white; }
            </style>
        </head>
        <body>
            <h1>Executive Security Assessment Report</h1>
            <div class="metadata">
                <p><strong>Report ID:</strong> {{ metadata.report_id }}</p>
                <p><strong>Generated:</strong> {{ metadata.generated_at }}</p>
                <p><strong>Target:</strong> {{ metadata.target }}</p>
            </div>
            
            <h2>Executive Summary</h2>
            <div class="metrics">
                <div class="metric">
                    <strong>Total Vulnerabilities:</strong> {{ executive_summary.total_vulnerabilities }}
                </div>
                <div class="metric critical">
                    <strong>Critical:</strong> {{ executive_summary.critical_findings }}
                </div>
                <div class="metric high">
                    <strong>High:</strong> {{ executive_summary.high_findings }}
                </div>
            </div>
            
            <h2>Financial Impact</h2>
            <table>
                <tr><th>Impact Type</th><th>Amount (USD)</th></tr>
                <tr><td>Potential Breach Cost</td><td>${{ "{:,.2f}".format(financial_impact.potential_breach_cost) }}</td></tr>
                <tr><td>Remediation Cost</td><td>${{ "{:,.2f}".format(financial_impact.remediation_cost) }}</td></tr>
                <tr><td>Total Potential Loss</td><td><strong>${{ "{:,.2f}".format(financial_impact.total_potential_loss) }}</strong></td></tr>
            </table>
            
            <h2>ROI Analysis</h2>
            <p><strong>ROI:</strong> {{ roi_analysis.roi_percentage }}%</p>
            <p><strong>Payback Period:</strong> {{ roi_analysis.payback_period_months }} months</p>
            
            <h2>Risk Assessment</h2>
            <div class="chart">
                <img src="{{ visualizations.risk_heatmap }}" alt="Risk Heatmap" style="max-width: 100%;">
            </div>
            
            <h2>Recommendations</h2>
            {% for rec in recommendations %}
            <div style="margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #1976d2;">
                <h3>{{ rec.title }} ({{ rec.priority }})</h3>
                <p>{{ rec.description }}</p>
                <p><strong>Impact:</strong> {{ rec.impact }}</p>
                <p><strong>Timeline:</strong> {{ rec.timeline }}</p>
            </div>
            {% endfor %}
        </body>
        </html>
        """)
        
        html_content = html_template.render(**report)
        
        report_path = self.report_dir / f"report_{report['metadata']['report_id']}.html"
        with open(report_path, 'w') as f:
            f.write(html_content)
    
    def _save_json_report(self, report: Dict):
        """Save report as JSON"""
        report_path = self.report_dir / f"report_{report['metadata']['report_id']}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _save_pdf_report(self, report: Dict):
        """Save report as PDF (requires additional libraries)"""
        # Placeholder for PDF generation
        # Would require libraries like reportlab or weasyprint
        pass
    
    # Helper methods
    def _calculate_risk_level(self, score: float) -> str:
        if score > 8: return 'Critical'
        if score > 6: return 'High'
        if score > 4: return 'Medium'
        return 'Low'
    
    def _score_to_level(self, score: float) -> str:
        if score >= 8: return 'Critical'
        if score >= 6: return 'High'
        if score >= 4: return 'Medium'
        return 'Low'
    
    def _identify_key_risks(self, findings: List[VulnerabilityFinding]) -> List[str]:
        risks = []
        if any(f.severity == 'Critical' for f in findings):
            risks.append('Critical vulnerabilities requiring immediate attention')
        if any('customer_data' in f.affected_assets for f in findings):
            risks.append('Customer data at risk')
        if any(f.cvss_score >= 9.0 for f in findings):
            risks.append('Remotely exploitable vulnerabilities with high impact')
        return risks
    
    def _generate_executive_recommendation(self, findings: List[VulnerabilityFinding]) -> str:
        critical_count = sum(1 for f in findings if f.severity == 'Critical')
        if critical_count > 0:
            return 'IMMEDIATE ACTION REQUIRED: Critical vulnerabilities pose immediate threat to business operations'
        high_count = sum(1 for f in findings if f.severity == 'High')
        if high_count > 3:
            return 'HIGH PRIORITY: Multiple high-severity vulnerabilities require urgent remediation'
        return 'SCHEDULED REMEDIATION: Vulnerabilities should be addressed in next maintenance cycle'
    
    def _calculate_technical_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        return min(10, np.mean([f.cvss_score for f in findings]) * 1.2)
    
    def _calculate_business_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        critical_systems = sum(1 for f in findings if any('critical' in asset.lower() for asset in f.affected_assets))
        return min(10, (critical_systems / len(findings)) * 10)
    
    def _calculate_compliance_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        compliance_violations = sum(len(f.compliance_implications) for f in findings)
        return min(10, compliance_violations * 2)
    
    def _calculate_reputation_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        public_facing = sum(1 for f in findings if any('public' in asset.lower() for asset in f.affected_assets))
        return min(10, (public_facing / len(findings)) * 10 * self.company_profile['reputation_multiplier'])
    
    def _calculate_operational_risk(self, findings: List[VulnerabilityFinding]) -> float:
        if not findings: return 0
        business_functions = set()
        for f in findings:
            business_functions.update(f.business_functions_affected)
        return min(10, len(business_functions) * 2)
    
    def _calculate_risk_trend(self) -> str:
        # Would compare with historical data
        return 'Increasing'  # Placeholder
    
    def _prioritize_mitigations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        # Sort by severity and confidence
        sorted_findings = sorted(findings, 
                                key=lambda x: (x.cvss_score * x.confidence_score), 
                                reverse=True)
        return [f.vulnerability_type for f in sorted_findings[:5]]
    
    def _calculate_compliance_fines(self, findings: List[VulnerabilityFinding]) -> float:
        fines = 0
        for f in findings:
            if 'GDPR' in f.compliance_implications:
                fines += 20_000_000 * 0.01  # 1% chance of max GDPR fine
            if 'PCI-DSS' in f.compliance_implications:
                fines += 500_000 * 0.05
        return fines
    
    def _calculate_disruption_cost(self, findings: List[VulnerabilityFinding]) -> float:
        # Estimate based on affected business functions
        disruption_hours = sum(f.time_to_exploit * 24 for f in findings if f.severity in ['Critical', 'High'])
        hourly_cost = self.company_profile['annual_revenue'] / (365 * 24)
        return disruption_hours * hourly_cost
    
    def _calculate_insurance_impact(self, total_loss: float) -> str:
        if total_loss > 10_000_000:
            return 'Premium increase likely (15-30%)'
        if total_loss > 1_000_000:
            return 'Premium increase possible (5-15%)'
        return 'Minimal impact on premiums'
    
    def _calculate_risk_reduction(self) -> float:
        # Placeholder - would calculate based on remediation effectiveness
        return 75.0
    
    def _check_compliance_violations(self, findings: List[VulnerabilityFinding], framework: str) -> List[str]:
        violations = []
        for f in findings:
            if framework in f.compliance_implications:
                violations.append(f.vulnerability_type)
        return violations
    
    def _check_certification_risk(self, violations: Dict) -> bool:
        return any(len(v) > 3 for v in violations.values())
    
    def _calculate_compliance_deadline(self, violations: Dict) -> str:
        if any(violations.values()):
            return '30 days for critical violations'
        return 'Next audit cycle'
    
    def _format_remediation_items(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        items = []
        for f in findings:
            items.append({
                'vulnerability': f.vulnerability_type,
                'severity': f.severity,
                'complexity': f.fix_complexity,
                'effort_hours': self.REMEDIATION_TIME[f.fix_complexity],
                'affected_assets': f.affected_assets[:3]  # Top 3 assets
            })
        return items
    
    def _calculate_team_size(self, findings: List[VulnerabilityFinding]) -> int:
        total_hours = sum(self.REMEDIATION_TIME[f.fix_complexity] for f in findings)
        # Assume 40 hours per week per person, want to complete in 2 weeks
        return max(1, int(total_hours / 80))
    
    def _generate_milestones(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        milestones = [
            {
                'week': 1,
                'target': 'Complete critical vulnerability remediation',
                'success_criteria': 'All critical vulnerabilities patched and verified'
            },
            {
                'week': 2,
                'target': 'Address high-priority vulnerabilities',
                'success_criteria': '80% of high vulnerabilities remediated'
            },
            {
                'week': 4,
                'target': 'Complete medium priority remediation',
                'success_criteria': 'All medium vulnerabilities addressed'
            },
            {
                'week': 8,
                'target': 'Full remediation complete',
                'success_criteria': 'All identified vulnerabilities resolved and validated'
            }
        ]
        return milestones
    
    def _generate_technical_appendix(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate technical details appendix"""
        return {
            'detailed_findings': [self._format_technical_finding(f) for f in findings],
            'exploitation_chains': self._identify_exploitation_chains(findings),
            'attack_vectors': self._categorize_attack_vectors(findings),
            'technical_recommendations': self._generate_technical_recommendations(findings)
        }
    
    def _format_technical_finding(self, finding: VulnerabilityFinding) -> Dict:
        return {
            'type': finding.vulnerability_type,
            'cvss': finding.cvss_score,
            'evidence': finding.exploitation_proof,
            'affected': finding.affected_assets,
            'remediation': f"Apply security patch for {finding.vulnerability_type}"
        }
    
    def _identify_exploitation_chains(self, findings: List[VulnerabilityFinding]) -> List[List[str]]:
        # Identify potential chaining opportunities
        chains = []
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if self._can_chain(f1, f2):
                    chains.append([f1.vulnerability_type, f2.vulnerability_type])
        return chains
    
    def _can_chain(self, f1: VulnerabilityFinding, f2: VulnerabilityFinding) -> bool:
        # Simple heuristic for chaining
        chainable_pairs = [
            ('XSS', 'CSRF'),
            ('SQLI', 'RCE'),
            ('LFI', 'RCE'),
            ('SSRF', 'RCE')
        ]
        return (f1.vulnerability_type, f2.vulnerability_type) in chainable_pairs
    
    def _categorize_attack_vectors(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        vectors = {
            'Network': [],
            'Application': [],
            'Physical': [],
            'Social': []
        }
        
        for f in findings:
            if f.vulnerability_type in ['RCE', 'SSRF']:
                vectors['Network'].append(f.vulnerability_type)
            elif f.vulnerability_type in ['XSS', 'SQLI', 'CSRF']:
                vectors['Application'].append(f.vulnerability_type)
        
        return vectors
    
    def _generate_technical_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        recommendations = set()
        
        for f in findings:
            if f.vulnerability_type == 'SQLI':
                recommendations.add('Implement parameterized queries and input validation')
            elif f.vulnerability_type == 'XSS':
                recommendations.add('Deploy Content Security Policy (CSP) headers')
            elif f.vulnerability_type == 'RCE':
                recommendations.add('Implement strict input sanitization and sandboxing')
        
        return list(recommendations)
