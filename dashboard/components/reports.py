import json
from typing import Dict, List
from datetime import datetime

class ReportGenerator:
    """Generate reports from dashboard data"""
    
    @staticmethod
    def generate_json_report(data: Dict) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        return json.dumps(report, indent=2)
    
    @staticmethod
    def generate_markdown_report(data: Dict) -> str:
        """Generate Markdown report"""
        md = f"# CyberShell Report\n\n"
        md += f"Generated: {datetime.now()}\n\n"
        # Add report content
        return md
