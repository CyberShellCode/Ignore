import streamlit as st
import pandas as pd
from typing import Dict, List

class MetricsDisplay:
    """Display metrics in the dashboard"""
    
    @staticmethod
    def show_summary_metrics(data: Dict):
        """Display summary metrics"""
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Vulnerabilities", data.get('total_vulns', 0))
        with col2:
            st.metric("Critical Findings", data.get('critical', 0))
        with col3:
            st.metric("Success Rate", f"{data.get('success_rate', 0):.1%}")
        with col4:
            st.metric("Confidence", f"{data.get('confidence', 0):.2f}")
    
    @staticmethod
    def show_exploitation_metrics(results: List[Dict]):
        """Display exploitation metrics"""
        df = pd.DataFrame(results)
        st.dataframe(df)
