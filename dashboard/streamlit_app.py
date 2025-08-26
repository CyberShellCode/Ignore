# Streamlit dashboard to run CyberShell and visualize ODS evidence (EMA/max) per family.
# Usage:
#   1) pip install -r requirements.txt -r requirements-dashboard.txt
#   2) streamlit run dashboard/streamlit_app.py

import streamlit as st
import pandas as pd

from cybershell.orchestrator import CyberShell
from cybershell.config import SafetyConfig
from cybershell.llm_connectors import OpenAIChatConnector, OllamaConnector, LocalFunctionConnector

st.set_page_config(page_title="CyberShell ODS Dashboard", layout="wide")

st.title("CyberShell — ODS Evidence Dashboard")

with st.sidebar:
    st.header("Run Settings")
    target = st.text_input("Target (lab/research only)", value="http://localhost:8000")
    planner = st.selectbox("Planner", ["depth_first", "breadth_first"])
    scorer = st.selectbox("Scorer", ["weighted_signal", "high_confidence", "default"])
    llm_choice = st.selectbox("LLM", ["none", "openai", "ollama", "localfn"])
    doc_root = st.text_input("Doc root", value="docs")
    run_button = st.button("Run")

def _make_llm(choice: str):
    if choice == "openai":
        return OpenAIChatConnector()
    if choice == "ollama":
        return OllamaConnector()
    if choice == "localfn":
        def gen(prompt: str) -> str:
            # Return lab-safe, no-network planning steps as JSON array
            return '[{"plugin":"HeuristicAnalyzerPlugin","why":"local","params":{"hint":"baseline"}}]'
        return LocalFunctionConnector(generate_fn=gen)
    return None

if run_button:
    llm = _make_llm(llm_choice)
    bot = CyberShell(
        SafetyConfig(allow_private_ranges=True, allow_localhost=True),
        doc_root=doc_root,
        planner_name=planner,
        scorer_name=scorer,
        llm=llm
    )
    res = bot.execute(target)
    st.subheader("Report")
    st.code(res["report"])

    # Evidence summary (EMA, max, n) from aggregator
    summary = bot.aggregator.summarize()  # {family: {'ema':..., 'max':..., 'n':...}}
    if summary:
        df = pd.DataFrame(summary).T.reset_index().rename(columns={'index': 'family'})
        st.subheader("ODS Evidence Summary")
        st.dataframe(df, use_container_width=True)

        # Matplotlib charts (Streamlit supports these fine)
        import matplotlib.pyplot as plt

        st.write("**EMA by family** (recency-weighted)")
        fig1, ax1 = plt.subplots()
        ax1.bar(df['family'], df['ema'])
        ax1.set_ylabel("EMA (0–1)")
        ax1.set_xticklabels(df['family'], rotation=45, ha='right')
        st.pyplot(fig1)

        st.write("**Max observed score by family**")
        fig2, ax2 = plt.subplots()
        ax2.bar(df['family'], df['max'])
        ax2.set_ylabel("Max (0–1)")
        ax2.set_xticklabels(df['family'], rotation=45, ha='right')
        st.pyplot(fig2)
    else:
        st.info("No evidence yet (try another target or plugin hints).")

    # Show plan & results
    st.subheader("Plan (steps)")
    st.json(res["plan"])
    st.subheader("Results (raw)")
    st.json(res["results"])
else:
    st.info("Configure settings in the sidebar and click **Run**.")
