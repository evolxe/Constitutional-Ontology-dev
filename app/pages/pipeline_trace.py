"""
Pipeline Trace Page - View current trace details and trace history
"""

import streamlit as st
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_manager import TraceManager
from ui_components import render_risk_explanation, render_sidebar_navigation


# Page configuration
st.set_page_config(
    page_title="Pipeline Trace",
    page_icon="🧭",
    layout="wide"
)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

trace_manager = st.session_state.trace_manager

# Sidebar with navigation
with st.sidebar:
    # Clickable title that navigates to home
    if st.button("🛡️ Governance Trust Layer", use_container_width=True, key="nav_title_home"):
        st.switch_page("app.py")
    
    # Navigation menu - placed below other sidebar content
    render_sidebar_navigation()

st.title("🧭 Pipeline Trace")
st.caption("Review current trace details and trace history")

st.markdown("---")

# Current trace details
current_trace_id = st.session_state.get("current_trace_id")
current_trace = trace_manager.get_trace(current_trace_id) if current_trace_id else None

st.markdown("### Current Trace")

if current_trace:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write(f"**Trace ID:** `{current_trace.trace_id}`")
    with col2:
        st.write(f"**Verdict:** {current_trace.verdict}")
    with col3:
        st.write(f"**Resolution:** {current_trace.resolution or 'Pending'}")

    # Display risk explanation if available
    if current_trace.risk_level and current_trace.risk_drivers:
        st.markdown("---")
        render_risk_explanation(current_trace.risk_level, current_trace.risk_drivers)

    st.markdown("---")
    st.markdown("#### Request Data")
    st.json(current_trace.request_data)

    st.markdown("#### Pipeline Results")
    st.json(current_trace.pipeline_results)
else:
    st.info("No current trace selected. Submit a request from the main dashboard to generate a trace.")

st.markdown("---")

# Trace history
st.markdown("### Trace History")
all_traces = trace_manager.get_all_traces()

if not all_traces:
    st.info("No traces available yet.")
else:
    trace_options = {f"{trace['trace_id']} - {trace['timestamp'][:19]}": trace["trace_id"] for trace in all_traces}
    selected_trace_label = st.selectbox(
        "Select a trace to view",
        options=list(trace_options.keys()),
        key="pipeline_trace_selector"
    )
    selected_trace_id = trace_options.get(selected_trace_label)

    if selected_trace_id:
        trace = trace_manager.get_trace(selected_trace_id)
        if trace:
            if st.button("Set as Current Trace", type="primary"):
                st.session_state.current_trace_id = selected_trace_id
                st.success("Current trace updated.")
                st.rerun()

            st.markdown("---")
            st.markdown("#### Trace Details")
            st.write(f"**Trace ID:** `{trace.trace_id}`")
            st.write(f"**Verdict:** {trace.verdict}")
            st.write(f"**Resolution:** {trace.resolution or 'Pending'}")
            st.write(f"**Timestamp:** {trace.timestamp}")

            # Display risk explanation if available
            if trace.risk_level and trace.risk_drivers:
                st.markdown("---")
                render_risk_explanation(trace.risk_level, trace.risk_drivers)

            st.markdown("---")
            st.markdown("#### Request Data")
            st.json(trace.request_data)

            st.markdown("#### Pipeline Results")
            st.json(trace.pipeline_results)

# Navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
