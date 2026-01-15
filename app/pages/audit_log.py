"""
Audit Log Page - Decision history and evidence
"""

import streamlit as st
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_manager import TraceManager


# Page configuration
st.set_page_config(
    page_title="Audit Log",
    page_icon="📜",
    layout="wide"
)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

st.title("📜 Audit Log")
st.caption("Decision history & evidence")

st.markdown("---")

if not st.session_state.get("enforcer"):
    st.error("No policy loaded. Please select a policy on the main dashboard.")
    st.markdown("---")
    if st.button("← Back to Main Dashboard"):
        st.switch_page("app.py")
    st.stop()

enforcer = st.session_state.enforcer
audit_log = enforcer.get_audit_log()

if not audit_log:
    st.info("No audit log entries yet.")
else:
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        filter_verdict = st.selectbox(
            "Filter by Verdict",
            ["All"] + list(set(entry.get("decision", "Unknown") for entry in audit_log)),
            key="audit_filter_verdict_page"
        )
    with col2:
        filter_gate = st.selectbox(
            "Filter by Gate",
            ["All"] + list(set(entry.get("gate", "Unknown") for entry in audit_log)),
            key="audit_filter_gate_page"
        )
    with col3:
        filter_user = st.selectbox(
            "Filter by User",
            ["All"] + list(set(entry.get("user_id", "Unknown") for entry in audit_log)),
            key="audit_filter_user_page"
        )
    with col4:
        days_back = st.selectbox("Time Range", [7, 30, 90, 365, "All"], key="audit_time_range_page")

    # Apply filters
    filtered_log = audit_log
    if filter_verdict != "All":
        filtered_log = [e for e in filtered_log if e.get("decision") == filter_verdict]
    if filter_gate != "All":
        filtered_log = [e for e in filtered_log if e.get("gate") == filter_gate]
    if filter_user != "All":
        filtered_log = [e for e in filtered_log if e.get("user_id") == filter_user]

    st.write(f"**{len(filtered_log)} audit log entry/entries**")

    # Display audit log as table
    if filtered_log:
        display_data = []
        for entry in filtered_log[-100:]:
            display_data.append({
                "Timestamp": entry.get("timestamp", "N/A")[:19],
                "Gate": entry.get("gate", "N/A"),
                "Action": entry.get("action", "N/A"),
                "Decision": entry.get("decision", "N/A"),
                "User": entry.get("user_id", "N/A"),
                "Controls": ", ".join(entry.get("controls", []))[:50]
            })

        st.dataframe(display_data, use_container_width=True, height=400)

        # Replay trace buttons
        st.markdown("### Replay Traces")
        recent_entries = filtered_log[-10:]
        for entry in recent_entries:
            trace_id_from_evidence = entry.get("evidence", {}).get("trace_id")
            if trace_id_from_evidence:
                if st.button(f"Replay Trace {trace_id_from_evidence[:20]}...", key=f"replay_{entry.get('timestamp')}"):
                    st.session_state.current_trace_id = trace_id_from_evidence
                    st.rerun()

# Navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
