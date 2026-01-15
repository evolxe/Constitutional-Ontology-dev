"""
Export Page - Generate evidence packets for audit and compliance
"""

import streamlit as st
import os
import sys
import json
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_manager import TraceManager


# Page configuration
st.set_page_config(
    page_title="Export",
    page_icon="📦",
    layout="wide"
)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

st.title("📦 Export")
st.caption("Generate evidence packets for audit and compliance")

st.markdown("---")

if not st.session_state.get("enforcer"):
    st.error("No policy loaded. Please select a policy on the main dashboard.")
    st.markdown("---")
    if st.button("← Back to Main Dashboard"):
        st.switch_page("app.py")
    st.stop()

enforcer = st.session_state.enforcer
trace_manager = st.session_state.trace_manager

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Export Options")
    export_trace_id = st.text_input("Trace ID (leave empty for all traces)", key="export_trace_id_page")

    include_full_trace = st.checkbox("Include full trace data", value=True, key="export_full_trace_page")
    include_audit_log = st.checkbox("Include audit log entries", value=True, key="export_audit_log_page")
    include_policy_version = st.checkbox("Include policy version hash", value=True, key="export_policy_hash_page")

    if st.button("Generate Evidence Packet", type="primary", key="generate_evidence_page"):
        def make_json_serializable(obj, _visited=None):
            """Recursively convert objects to JSON-serializable types, handling circular references"""
            if _visited is None:
                _visited = set()

            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj

            if isinstance(obj, dict):
                obj_id = id(obj)
                if obj_id in _visited:
                    return "<circular reference>"
                _visited.add(obj_id)
                try:
                    result = {k: make_json_serializable(v, _visited) for k, v in obj.items()}
                finally:
                    _visited.remove(obj_id)
                return result

            if isinstance(obj, list):
                obj_id = id(obj)
                if obj_id in _visited:
                    return "<circular reference>"
                _visited.add(obj_id)
                try:
                    result = [make_json_serializable(item, _visited) for item in obj]
                finally:
                    _visited.remove(obj_id)
                return result

            if hasattr(obj, "__dict__"):
                obj_id = id(obj)
                if obj_id in _visited:
                    return "<circular reference>"
                _visited.add(obj_id)
                try:
                    return make_json_serializable(vars(obj), _visited)
                finally:
                    _visited.remove(obj_id)

            return str(obj)

        evidence_packet = {
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
            "policy_version": enforcer.policy.get("policy_version", "N/A"),
            "policy_id": enforcer.policy.get("policy_id", "N/A")
        }

        if export_trace_id:
            trace = trace_manager.get_trace(export_trace_id)
            if trace:
                if include_full_trace:
                    trace_dict = trace_manager.to_dict(trace)
                    evidence_packet["trace"] = make_json_serializable(trace_dict)
                if include_audit_log:
                    audit_entries = [
                        make_json_serializable(e) for e in enforcer.get_audit_log()
                        if e.get("evidence", {}).get("trace_id") == export_trace_id
                    ]
                    evidence_packet["related_audit_entries"] = audit_entries
            else:
                st.error(f"Trace ID {export_trace_id} not found.")
        else:
            if include_full_trace:
                all_traces = trace_manager.get_all_traces()
                evidence_packet["all_traces"] = make_json_serializable(all_traces)
            if include_audit_log:
                audit_log = enforcer.get_audit_log()
                evidence_packet["audit_log"] = make_json_serializable(audit_log)

        if include_policy_version:
            policy_str = json.dumps(enforcer.policy, sort_keys=True)
            evidence_packet["policy_hash"] = str(hash(policy_str))

        st.session_state["evidence_packet"] = evidence_packet
        st.success("Evidence packet generated!")

    # Download button in Export Options section
    if "evidence_packet" in st.session_state:
        st.markdown("---")
        evidence_json = json.dumps(st.session_state["evidence_packet"], indent=2)
        st.download_button(
            label="Download Evidence Packet (JSON)",
            data=evidence_json,
            file_name=f"evidence_packet_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key="download_evidence_packet"
        )

with col2:
    if "evidence_packet" in st.session_state:
        st.markdown("#### Evidence Packet")
        st.json(st.session_state["evidence_packet"])

# Navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
