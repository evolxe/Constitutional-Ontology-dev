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
from ui_components import render_sidebar_navigation


# Page configuration
st.set_page_config(
    page_title="Export",
    page_icon="📦",
    layout="wide"
)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

# Sidebar with navigation
with st.sidebar:
    # Clickable title that navigates to home
    if st.button("🛡️ Governance Trust Layer", use_container_width=True, key="nav_title_home"):
        st.switch_page("app.py")
    
    # Navigation menu - placed below other sidebar content
    render_sidebar_navigation()

st.title("📦 Export")
st.caption("Generate evidence packets for audit and compliance")

st.markdown("---")

trace_manager = st.session_state.trace_manager

# Get policy info if available (optional - not required for audit log export)
policy_id = "N/A"
policy_version = "N/A"
if st.session_state.get("enforcer"):
    enforcer = st.session_state.enforcer
    policy_id = enforcer.policy.get("policy_id", "N/A")
    policy_version = enforcer.policy.get("policy_version", "N/A")

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Export Options")
    
    # Export type selection
    export_type = st.radio(
        "Export Type",
        ["Evidence Packet (Traces + Audit Log)", "Audit Log Only"],
        key="export_type_selector"
    )
    
    # Initialize variables
    export_trace_id = None
    include_full_trace = False
    include_audit_log = True
    include_policy_version = False
    
    if export_type == "Evidence Packet (Traces + Audit Log)":
        export_trace_id = st.text_input("Trace ID (leave empty for all traces)", key="export_trace_id_page")
        include_full_trace = st.checkbox("Include full trace data", value=True, key="export_full_trace_page")
        include_audit_log = st.checkbox("Include audit log entries", value=True, key="export_audit_log_page")
        include_policy_version = st.checkbox("Include policy version hash", value=True, key="export_policy_hash_page")
    else:
        # Audit log only export
        st.info("📜 Exporting complete audit log from TraceManager")
        
        # Show audit log stats
        audit_log = trace_manager.get_audit_log()
        st.metric("Total Audit Entries", len(audit_log))

    if st.button("Generate Export", type="primary", key="generate_evidence_page"):
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
            "policy_version": policy_version,
            "policy_id": policy_id
        }

        # Get audit log from TraceManager (centralized source)
        audit_log = trace_manager.get_audit_log()

        if export_type == "Audit Log Only":
            # Export only audit log
            evidence_packet["audit_log"] = make_json_serializable(audit_log)
            evidence_packet["audit_log_entry_count"] = len(audit_log)
            evidence_packet["export_type"] = "audit_log_only"
        elif export_trace_id:
            # Export specific trace with related audit entries
            trace = trace_manager.get_trace(export_trace_id)
            if trace:
                if include_full_trace:
                    trace_dict = trace_manager.to_dict(trace)
                    evidence_packet["trace"] = make_json_serializable(trace_dict)
                if include_audit_log:
                    # Filter audit entries for this specific trace
                    audit_entries = [
                        make_json_serializable(e) for e in audit_log
                        if e.get("evidence", {}).get("trace_id") == export_trace_id
                    ]
                    evidence_packet["related_audit_entries"] = audit_entries
                    evidence_packet["audit_log_entry_count"] = len(audit_entries)
            else:
                st.error(f"Trace ID {export_trace_id} not found.")
        else:
            # Export all traces and audit log
            if include_full_trace:
                all_traces = trace_manager.get_all_traces()
                evidence_packet["all_traces"] = make_json_serializable(all_traces)
            if include_audit_log:
                # Export all audit log entries
                evidence_packet["audit_log"] = make_json_serializable(audit_log)
                evidence_packet["audit_log_entry_count"] = len(audit_log)

        if include_policy_version and st.session_state.get("enforcer"):
            policy_str = json.dumps(enforcer.policy, sort_keys=True)
            evidence_packet["policy_hash"] = str(hash(policy_str))

        st.session_state["evidence_packet"] = evidence_packet
        if export_type == "Audit Log Only":
            st.success(f"✅ Audit log exported! ({len(audit_log)} entries)")
        else:
            st.success("✅ Evidence packet generated!")

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
