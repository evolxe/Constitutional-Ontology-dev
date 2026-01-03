"""
Constitutional Ontology Enforcement - Streamlit UI
Complete application with Pipeline Flow (8 gates) as primary view
"""

import streamlit as st
import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import existing enforcement engine
from constitutional_enforcement_interactive import ConstitutionalEnforcer, Decision

# Import new components
from trace_manager import TraceManager
from pipeline_mapper import execute_pipeline
from ui_components import (
    render_pipeline_flow,
    render_surface_activation,
    render_approval_modal,
    render_verdict_badge,
    get_gate_legend
)


# Page configuration
st.set_page_config(
    page_title="Constitutional Ontology Enforcement",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

if "enforcer" not in st.session_state:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.environ.get("POLICY_PATH", os.path.join(parent_dir, "policy_bank_compliance_v1.json"))
    try:
        st.session_state.enforcer = ConstitutionalEnforcer(policy_path)
    except:
        st.session_state.enforcer = None

if "pending_approvals" not in st.session_state:
    st.session_state.pending_approvals = []

if "current_trace_id" not in st.session_state:
    st.session_state.current_trace_id = None


def load_policy_summary():
    """Load policy summary for sidebar"""
    if st.session_state.enforcer:
        policy = st.session_state.enforcer.policy
        st.sidebar.markdown("### Policy Summary")
        st.sidebar.write(f"**Policy ID:** {policy.get('policy_id', 'N/A')}")
        st.sidebar.write(f"**Version:** {policy.get('policy_version', 'N/A')}")
        st.sidebar.write(f"**Description:** {policy.get('description', 'N/A')[:80]}...")
        
        st.sidebar.markdown("---")
        st.sidebar.markdown("### System Health")
        
        pending_count = len(st.session_state.pending_approvals)
        if pending_count > 0:
            st.sidebar.warning(f"⚠ {pending_count} pending approval(s)")
        else:
            st.sidebar.success("✓ No pending approvals")
        
        audit_count = len(st.session_state.enforcer.get_audit_log())
        st.sidebar.info(f"📊 {audit_count} audit log entries")
    else:
        st.sidebar.error("No policy loaded")


def process_sandbox_request(user_prompt: str, user_id: str = "analyst_123"):
    """Process a request through the full pipeline"""
    enforcer = st.session_state.enforcer
    trace_manager = st.session_state.trace_manager
    
    if not enforcer:
        return None
    
    # Execute pipeline
    pipeline_results = execute_pipeline(user_prompt, user_id, enforcer)
    
    # Create trace
    trace = trace_manager.create_trace(
        request_data={"prompt": user_prompt, "user_id": user_id},
        pipeline_results=pipeline_results,
        surface_activations=pipeline_results.get("surface_activations", {})
    )
    
    # Check if escalation occurred
    if pipeline_results.get("final_verdict") == "ESCALATE":
        approval_data = {
            "trace_id": trace.trace_id,
            "tool": "jira_create",  # This would be determined from the pipeline
            "user_id": user_id,
            "timestamp": trace.timestamp,
            "params": {"title": "Action requiring approval"},
            "resolution": None
        }
        st.session_state.pending_approvals.append(approval_data)
    
    return trace


# Sidebar
with st.sidebar:
    st.title("🛡️ Constitutional Ontology")
    load_policy_summary()
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Gate Legend")
    legend = get_gate_legend()
    for gate_name, description in legend.items():
        with st.expander(gate_name):
            st.caption(description)


# Main content area with tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "Enforcement Pipeline",
    "Surface Activation",
    "Approval Queue",
    "Audit Trail"
])


# Tab 1: Enforcement Pipeline
with tab1:
    st.header("Enforcement Pipeline")
    st.caption("8-gate runtime sequence")
    
    st.markdown("### Submit Request")
    st.markdown("Submit a single request to see it processed through the enforcement pipeline")
    
    if not st.session_state.enforcer:
        st.error("Please load a policy file first. Policy file should be in the parent directory.")
        st.stop()
    
    user_input = st.text_area(
        "User Prompt",
        placeholder="e.g., Draft a Q4 compliance policy update under OCC supervision.",
        height=100
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        submit_button = st.button("Submit Request", type="primary")
    
    if submit_button and user_input:
        with st.spinner("Processing request through enforcement pipeline..."):
            trace = process_sandbox_request(user_input)
            if trace:
                st.session_state.current_trace_id = trace.trace_id
                
                # Display trace ID prominently
                st.success(f"**Trace ID:** `{trace.trace_id}`")
                
                # Display verdict
                st.markdown("### Final Verdict")
                verdict = trace.verdict
                render_verdict_badge(verdict, trace.resolution)
                
                # PRIMARY VIEW: Pipeline Flow (8 gates)
                st.markdown("---")
                trace_dict = {
                    "pipeline_results": {
                        "gate_results": trace.pipeline_results.get("gate_results", [])
                    }
                }
                render_pipeline_flow(trace_dict, expandable=True)
    
    elif submit_button and not user_input:
        st.error("Please enter a user prompt before submitting.")


# Tab 2: Surface Activation
with tab2:
    st.header("Surface Activation")
    st.caption("Interaction points touched")
    
    st.markdown("### View Surface Activation by Trace ID")
    col1, col2 = st.columns([3, 1])
    with col1:
        trace_id_input = st.text_input(
            "Trace ID",
            value=st.session_state.current_trace_id or "",
            placeholder="TRACE-20241220120000-ABC12345"
        )
    with col2:
        search_button = st.button("Search", type="primary")
    
    if search_button and trace_id_input:
        trace_manager = st.session_state.trace_manager
        trace = trace_manager.get_trace(trace_id_input)
        
        if trace:
            st.success(f"Found trace: `{trace_id_input}`")
            
            # Request info
            st.markdown("### Request Information")
            col1, col2 = st.columns(2)
            with col1:
                st.write("**User Prompt:**", trace.request_data.get("prompt", "N/A"))
            with col2:
                st.write("**User ID:**", trace.request_data.get("user_id", "N/A"))
                st.write("**Timestamp:**", trace.timestamp)
            
            # Verdict
            st.markdown("### Final Verdict")
            render_verdict_badge(trace.verdict, trace.resolution)
            
            # Surface Activation view
            st.markdown("---")
            trace_dict = {
                "pipeline_results": {
                    "gate_results": trace.pipeline_results.get("gate_results", [])
                }
            }
            render_surface_activation(trace.surface_activations, trace_dict)
            
            # Full trace data (expandable)
            with st.expander("Full Trace Data (JSON)"):
                st.json(trace_manager.to_dict(trace))
        else:
            st.error(f"Trace ID `{trace_id_input}` not found.")
    elif search_button:
        st.warning("Please enter a Trace ID to search.")
    elif st.session_state.current_trace_id:
        # Show current trace if available
        trace_manager = st.session_state.trace_manager
        trace = trace_manager.get_trace(st.session_state.current_trace_id)
        if trace:
            trace_dict = {
                "pipeline_results": {
                    "gate_results": trace.pipeline_results.get("gate_results", [])
                }
            }
            render_surface_activation(trace.surface_activations, trace_dict)
    else:
        st.info("Submit a request in the Enforcement Pipeline tab to see surface activation, or search for a trace by ID.")


# Tab 3: Approval Queue
with tab3:
    st.header("Approval Queue")
    st.caption("Pending human review")
    
    pending_approvals = st.session_state.pending_approvals
    
    if not pending_approvals:
        st.info("No pending approvals. All requests have been processed.")
    else:
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            filter_tool = st.selectbox(
                "Filter by Tool",
                ["All"] + list(set(a.get("tool", "Unknown") for a in pending_approvals))
            )
        with col2:
            filter_user = st.selectbox(
                "Filter by User",
                ["All"] + list(set(a.get("user_id", "Unknown") for a in pending_approvals))
            )
        with col3:
            pass
        
        # Filter approvals
        filtered_approvals = pending_approvals
        if filter_tool != "All":
            filtered_approvals = [a for a in filtered_approvals if a.get("tool") == filter_tool]
        if filter_user != "All":
            filtered_approvals = [a for a in filtered_approvals if a.get("user_id") == filter_user]
        
        st.write(f"**{len(filtered_approvals)} pending approval(s)**")
        
        # Approval list
        for idx, approval in enumerate(filtered_approvals):
            with st.container():
                st.markdown("---")
                col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
                
                with col1:
                    st.write(f"**Trace ID:** `{approval.get('trace_id', 'N/A')}`")
                    st.write(f"**Tool:** {approval.get('tool', 'N/A')}")
                
                with col2:
                    st.write(f"**User:** {approval.get('user_id', 'N/A')}")
                    st.write(f"**Timestamp:** {approval.get('timestamp', 'N/A')}")
                
                with col3:
                    render_verdict_badge("ESCALATE", approval.get("resolution"))
                
                with col4:
                    if st.button("Review", key=f"review_{idx}"):
                        st.session_state[f"reviewing_{idx}"] = True
                
                # Approval modal with reason block
                if st.session_state.get(f"reviewing_{idx}", False):
                    st.markdown("#### Review Approval Request")
                    triggered_rule, risk_rationale, scope = render_approval_modal(
                        approval,
                        approval.get("trace_id", "")
                    )
                    
                    # Approval actions
                    col_approve, col_reject, col_cancel = st.columns(3)
                    with col_approve:
                        if st.button("✓ Approve", key=f"approve_{idx}", type="primary"):
                            approval["resolution"] = "APPROVED"
                            approval["approved_by"] = "current_user"
                            approval["approved_at"] = datetime.utcnow().isoformat() + "Z"
                            
                            trace_manager = st.session_state.trace_manager
                            trace = trace_manager.get_trace(approval.get("trace_id"))
                            if trace:
                                trace.resolution = "APPROVED"
                            
                            st.session_state.pending_approvals.remove(approval)
                            st.session_state[f"reviewing_{idx}"] = False
                            st.rerun()
                    
                    with col_reject:
                        comment = st.text_input("Rejection Reason", key=f"reject_reason_{idx}")
                        if st.button("✗ Reject", key=f"reject_{idx}"):
                            approval["resolution"] = "REJECTED"
                            approval["rejected_by"] = "current_user"
                            approval["rejected_at"] = datetime.utcnow().isoformat() + "Z"
                            approval["rejection_reason"] = comment
                            
                            trace_manager = st.session_state.trace_manager
                            trace = trace_manager.get_trace(approval.get("trace_id"))
                            if trace:
                                trace.resolution = "REJECTED"
                            
                            st.session_state.pending_approvals.remove(approval)
                            st.session_state[f"reviewing_{idx}"] = False
                            st.rerun()
                    
                    with col_cancel:
                        if st.button("Cancel", key=f"cancel_{idx}"):
                            st.session_state[f"reviewing_{idx}"] = False
                            st.rerun()


# Tab 4: Audit Trail
with tab4:
    st.header("Audit Trail")
    st.caption("Decision history & evidence")
    
    if not st.session_state.enforcer:
        st.error("No policy loaded.")
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
                ["All"] + list(set(entry.get("decision", "Unknown") for entry in audit_log))
            )
        with col2:
            filter_gate = st.selectbox(
                "Filter by Gate",
                ["All"] + list(set(entry.get("gate", "Unknown") for entry in audit_log))
            )
        with col3:
            filter_user = st.selectbox(
                "Filter by User",
                ["All"] + list(set(entry.get("user_id", "Unknown") for entry in audit_log))
            )
        with col4:
            days_back = st.selectbox("Time Range", [7, 30, 90, 365, "All"])
        
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
                        st.info(f"Trace ID set to: {trace_id_from_evidence}. Switch to 'Enforcement Pipeline' tab to view.")
                        st.rerun()
            
            # Export functionality
            st.markdown("---")
            st.markdown("### Evidence Export")
            st.markdown("Generate evidence packets for audit and compliance")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Export Options")
                export_trace_id = st.text_input("Trace ID (leave empty for all traces)", key="export_trace_id")
                
                include_full_trace = st.checkbox("Include full trace data", value=True, key="export_full_trace")
                include_audit_log = st.checkbox("Include audit log entries", value=True, key="export_audit_log")
                include_policy_version = st.checkbox("Include policy version hash", value=True, key="export_policy_hash")
                
                if st.button("Generate Evidence Packet", type="primary", key="generate_evidence"):
                    trace_manager = st.session_state.trace_manager
                    enforcer = st.session_state.enforcer
                    
                    evidence_packet = {
                        "export_timestamp": datetime.utcnow().isoformat() + "Z",
                        "policy_version": enforcer.policy.get("policy_version", "N/A"),
                        "policy_id": enforcer.policy.get("policy_id", "N/A")
                    }
                    
                    if export_trace_id:
                        trace = trace_manager.get_trace(export_trace_id)
                        if trace:
                            if include_full_trace:
                                evidence_packet["trace"] = trace_manager.to_dict(trace)
                            if include_audit_log:
                                evidence_packet["related_audit_entries"] = [
                                    e for e in enforcer.get_audit_log()
                                    if e.get("evidence", {}).get("trace_id") == export_trace_id
                                ]
                        else:
                            st.error(f"Trace ID {export_trace_id} not found.")
                            st.stop()
                    else:
                        if include_full_trace:
                            evidence_packet["all_traces"] = trace_manager.get_all_traces()
                        if include_audit_log:
                            evidence_packet["audit_log"] = enforcer.get_audit_log()
                    
                    if include_policy_version:
                        policy_str = json.dumps(enforcer.policy, sort_keys=True)
                        evidence_packet["policy_hash"] = str(hash(policy_str))
                    
                    st.session_state["evidence_packet"] = evidence_packet
            
            with col2:
                if "evidence_packet" in st.session_state:
                    st.markdown("#### Evidence Packet")
                    st.json(st.session_state["evidence_packet"])
                    
                    evidence_json = json.dumps(st.session_state["evidence_packet"], indent=2)
                    st.download_button(
                        label="Download Evidence Packet (JSON)",
                        data=evidence_json,
                        file_name=f"evidence_packet_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )


# Footer
st.markdown("---")
st.caption("Constitutional Ontology Enforcement System v1.0")
