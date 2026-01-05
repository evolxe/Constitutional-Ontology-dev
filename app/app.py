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
    get_gate_legend,
    render_cognitive_onramp,
    render_enforcement_pipeline_enhanced,
    render_escalation_details,
    render_policy_diff,
    render_surface_activation_compact,
    render_approval_queue_compact
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

if "pending_approvals" not in st.session_state:
    st.session_state.pending_approvals = []

if "current_trace_id" not in st.session_state:
    st.session_state.current_trace_id = None

if "selected_policy" not in st.session_state:
    st.session_state.selected_policy = None

if "simulate_mode" not in st.session_state:
    st.session_state.simulate_mode = True

if "nav_tab" not in st.session_state:
    st.session_state.nav_tab = "Pipeline Trace"


def get_policy_files():
    """Get all JSON policy files from root directory"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_files = []
    if os.path.exists(parent_dir):
        for file in os.listdir(parent_dir):
            if file.endswith('.json') and os.path.isfile(os.path.join(parent_dir, file)):
                policy_files.append(file)
    return sorted(policy_files)


def load_policy_json(policy_filename: str) -> Optional[Dict[str, Any]]:
    """Load a policy file as JSON dictionary"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.path.join(parent_dir, policy_filename)
    try:
        with open(policy_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None


def load_policy_file(policy_filename: str):
    """Load a policy file and create enforcer"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policy_path = os.path.join(parent_dir, policy_filename)
    try:
        return ConstitutionalEnforcer(policy_path)
    except Exception as e:
        st.error(f"Error loading policy {policy_filename}: {str(e)}")
        return None


def load_policy_summary():
    """Load policy summary for sidebar"""
    # Policy selector
    st.sidebar.markdown("### Policy Selection")
    policy_files = get_policy_files()
    
    if not policy_files:
        st.sidebar.error("No policy JSON files found in root directory")
        return
    
    # Get current selection or default to first file
    current_policy = st.session_state.get("selected_policy", policy_files[0] if policy_files else None)
    selected_policy = st.sidebar.selectbox(
        "Select Policy File",
        options=policy_files,
        index=policy_files.index(current_policy) if current_policy in policy_files else 0,
        key="policy_selector"
    )
    
    # Reload enforcer if policy changed
    if selected_policy != st.session_state.get("selected_policy"):
        st.session_state.selected_policy = selected_policy
        st.session_state.enforcer = load_policy_file(selected_policy)
        st.rerun()
    
    # Initialize enforcer if not already loaded
    if "enforcer" not in st.session_state or st.session_state.enforcer is None:
        st.session_state.enforcer = load_policy_file(selected_policy)
        st.session_state.selected_policy = selected_policy
    
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


def get_mock_state():
    """Generate mock state data for simulate mode"""
    from trace_manager import TraceData
    
    # Mock gate results matching the UI
    gate_results = [
        {"gate_num": 1, "gate_name": "Input Validation", "status": "passed", "verdict": "ALLOW", "signals": {}, "policies": [], "decision_reason": None, "processing_time_ms": 5.2},
        {"gate_num": 2, "gate_name": "Intent Classification", "status": "passed", "verdict": "ALLOW", "signals": {"intent_category": "task_management"}, "policies": [], "decision_reason": None, "processing_time_ms": 3.1},
        {"gate_num": 3, "gate_name": "Data Classification", "status": "passed", "verdict": "ALLOW", "signals": {"has_pii": False, "dlp_scan_passed": True}, "policies": [], "decision_reason": None, "processing_time_ms": 8.5},
        {"gate_num": 4, "gate_name": "Policy Lookup", "status": "passed", "verdict": "ALLOW", "signals": {"applicable_policies": ["OCC_MRM_v0"]}, "policies": ["OCC_MRM_v0"], "decision_reason": None, "processing_time_ms": 2.3},
        {"gate_num": 5, "gate_name": "Permission Check", "status": "passed", "verdict": "ALLOW", "signals": {"tool": "jira_create"}, "policies": ["OCC_MRM_v0"], "decision_reason": None, "processing_time_ms": 4.7},
        {"gate_num": 6, "gate_name": "Action Approval", "status": "escalated", "verdict": "ESCALATE", "signals": {"tool": "jira_create", "requires_approval": True}, "policies": ["OCC_MRM_v0"], "decision_reason": "requires_human_approval", "processing_time_ms": 6.1},
        {"gate_num": 7, "gate_name": "Evidence Capture", "status": "pending", "verdict": None, "signals": {}, "policies": [], "decision_reason": None, "processing_time_ms": 0},
        {"gate_num": 8, "gate_name": "Audit Export", "status": "pending", "verdict": None, "signals": {}, "policies": [], "decision_reason": None, "processing_time_ms": 0}
    ]
    
    # Mock surface activations matching UI: U-I, U-O, S-O are green/active
    surface_activations = {
        "U-I": True,   # User Inbound - active (green)
        "U-O": True,   # User Outbound - active (green)
        "S-I": False,  # System Inbound - inactive (gray)
        "S-O": True,   # System Outbound - active (green)
        "M-I": False,  # Memory Inbound - inactive (gray)
        "M-O": False,  # Memory Outbound - inactive (gray)
        "A-I": False,  # Agent Inbound - inactive (gray)
        "A-O": False   # Agent Outbound - inactive (gray)
    }
    
    # Create mock trace
    mock_trace = TraceData(
        trace_id="abc-123-def",
        timestamp=datetime.utcnow().isoformat() + "Z",
        request_data={"prompt": "Create a Jira task for Q4 compliance review", "user_id": "analyst_123"},
        pipeline_results={
            "gate_results": gate_results,
            "surface_activations": surface_activations,
            "final_verdict": "ESCALATE"
        },
        surface_activations=surface_activations,
        verdict="ESCALATE",
        resolution=None
    )
    
    # Mock approval data
    mock_approval_data = {
        "trace_id": "abc-123-def",
        "tool": "jira_create",
        "user_id": "analyst_123",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "params": {"title": "Q4 Compliance Review", "description": "Review compliance requirements for Q4"},
        "resolution": None,
        "controls_applied": ["approval_hitl"],
        "evidence": {
            "reason": "requires_human_approval",
            "policy_ref": "§3.2 - High-risk tool access"
        }
    }
    
    # Mock second approval for the queue
    mock_approval_data_2 = {
        "trace_id": "xyz-456-ghi",
        "tool": "jira_create",
        "user_id": "analyst_456",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "params": {"title": "Security Audit", "description": "Perform security audit"},
        "resolution": None,
        "controls_applied": ["approval_hitl"],
        "evidence": {
            "reason": "requires_human_approval",
            "policy_ref": "§3.2 - High-risk tool access"
        }
    }
    
    return mock_trace, mock_approval_data, [mock_approval_data, mock_approval_data_2]


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
    
    # Check if escalation occurred - use actual tool enforcement result
    if pipeline_results.get("final_verdict") == "ESCALATE" and pipeline_results.get("tool_enforcement_result"):
        tool_result = pipeline_results.get("tool_enforcement_result")
        approval_data = {
            "trace_id": trace.trace_id,
            "tool": tool_result.get("tool"),
            "user_id": user_id,
            "timestamp": trace.timestamp,
            "params": tool_result.get("params", {}),
            "resolution": None,
            "controls_applied": tool_result.get("controls_applied", []),
            "evidence": tool_result.get("evidence", {})
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


# Header with Simulate/Enforce toggle
header_col1, header_col2 = st.columns([4, 1])
with header_col1:
    pass  # Empty space for layout
with header_col2:
    simulate_mode = st.radio(
        "Mode",
        ["SIMULATE", "ENFORCE"],
        index=0 if st.session_state.simulate_mode else 1,
        horizontal=True,
        key="mode_toggle"
    )
    st.session_state.simulate_mode = (simulate_mode == "SIMULATE")

st.markdown("---")

# Submit Request section - only show in ENFORCE mode
if not st.session_state.simulate_mode:
    st.markdown("### Submit Request")
    if not st.session_state.enforcer:
        st.error("Please load a policy file first. Policy file should be in the parent directory.")
    else:
        # Canned prompts for demo
        st.markdown("**Demo Prompts:**")
        demo_col1, demo_col2, demo_col3 = st.columns(3)
        
        with demo_col1:
            if st.button("What's the weather?", key="demo_weather", use_container_width=True):
                st.session_state["user_prompt_input"] = "What's the weather?"
                st.rerun()
        
        with demo_col2:
            if st.button("Export customer PII", key="demo_export_pii", use_container_width=True):
                st.session_state["user_prompt_input"] = "Export customer PII"
                st.rerun()
        
        with demo_col3:
            if st.button("Delete all records", key="demo_delete", use_container_width=True):
                st.session_state["user_prompt_input"] = "Delete all records"
                st.rerun()
        
        # Initialize session state for user prompt if not exists
        if "user_prompt_input" not in st.session_state:
            st.session_state["user_prompt_input"] = ""
        
        user_input = st.text_area(
            "User Prompt",
            placeholder="e.g., Draft a Q4 compliance policy update under OCC supervision.",
            height=100,
            key="user_prompt_input"
        )
        
        col1, col2 = st.columns([1, 4])
        with col1:
            submit_button = st.button("Submit Request", type="primary")
        
        if submit_button and user_input:
            with st.spinner("Processing request through enforcement pipeline..."):
                trace = process_sandbox_request(user_input)
                if trace:
                    st.session_state.current_trace_id = trace.trace_id
                    st.success(f"**Trace ID:** `{trace.trace_id}`")
                    st.rerun()
        
        elif submit_button and not user_input:
            st.error("Please enter a user prompt before submitting.")
    
    st.markdown("---")

# Get current trace data or use mock state
current_trace = None
trace_dict = None
mock_approval_data = None
mock_pending_approvals = []

if st.session_state.current_trace_id:
    trace_manager = st.session_state.trace_manager
    current_trace = trace_manager.get_trace(st.session_state.current_trace_id)
    if current_trace:
        trace_dict = {
            "trace_id": current_trace.trace_id,
            "pipeline_results": {
                "gate_results": current_trace.pipeline_results.get("gate_results", [])
            }
        }
elif st.session_state.simulate_mode:
    # Use mock state in simulate mode only
    current_trace, mock_approval_data, mock_pending_approvals = get_mock_state()
    trace_dict = {
        "trace_id": current_trace.trace_id,
        "pipeline_results": {
            "gate_results": current_trace.pipeline_results.get("gate_results", [])
        }
    }

# Cognitive Onramp - Hero Section (Full Width)
if current_trace:
    gate_results = current_trace.pipeline_results.get("gate_results", [])
    render_cognitive_onramp(current_trace.surface_activations, gate_results)
else:
    st.markdown("### Cognitive Onramp")
    st.caption("Every AI request passes through 8 checkpoints across 4 surfaces.")
    st.info("Submit a request to see the cognitive onramp visualization.")

st.markdown("---")

# Main content area - two column layout
main_col1, main_col2 = st.columns([2, 1])

# LEFT COLUMN
with main_col1:
    # 1. Enforcement Pipeline
    if current_trace and trace_dict:
        render_enforcement_pipeline_enhanced(trace_dict)
    else:
        st.markdown("### Enforcement Pipeline - gate runtime sequence")
        st.info("Submit a request to see the enforcement pipeline flow.")
    
    st.markdown("---")
    
    # 2. Escalation Details
    if current_trace and trace_dict:
        approval_data = None
        if current_trace.verdict == "ESCALATE":
            # Use mock approval data if in simulate mode, otherwise find from pending approvals
            if st.session_state.simulate_mode and mock_approval_data:
                approval_data = mock_approval_data
            else:
                # Find matching approval data
                for approval in st.session_state.pending_approvals:
                    if approval.get("trace_id") == current_trace.trace_id:
                        approval_data = approval
                        break
        render_escalation_details(trace_dict, approval_data)
    
    # 3. Policy Diff
    # Load baseline and current policies for comparison
    baseline_policy = None
    current_policy = None
    
    # Try to load baseline policy
    baseline_file = "policy_bank_compliance_baseline.json"
    if baseline_file in get_policy_files():
        baseline_policy = load_policy_json(baseline_file)
    
    # Get current policy
    if st.session_state.get("selected_policy") and st.session_state.get("enforcer"):
        current_policy_file = st.session_state.get("selected_policy")
        current_policy = load_policy_json(current_policy_file)
        # If no current policy loaded, use baseline
        if not current_policy:
            current_policy = baseline_policy
    else:
        # If no policy selected, use baseline
        current_policy = baseline_policy
    
    render_policy_diff(baseline_policy, current_policy)

# RIGHT COLUMN
with main_col2:
    # 1. Surface Activation
    if current_trace:
        render_surface_activation_compact(current_trace.surface_activations, trace_dict)
    else:
        st.markdown("### Surface Activation")
        st.caption("Interaction points touched")
        st.info("Submit a request to see surface activation.")
    
    st.markdown("---")
    
    # 2. Approval Queue
    # Use mock approvals in simulate mode if no real approvals exist
    if st.session_state.simulate_mode and not st.session_state.pending_approvals and mock_pending_approvals:
        render_approval_queue_compact(mock_pending_approvals)
    else:
        render_approval_queue_compact(st.session_state.pending_approvals)

st.markdown("---")

# Key UI Elements section
st.markdown("### Key UI Elements (P0 Requirements)")
st.markdown("""
1. Cognitive Onramp — Always visible strip with 8-surface grid + gate progress timeline
2. Baseline vs Custom — Rule badges showing regulatory floor vs configurable
3. Policy Diff — Summary card when switching policies
4. Simulate/Enforce Toggle — Safe testing mode before deploying
""")

# Navigation tabs at bottom
nav_tab1, nav_tab2, nav_tab3, nav_tab4 = st.tabs(["Pipeline Trace", "Approval Queue", "Audit Log", "Export"])

# Tab content based on selection - show additional content in tabs
with nav_tab1:
    # Pipeline Trace content is already shown above in main layout
    st.info("Main pipeline trace content is displayed above in the single-page dashboard.")
    if current_trace:
        st.markdown("### Current Trace Details")
        st.write(f"**Trace ID:** `{current_trace.trace_id}`")
        st.write(f"**Verdict:** {current_trace.verdict}")
        if current_trace.resolution:
            st.write(f"**Resolution:** {current_trace.resolution}")

with nav_tab2:
    # Show full approval queue
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
                    ["All"] + list(set(a.get("tool", "Unknown") for a in pending_approvals)),
                    key="approval_filter_tool"
                )
            with col2:
                filter_user = st.selectbox(
                    "Filter by User",
                    ["All"] + list(set(a.get("user_id", "Unknown") for a in pending_approvals)),
                    key="approval_filter_user"
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
                        
                        col_approve, col_reject, col_cancel = st.columns(3)
                        
                        with col_approve:
                            if st.button("✓ Approve", key=f"approve_{idx}", type="primary"):
                                approval["resolution"] = "APPROVED"
                                approval["approved_by"] = "current_user"
                                approval["approved_at"] = datetime.utcnow().isoformat() + "Z"
                                
                                # Log to audit trail
                                enforcer = st.session_state.enforcer
                                tool = approval.get("tool", "unknown_tool")
                                evidence = {
                                    "trace_id": approval.get("trace_id"),
                                    "approval_timestamp": approval["approved_at"],
                                    "approver": "current_user",
                                    "tool": tool,
                                    "params": approval.get("params", {})
                                }
                                enforcer._log_audit(
                                    "S-O",
                                    tool,
                                    "APPROVED",
                                    "current_user",
                                    ["human_approval"],
                                    evidence
                                )
                                
                                trace_manager = st.session_state.trace_manager
                                trace = trace_manager.get_trace(approval.get("trace_id"))
                                if trace:
                                    trace.resolution = "APPROVED"
                                
                                st.session_state.pending_approvals.remove(approval)
                                st.session_state[f"reviewing_{idx}"] = False
                                st.rerun()
                        
                        with col_reject:
                            if st.button("✗ Reject", key=f"reject_{idx}"):
                                comment = st.session_state.get(f"reject_reason_{idx}", "")
                                approval["resolution"] = "REJECTED"
                                approval["rejected_by"] = "current_user"
                                approval["rejected_at"] = datetime.utcnow().isoformat() + "Z"
                                approval["rejection_reason"] = comment
                                
                                # Log to audit trail
                                enforcer = st.session_state.enforcer
                                tool = approval.get("tool", "unknown_tool")
                                evidence = {
                                    "trace_id": approval.get("trace_id"),
                                    "rejection_timestamp": approval["rejected_at"],
                                    "rejector": "current_user",
                                    "tool": tool,
                                    "params": approval.get("params", {}),
                                    "rejection_reason": comment
                                }
                                enforcer._log_audit(
                                    "S-O",
                                    tool,
                                    "REJECTED",
                                    "current_user",
                                    ["human_rejection"],
                                    evidence
                                )
                                
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
                        
                        # Rejection reason text input below the buttons
                        comment = st.text_input("Rejection Reason", key=f"reject_reason_{idx}", placeholder="Enter reason for rejection (optional)")

with nav_tab3:
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
                ["All"] + list(set(a.get("tool", "Unknown") for a in pending_approvals)),
                key="approval_filter_tool"
            )
        with col2:
            filter_user = st.selectbox(
                "Filter by User",
                ["All"] + list(set(a.get("user_id", "Unknown") for a in pending_approvals)),
                key="approval_filter_user"
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
                    
                    # Approval actions - Buttons in a row at the top
                    # Create a container with unique ID for styling
                    st.markdown(f'<div id="approval-actions-{idx}">', unsafe_allow_html=True)
                    
                    col_approve, col_reject, col_cancel = st.columns(3)
                    
                    with col_approve:
                        if st.button("✓ Approve", key=f"approve_{idx}", type="primary"):
                            approval["resolution"] = "APPROVED"
                            approval["approved_by"] = "current_user"
                            approval["approved_at"] = datetime.utcnow().isoformat() + "Z"
                            
                            # Log to audit trail
                            enforcer = st.session_state.enforcer
                            tool = approval.get("tool", "unknown_tool")
                            evidence = {
                                "trace_id": approval.get("trace_id"),
                                "approval_timestamp": approval["approved_at"],
                                "approver": "current_user",
                                "tool": tool,
                                "params": approval.get("params", {})
                            }
                            enforcer._log_audit(
                                "S-O",
                                tool,
                                "APPROVED",
                                "current_user",
                                ["human_approval"],
                                evidence
                            )
                            
                            trace_manager = st.session_state.trace_manager
                            trace = trace_manager.get_trace(approval.get("trace_id"))
                            if trace:
                                trace.resolution = "APPROVED"
                            
                            st.session_state.pending_approvals.remove(approval)
                            st.session_state[f"reviewing_{idx}"] = False
                            st.rerun()
                    
                    with col_reject:
                        if st.button("✗ Reject", key=f"reject_{idx}"):
                            comment = st.session_state.get(f"reject_reason_{idx}", "")
                            approval["resolution"] = "REJECTED"
                            approval["rejected_by"] = "current_user"
                            approval["rejected_at"] = datetime.utcnow().isoformat() + "Z"
                            approval["rejection_reason"] = comment
                            
                            # Log to audit trail
                            enforcer = st.session_state.enforcer
                            tool = approval.get("tool", "unknown_tool")
                            evidence = {
                                "trace_id": approval.get("trace_id"),
                                "rejection_timestamp": approval["rejected_at"],
                                "rejector": "current_user",
                                "tool": tool,
                                "params": approval.get("params", {}),
                                "rejection_reason": comment
                            }
                            enforcer._log_audit(
                                "S-O",
                                tool,
                                "REJECTED",
                                "current_user",
                                ["human_rejection"],
                                evidence
                            )
                            
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
                    
                    # Rejection reason text input below the buttons
                    comment = st.text_input("Rejection Reason", key=f"reject_reason_{idx}", placeholder="Enter reason for rejection (optional)")
                    
                    # Close container and inject CSS to style the Approve button as green
                    st.markdown(f"""
                    </div>
                    <style>
                    button[data-testid="baseButton-approve_{idx}"] {{
                        background-color: #28a745 !important;
                        border-color: #28a745 !important;
                        color: white !important;
                    }}
                    button[data-testid="baseButton-approve_{idx}"]:hover {{
                        background-color: #218838 !important;
                        border-color: #1e7e34 !important;
                    }}
                    button[data-testid="baseButton-approve_{idx}"]:focus {{
                        background-color: #218838 !important;
                        border-color: #1e7e34 !important;
                    }}
                    </style>
                    """, unsafe_allow_html=True)


        st.header("Audit Trail")
        st.caption("Decision history & evidence")
        
        if not st.session_state.enforcer:
            st.error("No policy loaded.")
        else:
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
                        key="audit_filter_verdict"
                    )
                with col2:
                    filter_gate = st.selectbox(
                        "Filter by Gate",
                        ["All"] + list(set(entry.get("gate", "Unknown") for entry in audit_log)),
                        key="audit_filter_gate"
                    )
                with col3:
                    filter_user = st.selectbox(
                        "Filter by User",
                        ["All"] + list(set(entry.get("user_id", "Unknown") for entry in audit_log)),
                        key="audit_filter_user"
                    )
                with col4:
                    days_back = st.selectbox("Time Range", [7, 30, 90, 365, "All"], key="audit_time_range")
                
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

with nav_tab4:
        st.header("Evidence Export")
        st.caption("Generate evidence packets for audit and compliance")
        
        if not st.session_state.enforcer:
            st.error("No policy loaded.")
        else:
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
                    
                    def make_json_serializable(obj, _visited=None):
                        """Recursively convert objects to JSON-serializable types, handling circular references"""
                        if _visited is None:
                            _visited = set()
                        
                        # Handle basic JSON-serializable types
                        if isinstance(obj, (str, int, float, bool, type(None))):
                            return obj
                        
                        # Handle dict
                        if isinstance(obj, dict):
                            # Check for circular reference by object id
                            obj_id = id(obj)
                            if obj_id in _visited:
                                return "<circular reference>"
                            _visited.add(obj_id)
                            try:
                                result = {k: make_json_serializable(v, _visited) for k, v in obj.items()}
                            finally:
                                _visited.remove(obj_id)
                            return result
                        
                        # Handle list
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
                        
                        # Handle objects with __dict__
                        if hasattr(obj, '__dict__'):
                            obj_id = id(obj)
                            if obj_id in _visited:
                                return "<circular reference>"
                            _visited.add(obj_id)
                            try:
                                return make_json_serializable(vars(obj), _visited)
                            finally:
                                _visited.remove(obj_id)
                        
                        # Fallback: convert to string
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
