"""
Governance Trust Layer - Streamlit UI
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
    render_surface_activation_compact
)


# Page configuration
st.set_page_config(
    page_title="Governance Trust Layer",
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

if "rule_states" not in st.session_state:
    st.session_state.rule_states = {}


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
        # Reset Policy Diff radio to "Baseline Only" when policy changes
        if "policy_view_selector" in st.session_state:
            st.session_state.policy_view_selector = "Baseline Only"
        st.rerun()
    
    # Initialize enforcer if not already loaded
    if "enforcer" not in st.session_state or st.session_state.enforcer is None:
        st.session_state.enforcer = load_policy_file(selected_policy)
        st.session_state.selected_policy = selected_policy
    
    # Initialize rule states from policy
    if st.session_state.enforcer:
        policy = st.session_state.enforcer.policy
        if "rules" in policy:
            for rule in policy["rules"]:
                rule_id = rule.get("rule_id")
                if rule_id and rule_id not in st.session_state.rule_states:
                    st.session_state.rule_states[rule_id] = {
                        "enabled": rule.get("enabled", True),
                        "baseline": rule.get("baseline", False)
                    }
    
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
    st.title("🛡️ Governance Trust Layer")
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

# Main content area - row 1: Enforcement Pipeline + Surface Activation
row1_col1, row1_col2 = st.columns([2, 1])

with row1_col1:
    # 1. Enforcement Pipeline
    if current_trace and trace_dict:
        render_enforcement_pipeline_enhanced(trace_dict)
    else:
        st.markdown("### Enforcement Pipeline")
        st.caption("Gate runtime sequence")
        st.info("Submit a request to see the enforcement pipeline flow.")
    
with row1_col2:
    # 2. Surface Activation
    if current_trace:
        render_surface_activation_compact(current_trace.surface_activations, trace_dict)
    else:
        st.markdown("### Surface Activation")
        st.caption("Interaction points touched")
        st.info("Submit a request to see surface activation.")
    
    st.markdown("---")
    
# Row 2: Escalation Details (full width)
st.markdown("### ⚠️ Escalation Details")

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
else:
    st.info("No escalation details available. Submit a request that triggers escalation to see details here.")

st.markdown("---")

# Row 3: Policy Diff (full width)
st.markdown("### 📊 Policy Comparison")
st.caption("Baseline vs Custom policy differences")

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


st.markdown("---")

# Key UI Elements section
with st.container():
    st.markdown("### 📋 Key UI Elements (P0 Requirements)")
    col_req1, col_req2 = st.columns(2)
    
    with col_req1:
        st.markdown("""
        - **Cognitive Onramp** — Always visible strip with 8-surface grid + gate progress timeline
        - **Baseline vs Custom** — Rule badges showing regulatory floor vs configurable
        """)
    
    with col_req2:
        st.markdown("""
        - **Policy Diff** — Summary card when switching policies
        - **Simulate/Enforce Toggle** — Safe testing mode before deploying
        """)


# Footer
st.markdown("---")
st.caption("Governance Trust Layer System v1.0")
