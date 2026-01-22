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
from pipeline_mapper import execute_pipeline, PolicyContext
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

if "mock_pending_approvals" not in st.session_state:
    st.session_state.mock_pending_approvals = []

if "request_submitted_successfully" not in st.session_state:
    st.session_state.request_submitted_successfully = False


def get_policy_files():
    """Get all JSON policy files from policies directory"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policies_dir = os.path.join(parent_dir, "policies")
    policy_files = []
    if os.path.exists(policies_dir):
        for file in os.listdir(policies_dir):
            if file.endswith('.json') and os.path.isfile(os.path.join(policies_dir, file)):
                policy_files.append(file)
    return sorted(policy_files)


def load_policy_json(policy_filename: str) -> Optional[Dict[str, Any]]:
    """Load a policy file as JSON dictionary from policies directory"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policies_dir = os.path.join(parent_dir, "policies")
    policy_path = os.path.join(policies_dir, policy_filename)
    try:
        with open(policy_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None


def find_baseline_policy_file(baseline_parent_policy_id: Optional[str]) -> Optional[str]:
    """
    Map baseline_parent_policy_id to actual policy filename.
    Returns the filename if found, None otherwise.
    """
    if not baseline_parent_policy_id:
        return None
    
    policy_files = get_policy_files()
    
    # Try exact match first (e.g., "bank_compliance_baseline" -> "policy_bank_compliance_baseline.json")
    # Check if any policy file contains the baseline_parent_policy_id
    for policy_file in policy_files:
        # Remove .json extension and "policy_" prefix for comparison
        policy_id_from_file = policy_file.replace('.json', '').replace('policy_', '')
        if policy_id_from_file == baseline_parent_policy_id:
            return policy_file
    
    # Try loading each policy to check its policy_id field
    for policy_file in policy_files:
        policy_json = load_policy_json(policy_file)
        if policy_json and policy_json.get("policy_id") == baseline_parent_policy_id:
            return policy_file
    
    return None


def load_policy_file(policy_filename: str):
    """Load a policy file and create enforcer from policies directory"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    policies_dir = os.path.join(parent_dir, "policies")
    policy_path = os.path.join(policies_dir, policy_filename)
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
        st.sidebar.error("No policy JSON files found in policies directory")
        return
    
    # Get current selection or default to first file
    current_policy = st.session_state.get("selected_policy", policy_files[0] if policy_files else None)
    
    # Create display labels with "(Baseline)" suffix for baseline policies
    policy_display_options = []
    for policy_file in policy_files:
        # Check if policy is a baseline (by filename or by loading and checking)
        is_baseline = "baseline" in policy_file.lower()
        if is_baseline:
            policy_display_options.append(f"{policy_file} (Baseline)")
        else:
            policy_display_options.append(policy_file)
    
    # Find current index
    current_index = 0
    if current_policy in policy_files:
        current_index = policy_files.index(current_policy)
    
    selected_display = st.sidebar.selectbox(
        "Select Policy File",
        options=policy_display_options,
        index=current_index,
        key="policy_selector"
    )
    
    # Extract actual filename from display option
    selected_policy = selected_display.replace(" (Baseline)", "")
    
    # Reload enforcer and policy context if policy changed
    if selected_policy != st.session_state.get("selected_policy"):
        st.session_state.selected_policy = selected_policy
        st.session_state.enforcer = load_policy_file(selected_policy)
        # Create PolicyContext from loaded policy
        if st.session_state.enforcer:
            try:
                policy_json = st.session_state.enforcer.policy
                st.session_state.policy_context = PolicyContext.from_policy_json(policy_json)
            except Exception as e:
                st.sidebar.error(f"Failed to create policy context: {str(e)}")
                st.session_state.policy_context = None
        else:
            st.session_state.policy_context = None
        # Reset Policy Diff radio to "Baseline Only" when policy changes
        if "policy_view_selector" in st.session_state:
            st.session_state.policy_view_selector = "Baseline Only"
        st.rerun()
    
    # Initialize enforcer and policy context if not already loaded
    if "enforcer" not in st.session_state or st.session_state.enforcer is None:
        st.session_state.enforcer = load_policy_file(selected_policy)
        st.session_state.selected_policy = selected_policy
        # Create PolicyContext from loaded policy
        if st.session_state.enforcer:
            try:
                policy_json = st.session_state.enforcer.policy
                st.session_state.policy_context = PolicyContext.from_policy_json(policy_json)
            except Exception as e:
                st.sidebar.error(f"Failed to create policy context: {str(e)}")
                st.session_state.policy_context = None
        else:
            st.session_state.policy_context = None
    
    # Ensure policy_context exists if enforcer exists
    if st.session_state.enforcer and "policy_context" not in st.session_state:
        try:
            policy_json = st.session_state.enforcer.policy
            st.session_state.policy_context = PolicyContext.from_policy_json(policy_json)
        except Exception as e:
            st.sidebar.error(f"Failed to create policy context: {str(e)}")
            st.session_state.policy_context = None
    
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
        
        # Show current policy information
        current_policy_id = policy.get('policy_id', 'N/A')
        current_version = policy.get('policy_version', 'N/A')
        st.sidebar.write(f"**Current Policy:** {current_policy_id} v{current_version}")
        st.sidebar.write(f"**Description:** {policy.get('description', 'N/A')[:80]}...")
        
        # Show baseline parent information if it exists
        baseline_parent_policy_id = policy.get('baseline_parent_policy_id')
        if baseline_parent_policy_id:
            st.sidebar.markdown("---")
            st.sidebar.write(f"**Baseline Parent:** `{baseline_parent_policy_id}`")
            st.sidebar.caption(f"This policy inherits from `{baseline_parent_policy_id}`")
        else:
            # Check if current policy is itself a baseline (by filename or policy_id)
            selected_policy = st.session_state.get("selected_policy", "")
            is_baseline = "baseline" in selected_policy.lower() or "baseline" in current_policy_id.lower()
            if is_baseline:
                st.sidebar.markdown("---")
                st.sidebar.write(f"**Type:** Baseline Policy")
                st.sidebar.caption("This is a baseline policy (regulatory floor)")
        
        # Show posture from current trace if available
        current_trace_id = st.session_state.get("current_trace_id")
        if current_trace_id:
            trace_manager = st.session_state.trace_manager
            current_trace = trace_manager.get_trace(current_trace_id)
            if current_trace and current_trace.posture_level:
                st.sidebar.markdown("---")
                st.sidebar.markdown("### Current Request Posture")
                st.sidebar.write(f"**Posture:** {current_trace.posture_level}")
                if current_trace.posture_rationale:
                    st.sidebar.write("**Why:**")
                    for rationale in current_trace.posture_rationale:
                        st.sidebar.write(f"- {rationale}")
        
        st.sidebar.markdown("---")
        st.sidebar.markdown("### System Health")
        
        # Count both real and mock pending approvals (only unresolved ones)
        real_pending = [a for a in st.session_state.pending_approvals if a.get("resolution") is None]
        mock_pending = [a for a in st.session_state.mock_pending_approvals if a.get("resolution") is None] if st.session_state.get("simulate_mode", True) else []
        pending_count = len(real_pending) + len(mock_pending)
        
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
    policy_context = st.session_state.get("policy_context")  # Optional - policies are cosmetic
    trace_manager = st.session_state.trace_manager
    
    # Execute pipeline - policy_context is optional (policies don't influence execution)
    pipeline_results = execute_pipeline(user_prompt, user_id, policy_context)
    
    # Create trace - each request gets its own unique trace_id
    trace = trace_manager.create_trace(
        request_data={"prompt": user_prompt, "user_id": user_id},
        pipeline_results=pipeline_results,
        surface_activations=pipeline_results.get("surface_activations", {})
    )
    
    # Extract and persist audit entries from enforcer, linking them to trace_id
    enforcer_audit_entries = pipeline_results.get("enforcer_audit_entries", [])
    for audit_entry in enforcer_audit_entries:
        # Ensure trace_id is in evidence
        if "evidence" not in audit_entry:
            audit_entry["evidence"] = {}
        if "trace_id" not in audit_entry["evidence"]:
            audit_entry["evidence"]["trace_id"] = trace.trace_id
        
        # Add to centralized audit log
        trace_manager.audit_log.append(audit_entry)
        # Also add to trace
        trace_manager.add_audit_to_trace(trace.trace_id, audit_entry)
    
    # Check if escalation occurred - create approval queue item and audit entry
    if pipeline_results.get("final_verdict") == "ESCALATE":
        # Extract tool information from pipeline results
        # Try tool_enforcement_result first, then fall back to Gate 6 signals
        tool_result = pipeline_results.get("tool_enforcement_result")
        gate_results = pipeline_results.get("gate_results", [])
        gate6_result = next((g for g in gate_results if g.get("gate_num") == 6), None)
        
        # Extract tool name and params
        tool_name = None
        tool_params = {}
        controls_applied = []
        evidence = {}
        
        if tool_result:
            tool_name = tool_result.get("tool")
            tool_params = tool_result.get("params", {})
            controls_applied = tool_result.get("controls_applied", [])
            evidence = tool_result.get("evidence", {})
        elif gate6_result:
            gate6_signals = gate6_result.get("signals", {})
            tool_name = gate6_signals.get("tool")
            tool_params = gate6_signals.get("tool_params", {})
            controls_applied = gate6_signals.get("controls_applied", [])
            evidence = {}
        
        # Get verdict details from pipeline results
        verdict_rule_id = pipeline_results.get("verdict_rule_id")
        verdict_rationale = pipeline_results.get("verdict_rationale")
        
        # Create approval queue item
        approval_data = {
            "trace_id": trace.trace_id,  # Link approval to specific trace_id
            "tool": tool_name or "escalation_required",
            "user_id": user_id,
            "timestamp": trace.timestamp,
            "params": tool_params,
            "resolution": None,
            "controls_applied": controls_applied,
            "evidence": evidence,
            "verdict_rule_id": verdict_rule_id,
            "verdict_rationale": verdict_rationale
        }
        # Add to pending approvals - each request maintains independent state via trace_id
        st.session_state.pending_approvals.append(approval_data)
        
        # Create audit log entry for ESCALATE
        trace_manager.add_audit_entry(
            trace_id=trace.trace_id,
            gate="S-O",  # System-Outbound, where tool calls happen
            action=tool_name or "escalation_required",
            decision="REQUIRE_APPROVAL",
            user_id=user_id,
            controls=controls_applied,
            evidence={
                "trace_id": trace.trace_id,
                "verdict_rule_id": verdict_rule_id,
                "verdict_rationale": verdict_rationale,
                "tool_params": tool_params,
                "request": user_prompt
            }
        )
    
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
    policy_context = st.session_state.get("policy_context")
    
    # Demo prompts dropdown - always visible
    st.markdown("**Load Demo Prompt:**")
    demo_prompts = {
        "Select a demo prompt...": None,
        "PASS: What's the weather?": "What's the weather?",
        "ESCALATE: Create a jira ticket": "Create a jira ticket",
        "DENY: Delete all records": "Delete all records",
        "DENY: Export customer PII data": "Export customer PII data"
    }
    
    # Demo prompts dropdown - selection persists across policy changes via key
    demo_options = list(demo_prompts.keys())
    
    # Streamlit automatically persists widget state when using a key
    # The selection will be preserved across policy changes and reruns
    selected_demo = st.selectbox(
        "Demo Prompts",
        options=demo_options,
        index=0,  # Only used on first render when key doesn't exist
        key="demo_prompt_selector",
        label_visibility="collapsed"
    )
    
    # Button is always visible, but disabled if no option selected
    prompt_selected = selected_demo and demo_prompts[selected_demo]
    if st.button("Load Selected Prompt", type="primary", use_container_width=True, disabled=not prompt_selected):
        if prompt_selected:
            st.session_state["user_prompt_input"] = demo_prompts[selected_demo]
            st.rerun()
    
    # Policy selection is optional - policies are independent and don't influence execution
    
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
        
        with col2:
            # Show highlighted success message next to button if submission was successful
            if st.session_state.request_submitted_successfully:
                st.markdown(
                    f'<div style="background-color: #d4edda; color: #155724; padding: 0.5rem 1rem; border-radius: 0.25rem; border: 1px solid #c3e6cb; margin-top: 0.5rem;">'
                    f'<strong>✓ Submission processed successfully!</strong> Trace ID: <code>{st.session_state.current_trace_id}</code>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                # Reset the flag after showing (optional - can keep it visible until next submission)
                # st.session_state.request_submitted_successfully = False
        
        if submit_button and user_input:
            with st.spinner("Processing request through enforcement pipeline..."):
                # Clear any mock state references when submitting in ENFORCE mode
                # (though current_trace_id will be set to new trace anyway)
                trace = process_sandbox_request(user_input)
                if trace:
                    st.session_state.current_trace_id = trace.trace_id
                    st.session_state.request_submitted_successfully = True
                    st.rerun()
        
        elif submit_button and not user_input:
            st.error("Please enter a user prompt before submitting.")
            st.session_state.request_submitted_successfully = False
    
    st.markdown("---")

# Initialize predefined state for simulate mode
if st.session_state.simulate_mode:
    trace_manager = st.session_state.trace_manager
    # Initialize mock state if not already done or if mock approvals are empty
    if not st.session_state.mock_pending_approvals:
        mock_trace, mock_approval_data, mock_pending_approvals = get_mock_state()
        # Store mock trace in trace manager (always ensure it exists)
        if not trace_manager.get_trace(mock_trace.trace_id):
            trace_manager.traces[mock_trace.trace_id] = mock_trace
        # Store mock approvals in session state
        st.session_state.mock_pending_approvals = mock_pending_approvals.copy()
        # Set current trace to mock trace if not already set
        if not st.session_state.current_trace_id:
            st.session_state.current_trace_id = mock_trace.trace_id
    # Ensure mock trace exists in trace manager even if approvals were cleared
    elif not st.session_state.current_trace_id:
        # Reinitialize mock trace if current_trace_id is not set
        mock_trace, _, _ = get_mock_state()
        if not trace_manager.get_trace(mock_trace.trace_id):
            trace_manager.traces[mock_trace.trace_id] = mock_trace
        st.session_state.current_trace_id = mock_trace.trace_id

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
    # If in simulate mode and trace not found, reinitialize mock state
    elif st.session_state.simulate_mode:
        mock_trace, mock_approval_data, mock_pending_approvals = get_mock_state()
        trace_manager.traces[mock_trace.trace_id] = mock_trace
        st.session_state.mock_pending_approvals = mock_pending_approvals.copy()
        st.session_state.current_trace_id = mock_trace.trace_id
        current_trace = mock_trace
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
row1_col1, row1_col2 = st.columns([3, 2])

with row1_col1:
    # 1. Enforcement Pipeline (WHEN)
    if current_trace and trace_dict:
        render_enforcement_pipeline_enhanced(trace_dict)
    else:
        st.markdown("### Enforcement Pipeline")
        st.caption("Temporal sequence: what happened step-by-step")
        st.info("Submit a request to see the enforcement pipeline flow.")
    
with row1_col2:
    # 2. Surface Activation (WHERE)
    if current_trace:
        render_surface_activation_compact(current_trace.surface_activations, trace_dict)
    else:
        st.markdown("### Surface Activation (interaction points touched)")
        st.caption("Spatial boundaries: where governance applied")
        st.info("Submit a request to see surface activation.")
    
    st.markdown("---")
    
# Row 2: Escalation Details (full width)
st.markdown("### ⚠️ Escalation Details")

if current_trace and trace_dict:
    approval_data = None
    if current_trace.verdict == "ESCALATE":
        # Find matching approval data from either mock or real approvals
        if st.session_state.simulate_mode:
            # Check mock approvals first (only in simulate mode)
            for approval in st.session_state.mock_pending_approvals:
                if approval.get("trace_id") == current_trace.trace_id and approval.get("resolution") is None:
                    approval_data = approval
                    break
        # Check real approvals (for ENFORCE mode or if no mock approval found)
        if not approval_data:
            for approval in st.session_state.pending_approvals:
                if approval.get("trace_id") == current_trace.trace_id:
                    approval_data = approval
                    break
    # Always render escalation details if we have a trace with ESCALATE verdict
    # This ensures the section is populated in ENFORCE mode, even if approval_data hasn't been found yet
    if current_trace.verdict == "ESCALATE":
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
baseline_explanation = None

# Get current policy
if st.session_state.get("selected_policy") and st.session_state.get("enforcer"):
    current_policy_file = st.session_state.get("selected_policy")
    current_policy = load_policy_json(current_policy_file)
    
    if current_policy:
        # Try to find baseline based on baseline_parent_policy_id
        baseline_parent_policy_id = current_policy.get('baseline_parent_policy_id')
        current_policy_id = current_policy.get('policy_id', 'N/A')
        
        if baseline_parent_policy_id:
            # Find the baseline policy file
            baseline_file = find_baseline_policy_file(baseline_parent_policy_id)
            if baseline_file:
                baseline_policy = load_policy_json(baseline_file)
                baseline_policy_id = baseline_policy.get('policy_id', baseline_parent_policy_id) if baseline_policy else baseline_parent_policy_id
                baseline_explanation = f"Using `{baseline_policy_id}` because the selected policy (`{current_policy_id}`) has `baseline_parent_policy_id: {baseline_parent_policy_id}`"
            else:
                # Baseline parent specified but file not found
                baseline_explanation = f"⚠️ Baseline parent `{baseline_parent_policy_id}` specified but policy file not found. Using default baseline."
                baseline_file = "policy_bank_compliance_baseline.json"
                if baseline_file in get_policy_files():
                    baseline_policy = load_policy_json(baseline_file)
        else:
            # No baseline_parent_policy_id - use default
            baseline_file = "policy_bank_compliance_baseline.json"
            if baseline_file in get_policy_files():
                baseline_policy = load_policy_json(baseline_file)
            baseline_explanation = f"Using default baseline: `policy_bank_compliance_baseline.json` (no `baseline_parent_policy_id` specified in `{current_policy_id}`)"
    else:
        # Current policy failed to load, try default baseline
        baseline_file = "policy_bank_compliance_baseline.json"
        if baseline_file in get_policy_files():
            baseline_policy = load_policy_json(baseline_file)
            current_policy = baseline_policy
        baseline_explanation = "Using default baseline (current policy failed to load)"
else:
    # No policy selected, use default baseline
    baseline_file = "policy_bank_compliance_baseline.json"
    if baseline_file in get_policy_files():
        baseline_policy = load_policy_json(baseline_file)
        current_policy = baseline_policy
    baseline_explanation = "Using default baseline (no policy selected)"

# Display baseline explanation if available
if baseline_explanation:
    st.caption(f"📋 {baseline_explanation}")

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
