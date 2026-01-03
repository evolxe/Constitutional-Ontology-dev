"""
UI Components - Reusable Streamlit UI components
Pipeline visualization, surface activation grid, approval modal, verdict badges
"""

import streamlit as st
from typing import Dict, Any, List, Optional
from enum import Enum


class Verdict(Enum):
    ALLOW = "ALLOW"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


class Resolution(Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


def render_verdict_badge(verdict: str, resolution: Optional[str] = None):
    """Render a color-coded verdict badge"""
    verdict_upper = verdict.upper() if verdict else "UNKNOWN"
    
    if verdict_upper == "ALLOW":
        st.success(f"✓ {verdict_upper}")
    elif verdict_upper == "ESCALATE":
        st.warning(f"⚠ {verdict_upper}")
        if resolution:
            resolution_upper = resolution.upper()
            if resolution_upper == "APPROVED":
                st.info(f"Resolution: ✓ {resolution_upper}")
            elif resolution_upper == "REJECTED":
                st.error(f"Resolution: ✗ {resolution_upper}")
    elif verdict_upper == "DENY":
        st.error(f"✗ {verdict_upper}")
    else:
        st.info(verdict_upper)


def render_pipeline_flow(trace_data: Dict[str, Any], expandable: bool = True):
    """Render the 8-gate pipeline as a horizontal flow diagram"""
    gate_results = trace_data.get("pipeline_results", {}).get("gate_results", [])
    
    st.markdown("### Enforcement Pipeline")
    st.caption("8-gate runtime sequence")
    
    # Color scheme by phase
    phase_colors = {
        "PRE-FLIGHT": "#d4edda",  # Light green
        "VERDICT": "#fff3cd",      # Light amber
        "EVIDENCE": "#d1ecf1"      # Light blue
    }
    
    # Gate phase mapping
    gate_phases = {
        1: "PRE-FLIGHT", 2: "PRE-FLIGHT", 3: "PRE-FLIGHT", 4: "PRE-FLIGHT",
        5: "VERDICT", 6: "VERDICT",
        7: "EVIDENCE", 8: "EVIDENCE"
    }
    
    # Create columns for gates
    cols = st.columns(8)
    
    for i, gate_info in enumerate([
        {"num": 1, "name": "Input Validation", "desc": "Input Validation"},
        {"num": 2, "name": "Intent Classification", "desc": "Intent Classification"},
        {"num": 3, "name": "Data Classification", "desc": "Data Classification"},
        {"num": 4, "name": "Policy Lookup", "desc": "Policy Lookup"},
        {"num": 5, "name": "Permission Check", "desc": "Permission Check"},
        {"num": 6, "name": "Action Approval", "desc": "Action Approval"},
        {"num": 7, "name": "Evidence Capture", "desc": "Evidence Capture"},
        {"num": 8, "name": "Audit Export", "desc": "Audit Export"}
    ]):
        gate_num = gate_info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with cols[i]:
            if gate_result:
                status = gate_result.get("status", "unknown")
                verdict = gate_result.get("verdict", "")
                phase = gate_phases.get(gate_num, "PRE-FLIGHT")
                bg_color = phase_colors.get(phase, "#f8f9fa")
                
                # Status icon
                if status == "passed":
                    icon = "✓"
                    color = "green"
                elif status == "escalated":
                    icon = "⚠"
                    color = "orange"
                elif status == "failed":
                    icon = "✗"
                    color = "red"
                elif status == "skipped":
                    icon = "⏭"
                    color = "gray"
                else:
                    icon = "?"
                    color = "gray"
                
                # Gate card
                st.markdown(f"""
                <div style="
                    background-color: {bg_color};
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 10px;
                    text-align: center;
                    margin-bottom: 10px;
                ">
                    <div style="font-size: 20px; color: {color}; font-weight: bold;">{icon}</div>
                    <div style="font-weight: bold; font-size: 12px;">Gate {gate_num}</div>
                    <div style="font-size: 10px; margin-top: 5px;">{gate_info['name']}</div>
                    <div style="font-size: 9px; color: #666; margin-top: 3px;">{verdict or 'N/A'}</div>
                </div>
                """, unsafe_allow_html=True)
                
                # Expandable details
                if expandable and status != "skipped":
                    with st.expander("Details", expanded=False):
                        st.write("**Status:**", status)
                        st.write("**Verdict:**", verdict or "N/A")
                        if gate_result.get("signals"):
                            st.write("**Signals:**")
                            st.json(gate_result["signals"])
                        if gate_result.get("policies"):
                            st.write("**Policies:**", ", ".join(gate_result["policies"]))
                        if gate_result.get("decision_reason"):
                            st.write("**Reason:**", gate_result["decision_reason"])
                        st.write("**Processing Time:**", f"{gate_result.get('processing_time_ms', 0):.2f} ms")
            else:
                # Gate not yet processed
                st.markdown(f"""
                <div style="
                    background-color: #f8f9fa;
                    border: 2px dashed #ccc;
                    border-radius: 8px;
                    padding: 10px;
                    text-align: center;
                ">
                    <div style="font-weight: bold; font-size: 12px;">Gate {gate_num}</div>
                    <div style="font-size: 10px; margin-top: 5px;">{gate_info['name']}</div>
                 </div>
                 """, unsafe_allow_html=True)
 

def render_surface_activation(surfaces_touched: Dict[str, bool], trace_data: Dict[str, Any] = None):
    """Render the 4×2 Trust Surfaces grid"""
    st.markdown("### Surface Activation")
    st.caption("Interaction points touched")
    
    surface_labels = {
        "U-I": {"label": "Inputs & instructions", "desc": "Inputs & instructions"},
        "U-O": {"label": "Responses & notifications", "desc": "Responses & notifications"},
        "S-I": {"label": "Tool results & retrievals", "desc": "Tool results & retrievals"},
        "S-O": {"label": "Tool calls & actions", "desc": "Tool calls & actions"},
        "M-I": {"label": "Context retrieval", "desc": "Context retrieval"},
        "M-O": {"label": "Data storage", "desc": "Data storage"},
        "A-I": {"label": "Inter-agent messages", "desc": "Inter-agent messages"},
        "A-O": {"label": "Delegation & handoffs", "desc": "Delegation & handoffs"}
    }
    
    surface_grid = [
        [("U-I", "User"), ("U-O", "User")],
        [("S-I", "System"), ("S-O", "System")],
        [("M-I", "Memory"), ("M-O", "Memory")],
        [("A-I", "Agent"), ("A-O", "Agent")]
    ]
    
    # Determine surface statuses from trace data if available
    surface_statuses = {}
    if trace_data:
        gate_results = trace_data.get("pipeline_results", {}).get("gate_results", [])
        # Check for escalated or denied gates that might affect surfaces
        for gate_result in gate_results:
            gate_status = gate_result.get("status", "")
            gate_verdict = gate_result.get("verdict", "")
            if gate_status == "escalated" or gate_verdict == "ESCALATE":
                # Map gates to surfaces (simplified mapping)
                gate_num = gate_result.get("gate_num", 0)
                if gate_num <= 4:  # Pre-flight gates affect S-O, S-I
                    if "S-O" not in surface_statuses:
                        surface_statuses["S-O"] = "escalated"
                    if "S-I" not in surface_statuses:
                        surface_statuses["S-I"] = "escalated"
            elif gate_status == "failed" or gate_verdict == "DENY":
                if gate_num <= 4:
                    if "S-O" not in surface_statuses:
                        surface_statuses["S-O"] = "denied"
                    if "S-I" not in surface_statuses:
                        surface_statuses["S-I"] = "denied"
    
    # Create grid
    for row in surface_grid:
        cols = st.columns(2)
        for idx, (surface_id, surface_type) in enumerate(row):
            with cols[idx]:
                activated = surfaces_touched.get(surface_id, False)
                info = surface_labels.get(surface_id, {})
                
                # Determine status and icon
                if surface_id in surface_statuses:
                    status_type = surface_statuses[surface_id]
                    if status_type == "escalated":
                        icon = "⚠"
                        color = "#ffc107"  # Amber
                        status = "Escalated"
                        bg_color = "#fff3cd"
                    elif status_type == "denied":
                        icon = "✗"
                        color = "#dc3545"  # Red
                        status = "Denied"
                        bg_color = "#f8d7da"
                    else:
                        icon = "✓"
                        color = "#28a745"  # Green
                        status = "Activated"
                        bg_color = "#d4edda"
                elif activated:
                    icon = "✓"
                    color = "#28a745"  # Green
                    status = "Activated"
                    bg_color = "#d4edda"
                else:
                    icon = "○"
                    color = "#6c757d"  # Gray
                    status = "Not touched"
                    bg_color = "#f8f9fa"
                
                # Card container
                st.markdown(f"""
                <div style="
                    background-color: {bg_color};
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 15px;
                    text-align: center;
                    margin-bottom: 5px;
                ">
                    <div style="font-size: 32px; color: {color}; font-weight: bold; margin-bottom: 8px;">{icon}</div>
                    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">{surface_id}</div>
                    <div style="font-size: 12px; color: #666; margin-bottom: 5px;">{info.get('label', surface_id)}</div>
                    <div style="font-size: 10px; color: #888;">{status}</div>
                </div>
                """, unsafe_allow_html=True)
                
                # Use expander for clickable details (acts as "click" handler for the card)
                if trace_data:
                    with st.expander(f"{surface_id} - Show details", expanded=False):
                        # Determine which gates processed this surface
                        gates_processed = []
                        controls_applied = []
                        
                        gate_results = trace_data.get("pipeline_results", {}).get("gate_results", [])
                        for gate_result in gate_results:
                            gate_num = gate_result.get("gate_num", 0)
                            gate_name = gate_result.get("gate_name", "")
                            # Map gates to surfaces based on gate logic
                            # This is simplified - in reality you'd have better mapping
                            if surface_id == "U-I" and gate_num == 1:
                                gates_processed.append(f"Gate {gate_num}: {gate_name}")
                                controls_applied.extend(gate_result.get("signals", {}).keys())
                            elif surface_id == "S-O" and gate_num in [5, 6]:
                                gates_processed.append(f"Gate {gate_num}: {gate_name}")
                                controls_applied.extend(gate_result.get("signals", {}).keys())
                            elif surface_id == "S-I" and gate_num in [3, 7]:
                                gates_processed.append(f"Gate {gate_num}: {gate_name}")
                                controls_applied.extend(gate_result.get("signals", {}).keys())
                            elif surface_id == "U-O" and gate_num == 6:
                                gates_processed.append(f"Gate {gate_num}: {gate_name}")
                                controls_applied.extend(gate_result.get("signals", {}).keys())
                        
                        st.markdown(f"#### {surface_id} Details")
                        st.write("**Description:**", info.get("desc", ""))
                        
                        if gates_processed:
                            st.write("**Gates that processed this surface:**")
                            for gate in gates_processed:
                                st.write(f"- {gate}")
                        else:
                            # If no specific gates found, show general info
                            if activated:
                                st.write("**Gates that processed this surface:**")
                                st.write("*This surface was activated during request processing*")
                            else:
                                st.write("*No gates processed this surface*")
                        
                        if controls_applied:
                            st.write("**Controls applied:**")
                            unique_controls = list(set(controls_applied))
                            for control in unique_controls:
                                st.write(f"- {control}")
                        elif activated:
                            st.write("**Controls applied:**")
                            st.write("*Standard controls applied*")
                        else:
                            st.write("*No controls applied*")
                


def render_approval_modal(approval_request: Dict[str, Any], trace_id: str):
    """Render approval modal with reason block"""
    st.markdown("### Approval Request")
    
    # Action details
    st.markdown("#### Action Details")
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Tool:**", approval_request.get("tool", "N/A"))
        st.write("**User:**", approval_request.get("user_id", "N/A"))
    with col2:
        st.write("**Trace ID:**", trace_id)
        st.write("**Timestamp:**", approval_request.get("timestamp", "N/A"))
    
    if approval_request.get("params"):
        st.write("**Parameters:**")
        st.json(approval_request["params"])
    
    # Reason block
    st.markdown("---")
    st.markdown("#### Reason for Escalation")
    
    # Triggered rule/clause
    tool = approval_request.get("tool", "")
    if tool == "jira_create":
        triggered_rule = "Policy: S-O gate requires approval_hitl control for execute actions (jira_create_task)"
        risk_rationale = "Creating Jira tasks is a consequential action that may trigger notifications and workflow changes. Requires human oversight to ensure appropriate use."
        scope = "Approving grants permission to create the specified Jira task with the provided title and description. The task will be created immediately upon approval."
    else:
        triggered_rule = "Policy: Approval required for this action type"
        risk_rationale = "This action requires human review based on policy configuration."
        scope = "Approving grants permission to execute this action."
    
    st.markdown(f"**Triggered Rule/Clause:**")
    st.info(triggered_rule)
    
    st.markdown(f"**Risk Rationale:**")
    st.warning(risk_rationale)
    
    st.markdown(f"**What Approving Grants:**")
    st.success(scope)
    
    # Verdict display
    st.markdown("---")
    st.markdown("#### Current Status")
    render_verdict_badge("ESCALATE", approval_request.get("resolution"))
    
    return triggered_rule, risk_rationale, scope


def get_gate_legend() -> Dict[str, str]:
    """Get legend explaining what each gate does"""
    return {
        "Gate 1 - Input Validation": "Checks user input for proper format, schema compliance, and potential prompt injection attacks.",
        "Gate 2 - Intent Classification": "Determines the user's goal or request category (e.g., content creation, information retrieval, task management).",
        "Gate 3 - Data Classification": "Detects and classifies sensitive data types (PII, PHI, regulated data) in the request or content.",
        "Gate 4 - Policy Lookup": "Selects applicable policy rules based on the context, intent, and data classification.",
        "Gate 5 - Permission Check": "Verifies if the user/agent has permission to perform the requested action with the given data classification.",
        "Gate 6 - Action Approval": "Makes the final verdict: ALLOW (proceed), ESCALATE (require human approval), or DENY (block).",
        "Gate 7 - Evidence Capture": "Records all signals, policies applied, decisions made, and timestamps for audit purposes.",
        "Gate 8 - Audit Export": "Prepares the complete evidence packet with full trace, decisions, and metadata for export."
    }

