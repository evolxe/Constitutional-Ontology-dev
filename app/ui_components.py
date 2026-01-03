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
        {"num": 1, "name": "Schema & injection checks", "desc": "Schema & injection checks"},
        {"num": 2, "name": "Goal classification", "desc": "Goal classification"},
        {"num": 3, "name": "PII/PHI detection", "desc": "PII/PHI detection"},
        {"num": 4, "name": "Rule selection", "desc": "Rule selection"},
        {"num": 5, "name": "Eligibility check", "desc": "Eligibility check"},
        {"num": 6, "name": "Final verdict", "desc": "Final verdict"},
        {"num": 7, "name": "Decision capture", "desc": "Decision capture"},
        {"num": 8, "name": "Audit packet", "desc": "Audit packet"}
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
    
    # Draw arrows between gates (using markdown)
    st.markdown("""
    <div style="display: flex; justify-content: space-between; margin-top: -20px; margin-bottom: 20px;">
        <span>→</span><span>→</span><span>→</span><span>→</span><span>→</span><span>→</span><span>→</span>
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
    
    # Create grid
    for row in surface_grid:
        cols = st.columns(2)
        for idx, (surface_id, surface_type) in enumerate(row):
            with cols[idx]:
                activated = surfaces_touched.get(surface_id, False)
                info = surface_labels.get(surface_id, {})
                
                if activated:
                    icon = "✓"
                    color = "#28a745"
                    status = "Activated"
                else:
                    icon = "○"
                    color = "#6c757d"
                    status = "Not touched"
                
                st.markdown(f"""
                <div style="
                    background-color: {'#d4edda' if activated else '#f8f9fa'};
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 15px;
                    text-align: center;
                    margin-bottom: 10px;
                ">
                    <div style="font-size: 24px; color: {color}; font-weight: bold;">{icon}</div>
                    <div style="font-weight: bold; margin-top: 5px;">{surface_id}</div>
                    <div style="font-size: 12px; color: #666; margin-top: 3px;">{info.get('label', surface_id)}</div>
                    <div style="font-size: 10px; color: #888; margin-top: 5px;">{status}</div>
                </div>
                """, unsafe_allow_html=True)
                
                # Show details if activated
                if activated and trace_data:
                    with st.expander(f"{surface_id} Details", expanded=False):
                        st.write("**Description:**", info.get("desc", ""))
                        # Could add more details about which gates processed this surface


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

