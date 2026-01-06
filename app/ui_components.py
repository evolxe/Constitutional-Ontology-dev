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
            gate_num = gate_result.get("gate_num", 0)  # Extract gate_num before if/elif
            if gate_status == "escalated" or gate_verdict == "ESCALATE":
                # Map gates to surfaces (simplified mapping)
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


def render_gate_progress_timeline(gate_results: List[Dict[str, Any]]):
    """Render 8 numbered indicators in horizontal timeline using st.columns"""
    st.markdown("**Gate Progress**")
    cols = st.columns(8)
    
    for i in range(1, 9):
        gate_result = next((g for g in gate_results if g.get("gate_num") == i), None)
        with cols[i-1]:
            if gate_result:
                status = gate_result.get("status", "unknown")
                verdict = gate_result.get("verdict", "")
                
                if status == "passed" or verdict == "ALLOW":
                    st.success(f"**{i}**")
                elif status == "escalated" or verdict == "ESCALATE":
                    st.warning(f"**{i}**")
                elif status == "failed" or verdict == "DENY":
                    st.error(f"**{i}**")
                else:
                    st.info(f"**{i}**")
            else:
                st.info(f"**{i}**")


def render_cognitive_onramp(surfaces_touched: Dict[str, bool], gate_results: List[Dict[str, Any]]):
    """Render Cognitive Onramp section with 8-surface grid and gate progress timeline"""
    st.markdown("### Cognitive Onramp")
    st.caption("Every AI request passes through 8 checkpoints across 4 surfaces.")
    
    # Line 1: 8-surface grid in a single horizontal row (full width)
    # Green background: U-I, U-O, S-O; Gray background: all others
    surface_order = ["U-I", "U-O", "S-I", "S-O", "M-I", "M-O", "A-I", "A-O"]
    green_surfaces = {"U-I", "U-O", "S-O"}
    surface_cols = st.columns(8)
    for i, surface_id in enumerate(surface_order):
        with surface_cols[i]:
            if surface_id in green_surfaces:
                # Green background with white text
                st.success(f"**{surface_id}**")
            else:
                # Gray background - using st.info for colored background (closest to gray in Streamlit)
                # Note: st.info gives blue background, but it's the closest we can get without CSS
                st.info(f"**{surface_id}**")
    
    # Line 2: Gate Progress (left) and Legend (right) with space between
    progress_col, spacer_col, legend_col = st.columns([4, 1, 2])
    
    # Gate Progress timeline
    with progress_col:
        st.markdown("**Gate Progress:**")
        gate_cols = st.columns(8)
        for i in range(1, 9):
            gate_result = next((g for g in gate_results if g.get("gate_num") == i), None)
            with gate_cols[i - 1]:
                if gate_result:
                    status = gate_result.get("status", "unknown")
                    verdict = gate_result.get("verdict", "")
                    
                    if status == "passed" or verdict == "ALLOW":
                        st.success(f"**{i}**")
                    elif status == "escalated" or verdict == "ESCALATE":
                        st.warning(f"**{i}**")
                    elif status == "failed" or verdict == "DENY":
                        st.error(f"**{i}**")
                    else:
                        st.info(f"**{i}**")
                else:
                    st.info(f"**{i}**")
    
    # Legend as vertical column of three items
    with legend_col:
        st.markdown("**Legend:**")
        st.success("Pass")
        st.warning("Escalate")
        st.info("Pending")


def render_enforcement_pipeline_enhanced(trace_data: Dict[str, Any]):
    """Render enhanced enforcement pipeline with 8 steps in a 4x2 grid"""
    st.markdown("### Enforcement Pipeline")
    st.caption("gate runtime sequence")
    
    gate_results = trace_data.get("pipeline_results", {}).get("gate_results", [])
    
    gate_info = [
        {"num": 1, "name": "INPUT VAL", "desc": "Schema & injection"},
        {"num": 2, "name": "INTENT", "desc": "Goal classification"},
        {"num": 3, "name": "DATA CLASS", "desc": "PII/PHI detection"},
        {"num": 4, "name": "POLICY", "desc": "Rule selection"},
        {"num": 5, "name": "PERMISSION", "desc": "Eligibility check"},
        {"num": 6, "name": "APPROVAL", "desc": "Final verdict"},
        {"num": 7, "name": "EVIDENCE", "desc": "Decision capture"},
        {"num": 8, "name": "EXPORT", "desc": "Audit packet"}
    ]
    
    # Create 4x2 grid: 4 columns, 2 rows
    # Row 1: Gates 1-4
    row1_cols = st.columns(4)
    for i in range(4):
        info = gate_info[i]
        gate_num = info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with row1_cols[i]:
            if gate_result:
                status = gate_result.get("status", "unknown")
                verdict = gate_result.get("verdict", "")
                
                # Single write call with three lines: Gate number/name, Description, Status
                if status == "passed" or verdict == "ALLOW":
                    st.success(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PASS**")
                elif status == "escalated" or verdict == "ESCALATE":
                    st.warning(f"**{gate_num} {info['name']}**\n{info['desc']}\n**ESCALATE**")
                elif status == "failed" or verdict == "DENY":
                    st.error(f"**{gate_num} {info['name']}**\n{info['desc']}\n**DENY**")
                else:
                    st.write(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PENDING**")
                
                # Show matched rules for Gate 4 (Policy Lookup)
                if gate_num == 4:
                    matched_rules = gate_result.get("matched_rules", [])
                    verdict_rule = gate_result.get("verdict_rule") or gate_result.get("signals", {}).get("verdict_rule")
                    
                    if matched_rules:
                        with st.expander("View Matched Rules", expanded=False):
                            for rule in matched_rules:
                                rule_id = rule.get("rule_id", "Unknown")
                                is_baseline = rule.get("baseline", False)
                                clause_ref = rule.get("policy_clause_ref", "")
                                description = rule.get("description", "")
                                
                                # Highlight the verdict rule
                                is_verdict_rule = verdict_rule and rule_id == verdict_rule.get("rule_id")
                                
                                # Display rule with badge
                                if is_baseline:
                                    rule_text = f"**Matched Rule:** {rule_id} 🔒 **BASELINE**"
                                else:
                                    rule_text = f"**Matched Rule:** {rule_id} ⚙️ **CUSTOM**"
                                
                                if is_verdict_rule:
                                    rule_text = f"**→ {rule_text}** (Verdict Rule)"
                                
                                st.markdown(rule_text)
                                
                                if clause_ref:
                                    st.caption(f"Clause: {clause_ref}")
                                if description:
                                    st.caption(description)
            else:
                st.write(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PENDING**")
    
    # Row 2: Gates 5-8
    row2_cols = st.columns(4)
    for i in range(4, 8):
        info = gate_info[i]
        gate_num = info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with row2_cols[i - 4]:
            if gate_result:
                status = gate_result.get("status", "unknown")
                verdict = gate_result.get("verdict", "")
                
                # Single write call with three lines: Gate number/name, Description, Status
                if status == "passed" or verdict == "ALLOW":
                    st.success(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PASS**")
                elif status == "escalated" or verdict == "ESCALATE":
                    st.warning(f"**{gate_num} {info['name']}**\n{info['desc']}\n**ESCALATE**")
                elif status == "failed" or verdict == "DENY":
                    st.error(f"**{gate_num} {info['name']}**\n{info['desc']}\n**DENY**")
                else:
                    st.write(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PENDING**")
            else:
                st.write(f"**{gate_num} {info['name']}**\n{info['desc']}\n**PENDING**")


def render_escalation_details(trace_data: Dict[str, Any], approval_data: Optional[Dict[str, Any]] = None):
    """Render escalation details card"""
    gate_results = trace_data.get("pipeline_results", {}).get("gate_results", [])
    escalated_gate = next((g for g in gate_results if g.get("verdict") == "ESCALATE" or g.get("status") == "escalated"), None)
    
    if not escalated_gate and not approval_data:
        return
    
    with st.container():
        st.warning("**ESCALATE**")
        
        if approval_data:
            trace_id = approval_data.get("trace_id", "N/A")
            reason = approval_data.get("evidence", {}).get("reason", "requires_human_approval")
            policy_ref = approval_data.get("evidence", {}).get("policy_ref", "§3.2 - High-risk tool access")
        else:
            trace_id = trace_data.get("trace_id", "N/A")
            reason = escalated_gate.get("decision_reason", "requires_human_approval") if escalated_gate else "requires_human_approval"
            policy_ref = "§3.2 - High-risk tool access"
        
        # Trace ID with Copy button
        trace_col1, trace_col2 = st.columns([3, 1])
        with trace_col1:
            st.text_input("Trace", value=trace_id, key="trace_id_display", disabled=True, label_visibility="collapsed")
        with trace_col2:
            if st.button("Copy ID", key="copy_trace_id"):
                st.session_state["copied_trace_id"] = trace_id
                st.rerun()
        
        # Show success message if trace ID was copied
        if st.session_state.get("copied_trace_id") == trace_id:
            st.success(f"Trace ID `{trace_id}` ready to copy (select text above and use Ctrl+C)")
        
        st.write(f"**Reason:** {reason}")
        st.write(f"**Policy Reference:** {policy_ref}")
        
        if st.button("Open Approval Queue →", type="primary", key="open_approval_queue"):
            st.session_state["nav_tab"] = "Approval Queue"
            st.rerun()


def compare_policies(baseline_policy: Dict[str, Any], current_policy: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two policies and return diff summary"""
    diff = {
        "added_escalation_triggers": [],
        "removed_tools": [],
        "tightened_thresholds": [],
        "new_approval_requirements": []
    }
    
    # Compare S-O gate (System Outbound) for tools and approvals
    baseline_s_o = baseline_policy.get("gates", {}).get("S-O", {}).get("allow", [])
    current_s_o = current_policy.get("gates", {}).get("S-O", {}).get("allow", [])
    
    # Extract tool names from baseline
    baseline_tools = set()
    for item in baseline_s_o:
        if isinstance(item, dict):
            target = item.get("target", "")
            if target:
                baseline_tools.add(target)
        elif isinstance(item, str):
            baseline_tools.add(item)
    
    # Extract tool names from current
    current_tools = set()
    current_approval_tools = set()
    for item in current_s_o:
        if isinstance(item, dict):
            target = item.get("target", "")
            controls = item.get("controls", [])
            if target:
                current_tools.add(target)
                if "approval_hitl" in controls:
                    current_approval_tools.add(target)
        elif isinstance(item, str):
            current_tools.add(item)
    
    # Find removed tools
    removed = baseline_tools - current_tools
    diff["removed_tools"] = list(removed)
    
    # Find new approval requirements
    for item in current_s_o:
        if isinstance(item, dict):
            target = item.get("target", "")
            controls = item.get("controls", [])
            if target and "approval_hitl" in controls:
                # Check if baseline had this tool without approval
                baseline_item = next((i for i in baseline_s_o if (isinstance(i, dict) and i.get("target") == target) or i == target), None)
                if baseline_item:
                    if isinstance(baseline_item, dict):
                        baseline_controls = baseline_item.get("controls", [])
                        if "approval_hitl" not in baseline_controls:
                            diff["new_approval_requirements"].append(target)
                    else:
                        diff["new_approval_requirements"].append(target)
    
    # Compare overlays for escalation triggers
    baseline_overlays = baseline_policy.get("overlays_enabled", [])
    current_overlays = current_policy.get("overlays_enabled", [])
    added_overlays = set(current_overlays) - set(baseline_overlays)
    
    if added_overlays:
        for overlay_id in added_overlays:
            overlay = current_policy.get("overlays", {}).get(overlay_id, {})
            constraints = overlay.get("constraints", [])
            for constraint in constraints:
                trigger = constraint.get("trigger", {})
                if trigger.get("gate") == "S-O" and "approval_hitl" in constraint.get("add_controls", []):
                    diff["added_escalation_triggers"].append(f"{overlay_id}: {trigger.get('action', 'action')}")
    
    # Compare dials for tightened thresholds
    baseline_autonomy = baseline_policy.get("dials", {}).get("autonomy", {}).get("level", "L3")
    current_autonomy = current_policy.get("dials", {}).get("autonomy", {}).get("level", "L3")
    if baseline_autonomy > current_autonomy:  # L3 > L2 > L1 means more restrictive
        diff["tightened_thresholds"].append(f"Autonomy: {baseline_autonomy} → {current_autonomy}")
    
    baseline_tool_access = baseline_policy.get("dials", {}).get("tool_access", {}).get("level", "L3")
    current_tool_access = current_policy.get("dials", {}).get("tool_access", {}).get("level", "L3")
    if baseline_tool_access > current_tool_access:
        diff["tightened_thresholds"].append(f"Tool Access: {baseline_tool_access} → {current_tool_access}")
    
    return diff


def render_policy_diff(baseline_policy: Optional[Dict[str, Any]] = None, current_policy: Optional[Dict[str, Any]] = None):
    """Render policy diff section with Baseline vs Custom rule management"""
    st.markdown("### Policy Diff (vs Baseline):")
    
    # Policy View selector - renamed from Policy Mode
    # Default to "Baseline Only" if not set
    if "policy_view_selector" not in st.session_state:
        st.session_state.policy_view_selector = "Baseline Only"
    
    policy_view = st.radio(
        "Policy View", 
        ["Baseline Only", "Custom"], 
        horizontal=True, 
        key="policy_view_selector"
    )
    
    # Initialize rule_states if not exists
    if "rule_states" not in st.session_state:
        st.session_state.rule_states = {}
    
    # Get rules from current policy (or baseline if no current policy)
    rules = []
    if current_policy and "rules" in current_policy:
        rules = current_policy["rules"]
    elif baseline_policy and "rules" in baseline_policy:
        rules = baseline_policy["rules"]
    
    # Initialize rule states from policy
    for rule in rules:
        rule_id = rule.get("rule_id")
        if rule_id and rule_id not in st.session_state.rule_states:
            st.session_state.rule_states[rule_id] = {
                "enabled": rule.get("enabled", True),
                "baseline": rule.get("baseline", False)
            }
    
    if policy_view == "Baseline Only":
        # Show summary text
        if baseline_policy and current_policy:
            current_policy_id = current_policy.get("policy_id", "")
            baseline_policy_id = baseline_policy.get("policy_id", "")
            if current_policy_id == baseline_policy_id:
                st.info("+2 escalation triggers, -1 tool")
            else:
                diff = compare_policies(baseline_policy, current_policy)
                summary_parts = []
                if diff["added_escalation_triggers"]:
                    summary_parts.append(f"+{len(diff['added_escalation_triggers'])} escalation trigger(s)")
                if diff["removed_tools"]:
                    summary_parts.append(f"−{len(diff['removed_tools'])} tool(s)")
                if diff["tightened_thresholds"]:
                    summary_parts.append(f"↑{len(diff['tightened_thresholds'])} threshold(s) tightened")
                if diff["new_approval_requirements"]:
                    summary_parts.append(f"⚠{len(diff['new_approval_requirements'])} new approval requirement(s)")
                if summary_parts:
                    st.info(", ".join(summary_parts))
                else:
                    st.info("No changes detected")
        else:
            st.info("+2 escalation triggers, -1 tool")
    
    elif policy_view == "Custom":
        # Show rule list with badges and toggles
        if rules:
            st.markdown("#### Rule List")
            for rule in rules:
                rule_id = rule.get("rule_id", "Unknown")
                is_baseline = rule.get("baseline", False)
                description = rule.get("description", "")
                severity = rule.get("severity", "")
                clause_ref = rule.get("policy_clause_ref", "")
                
                # Create columns for rule display
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    # Rule ID and description
                    rule_text = f"**{rule_id}** - {description}"
                    if clause_ref:
                        rule_text += f" ({clause_ref})"
                    st.write(rule_text)
                
                with col2:
                    # Badge
                    if is_baseline:
                        st.markdown("🔒 **BASELINE**")
                    else:
                        st.markdown("⚙️ **CUSTOM**")
                
                with col3:
                    # Toggle (disabled for baseline rules)
                    if is_baseline:
                        # Baseline rules are always enabled, show disabled toggle
                        st.checkbox(
                            "Enabled",
                            value=True,
                            disabled=True,
                            key=f"rule_toggle_{rule_id}",
                            help="Regulatory floor — cannot be disabled"
                        )
                    else:
                        # Custom rules can be toggled
                        current_state = st.session_state.rule_states.get(rule_id, {}).get("enabled", rule.get("enabled", True))
                        new_state = st.checkbox(
                            "Enabled",
                            value=current_state,
                            disabled=False,
                            key=f"rule_toggle_{rule_id}",
                            help="Organizational policy — can be adjusted"
                        )
                        # Update session state if changed
                        if new_state != current_state:
                            st.session_state.rule_states[rule_id] = {
                                "enabled": new_state,
                                "baseline": False
                            }
                            # Update the rule in the policy (in memory)
                            rule["enabled"] = new_state
                            st.rerun()
                
                st.markdown("---")
        else:
            st.info("No rules defined in policy")


def render_surface_activation_compact(surfaces_touched: Dict[str, bool], trace_data: Dict[str, Any] = None):
    """Render compact surface activation for right column"""
    st.markdown("### Surface Activation")
    st.caption("Interaction points touched")
    
    surface_labels = {
        "U-I": "User Inbound",
        "U-O": "User Outbound",
        "S-I": "System Inbound",
        "S-O": "System Outbound",
        "M-I": "Memory Inbound",
        "M-O": "Memory Outbound",
        "A-I": "Agent Inbound",
        "A-O": "Agent Outbound"
    }
    
    surface_grid = [
        [("U-I", "User"), ("U-O", "User")],
        [("S-I", "System"), ("S-O", "System")],
        [("M-I", "Memory"), ("M-O", "Memory")],
        [("A-I", "Agent"), ("A-O", "Agent")]
    ]
    
    # Create grid with row labels: Label | Surface 1 | Surface 2
    for row in surface_grid:
        cols = st.columns([1, 1, 1])
        surface_type = row[0][1]  # Get the type (User, System, Memory, Agent)
        
        # Column 1: Row label
        with cols[0]:
            st.write(surface_type)
        
        # Columns 2-3: Surface buttons
        for idx, (surface_id, _) in enumerate(row):
            with cols[idx + 1]:
                activated = surfaces_touched.get(surface_id, False)
                if activated:
                    st.success(f"**{surface_id}**")
                else:
                    st.info(f"**{surface_id}**")


def render_approval_queue_compact(pending_approvals: List[Dict[str, Any]]):
    """Render compact approval queue for right column"""
    st.markdown("### Approval Queue")
    st.caption("Pending human review")
    
    if not pending_approvals:
        st.info("No pending approvals")
        return
    
    for idx, approval in enumerate(pending_approvals[:5]):  # Show max 5
        with st.container():
            trace_id = approval.get("trace_id", "N/A")
            st.write(f"`{trace_id}`")
            st.warning("ESCALATE")
            if st.button("Review", key=f"compact_review_{idx}"):
                st.session_state[f"reviewing_{idx}"] = True
                st.session_state["nav_tab"] = "Approval Queue"
                st.rerun()
            if idx < len(pending_approvals) - 1:
                st.markdown("---")

