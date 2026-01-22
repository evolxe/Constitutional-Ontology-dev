"""
Approval Queue Page - View and manage pending approval requests
"""

import streamlit as st
import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui_components import render_approval_modal, render_verdict_badge, render_sidebar_navigation
from trace_manager import TraceManager


# Page configuration
st.set_page_config(
    page_title="Approval Queue",
    page_icon="✅",
    layout="wide"
)

# Get trace_id from session state
trace_id = st.session_state.get("review_trace_id", None)

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

if "pending_approvals" not in st.session_state:
    st.session_state.pending_approvals = []

if "mock_pending_approvals" not in st.session_state:
    st.session_state.mock_pending_approvals = []

trace_manager = st.session_state.trace_manager

# Sidebar with navigation
with st.sidebar:
    # Clickable title that navigates to home
    if st.button("🛡️ Governance Trust Layer", use_container_width=True, key="nav_title_home"):
        st.switch_page("app.py")
    
    # Navigation menu - placed below other sidebar content
    render_sidebar_navigation()

st.title("✅ Approval Queue")
st.caption("View and manage pending approval requests")

st.markdown("---")

# Initialize mock approvals in session state if in simulate mode and not already initialized
if st.session_state.get("simulate_mode", True) and not st.session_state.mock_pending_approvals:
    # Create mock approvals for demo
    mock_approval_data_1 = {
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
    st.session_state.mock_pending_approvals = [mock_approval_data_1, mock_approval_data_2]

# Combine real and mock approvals, filtering out resolved ones
all_pending_approvals = []
# Add real approvals that are not resolved
for approval in st.session_state.pending_approvals:
    if approval.get("resolution") is None:
        all_pending_approvals.append(approval)
# Add mock approvals that are not resolved (only in simulate mode)
if st.session_state.get("simulate_mode", True):
    for approval in st.session_state.mock_pending_approvals:
        if approval.get("resolution") is None:
            all_pending_approvals.append(approval)

pending_approvals = all_pending_approvals

# If trace_id provided, show review interface
approval_data = None
if trace_id:
    # Find approval in combined pending approvals (real + mock)
    # If there are multiple approvals for the same trace_id, show the first unresolved one
    for approval in pending_approvals:
        if approval.get("trace_id") == trace_id and approval.get("resolution") is None:
            approval_data = approval
            break
    
    # If not found in pending, check if it was already resolved
    if not approval_data:
        trace = trace_manager.get_trace(trace_id)
        if trace and trace.resolution:
            st.warning(f"Approval for trace `{trace_id}` has already been {trace.resolution.lower()}.")
            st.info("This approval request has been processed.")
            st.session_state["review_trace_id"] = None
            st.rerun()

# Show approval queue list or review interface
if approval_data:
    # Display approval review interface
    st.markdown("### Reviewing Approval Request")
    
    col_back, col_info = st.columns([1, 3])
    with col_back:
        if st.button("← Back to Queue", type="secondary"):
            st.session_state["review_trace_id"] = None
            st.rerun()
    with col_info:
        st.write(f"**Trace ID:** `{approval_data.get('trace_id', 'N/A')}`")
        if approval_data.get('verdict_rule_id'):
            st.write(f"**Rule:** `{approval_data.get('verdict_rule_id', 'N/A')}`")
        if approval_data.get('verdict_rationale'):
            st.caption(f"**Rationale:** {approval_data.get('verdict_rationale', 'N/A')}")
    
    st.markdown("---")
    
    # Decision section - moved to top after title
    st.markdown("### Decision")
    
    col_approve, col_reject, col_cancel = st.columns([1, 1, 1])
    
    # Rejection reason input (shown before buttons for better UX)
    rejection_reason = st.text_area(
        "Rejection Reason (if rejecting)",
        placeholder="Enter reason for rejection (optional but recommended)",
        key="rejection_reason_input",
        help="This reason will be recorded in the audit log"
    )
    
    with col_approve:
        if st.button("✓ Approve", type="primary", use_container_width=True):
            approval_data["resolution"] = "APPROVED"
            approval_data["approved_by"] = "current_user"
            approval_data["approved_at"] = datetime.utcnow().isoformat() + "Z"
            
            # Log to audit trail (centralized)
            tool = approval_data.get("tool", "unknown_tool")
            evidence = {
                "trace_id": approval_data.get("trace_id"),
                "approval_timestamp": approval_data["approved_at"],
                "approver": "current_user",
                "tool": tool,
                "params": approval_data.get("params", {})
            }
            trace_manager.add_audit_entry(
                trace_id=approval_data.get("trace_id"),
                gate="S-O",
                action=tool,
                decision="APPROVED",
                user_id="current_user",
                controls=["human_approval"],
                evidence=evidence
            )
            
            # Also log to enforcer if it exists (for backward compatibility)
            if "enforcer" in st.session_state and st.session_state.enforcer:
                st.session_state.enforcer._log_audit(
                    "S-O",
                    tool,
                    "APPROVED",
                    "current_user",
                    ["human_approval"],
                    evidence
                )
            
            # Update trace resolution - each trace maintains independent state
            trace = trace_manager.get_trace(approval_data.get("trace_id"))
            if trace:
                trace.resolution = "APPROVED"
            
            # Remove from appropriate list (real or mock) based on approval_id or trace_id
            approval_id = approval_data.get("approval_id")
            trace_id = approval_data.get("trace_id")
            # Check if it's a mock approval by checking if it exists in mock_pending_approvals
            is_mock = any(a.get("trace_id") == trace_id for a in st.session_state.mock_pending_approvals) if trace_id else False
            
            if is_mock and st.session_state.get("simulate_mode", True):
                # Remove from mock approvals - use approval_id if available, otherwise use trace_id
                if approval_id:
                    st.session_state.mock_pending_approvals = [
                        a for a in st.session_state.mock_pending_approvals 
                        if a.get("approval_id") != approval_id
                    ]
                else:
                    st.session_state.mock_pending_approvals = [
                        a for a in st.session_state.mock_pending_approvals 
                        if a.get("trace_id") != trace_id
                    ]
            else:
                # Remove from real approvals - use approval_id if available, otherwise use trace_id
                if approval_id:
                    st.session_state.pending_approvals = [
                        a for a in st.session_state.pending_approvals 
                        if a.get("approval_id") != approval_id
                    ]
                else:
                    st.session_state.pending_approvals = [
                        a for a in st.session_state.pending_approvals 
                        if a.get("trace_id") != trace_id
                    ]
            
            st.success("Approval request approved!")
            st.balloons()
            st.session_state["review_trace_id"] = None
            st.rerun()
    
    with col_reject:
        if st.button("✗ Reject", use_container_width=True):
            approval_data["resolution"] = "REJECTED"
            approval_data["rejected_by"] = "current_user"
            approval_data["rejected_at"] = datetime.utcnow().isoformat() + "Z"
            approval_data["rejection_reason"] = rejection_reason
            
            # Log to audit trail (centralized)
            tool = approval_data.get("tool", "unknown_tool")
            evidence = {
                "trace_id": approval_data.get("trace_id"),
                "rejection_timestamp": approval_data["rejected_at"],
                "rejector": "current_user",
                "tool": tool,
                "params": approval_data.get("params", {}),
                "rejection_reason": rejection_reason
            }
            trace_manager.add_audit_entry(
                trace_id=approval_data.get("trace_id"),
                gate="S-O",
                action=tool,
                decision="REJECTED",
                user_id="current_user",
                controls=["human_rejection"],
                evidence=evidence
            )
            
            # Also log to enforcer if it exists (for backward compatibility)
            if "enforcer" in st.session_state and st.session_state.enforcer:
                st.session_state.enforcer._log_audit(
                    "S-O",
                    tool,
                    "REJECTED",
                    "current_user",
                    ["human_rejection"],
                    evidence
                )
            
            # Update trace resolution - each trace maintains independent state
            trace = trace_manager.get_trace(approval_data.get("trace_id"))
            if trace:
                trace.resolution = "REJECTED"
            
            # Remove from appropriate list (real or mock) based on approval_id or trace_id
            approval_id = approval_data.get("approval_id")
            trace_id = approval_data.get("trace_id")
            # Check if it's a mock approval by checking if it exists in mock_pending_approvals
            is_mock = any(a.get("trace_id") == trace_id for a in st.session_state.mock_pending_approvals) if trace_id else False
            
            if is_mock and st.session_state.get("simulate_mode", True):
                # Remove from mock approvals - use approval_id if available, otherwise use trace_id
                if approval_id:
                    st.session_state.mock_pending_approvals = [
                        a for a in st.session_state.mock_pending_approvals 
                        if a.get("approval_id") != approval_id
                    ]
                else:
                    st.session_state.mock_pending_approvals = [
                        a for a in st.session_state.mock_pending_approvals 
                        if a.get("trace_id") != trace_id
                    ]
            else:
                # Remove from real approvals - use approval_id if available, otherwise use trace_id
                if approval_id:
                    st.session_state.pending_approvals = [
                        a for a in st.session_state.pending_approvals 
                        if a.get("approval_id") != approval_id
                    ]
                else:
                    st.session_state.pending_approvals = [
                        a for a in st.session_state.pending_approvals 
                        if a.get("trace_id") != trace_id
                    ]
            
            st.error("Approval request rejected!")
            st.session_state["review_trace_id"] = None
            st.rerun()
    
    with col_cancel:
        if st.button("Cancel", use_container_width=True):
            st.session_state["review_trace_id"] = None
            st.rerun()
    
    st.markdown("---")
    
    # Render approval modal content
    triggered_rule, risk_rationale, scope = render_approval_modal(
        approval_data,
        approval_data.get("trace_id", "")
    )
    
    st.markdown("---")
    
    # Approval history section
    st.markdown("### Approval History")
    if approval_data.get("approved_at") or approval_data.get("rejected_at"):
        if approval_data.get("approved_at"):
            st.success(f"✓ Approved by {approval_data.get('approved_by', 'Unknown')} on {approval_data.get('approved_at', '')[:19]}")
        if approval_data.get("rejected_at"):
            st.error(f"✗ Rejected by {approval_data.get('rejected_by', 'Unknown')} on {approval_data.get('rejected_at', '')[:19]}")
            if approval_data.get("rejection_reason"):
                st.caption(f"Reason: {approval_data['rejection_reason']}")
    else:
        st.info("No previous decisions recorded for this approval request.")

else:
    # Show approval queue list
    st.markdown("### Pending Approval Requests")
    
    # Add reset button for mock data in simulate mode
    if st.session_state.get("simulate_mode", True):
        col_reset, col_spacer = st.columns([1, 4])
        with col_reset:
            if st.button("🔄 Reset Mock Data", type="secondary", help="Restore mock approvals for testing"):
                # Reinitialize mock approvals
                mock_approval_data_1 = {
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
                st.session_state.mock_pending_approvals = [mock_approval_data_1, mock_approval_data_2]
                # Also reset trace resolutions if they exist
                trace1 = trace_manager.get_trace("abc-123-def")
                if trace1:
                    trace1.resolution = None
                trace2 = trace_manager.get_trace("xyz-456-ghi")
                if trace2:
                    trace2.resolution = None
                st.success("Mock data reset!")
                st.rerun()
    
    if not pending_approvals:
        st.info("✅ No pending approvals. All requests have been processed.")
        st.markdown("---")
        st.markdown("### Recent Approvals")
        st.info("Recent approval history will be displayed here.")
    else:
        st.write(f"**{len(pending_approvals)} pending approval(s)**")
        
        # Filters
        col_filter1, col_filter2, col_filter3 = st.columns(3)
        with col_filter1:
            filter_tool = st.selectbox(
                "Filter by Tool",
                ["All"] + list(set(a.get("tool", "Unknown") for a in pending_approvals)),
                key="approval_filter_tool"
            )
        with col_filter2:
            filter_user = st.selectbox(
                "Filter by User",
                ["All"] + list(set(a.get("user_id", "Unknown") for a in pending_approvals)),
                key="approval_filter_user"
            )
        with col_filter3:
            pass
        
        # Filter approvals
        filtered_approvals = pending_approvals
        if filter_tool != "All":
            filtered_approvals = [a for a in filtered_approvals if a.get("tool") == filter_tool]
        if filter_user != "All":
            filtered_approvals = [a for a in filtered_approvals if a.get("user_id") == filter_user]
        
        if len(filtered_approvals) != len(pending_approvals):
            st.caption(f"Showing {len(filtered_approvals)} of {len(pending_approvals)} approval(s)")
        
        st.markdown("---")
        
        # Approval list
        for idx, approval in enumerate(filtered_approvals):
            with st.container():
                col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
                
                with col1:
                    st.write(f"**Trace ID:** `{approval.get('trace_id', 'N/A')}`")
                    if approval.get('gate_num'):
                        st.write(f"**Gate:** {approval.get('gate_num')} - {approval.get('gate_name', 'N/A')}")
                    st.write(f"**Tool:** {approval.get('tool', 'N/A')}")
                    if approval.get('verdict_rule_id'):
                        st.caption(f"**Rule:** `{approval.get('verdict_rule_id', 'N/A')}`")
                
                with col2:
                    st.write(f"**User:** {approval.get('user_id', 'N/A')}")
                    st.write(f"**Timestamp:** {approval.get('timestamp', 'N/A')[:19]}")
                    if approval.get('verdict_rationale'):
                        st.caption(f"**Rationale:** {approval.get('verdict_rationale', 'N/A')[:100]}...")
                
                with col3:
                    render_verdict_badge("ESCALATE", approval.get("resolution"))
                
                with col4:
                    # Use approval_id if available, otherwise use trace_id + gate_num, fallback to idx
                    approval_id = approval.get("approval_id") or f"{approval.get('trace_id', 'unknown')}_gate_{approval.get('gate_num', idx)}"
                    if st.button("Review", key=f"review_{approval_id}", type="primary"):
                        st.session_state["review_trace_id"] = approval.get("trace_id")
                        st.rerun()
                
                st.markdown("---")

# Footer navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
