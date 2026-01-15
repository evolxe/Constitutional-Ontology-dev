"""
Gate Details Page - Detailed gate results and export functionality
"""

import streamlit as st
import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_manager import TraceManager


# Page configuration
st.set_page_config(
    page_title="Gate Details",
    page_icon="🚪",
    layout="wide"
)

st.title("🚪 Gate Details")
st.caption("View detailed results for each gate and export evidence packets")

st.markdown("---")

# Initialize session state
if "trace_manager" not in st.session_state:
    st.session_state.trace_manager = TraceManager()

trace_manager = st.session_state.trace_manager

# Get trace selection
st.markdown("### Select Trace to View")

all_traces = trace_manager.get_all_traces()

if not all_traces:
    st.info("No traces available. Submit a request from the main dashboard to generate traces.")
    st.markdown("---")
    if st.button("← Back to Main Dashboard"):
        st.switch_page("app.py")
    st.stop()

# Trace selector
trace_options = {
    f"{trace['trace_id']} - {trace['timestamp'][:19]}": trace["trace_id"]
    for trace in all_traces
}
selected_trace_label = st.selectbox(
    "Select Trace",
    options=list(trace_options.keys()),
    key="gate_details_trace_selector"
)

selected_trace_id = trace_options.get(selected_trace_label)

if not selected_trace_id:
    st.error("No trace selected")
    st.stop()

# Get trace data
trace = trace_manager.get_trace(selected_trace_id)

if not trace:
    st.error(f"Trace {selected_trace_id} not found")
    st.stop()

st.markdown("---")

# Trace overview
st.markdown("### Trace Overview")
col_overview1, col_overview2, col_overview3, col_overview4 = st.columns(4)

with col_overview1:
    st.metric("Trace ID", trace.trace_id[:20] + "...")
with col_overview2:
    st.metric("Verdict", trace.verdict or "N/A")
with col_overview3:
    st.metric("Resolution", trace.resolution or "Pending")
with col_overview4:
    st.metric("Timestamp", trace.timestamp[:19])

st.markdown("---")

# Gate results
gate_results = trace.pipeline_results.get("gate_results", [])

if not gate_results:
    st.warning("No gate results available for this trace.")
    st.stop()

st.markdown("### Gate Results")

# Gate definitions
GATES = [
    {"num": 1, "name": "Input Validation", "phase": "PRE-FLIGHT"},
    {"num": 2, "name": "Intent Classification", "phase": "PRE-FLIGHT"},
    {"num": 3, "name": "Data Classification", "phase": "PRE-FLIGHT"},
    {"num": 4, "name": "Policy Lookup", "phase": "PRE-FLIGHT"},
    {"num": 5, "name": "Permission Check", "phase": "VERDICT"},
    {"num": 6, "name": "Action Approval", "phase": "VERDICT"},
    {"num": 7, "name": "Evidence Capture", "phase": "EVIDENCE"},
    {"num": 8, "name": "Audit Export", "phase": "EVIDENCE"}
]

# Display gates in tabs by phase
phase_tabs = st.tabs(["Pre-Flight (Gates 1-4)", "Verdict (Gates 5-6)", "Evidence (Gates 7-8)"])

with phase_tabs[0]:
    st.markdown("#### Pre-Flight Gates")
    for gate_info in GATES[:4]:
        gate_num = gate_info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with st.expander(f"Gate {gate_num}: {gate_info['name']}", expanded=False):
            if gate_result:
                col_gate1, col_gate2 = st.columns([1, 1])
                
                with col_gate1:
                    st.write("**Status:**", gate_result.get("status", "unknown"))
                    st.write("**Verdict:**", gate_result.get("verdict", "N/A"))
                    st.write("**Processing Time:**", f"{gate_result.get('processing_time_ms', 0):.2f} ms")
                
                with col_gate2:
                    if gate_result.get("policies"):
                        st.write("**Policies Applied:**")
                        for policy in gate_result["policies"]:
                            st.caption(f"• {policy}")
                
                if gate_result.get("signals"):
                    st.markdown("**Signals:**")
                    st.json(gate_result["signals"])
                
                if gate_result.get("decision_reason"):
                    st.markdown("**Decision Reason:**")
                    st.info(gate_result["decision_reason"])
            else:
                st.info("Gate not yet processed")

with phase_tabs[1]:
    st.markdown("#### Verdict Gates")
    for gate_info in GATES[4:6]:
        gate_num = gate_info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with st.expander(f"Gate {gate_num}: {gate_info['name']}", expanded=False):
            if gate_result:
                col_gate1, col_gate2 = st.columns([1, 1])
                
                with col_gate1:
                    st.write("**Status:**", gate_result.get("status", "unknown"))
                    st.write("**Verdict:**", gate_result.get("verdict", "N/A"))
                    st.write("**Processing Time:**", f"{gate_result.get('processing_time_ms', 0):.2f} ms")
                
                with col_gate2:
                    if gate_result.get("policies"):
                        st.write("**Policies Applied:**")
                        for policy in gate_result["policies"]:
                            st.caption(f"• {policy}")
                
                if gate_result.get("signals"):
                    st.markdown("**Signals:**")
                    st.json(gate_result["signals"])
                
                if gate_result.get("decision_reason"):
                    st.markdown("**Decision Reason:**")
                    st.info(gate_result["decision_reason"])
            else:
                st.info("Gate not yet processed")

with phase_tabs[2]:
    st.markdown("#### Evidence Gates")
    for gate_info in GATES[6:8]:
        gate_num = gate_info["num"]
        gate_result = next((g for g in gate_results if g.get("gate_num") == gate_num), None)
        
        with st.expander(f"Gate {gate_num}: {gate_info['name']}", expanded=False):
            if gate_result:
                col_gate1, col_gate2 = st.columns([1, 1])
                
                with col_gate1:
                    st.write("**Status:**", gate_result.get("status", "unknown"))
                    st.write("**Verdict:**", gate_result.get("verdict", "N/A"))
                    st.write("**Processing Time:**", f"{gate_result.get('processing_time_ms', 0):.2f} ms")
                
                with col_gate2:
                    if gate_result.get("policies"):
                        st.write("**Policies Applied:**")
                        for policy in gate_result["policies"]:
                            st.caption(f"• {policy}")
                
                if gate_result.get("signals"):
                    st.markdown("**Signals:**")
                    st.json(gate_result["signals"])
                
                if gate_result.get("decision_reason"):
                    st.markdown("**Decision Reason:**")
                    st.info(gate_result["decision_reason"])
            else:
                st.info("Gate not yet processed")

st.markdown("---")

# Timeline visualization
st.markdown("### Gate Execution Timeline")

# Create a simple timeline visualization
timeline_data = []
for gate_result in gate_results:
    timeline_data.append({
        "Gate": gate_result.get("gate_num"),
        "Name": gate_result.get("gate_name", ""),
        "Status": gate_result.get("status", "unknown"),
        "Time (ms)": gate_result.get("processing_time_ms", 0)
    })

if timeline_data:
    st.dataframe(timeline_data, use_container_width=True)
    
    # Visual timeline
    st.markdown("**Visual Timeline:**")
    timeline_cols = st.columns(8)
    for i, gate_result in enumerate(gate_results[:8]):
        with timeline_cols[i]:
            gate_num = gate_result.get("gate_num", i + 1)
            status = gate_result.get("status", "unknown")
            
            if status == "passed":
                st.success(f"**{gate_num}**")
            elif status == "escalated":
                st.warning(f"**{gate_num}**")
            elif status == "failed":
                st.error(f"**{gate_num}**")
            else:
                st.info(f"**{gate_num}**")
            
            st.caption(f"{gate_result.get('processing_time_ms', 0):.1f}ms")

st.markdown("---")

# Export section
st.markdown("### Export Evidence Packet")

col_export1, col_export2 = st.columns(2)

with col_export1:
    st.markdown("#### Export Options")
    
    include_full_trace = st.checkbox("Include full trace data", value=True, key="gate_export_full_trace")
    include_gate_details = st.checkbox("Include detailed gate results", value=True, key="gate_export_details")
    include_signals = st.checkbox("Include all signals", value=True, key="gate_export_signals")
    include_policies = st.checkbox("Include policy references", value=True, key="gate_export_policies")
    
    if st.button("Generate Evidence Packet", type="primary", key="gate_generate_evidence"):
        evidence_packet = {
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
            "trace_id": trace.trace_id,
            "trace_timestamp": trace.timestamp,
            "verdict": trace.verdict,
            "resolution": trace.resolution
        }
        
        if include_full_trace:
            trace_dict = trace_manager.to_dict(trace)
            evidence_packet["trace"] = trace_dict
        
        if include_gate_details:
            evidence_packet["gate_results"] = gate_results
        
        if include_signals:
            signals = {}
            for gate_result in gate_results:
                if gate_result.get("signals"):
                    signals[f"gate_{gate_result.get('gate_num')}"] = gate_result["signals"]
            evidence_packet["signals"] = signals
        
        if include_policies:
            policies = []
            for gate_result in gate_results:
                if gate_result.get("policies"):
                    policies.extend(gate_result["policies"])
            evidence_packet["policies"] = list(set(policies))
        
        st.session_state["gate_evidence_packet"] = evidence_packet
        st.success("Evidence packet generated!")

with col_export2:
    if "gate_evidence_packet" in st.session_state:
        st.markdown("#### Evidence Packet")
        st.json(st.session_state["gate_evidence_packet"])
        
        evidence_json = json.dumps(st.session_state["gate_evidence_packet"], indent=2)
        st.download_button(
            label="Download Evidence Packet (JSON)",
            data=evidence_json,
            file_name=f"gate_evidence_{trace.trace_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

# Navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
