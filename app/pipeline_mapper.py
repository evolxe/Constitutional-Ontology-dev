"""
Pipeline Mapper - Maps existing enforcement methods to 8-gate pipeline stages
Orchestrates execution through 8 gates and tracks Trust Surface activations
"""

import os
import sys
import time
from typing import Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constitutional_enforcement_interactive import ConstitutionalEnforcer, Decision, EnforcementResult


# Gate definitions
GATES = [
    {"num": 1, "name": "Input Validation", "phase": "PRE-FLIGHT", "description": "Schema & injection checks"},
    {"num": 2, "name": "Intent Classification", "phase": "PRE-FLIGHT", "description": "Goal classification"},
    {"num": 3, "name": "Data Classification", "phase": "PRE-FLIGHT", "description": "PII/PHI detection"},
    {"num": 4, "name": "Policy Lookup", "phase": "PRE-FLIGHT", "description": "Rule selection"},
    {"num": 5, "name": "Permission Check", "phase": "VERDICT", "description": "Eligibility check"},
    {"num": 6, "name": "Action Approval", "phase": "VERDICT", "description": "Final verdict"},
    {"num": 7, "name": "Evidence Capture", "phase": "EVIDENCE", "description": "Decision capture"},
    {"num": 8, "name": "Audit Export", "phase": "EVIDENCE", "description": "Audit packet"}
]


def classify_intent(user_input: str) -> str:
    """Classify user intent/category (Gate 2)"""
    user_lower = user_input.lower()
    
    if any(word in user_lower for word in ["draft", "write", "create", "generate"]):
        return "content_creation"
    elif any(word in user_lower for word in ["read", "get", "fetch", "retrieve", "query"]):
        return "information_retrieval"
    elif any(word in user_lower for word in ["update", "modify", "edit", "change"]):
        return "content_modification"
    elif any(word in user_lower for word in ["task", "jira", "issue", "ticket"]):
        return "task_management"
    elif any(word in user_lower for word in ["policy", "compliance", "regulation", "occ", "fdic"]):
        return "regulatory_query"
    else:
        return "general_query"


def execute_pipeline(request: str, user_id: str, enforcer: ConstitutionalEnforcer) -> Dict[str, Any]:
    """
    Execute the 8-gate pipeline for a request.
    Maps existing enforcement methods to pipeline stages.
    Returns trace data with gate results.
    """
    gate_results = []
    surfaces_touched = {
        "U-I": False, "U-O": False,
        "S-I": False, "S-O": False,
        "M-I": False, "M-O": False,
        "A-I": False, "A-O": False
    }
    short_circuited = False
    final_verdict = None
    
    # Gate 1: Input Validation
    start_time = time.time()
    ui_result = enforcer.post_user_input(request, user_id, f"session_{int(time.time())}")
    processing_time = (time.time() - start_time) * 1000  # ms
    
    injection_detected = enforcer._detect_injection(request)
    gate1_result = {
        "gate_num": 1,
        "gate_name": "Input Validation",
        "status": "passed" if ui_result.decision in [Decision.ALLOW, Decision.ALLOW_WITH_CONTROLS] else "failed",
        "verdict": "ALLOW" if ui_result.decision in [Decision.ALLOW, Decision.ALLOW_WITH_CONTROLS] else "DENY",
        "signals": {
            "injection_detected": injection_detected,
            "auth_validated": "auth_validated" in ui_result.controls_applied
        },
        "policies": [],
        "decision_reason": None if ui_result.decision != Decision.DENY else ui_result.denial_reason,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate1_result)
    surfaces_touched["U-I"] = True
    
    if ui_result.decision == Decision.DENY:
        short_circuited = True
        final_verdict = "DENY"
    
    if short_circuited:
        # Mark remaining gates as skipped
        for i in range(2, 9):
            gate_results.append({
                "gate_num": i,
                "gate_name": GATES[i-1]["name"],
                "status": "skipped",
                "verdict": None,
                "signals": {},
                "policies": [],
                "decision_reason": "Pipeline short-circuited at Gate 1",
                "processing_time_ms": 0
            })
        return {
            "gate_results": gate_results,
            "surface_activations": surfaces_touched,
            "final_verdict": final_verdict,
            "short_circuited": True
        }
    
    # Gate 2: Intent Classification
    start_time = time.time()
    intent_category = classify_intent(request)
    processing_time = (time.time() - start_time) * 1000
    
    gate2_result = {
        "gate_num": 2,
        "gate_name": "Intent Classification",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": {"intent_category": intent_category},
        "policies": [],
        "decision_reason": None,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate2_result)
    
    # Gate 3: Data Classification
    start_time = time.time()
    has_pii = enforcer._is_regulated_data(request)
    dlp_result = enforcer._dlp_scan(request)
    processing_time = (time.time() - start_time) * 1000
    
    data_class = "regulated" if has_pii or not dlp_result else "unregulated"
    
    gate3_result = {
        "gate_num": 3,
        "gate_name": "Data Classification",
        "status": "passed" if dlp_result else "failed",
        "verdict": "ALLOW" if dlp_result else "DENY",
        "signals": {
            "has_pii": has_pii,
            "dlp_scan_passed": dlp_result,
            "data_classification": data_class
        },
        "policies": [],
        "decision_reason": None if dlp_result else "DLP scan detected sensitive data",
        "processing_time_ms": processing_time
    }
    gate_results.append(gate3_result)
    
    if not dlp_result:
        short_circuited = True
        final_verdict = "DENY"
    
    if short_circuited:
        for i in range(4, 9):
            gate_results.append({
                "gate_num": i,
                "gate_name": GATES[i-1]["name"],
                "status": "skipped",
                "verdict": None,
                "signals": {},
                "policies": [],
                "decision_reason": "Pipeline short-circuited at Gate 3",
                "processing_time_ms": 0
            })
        return {
            "gate_results": gate_results,
            "surface_activations": surfaces_touched,
            "final_verdict": final_verdict,
            "short_circuited": True
        }
    
    # Gate 4: Policy Lookup
    start_time = time.time()
    # Load applicable policies based on intent and data classification
    applicable_policies = []
    if intent_category == "regulatory_query":
        applicable_policies.append("OCC_MRM_v0")
    if data_class == "regulated":
        applicable_policies.append("EU_AIACT_HR_v0")
    
    # Get policy gates that apply
    policy_gates = list(enforcer.policy.get("gates", {}).keys())
    processing_time = (time.time() - start_time) * 1000
    
    gate4_result = {
        "gate_num": 4,
        "gate_name": "Policy Lookup",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": {
            "applicable_policies": applicable_policies,
            "policy_gates": policy_gates
        },
        "policies": applicable_policies,
        "decision_reason": None,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate4_result)
    
    # Gate 5: Permission Check (simulate by checking if this would be a tool call)
    # For demo purposes, we'll simulate a tool call scenario
    start_time = time.time()
    # Check what tools might be called based on intent
    potential_tools = []
    if intent_category == "information_retrieval":
        potential_tools = ["sharepoint_read", "occ_query"]
    elif intent_category == "content_creation":
        potential_tools = ["write_draft"]
    elif intent_category == "task_management":
        potential_tools = ["jira_create"]
    
    permission_results = {}
    # Do a lightweight permission check
    gate = enforcer.policy.get("gates", {}).get("S-O", {})
    allowed_actions = [a.get("target") if isinstance(a, dict) else a for a in gate.get("allow", [])]
    tool_mapping = {
        "sharepoint_read": "sharepoint",
        "occ_query": "occ_fdic_db",
        "write_draft": "draft_doc",
        "jira_create": "jira_create_task"
    }
    for tool in potential_tools:
        mapped = tool_mapping.get(tool)
        permission_results[tool] = mapped in allowed_actions if mapped else False
        if mapped in allowed_actions:
            surfaces_touched["S-O"] = True
    
    processing_time = (time.time() - start_time) * 1000
    
    gate5_result = {
        "gate_num": 5,
        "gate_name": "Permission Check",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": {
            "potential_tools": potential_tools,
            "permission_results": permission_results
        },
        "policies": applicable_policies,
        "decision_reason": None,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate5_result)
    
    # Gate 6: Action Approval (final verdict)
    start_time = time.time()
    # Check if any tool would require approval
    requires_approval = False
    for tool in potential_tools:
        if tool == "jira_create":  # This one requires approval per policy
            requires_approval = True
            break
    
    if requires_approval:
        verdict = "ESCALATE"
        status = "escalated"
    else:
        verdict = "ALLOW"
        status = "passed"
    
    final_verdict = verdict
    processing_time = (time.time() - start_time) * 1000
    
    gate6_result = {
        "gate_num": 6,
        "gate_name": "Action Approval",
        "status": status,
        "verdict": verdict,
        "signals": {
            "requires_approval": requires_approval,
            "tools_requiring_approval": [t for t in potential_tools if t == "jira_create"]
        },
        "policies": applicable_policies,
        "decision_reason": "Human approval required" if requires_approval else None,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate6_result)
    
    # Gate 7: Evidence Capture
    start_time = time.time()
    # Evidence is captured through the audit log
    evidence_captured = {
        "request": request,
        "user_id": user_id,
        "intent": intent_category,
        "data_class": data_class,
        "verdict": verdict,
        "surfaces_activated": [k for k, v in surfaces_touched.items() if v]
    }
    processing_time = (time.time() - start_time) * 1000
    
    gate7_result = {
        "gate_num": 7,
        "gate_name": "Evidence Capture",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": evidence_captured,
        "policies": applicable_policies,
        "decision_reason": None,
        "processing_time_ms": processing_time
    }
    gate_results.append(gate7_result)
    
    # Gate 8: Audit Export
    start_time = time.time()
    # Prepare evidence packet
    evidence_packet = {
        "trace_id": None,  # Will be set by trace manager
        "timestamp": enforcer._now(),
        "request": request,
        "pipeline_results": gate_results,
        "audit_entries": enforcer.get_audit_log()[-10:]  # Last 10 entries
    }
    processing_time = (time.time() - start_time) * 1000
    
    gate8_result = {
        "gate_num": 8,
        "gate_name": "Audit Export",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": {"evidence_packet_prepared": True},
        "policies": applicable_policies,
        "decision_reason": None,
        "processing_time_ms": processing_time,
        "evidence_packet": evidence_packet
    }
    gate_results.append(gate8_result)
    
    # Check if response would go through U-O gate
    if verdict == "ALLOW" or requires_approval:
        surfaces_touched["U-O"] = True
    
    return {
        "gate_results": gate_results,
        "surface_activations": surfaces_touched,
        "final_verdict": final_verdict,
        "evidence_packet": evidence_packet,
        "short_circuited": False
    }

