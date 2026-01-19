"""
Pipeline Mapper - Maps existing enforcement methods to 8-gate pipeline stages
Orchestrates execution through 8 gates and tracks Trust Surface activations
"""

import os
import sys
import time
import re
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constitutional_enforcement_interactive import ConstitutionalEnforcer, Decision, EnforcementResult

# Try to import streamlit for session state access (optional)
try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    HAS_STREAMLIT = False


@dataclass
class PolicyContext:
    """
    Immutable policy context object that encapsulates all policy data.
    Required for all pipeline execution - no execution without policy context.
    """
    policy_id: str
    policy_version: str
    baseline_parent_policy_id: Optional[str] = None
    rules: List[Dict[str, Any]] = field(default_factory=list)
    gates: Dict[str, Any] = field(default_factory=dict)
    overlays: Dict[str, Any] = field(default_factory=dict)
    policy_json: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_policy_json(cls, policy_json: Dict[str, Any]) -> 'PolicyContext':
        """Create PolicyContext from loaded policy JSON"""
        return cls(
            policy_id=policy_json.get("policy_id", "unknown"),
            policy_version=policy_json.get("policy_version", "1.0.0"),
            baseline_parent_policy_id=policy_json.get("baseline_parent_policy_id"),
            rules=policy_json.get("rules", []),
            gates=policy_json.get("gates", {}),
            overlays=policy_json.get("overlays", {}),
            policy_json=policy_json
        )


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


def get_matched_rules(request: str, intent_category: str, data_class: str, tool_name: Optional[str], policy_context: PolicyContext) -> List[Dict[str, Any]]:
    """Get matched rules based on request context from PolicyContext"""
    matched_rules = []
    
    # Get rules from policy context
    if not policy_context or not policy_context.rules:
        return matched_rules
    
    rules = policy_context.rules
    
    # Get rule states (from session state if available, otherwise from policy)
    rule_states = {}
    if HAS_STREAMLIT and "rule_states" in st.session_state:
        rule_states = st.session_state.rule_states
    else:
        # Fallback: initialize from policy
        for rule in rules:
            rule_id = rule.get("rule_id")
            if rule_id:
                rule_states[rule_id] = {
                    "enabled": rule.get("enabled", True),
                    "baseline": rule.get("baseline", False)
                }
    
    # Match rules based on context
    for rule in rules:
        rule_id = rule.get("rule_id")
        applies_to_gate = rule.get("applies_to_gate", "")
        applies_to_control = rule.get("applies_to_control", "")
        
        # Check if rule is enabled (baseline rules are always enabled)
        is_baseline = rule.get("baseline", False)
        rule_state = rule_states.get(rule_id, {})
        is_enabled = rule_state.get("enabled", rule.get("enabled", True)) if not is_baseline else True
        
        # Only include enabled rules
        if not is_enabled:
            continue
        
        # Match rules based on gate and control
        matched = False
        
        # R-001: Authentication rule (Gate 1 / U-I)
        if rule_id == "R-001" and applies_to_gate == "U-I":
            matched = True
        
        # R-011: Delete operations rule (Gate 5/6 / S-O)
        # Also matches for export operations when R-145 is disabled (baseline rule applies)
        elif rule_id == "R-011" and applies_to_gate == "S-O":
            # Match for delete operations
            if tool_name and "delete" in tool_name.lower():
                matched = True
            # Match for export operations when R-145 is disabled (baseline rule takes precedence)
            elif tool_name and "export" in tool_name.lower():
                # Check if R-145 is disabled
                r145_rule = next((r for r in rules if r.get("rule_id") == "R-145"), None)
                if r145_rule:
                    r145_state = rule_states.get("R-145", {})
                    r145_enabled = r145_state.get("enabled", r145_rule.get("enabled", True)) if not r145_rule.get("baseline", False) else True
                    # If R-145 is disabled, R-011 (baseline) applies
                    if not r145_enabled:
                        matched = True
        
        # R-145: PII export rule (Gate 3 data classification)
        elif rule_id == "R-145" and applies_to_gate == "Gate 3" and applies_to_control == "data_classification":
            # Match if R-145 is enabled AND (PII is detected or export tool is used)
            rule_state = rule_states.get("R-145", {})
            r145_enabled = rule_state.get("enabled", rule.get("enabled", True)) if not rule.get("baseline", False) else True
            if r145_enabled and (data_class == "regulated" or (tool_name and "export" in tool_name.lower())):
                matched = True
        
        if matched:
            matched_rules.append({
                "rule_id": rule_id,
                "baseline": is_baseline,
                "enabled": is_enabled,
                "description": rule.get("description", ""),
                "policy_clause_ref": rule.get("policy_clause_ref", ""),
                "severity": rule.get("severity", "")
            })
    
    return matched_rules


def infer_tool_and_params(user_input: str, intent_category: str) -> tuple:
    """
    Infer which tool would be called and extract basic parameters from user input.
    Returns (tool_name, params_dict) or (None, {}) if no tool can be inferred.
    """
    user_lower = user_input.lower()
    
    # High-risk actions that should be denied
    if any(word in user_lower for word in ["delete", "remove", "erase", "wipe", "destroy"]):
        if any(word in user_lower for word in ["all", "every", "entire", "complete"]):
            return "delete_all_records", {"scope": "all", "confirmation": False}
        return "delete_records", {"scope": "selected"}
    
    # Export actions (high risk, needs approval)
    if "export" in user_lower:
        # Extract what to export
        export_match = re.search(r'export\s+(?:all\s+)?(?:customer\s+)?(?:records?|data|pii|phi|information)', user_lower)
        if export_match:
            format_match = re.search(r'(csv|excel|xlsx|json|pdf)', user_lower)
            format_type = format_match.group(1) if format_match else "csv"
            return "export_data", {"format": format_type, "scope": "all" if "all" in user_lower else "selected"}
    
    # Tool inference based on keywords and intent
    if "jira" in user_lower or "issue" in user_lower or "ticket" in user_lower or intent_category == "task_management":
        # Extract title and description from input
        # Try to find quoted text as title
        quoted = re.findall(r'"([^"]*)"', user_input)
        title = quoted[0] if quoted else user_input[:50].strip()
        description = user_input.replace(f'"{quoted[0]}"', '').strip() if quoted else user_input
        return "jira_create", {"title": title, "description": description}
    
    elif "sharepoint" in user_lower or ("read" in user_lower and "document" in user_lower):
        # Extract file path or document name
        file_match = re.search(r'(?:file|document|path)[\s:]+([^\s,\.]+)', user_input, re.IGNORECASE)
        file_path = file_match.group(1) if file_match else "document.pdf"
        return "sharepoint_read", {"file_path": file_path}
    
    elif "occ" in user_lower or "fdic" in user_lower or ("query" in user_lower and "regulation" in user_lower):
        # Extract query text
        query = user_input.replace("query", "").replace("occ", "").replace("fdic", "").strip()
        return "occ_query", {"query": query[:200]}
    
    elif any(word in user_lower for word in ["draft", "write", "create", "generate"]) and intent_category == "content_creation":
        # Extract topic or subject
        topic_keywords = ["about", "on", "topic", "subject"]
        topic = user_input
        for keyword in topic_keywords:
            if keyword in user_lower:
                parts = user_input.lower().split(keyword, 1)
                if len(parts) > 1:
                    topic = parts[1].strip()
                    break
        return "write_draft", {"topic": topic[:200], "content_type": "document"}
    
    # No tool inferred (e.g., "What's the weather?" - informational query)
    return None, {}


def compute_posture_level(
    gate2_intent: str,
    gate3_data_class: str,
    gate3_has_pii: bool,
    tool_name: Optional[str]
) -> tuple:
    """
    Compute posture level (L1/L2/L3) from pipeline signals.
    Returns (posture_level, rationale_list)
    """
    rationale = []
    
    # L3: Highest risk - PII/PHI/regulated data detected
    if gate3_has_pii or gate3_data_class == "regulated":
        rationale.append("PII/PHI detected" if gate3_has_pii else "Regulated data detected")
        return "L3", rationale
    
    # L2: Medium risk - write/externalize actions or medium/high intent risk
    intent_risk_medium = gate2_intent in ["content_modification", "task_management", "information_retrieval"]
    tool_risk_medium = tool_name and any(keyword in tool_name.lower() for keyword in ["write", "export", "execute", "create"])
    
    if intent_risk_medium or tool_risk_medium:
        if intent_risk_medium:
            rationale.append(f"Intent risk: {gate2_intent}")
        if tool_risk_medium:
            rationale.append(f"Tool risk: {tool_name}")
        return "L2", rationale
    
    # L1: Low risk - default
    rationale.append("No elevated risk signals detected")
    return "L1", rationale


def compute_risk_level(
    gate2_intent: str,
    gate3_data_class: str,
    gate3_has_pii: bool,
    gate3_dlp_scan_passed: bool,
    tool_name: Optional[str],
    gate5_verdict: str
) -> tuple:
    """
    Compute risk level (low/medium/high) from gate outputs.
    Returns (risk_level, risk_drivers_list)
    """
    drivers = []
    
    # High risk: PII detected + export/write action
    if gate3_has_pii and tool_name and "export" in tool_name.lower():
        drivers.append("PII detected")
        drivers.append(f"Intent: {gate2_intent}")
        drivers.append(f"Tool: {tool_name}")
        return "high", drivers
    
    # High risk: Regulated data + external action
    if gate3_data_class == "regulated" and tool_name:
        drivers.append("Regulated data detected")
        drivers.append(f"Tool: {tool_name}")
        return "high", drivers
    
    # Medium risk: Write/execute actions without PII
    if tool_name and any(kw in tool_name.lower() for kw in ["write", "execute", "create"]):
        drivers.append(f"Tool: {tool_name}")
        if gate2_intent != "general_query":
            drivers.append(f"Intent: {gate2_intent}")
        return "medium", drivers
    
    # Low risk: Read-only or informational queries
    drivers.append(f"Intent: {gate2_intent}")
    if not tool_name:
        drivers.append("No tool call")
    return "low", drivers


def _execute_weather_prompt(request: str, user_id: str, enforcer: ConstitutionalEnforcer) -> Dict[str, Any]:
    """Execute pipeline for 'What's the weather?' - No tool inferred → ALLOW"""
    import time
    gate_results = []
    surfaces_touched = {"U-I": True, "U-O": True, "S-I": False, "S-O": False, "M-I": False, "M-O": False, "A-I": False, "A-O": False}
    
    # Gate 1: Input Validation - PASS
    start_time = time.time()
    ui_result = enforcer.post_user_input(request, user_id, f"session_{int(time.time())}")
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 1, "gate_name": "Input Validation", "status": "passed", "verdict": "ALLOW",
        "signals": {"injection_detected": False, "auth_validated": True}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 2: Intent Classification - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 2, "gate_name": "Intent Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"intent_category": "general_query"}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 3: Data Classification - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 3, "gate_name": "Data Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"has_pii": False, "dlp_scan_passed": True, "data_classification": "unregulated"},
        "policies": [], "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 4: Policy Lookup - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 4, "gate_name": "Policy Lookup", "status": "passed", "verdict": "ALLOW",
        "signals": {"applicable_policies": [], "policy_gates": list(enforcer.policy.get("gates", {}).keys())},
        "policies": [], "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 5: Permission Check - No tool, so PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 5, "gate_name": "Permission Check", "status": "passed", "verdict": "ALLOW",
        "signals": {"tool": None, "tool_params": {}}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 6: Action Approval - No tool, so ALLOW
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 6, "gate_name": "Action Approval", "status": "passed", "verdict": "ALLOW",
        "signals": {"tool": None, "requires_approval": False}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 7: Evidence Capture - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 7, "gate_name": "Evidence Capture", "status": "passed", "verdict": "ALLOW",
        "signals": {"request": request, "verdict": "ALLOW"}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 8: Audit Export - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 8, "gate_name": "Audit Export", "status": "passed", "verdict": "ALLOW",
        "signals": {"evidence_packet_prepared": True}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Compute posture and risk for weather prompt
    posture_level, posture_rationale = compute_posture_level(
        gate2_intent="general_query",
        gate3_data_class="unregulated",
        gate3_has_pii=False,
        tool_name=None
    )
    risk_level, risk_drivers = compute_risk_level(
        gate2_intent="general_query",
        gate3_data_class="unregulated",
        gate3_has_pii=False,
        gate3_dlp_scan_passed=True,
        tool_name=None,
        gate5_verdict="ALLOW"
    )
    baseline_policy_id = enforcer.policy.get("policy_id", "unknown")
    
    return {
        "gate_results": gate_results,
        "surface_activations": surfaces_touched,
        "final_verdict": "ALLOW",
        "short_circuited": False,
        "baseline_policy_id": baseline_policy_id,
        "posture_level": posture_level,
        "posture_rationale": posture_rationale,
        "risk_level": risk_level,
        "risk_drivers": risk_drivers
    }


def _execute_export_pii_prompt(request: str, user_id: str, enforcer: ConstitutionalEnforcer) -> Dict[str, Any]:
    """Execute pipeline for 'Export customer PII' or 'Export all customer records with emails and SSNs to CSV' - export_data tool → PII detected → ESCALATE (if R-145 enabled)"""
    import time
    gate_results = []
    surfaces_touched = {"U-I": True, "U-O": False, "S-I": False, "S-O": True, "M-I": False, "M-O": False, "A-I": False, "A-O": False}
    
    # Check if R-145 (data sensitivity classification rule) is enabled
    rule_r145_enabled = True  # Default to enabled
    if HAS_STREAMLIT and "rule_states" in st.session_state:
        rule_states = st.session_state.rule_states
        r145_state = rule_states.get("R-145", {})
        rule_r145_enabled = r145_state.get("enabled", True)
    else:
        # Fallback: check policy directly
        policy = enforcer.policy
        if "rules" in policy:
            for rule in policy["rules"]:
                if rule.get("rule_id") == "R-145":
                    rule_r145_enabled = rule.get("enabled", True)
                    break
    
    # Gate 1: Input Validation - PASS
    start_time = time.time()
    ui_result = enforcer.post_user_input(request, user_id, f"session_{int(time.time())}")
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 1, "gate_name": "Input Validation", "status": "passed", "verdict": "ALLOW",
        "signals": {"injection_detected": False, "auth_validated": True}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 2: Intent Classification - PASS
    start_time = time.time()
    intent_category = classify_intent(request)
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 2, "gate_name": "Intent Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"intent_category": intent_category}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 3: Data Classification - Check R-145 rule state
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    
    # Check for PII keywords in request (emails, SSNs, etc.)
    pii_keywords = ["ssn", "ssns", "email", "emails", "pii", "phi", "customer"]
    has_pii_keywords = any(keyword in request.lower() for keyword in pii_keywords)
    
    # If R-145 is enabled, classify as regulated (PII detected)
    # If R-145 is disabled, classify as unregulated (no PII detection)
    if rule_r145_enabled or has_pii_keywords:
        has_pii = True
        dlp_scan_passed = False
        data_classification = "regulated"
    else:
        has_pii = False
        dlp_scan_passed = True
        data_classification = "unregulated"
    
    gate_results.append({
        "gate_num": 3, "gate_name": "Data Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"has_pii": has_pii, "dlp_scan_passed": dlp_scan_passed, "data_classification": data_classification},
        "policies": [], "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 4: Policy Lookup - PASS
    start_time = time.time()
    tool_name = "export_data"  # Known for this prompt
    intent_category = "information_retrieval"
    matched_rules = get_matched_rules(request, intent_category, data_classification, tool_name, enforcer)
    
    # Determine which rule derived the verdict
    verdict_rule = None
    if matched_rules:
        # If R-145 is in matched rules and enabled, it derives the verdict
        r145_rule = next((r for r in matched_rules if r.get("rule_id") == "R-145"), None)
        if r145_rule and r145_rule.get("enabled", True):
            verdict_rule = r145_rule
        else:
            # Otherwise, use the first baseline rule (e.g., R-011)
            baseline_rule = next((r for r in matched_rules if r.get("baseline", False)), None)
            if baseline_rule:
                verdict_rule = baseline_rule
            else:
                # Fallback to first matched rule
                verdict_rule = matched_rules[0]
    
    # Determine applicable policies based on data classification
    applicable_policies = []
    if data_classification == "regulated":
        applicable_policies.append("EU_AIACT_HR_v0")
    
    # Create verdict derivation message
    decision_reason = None
    if verdict_rule:
        rule_id = verdict_rule.get("rule_id", "Unknown")
        is_baseline = verdict_rule.get("baseline", False)
        if is_baseline:
            decision_reason = f"Verdict derived from BASELINE rule {rule_id}"
        else:
            decision_reason = f"Verdict derived from CUSTOM rule {rule_id}"
    
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 4, "gate_name": "Policy Lookup", "status": "passed", "verdict": "ALLOW",
        "signals": {
            "applicable_policies": applicable_policies, 
            "policy_gates": list(enforcer.policy.get("gates", {}).keys()),
            "matched_rules": matched_rules,
            "verdict_rule": verdict_rule
        },
        "policies": applicable_policies, 
        "decision_reason": decision_reason, 
        "processing_time_ms": processing_time,
        "matched_rules": matched_rules,
        "verdict_rule": verdict_rule
    })
    
    # Gate 5 & 6: Permission Check and Action Approval
    # If R-145 is disabled and data is unregulated, allow without escalation
    # If R-145 is enabled and data is regulated, require approval (escalate)
    start_time = time.time()
    tool_params = {"format": "csv", "scope": "all"}
    enforcement_result = enforcer.pre_tool_call(tool_name, tool_params, user_id)
    processing_time = (time.time() - start_time) * 1000
    
    # Determine which rule derived the verdict
    if rule_r145_enabled and data_classification == "regulated":
        # R-145 enabled: require approval → ESCALATE
        gate5_status = "escalated"
        gate5_verdict = "ESCALATE"
        gate6_status = "escalated"
        gate6_verdict = "ESCALATE"
        final_verdict = "ESCALATE"
        # Find R-145 in matched rules to get its details
        r145_rule = next((r for r in matched_rules if r.get("rule_id") == "R-145"), None)
        if r145_rule:
            decision_reason = f"Verdict derived from: CUSTOM rule R-145 (enabled=true) - {r145_rule.get('description', 'PII export requires approval')}"
        else:
            decision_reason = "Verdict derived from: CUSTOM rule R-145 (enabled=true)"
    else:
        # R-145 disabled: allow without escalation
        # Check if a baseline rule applies (e.g., R-011)
        baseline_rule = next((r for r in matched_rules if r.get("baseline", False)), None)
        gate5_status = "passed"
        gate5_verdict = "ALLOW"
        gate6_status = "passed"
        gate6_verdict = "ALLOW"
        final_verdict = "ALLOW"
        if baseline_rule:
            decision_reason = f"Verdict derived from: BASELINE rule {baseline_rule.get('rule_id', 'R-011')}"
        else:
            decision_reason = "Data classified as unregulated (R-145 disabled)"
    
    gate_results.append({
        "gate_num": 5, "gate_name": "Permission Check", "status": gate5_status, "verdict": gate5_verdict,
        "signals": {
            "tool": tool_name, "tool_params": tool_params,
            "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
            "controls_applied": enforcement_result.controls_applied
        },
        "policies": applicable_policies,
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 6: Action Approval
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 6, "gate_name": "Action Approval", "status": gate6_status, "verdict": gate6_verdict,
        "signals": {
            "tool": tool_name, "requires_approval": rule_r145_enabled and data_classification == "regulated",
            "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
            "controls_applied": enforcement_result.controls_applied
        },
        "policies": applicable_policies,
        "decision_reason": decision_reason, "processing_time_ms": processing_time
    })
    
    # Gate 7: Evidence Capture - Include matched rules in evidence
    start_time = time.time()
    # Get policy version/hash
    policy_version = enforcer.policy.get("policy_version", "1.0.0")
    policy_id = enforcer.policy.get("policy_id", "unknown")
    
    evidence_packet = {
        "request": request,
        "verdict": final_verdict,
        "policy_version": policy_version,
        "policy_id": policy_id,
        "matched_rules": matched_rules,
        "rule_states_at_decision": [
            {
                "rule_id": rule["rule_id"],
                "baseline": rule["baseline"],
                "enabled": rule["enabled"]
            }
            for rule in matched_rules
        ]
    }
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 7, "gate_name": "Evidence Capture", "status": "passed", "verdict": "ALLOW",
        "signals": evidence_packet, 
        "policies": applicable_policies,
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 8: Audit Export - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 8, "gate_name": "Audit Export", "status": "passed", "verdict": "ALLOW",
        "signals": {"evidence_packet_prepared": True}, "policies": applicable_policies,
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Compute posture and risk for export PII prompt
    posture_level, posture_rationale = compute_posture_level(
        gate2_intent=intent_category,
        gate3_data_class=data_classification,
        gate3_has_pii=has_pii,
        tool_name=tool_name
    )
    risk_level, risk_drivers = compute_risk_level(
        gate2_intent=intent_category,
        gate3_data_class=data_classification,
        gate3_has_pii=has_pii,
        gate3_dlp_scan_passed=dlp_scan_passed,
        tool_name=tool_name,
        gate5_verdict=gate5_verdict
    )
    baseline_policy_id = enforcer.policy.get("policy_id", "unknown")
    
    return {
        "gate_results": gate_results,
        "surface_activations": surfaces_touched,
        "final_verdict": final_verdict,
        "short_circuited": False,
        "baseline_policy_id": baseline_policy_id,
        "posture_level": posture_level,
        "posture_rationale": posture_rationale,
        "risk_level": risk_level,
        "risk_drivers": risk_drivers,
        "tool_enforcement_result": {
            "tool": tool_name,
            "params": tool_params,
            "controls_applied": enforcement_result.controls_applied,
            "evidence": enforcement_result.evidence
        }
    }


def _execute_delete_prompt(request: str, user_id: str, enforcer: ConstitutionalEnforcer) -> Dict[str, Any]:
    """Execute pipeline for 'Delete all records' - delete_all_records tool → DENY"""
    import time
    gate_results = []
    surfaces_touched = {"U-I": True, "U-O": False, "S-I": False, "S-O": True, "M-I": False, "M-O": False, "A-I": False, "A-O": False}
    
    # Gate 1: Input Validation - PASS
    start_time = time.time()
    ui_result = enforcer.post_user_input(request, user_id, f"session_{int(time.time())}")
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 1, "gate_name": "Input Validation", "status": "passed", "verdict": "ALLOW",
        "signals": {"injection_detected": False, "auth_validated": True}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 2: Intent Classification - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 2, "gate_name": "Intent Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"intent_category": "content_modification"}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 3: Data Classification - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 3, "gate_name": "Data Classification", "status": "passed", "verdict": "ALLOW",
        "signals": {"has_pii": False, "dlp_scan_passed": True, "data_classification": "unregulated"},
        "policies": [], "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 4: Policy Lookup - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 4, "gate_name": "Policy Lookup", "status": "passed", "verdict": "ALLOW",
        "signals": {"applicable_policies": [], "policy_gates": list(enforcer.policy.get("gates", {}).keys())},
        "policies": [], "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 5: Permission Check - delete_all_records tool in deny list → DENY
    start_time = time.time()
    tool_name = "delete_all_records"
    tool_params = {"scope": "all", "confirmation": False}
    enforcement_result = enforcer.pre_tool_call(tool_name, tool_params, user_id)
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 5, "gate_name": "Permission Check", "status": "failed", "verdict": "DENY",
        "signals": {
            "tool": tool_name, "tool_params": tool_params,
            "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
            "controls_applied": enforcement_result.controls_applied
        },
        "policies": [],
        "decision_reason": enforcement_result.denial_reason or "Tool 'delete_all_records' not in allowlist",
        "processing_time_ms": processing_time
    })
    
    # Gate 6: Action Approval - DENY
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 6, "gate_name": "Action Approval", "status": "failed", "verdict": "DENY",
        "signals": {
            "tool": tool_name, "requires_approval": False,
            "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
            "controls_applied": enforcement_result.controls_applied
        },
        "policies": [],
        "decision_reason": enforcement_result.denial_reason or "Action denied by policy",
        "processing_time_ms": processing_time
    })
    
    # Gate 7: Evidence Capture - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 7, "gate_name": "Evidence Capture", "status": "passed", "verdict": "ALLOW",
        "signals": {"request": request, "verdict": "DENY"}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Gate 8: Audit Export - PASS
    start_time = time.time()
    processing_time = (time.time() - start_time) * 1000
    gate_results.append({
        "gate_num": 8, "gate_name": "Audit Export", "status": "passed", "verdict": "ALLOW",
        "signals": {"evidence_packet_prepared": True}, "policies": [],
        "decision_reason": None, "processing_time_ms": processing_time
    })
    
    # Compute posture and risk for delete prompt
    posture_level, posture_rationale = compute_posture_level(
        gate2_intent="content_modification",
        gate3_data_class="unregulated",
        gate3_has_pii=False,
        tool_name=tool_name
    )
    risk_level, risk_drivers = compute_risk_level(
        gate2_intent="content_modification",
        gate3_data_class="unregulated",
        gate3_has_pii=False,
        gate3_dlp_scan_passed=True,
        tool_name=tool_name,
        gate5_verdict="DENY"
    )
    baseline_policy_id = enforcer.policy.get("policy_id", "unknown")
    
    return {
        "gate_results": gate_results,
        "surface_activations": surfaces_touched,
        "final_verdict": "DENY",
        "short_circuited": False,
        "baseline_policy_id": baseline_policy_id,
        "posture_level": posture_level,
        "posture_rationale": posture_rationale,
        "risk_level": risk_level,
        "risk_drivers": risk_drivers
    }


def execute_pipeline(request: str, user_id: str, policy_context: PolicyContext) -> Dict[str, Any]:
    """
    Execute the 8-gate pipeline for a request.
    Maps existing enforcement methods to pipeline stages.
    Returns trace data with gate results.
    All prompts (including demo prompts) flow through the normal pipeline
    to ensure policy-based enforcement is applied.
    
    Args:
        request: User prompt/request
        user_id: User identifier
        policy_context: PolicyContext object (required - no execution without policy)
    
    Returns:
        Dict with gate results, verdict, and policy enforcement evidence
    """
    # Validate policy context is present
    if policy_context is None:
        raise ValueError("Policy context is required for pipeline execution. No execution without policy.")
    
    # Create enforcer from policy context
    # We need to save policy to temp file or pass policy_json directly
    # For now, create enforcer from policy_json by saving to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
        json.dump(policy_context.policy_json, tmp_file)
        tmp_path = tmp_file.name
    
    try:
        enforcer = ConstitutionalEnforcer(tmp_path)
    finally:
        # Clean up temp file
        import os
        try:
            os.unlink(tmp_path)
        except:
            pass
    
    # Log policy ID at execution start
    if HAS_STREAMLIT:
        st.write(f"🔒 Executing with policy: {policy_context.policy_id} (v{policy_context.policy_version})")
    
    # All requests use normal pipeline execution to respect selected policy
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
        # Compute posture and risk even for short-circuited paths
        baseline_policy_id = enforcer.policy.get("policy_id", "unknown")
        # For short-circuited at Gate 1, we have minimal info - default to L1
        posture_level, posture_rationale = compute_posture_level(
            gate2_intent="unknown",
            gate3_data_class="unknown",
            gate3_has_pii=False,
            tool_name=None
        )
        risk_level, risk_drivers = compute_risk_level(
            gate2_intent="unknown",
            gate3_data_class="unknown",
            gate3_has_pii=False,
            gate3_dlp_scan_passed=True,
            tool_name=None,
            gate5_verdict="DENY"
        )
        
        return {
            "gate_results": gate_results,
            "surface_activations": surfaces_touched,
            "final_verdict": final_verdict,
            "short_circuited": True,
            "baseline_policy_id": baseline_policy_id,
            "policy_id": policy_context.policy_id,
            "policy_version": policy_context.policy_version,
            "baseline_parent_policy_id": policy_context.baseline_parent_policy_id,
            "posture_level": posture_level,
            "posture_rationale": posture_rationale,
            "risk_level": risk_level,
            "risk_drivers": risk_drivers,
            "verdict_rule_id": None,
            "verdict_rule_type": None,
            "verdict_rationale": "Pipeline short-circuited before policy rule evaluation"
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
    
    # Check for PII keywords in request (for demo scenarios like "Export customer PII" or "Export all customer records with emails and SSNs")
    pii_keywords = ["pii", "phi", "customer", "ssn", "ssns", "social security", "credit card", "account number", "email", "emails"]
    has_pii_keywords = any(keyword in request.lower() for keyword in pii_keywords)
    if has_pii_keywords:
        has_pii = True
        # If PII detected, DLP scan should fail for demo purposes
        dlp_result = False
    
    processing_time = (time.time() - start_time) * 1000
    
    data_class = "regulated" if has_pii or not dlp_result else "unregulated"
    
    gate3_result = {
        "gate_num": 3,
        "gate_name": "Data Classification",
        "status": "passed",  # Gate 3 classifies data but doesn't make final decision
        "verdict": "ALLOW",  # Always allow to continue to policy evaluation
        "signals": {
            "has_pii": has_pii,
            "dlp_scan_passed": dlp_result,
            "data_classification": data_class
        },
        "policies": [],
        "decision_reason": None if dlp_result else "DLP scan detected sensitive data - will be evaluated by policy",
        "processing_time_ms": processing_time
    }
    gate_results.append(gate3_result)
    
    # Compute posture level after Gate 3 (we have intent, data_class, has_pii)
    # Tool name will be inferred in Gate 4, so we'll recompute posture after Gate 4
    posture_level = None
    posture_rationale = []
    
    # Don't short-circuit at Gate 3 - let policy evaluation (Gate 5/6) make the decision
    # Gate 3 only classifies data; the policy's S-O gate will determine ALLOW/ESCALATE/DENY
    
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
        # Compute posture and risk for short-circuited at Gate 3
        baseline_policy_id = policy_context.policy_id
        # We have intent from Gate 2, but data classification failed
        gate2_result = next((g for g in gate_results if g.get("gate_num") == 2), None)
        intent_category = gate2_result.get("signals", {}).get("intent_category", "unknown") if gate2_result else "unknown"
        
        posture_level, posture_rationale = compute_posture_level(
            gate2_intent=intent_category,
            gate3_data_class="regulated",  # DLP failed, so regulated
            gate3_has_pii=True,  # DLP failed implies PII
            tool_name=None
        )
        risk_level, risk_drivers = compute_risk_level(
            gate2_intent=intent_category,
            gate3_data_class="regulated",
            gate3_has_pii=True,
            gate3_dlp_scan_passed=False,
            tool_name=None,
            gate5_verdict="DENY"
        )
        
        return {
            "gate_results": gate_results,
            "surface_activations": surfaces_touched,
            "final_verdict": final_verdict,
            "short_circuited": True,
            "baseline_policy_id": baseline_policy_id,
            "policy_id": policy_context.policy_id,
            "policy_version": policy_context.policy_version,
            "baseline_parent_policy_id": policy_context.baseline_parent_policy_id,
            "posture_level": posture_level,
            "posture_rationale": posture_rationale,
            "risk_level": risk_level,
            "risk_drivers": risk_drivers,
            "verdict_rule_id": None,
            "verdict_rule_type": None,
            "verdict_rationale": "Pipeline short-circuited before policy rule evaluation"
        }
    
    # Gate 4: Policy Lookup
    start_time = time.time()
    # Load applicable policies based on intent and data classification
    applicable_policies = []
    if intent_category == "regulatory_query":
        applicable_policies.append("OCC_MRM_v0")
    if data_class == "regulated":
        applicable_policies.append("EU_AIACT_HR_v0")
    
    # Get policy gates that apply from policy context
    policy_gates = list(policy_context.gates.keys())
    
    # Get matched rules from policy context
    tool_name, _ = infer_tool_and_params(request, intent_category)
    matched_rules = get_matched_rules(request, intent_category, data_class, tool_name, policy_context)
    
    # Extract matched rule IDs and categorize by baseline/custom
    matched_rule_ids = [r.get("rule_id") for r in matched_rules if r.get("rule_id")]
    baseline_rules = [r.get("rule_id") for r in matched_rules if r.get("baseline", False) and r.get("rule_id")]
    custom_rules = [r.get("rule_id") for r in matched_rules if not r.get("baseline", False) and r.get("rule_id")]
    
    # Compute posture level now that we have tool_name
    posture_level, posture_rationale = compute_posture_level(
        gate2_intent=intent_category,
        gate3_data_class=data_class,
        gate3_has_pii=has_pii,
        tool_name=tool_name
    )
    
    # Determine which rule derived the verdict
    verdict_rule = None
    if matched_rules:
        # If R-145 is in matched rules and enabled, it derives the verdict
        r145_rule = next((r for r in matched_rules if r.get("rule_id") == "R-145"), None)
        if r145_rule and r145_rule.get("enabled", True):
            verdict_rule = r145_rule
        else:
            # Otherwise, use the first baseline rule (e.g., R-011)
            baseline_rule = next((r for r in matched_rules if r.get("baseline", False)), None)
            if baseline_rule:
                verdict_rule = baseline_rule
            else:
                # Fallback to first matched rule
                verdict_rule = matched_rules[0]
    
    # Create verdict derivation message
    decision_reason = None
    if verdict_rule:
        rule_id = verdict_rule.get("rule_id", "Unknown")
        is_baseline = verdict_rule.get("baseline", False)
        if is_baseline:
            decision_reason = f"Verdict derived from BASELINE rule {rule_id}"
        else:
            decision_reason = f"Verdict derived from CUSTOM rule {rule_id}"
    
    processing_time = (time.time() - start_time) * 1000
    
    gate4_result = {
        "gate_num": 4,
        "gate_name": "Policy Lookup",
        "status": "passed",
        "verdict": "ALLOW",
        "signals": {
            "applicable_policies": applicable_policies,
            "policy_gates": policy_gates,
            "matched_rules": matched_rules,
            "verdict_rule": verdict_rule
        },
        "policies": applicable_policies,
        "decision_reason": decision_reason,
        "processing_time_ms": processing_time,
        "matched_rules": matched_rules,
        "matched_rule_ids": matched_rule_ids,
        "baseline_rules": baseline_rules,
        "custom_rules": custom_rules,
        "verdict_rule": verdict_rule
    }
    gate_results.append(gate4_result)
    
    # Gate 5 & 6: Permission Check and Action Approval
    # Infer which tool would be called and run real enforcement
    start_time = time.time()
    tool_name, tool_params = infer_tool_and_params(request, intent_category)
    
    tool_enforcement_result = None
    tool_decision = None
    requires_approval = False
    approval_required = False
    
    # Initialize verdict rule variables (used in both tool and no-tool paths)
    verdict_rule_id = None
    verdict_rule_type = None
    verdict_rationale = None
    
    if tool_name:
        # Gate 5: Permission Check - Actually call pre_tool_call enforcement
        enforcement_result = enforcer.pre_tool_call(tool_name, tool_params, user_id)
        tool_enforcement_result = enforcement_result
        tool_decision = enforcement_result.decision
        surfaces_touched["S-O"] = True
        
        processing_time_gate5 = (time.time() - start_time) * 1000
        
        gate5_result = {
            "gate_num": 5,
            "gate_name": "Permission Check",
            "status": "passed" if enforcement_result.decision in [Decision.ALLOW, Decision.ALLOW_WITH_CONTROLS, Decision.REQUIRE_APPROVAL] else "failed",
            "verdict": "ALLOW" if enforcement_result.decision in [Decision.ALLOW, Decision.ALLOW_WITH_CONTROLS] else ("ESCALATE" if enforcement_result.decision == Decision.REQUIRE_APPROVAL else "DENY"),
            "signals": {
                "tool": tool_name,
                "tool_params": tool_params,
                "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
                "controls_applied": enforcement_result.controls_applied
            },
            "policies": applicable_policies,
            "decision_reason": enforcement_result.denial_reason if enforcement_result.decision == Decision.DENY else None,
            "processing_time_ms": processing_time_gate5
        }
        gate_results.append(gate5_result)
        
        # Gate 6: Action Approval - Derive verdict from policy rules
        start_time_gate6 = time.time()
        
        # Aggregate all matched rules from Gate 4 and their severities
        # Verdict selection logic: deny > escalate > allow
        verdict_rule_id = None
        verdict_rule_type = None
        verdict_rationale = None
        
        # Check for deny rules first
        deny_rules = [r for r in matched_rules if r.get("severity") == "deny"]
        if deny_rules:
            verdict_rule = deny_rules[0]  # Use first deny rule
            verdict = "DENY"
            status = "failed"
            final_verdict = "DENY"
            verdict_rule_id = verdict_rule.get("rule_id", "Unknown")
            verdict_rule_type = "BASELINE" if verdict_rule.get("baseline", False) else "CUSTOM"
            verdict_rationale = f"Verdict derived from rule {verdict_rule_id} ({verdict_rule_type}) - severity: deny"
        # Check for escalate rules
        elif enforcement_result.decision == Decision.REQUIRE_APPROVAL:
            # Find escalate rule that caused this
            escalate_rules = [r for r in matched_rules if r.get("severity") == "escalate"]
            if escalate_rules:
                verdict_rule = escalate_rules[0]
                verdict_rule_id = verdict_rule.get("rule_id", "Unknown")
                verdict_rule_type = "BASELINE" if verdict_rule.get("baseline", False) else "CUSTOM"
            else:
                # Fallback to verdict rule from Gate 4
                if verdict_rule:
                    verdict_rule_id = verdict_rule.get("rule_id", "Unknown")
                    verdict_rule_type = "BASELINE" if verdict_rule.get("baseline", False) else "CUSTOM"
            
            verdict = "ESCALATE"
            status = "escalated"
            final_verdict = "ESCALATE"
            requires_approval = True
            approval_required = True
            verdict_rationale = f"Verdict derived from rule {verdict_rule_id} ({verdict_rule_type}) - severity: escalate" if verdict_rule_id else "Human approval required"
        # Default to ALLOW
        else:
            verdict = "ALLOW"
            status = "passed"
            final_verdict = "ALLOW"
            # Use verdict rule from Gate 4 if available
            if verdict_rule:
                verdict_rule_id = verdict_rule.get("rule_id", "Unknown")
                verdict_rule_type = "BASELINE" if verdict_rule.get("baseline", False) else "CUSTOM"
                verdict_rationale = f"Verdict derived from rule {verdict_rule_id} ({verdict_rule_type}) - severity: allow"
            else:
                verdict_rationale = "No matching rules - default ALLOW"
        
        processing_time_gate6 = (time.time() - start_time_gate6) * 1000
        
        gate6_result = {
            "gate_num": 6,
            "gate_name": "Action Approval",
            "status": status,
            "verdict": verdict,
            "signals": {
                "tool": tool_name,
                "requires_approval": requires_approval,
                "decision": enforcement_result.decision.value if hasattr(enforcement_result.decision, 'value') else str(enforcement_result.decision),
                "controls_applied": enforcement_result.controls_applied,
                "verdict_rule_id": verdict_rule_id,
                "verdict_rule_type": verdict_rule_type
            },
            "policies": applicable_policies,
            "decision_reason": verdict_rationale,
            "processing_time_ms": processing_time_gate6,
            "matched_rule_ids": matched_rule_ids,
            "baseline_rules": baseline_rules,
            "custom_rules": custom_rules
        }
        gate_results.append(gate6_result)
    else:
        # No tool inferred - treat as informational query (ALLOW)
        processing_time_gate5 = (time.time() - start_time) * 1000
        
        gate5_result = {
            "gate_num": 5,
            "gate_name": "Permission Check",
            "status": "passed",
            "verdict": "ALLOW",
            "signals": {
                "tool": None,
                "note": "No tool call inferred - informational query"
            },
            "policies": applicable_policies,
            "decision_reason": None,
            "processing_time_ms": processing_time_gate5
        }
        gate_results.append(gate5_result)
        
        start_time_gate6 = time.time()
        verdict = "ALLOW"
        status = "passed"
        final_verdict = "ALLOW"
        # For no-tool case, set default verdict rationale
        verdict_rule_id = None
        verdict_rule_type = None
        verdict_rationale = "No tool call - informational query allowed"
        processing_time_gate6 = (time.time() - start_time_gate6) * 1000
        
        gate6_result = {
            "gate_num": 6,
            "gate_name": "Action Approval",
            "status": status,
            "verdict": verdict,
            "signals": {
                "note": "No tool call - informational query allowed",
                "verdict_rule_id": verdict_rule_id,
                "verdict_rule_type": verdict_rule_type
            },
            "policies": applicable_policies,
            "decision_reason": verdict_rationale,
            "processing_time_ms": processing_time_gate6,
            "matched_rule_ids": matched_rule_ids if 'matched_rule_ids' in locals() else [],
            "baseline_rules": baseline_rules if 'baseline_rules' in locals() else [],
            "custom_rules": custom_rules if 'custom_rules' in locals() else []
        }
        gate_results.append(gate6_result)
    
    # Compute risk level after Gate 5/6 (we have gate5_verdict from enforcement_result or "ALLOW" if no tool)
    gate5_verdict_str = gate5_result.get("verdict", "ALLOW") if tool_name else "ALLOW"
    risk_level, risk_drivers = compute_risk_level(
        gate2_intent=intent_category,
        gate3_data_class=data_class,
        gate3_has_pii=has_pii,
        gate3_dlp_scan_passed=dlp_result,
        tool_name=tool_name,
        gate5_verdict=gate5_verdict_str
    )
    
    # Gate 7: Evidence Capture
    start_time = time.time()
    # Get matched rules from Gate 4
    gate4_result = next((g for g in gate_results if g.get("gate_num") == 4), None)
    matched_rules = gate4_result.get("matched_rules", []) if gate4_result else []
    
    # Get matched rule IDs from Gate 4 (may not exist if no tool was inferred)
    matched_rule_ids = gate4_result.get("matched_rule_ids", []) if gate4_result else []
    baseline_rules = gate4_result.get("baseline_rules", []) if gate4_result else []
    custom_rules = gate4_result.get("custom_rules", []) if gate4_result else []
    
    # Get policy version/hash from policy context
    policy_version = policy_context.policy_version
    policy_id = policy_context.policy_id
    
    # Evidence is captured through the audit log
    evidence_captured = {
        "request": request,
        "user_id": user_id,
        "intent": intent_category,
        "data_class": data_class,
        "verdict": final_verdict,
        "surfaces_activated": [k for k, v in surfaces_touched.items() if v],
        "policy_version": policy_version,
        "policy_id": policy_id,
        "baseline_parent_policy_id": policy_context.baseline_parent_policy_id,
        "matched_rules": matched_rules,
        "matched_rule_ids": matched_rule_ids,
        "baseline_rules": baseline_rules,
        "custom_rules": custom_rules,
        "verdict_rule_id": verdict_rule_id,
        "verdict_rule_type": verdict_rule_type,
        "verdict_rationale": verdict_rationale,
        "rule_states_at_decision": [
            {
                "rule_id": rule["rule_id"],
                "baseline": rule.get("baseline", False),
                "enabled": rule.get("enabled", True)
            }
            for rule in matched_rules
        ]
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
    if final_verdict == "ALLOW" or requires_approval:
        surfaces_touched["U-O"] = True
    
    # Get policy information from policy context
    baseline_policy_id = policy_context.policy_id
    
    return {
        "gate_results": gate_results,
        "surface_activations": surfaces_touched,
        "final_verdict": final_verdict,
        "evidence_packet": evidence_packet,
        "short_circuited": False,
        "approval_required": approval_required,
        "baseline_policy_id": baseline_policy_id,
        "policy_id": policy_context.policy_id,
        "policy_version": policy_context.policy_version,
        "baseline_parent_policy_id": policy_context.baseline_parent_policy_id,
        "posture_level": posture_level,
        "posture_rationale": posture_rationale,
        "risk_level": risk_level,
        "risk_drivers": risk_drivers,
        "verdict_rule_id": verdict_rule_id,
        "verdict_rule_type": verdict_rule_type,
        "verdict_rationale": verdict_rationale,
        "tool_enforcement_result": {
            "tool": tool_name,
            "params": tool_params,
            "decision": tool_decision.value if tool_decision and hasattr(tool_decision, 'value') else (str(tool_decision) if tool_decision else None),
            "controls_applied": tool_enforcement_result.controls_applied if tool_enforcement_result else [],
            "evidence": tool_enforcement_result.evidence if tool_enforcement_result else {}
        } if tool_enforcement_result else None
    }

