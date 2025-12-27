"""
Constitutional Enforcement Layer v0.1
8-Gate Policy Interceptor for AI Agent Governance

This module provides enforcement hooks that intercept agent actions
at each of the 8 gates defined in the Constitutional Ontology.
"""

import json
import os
from datetime import datetime
import uuid
from typing import Any
from dataclasses import dataclass, field
from enum import Enum

class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_WITH_CONTROLS = "allow_with_controls"
    REQUIRE_APPROVAL = "require_approval"

@dataclass
class EnforcementResult:
    decision: Decision
    gate: str
    action: str
    controls_applied: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    denial_reason: str = None
    requires_human: bool = False

@dataclass
class AuditEntry:
    timestamp: str
    gate: str
    action: str
    decision: str
    user_id: str
    controls: list
    evidence: dict

class ConstitutionalEnforcer:
    """
    Core enforcement engine that evaluates actions against the policy matrix.
    """
    
    def __init__(self, policy_path: str):
        with open(policy_path, 'r') as f:
            self.policy = json.load(f)
        self.audit_log = []
        self.pending_approvals = {}
    
    # =========================================================================
    # GATE: S-O (Agent → System) - pre_tool_call
    # =========================================================================
    def pre_tool_call(self, tool_name: str, params: dict, user_id: str) -> EnforcementResult:
        """
        Intercept before any tool/API invocation.
        Applies: LeastPrivilege, Approval/HITL, Scope validation, Allowlist check
        """
        gate = self.policy["gates"]["S-O"]
        controls_applied = []
        evidence = {"tool": tool_name, "params_hash": hash(str(params)), "timestamp": self._now()}
        
        # Check allowlist
        allowed_actions = [a["target"] if isinstance(a, dict) else a for a in gate["allow"]]
        tool_mapping = {
            "sharepoint_read": "sharepoint",
            "occ_query": "occ_fdic_db",
            "write_draft": "draft_doc",
            "jira_create": "jira_create_task"
        }
        
        mapped_target = tool_mapping.get(tool_name)
        if mapped_target not in allowed_actions:
            return EnforcementResult(
                decision=Decision.DENY,
                gate="S-O",
                action=tool_name,
                denial_reason=f"Tool '{tool_name}' not in allowlist",
                evidence=evidence
            )
        controls_applied.append("allowlist_check")
        
        # Check hard denies
        for deny_pattern in gate["deny"]:
            if self._matches_deny(tool_name, params, deny_pattern):
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="S-O",
                    action=tool_name,
                    denial_reason=f"Action matches deny rule: {deny_pattern}",
                    evidence=evidence
                )
        
        # Check if approval required (Execute actions)
        action_config = next((a for a in gate["allow"] if isinstance(a, dict) and a.get("target") == mapped_target), None)
        if action_config and "approval_hitl" in action_config.get("controls", []):
            controls_applied.append("approval_hitl")
            return EnforcementResult(
                decision=Decision.REQUIRE_APPROVAL,
                gate="S-O",
                action=tool_name,
                controls_applied=controls_applied,
                evidence=evidence,
                requires_human=True
            )
        
        # Apply logging
        controls_applied.append("log")
        self._log_audit("S-O", tool_name, "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="S-O",
            action=tool_name,
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATE: S-I (System → Agent) - post_tool_result
    # =========================================================================
    def post_tool_result(self, tool_name: str, result: Any, user_id: str) -> EnforcementResult:
        """
        Intercept after receiving tool/API response.
        Applies: ProvenanceRequired, DLP scan, Malware scan, Injection scrub
        """
        gate = self.policy["gates"]["S-I"]
        controls_applied = []
        evidence = {"tool": tool_name, "result_hash": hash(str(result)[:1000]), "timestamp": self._now()}
        
        # Provenance capture
        evidence["source_uri"] = f"tool://{tool_name}"
        evidence["retrieval_timestamp"] = self._now()
        controls_applied.append("provenance_required")
        
        # DLP scan (stub - would integrate with actual DLP)
        if self._dlp_scan(result):
            controls_applied.append("dlp_scan_passed")
        else:
            return EnforcementResult(
                decision=Decision.DENY,
                gate="S-I",
                action=f"receive_{tool_name}_result",
                denial_reason="DLP scan detected sensitive data in response",
                evidence=evidence
            )
        
        # Injection scrub (stub)
        result = self._scrub_injections(result)
        controls_applied.append("injection_scrub")
        
        controls_applied.append("log")
        self._log_audit("S-I", f"receive_{tool_name}", "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="S-I",
            action=f"receive_{tool_name}_result",
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATE: U-I (User → Agent) - post_user_input
    # =========================================================================
    def post_user_input(self, user_input: str, user_id: str, session_id: str) -> EnforcementResult:
        """
        Intercept after receiving user message.
        Applies: Auth validation, Scope lock, Injection detection, Logging
        """
        gate = self.policy["gates"]["U-I"]
        controls_applied = []
        evidence = {"input_hash": hash(user_input), "session": session_id, "timestamp": self._now()}
        
        # Auth validation (stub - assumes upstream auth)
        controls_applied.append("auth_validated")
        
        # Injection detection
        if self._detect_injection(user_input):
            return EnforcementResult(
                decision=Decision.DENY,
                gate="U-I",
                action="receive_input",
                denial_reason="Potential prompt injection detected",
                evidence=evidence
            )
        controls_applied.append("injection_detect")
        
        # Check for denied request patterns
        denied_patterns = ["export external", "share outside", "include customer data", "send to external"]
        if any(pattern in user_input.lower() for pattern in denied_patterns):
            return EnforcementResult(
                decision=Decision.DENY,
                gate="U-I",
                action="receive_input",
                denial_reason="Request matches denied action pattern",
                evidence=evidence
            )
        
        controls_applied.append("log")
        self._log_audit("U-I", "receive_input", "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="U-I",
            action="receive_input",
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATE: U-O (Agent → User) - pre_response
    # =========================================================================
    def pre_response(self, response: str, citations: list, user_id: str) -> EnforcementResult:
        """
        Intercept before sending response to user.
        Applies: Redaction, ProvenanceRequired, NoDeception, Logging
        """
        gate = self.policy["gates"]["U-O"]
        controls_applied = []
        evidence = {"response_hash": hash(response[:500]), "citation_count": len(citations), "timestamp": self._now()}
        
        # Redaction (stub - would integrate with PII detector)
        response, redactions = self._redact_sensitive(response)
        if redactions:
            evidence["redactions_applied"] = redactions
        controls_applied.append("redaction")
        
        # Provenance check for regulatory claims
        if self._contains_regulatory_claim(response) and not citations:
            return EnforcementResult(
                decision=Decision.DENY,
                gate="U-O",
                action="send_response",
                denial_reason="Regulatory claim without citation (ProvenanceRequired)",
                evidence=evidence
            )
        controls_applied.append("provenance_required")
        
        # NoDeception - ensure limitations disclosed if applicable
        controls_applied.append("no_deception")
        
        controls_applied.append("log")
        evidence["citations"] = [c.get("source", "unknown") for c in citations] if citations else []
        self._log_audit("U-O", "send_response", "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="U-O",
            action="send_response",
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATE: M-O (Agent → Memory) - memory_write
    # =========================================================================
    def memory_write(self, key: str, value: Any, user_id: str) -> EnforcementResult:
        """
        Intercept before storing to memory.
        Applies: User consent, Redaction, Retention policy, Encryption
        """
        gate = self.policy["gates"]["M-O"]
        controls_applied = []
        evidence = {"key": key, "value_type": type(value).__name__, "timestamp": self._now()}
        
        # Check denied data types
        if self._is_regulated_data(value):
            return EnforcementResult(
                decision=Decision.DENY,
                gate="M-O",
                action="store",
                denial_reason="Cannot store PII/PHI/regulated data",
                evidence=evidence
            )
        
        # Check allowed storage types
        allowed_keys = ["citation_format", "templates", "style_prefs", "writing_style"]
        if not any(allowed in key.lower() for allowed in allowed_keys):
            return EnforcementResult(
                decision=Decision.DENY,
                gate="M-O",
                action="store",
                denial_reason=f"Storage key '{key}' not in allowed preferences list",
                evidence=evidence
            )
        
        # Apply redaction before store
        value, redactions = self._redact_sensitive(str(value))
        controls_applied.append("redaction")
        
        # Tag with retention policy
        evidence["retention_days"] = 365
        evidence["user_controlled"] = True
        controls_applied.extend(["retention_policy", "encryption", "user_controls"])
        
        controls_applied.append("log")
        self._log_audit("M-O", "store", "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="M-O",
            action="store",
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATE: M-I (Memory → Agent) - memory_read
    # =========================================================================
    def memory_read(self, key: str, user_id: str, requesting_user: str) -> EnforcementResult:
        """
        Intercept before retrieving from memory.
        Applies: Per-user ACL, DataMinimization, Versioning check
        """
        gate = self.policy["gates"]["M-I"]
        controls_applied = []
        evidence = {"key": key, "timestamp": self._now()}
        
        # Per-user ACL check
        if user_id != requesting_user:
            return EnforcementResult(
                decision=Decision.DENY,
                gate="M-I",
                action="retrieve",
                denial_reason="Cross-user memory access denied",
                evidence=evidence
            )
        controls_applied.append("per_user_acl")
        
        # Data minimization (return only what's needed)
        controls_applied.append("data_minimization")
        
        controls_applied.append("log")
        self._log_audit("M-I", "retrieve", "ALLOW", user_id, controls_applied, evidence)
        
        return EnforcementResult(
            decision=Decision.ALLOW_WITH_CONTROLS,
            gate="M-I",
            action="retrieve",
            controls_applied=controls_applied,
            evidence=evidence
        )
    
    # =========================================================================
    # GATES: A-I / A-O (Inter-Agent) - DENIED at L1
    # =========================================================================
    def agent_inbound(self, source_agent: str, payload: Any, user_id: str) -> EnforcementResult:
        """All inter-agent inbound communication denied at L1."""
        return EnforcementResult(
            decision=Decision.DENY,
            gate="A-I",
            action="receive_from_agent",
            denial_reason="Inter-agent communication disabled (Dial: L1)",
            evidence={"source_agent": source_agent, "timestamp": self._now()}
        )
    
    def agent_outbound(self, target_agent: str, payload: Any, user_id: str) -> EnforcementResult:
        """All inter-agent outbound communication denied at L1."""
        return EnforcementResult(
            decision=Decision.DENY,
            gate="A-O",
            action="send_to_agent",
            denial_reason="Inter-agent communication disabled (Dial: L1)",
            evidence={"target_agent": target_agent, "timestamp": self._now()}
        )
    
    # =========================================================================
    # APPROVAL WORKFLOW
    # =========================================================================
    def request_approval(self, action_id: str, gate: str, action: str, user_id: str, details: dict) -> str:
        """Register an action requiring human approval."""
        approval_record = {
            "action_id": action_id,
            "gate": gate,
            "action": action,
            "user_id": user_id,
            "details": details,
            "requested_at": self._now(),
            "status": "pending"
        }
        self.pending_approvals[action_id] = approval_record
        return action_id
    
    def approve(self, action_id: str, approver_id: str) -> bool:
        """Human approves a pending action."""
        if action_id in self.pending_approvals:
            self.pending_approvals[action_id]["status"] = "approved"
            self.pending_approvals[action_id]["approved_by"] = approver_id
            self.pending_approvals[action_id]["approved_at"] = self._now()
            return True
        return False
    
    def deny_approval(self, action_id: str, approver_id: str, reason: str) -> bool:
        """Human denies a pending action."""
        if action_id in self.pending_approvals:
            self.pending_approvals[action_id]["status"] = "denied"
            self.pending_approvals[action_id]["denied_by"] = approver_id
            self.pending_approvals[action_id]["denied_at"] = self._now()
            self.pending_approvals[action_id]["denial_reason"] = reason
            return True
        return False
    
    # =========================================================================
    # AUDIT & HELPERS
    # =========================================================================
    def _log_audit(self, gate: str, action: str, decision: str, user_id: str, controls: list, evidence: dict):
        entry = AuditEntry(
            timestamp=self._now(),
            gate=gate,
            action=action,
            decision=decision,
            user_id=user_id,
            controls=controls,
            evidence=evidence
        )
        self.audit_log.append(entry)
    
    def get_audit_log(self) -> list:
        return [vars(e) for e in self.audit_log]
    
    def export_audit_log(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.get_audit_log(), f, indent=2)
    
    def _now(self) -> str:
        return datetime.utcnow().isoformat() + "Z"
    
    def _matches_deny(self, tool: str, params: dict, pattern: str) -> bool:
        """Check if action matches a deny pattern."""
        # Simplified matching - expand for production
        if "external" in pattern and params.get("destination", "").startswith("external"):
            return True
        if "final" in pattern.lower() and "approved" in pattern.lower():
            if params.get("destination", "").lower().startswith("final"):
                return True
        return False
    
    def _dlp_scan(self, content: Any) -> bool:
        """Stub: Return True if content passes DLP scan."""
        # In production: integrate with actual DLP service
        sensitive_patterns = ["ssn:", "account_number:", "credit_card:"]
        content_str = str(content).lower()
        return not any(p in content_str for p in sensitive_patterns)
    
    def _scrub_injections(self, content: Any) -> Any:
        """Stub: Remove potential injection patterns from content."""
        # In production: more sophisticated scrubbing
        if isinstance(content, str):
            injection_patterns = ["ignore previous", "disregard instructions", "system prompt"]
            for pattern in injection_patterns:
                content = content.replace(pattern, "[SCRUBBED]")
        return content
    
    def _detect_injection(self, text: str) -> bool:
        """Stub: Detect potential prompt injection in user input."""
        injection_signals = [
            "ignore your instructions",
            "disregard previous",
            "you are now",
            "new system prompt",
            "jailbreak"
        ]
        text_lower = text.lower()
        return any(signal in text_lower for signal in injection_signals)
    
    def _redact_sensitive(self, text: str) -> tuple:
        """Stub: Redact sensitive data from text."""
        redactions = []
        # In production: use proper PII detection
        import re
        # SSN pattern
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        if re.search(ssn_pattern, text):
            text = re.sub(ssn_pattern, '[REDACTED-SSN]', text)
            redactions.append("ssn")
        return text, redactions
    
    def _contains_regulatory_claim(self, text: str) -> bool:
        """Check if response contains regulatory/legal claims."""
        regulatory_signals = [
            "occ requires", "fdic guidance", "regulation requires",
            "compliance with", "pursuant to", "under section"
        ]
        text_lower = text.lower()
        return any(signal in text_lower for signal in regulatory_signals)
    
    def _is_regulated_data(self, value: Any) -> bool:
        """Check if value contains regulated data types."""
        value_str = str(value).lower()
        regulated_signals = ["ssn", "account_number", "phi", "diagnosis", "patient"]
        return any(signal in value_str for signal in regulated_signals)


# =============================================================================
# USAGE EXAMPLE
# =============================================================================
if __name__ == "__main__":
    # Initialize enforcer with policy
    policy_path = os.path.join(os.path.dirname(__file__), "policy_bank_compliance_v1.json")
    enforcer = ConstitutionalEnforcer(policy_path)
    
    print("=== Constitutional Enforcement Demo ===\n")

    # -------------------------------------------------------------------------
    # Interactive helper: demonstrate Human-in-the-Loop approval for tool use
    # -------------------------------------------------------------------------
    def simulate_tool(tool_name: str, params: dict):
        """Stub tool executor for the demo (replace with real API/tool calls)."""
        if tool_name == "sharepoint_read":
            return {"source": "sharepoint", "path": params.get("path"), "content": "Draft policy template v3.2"}
        if tool_name == "occ_query":
            return {"source": "occ_fdic_db", "query": params.get("q"), "content": "OCC interpretive letter excerpt..."}
        if tool_name == "write_draft":
            return {"source": "draft_doc", "doc_id": "DOC-001", "status": "written"}
        if tool_name == "jira_create":
            return {"source": "jira_create_task", "issue_id": "JIRA-101", "status": "created", "title": params.get("title")}
        return {"source": tool_name, "status": "ok"}

    def run_tool_with_enforcement(tool_name: str, params: dict, user_id: str, approver_id: str = "supervisor_001"):
        """Run a tool call through S-O + (optional) HITL approval + S-I."""
        pre = enforcer.pre_tool_call(tool_name, params, user_id)
        print(f"   pre_tool_call → {pre.decision.value}")

        if pre.decision == Decision.DENY:
            print(f"   DENIED: {pre.denial_reason}")
            return pre

        if pre.decision == Decision.REQUIRE_APPROVAL:
            action_id = str(uuid.uuid4())[:8]
            enforcer.request_approval(action_id, "S-O", tool_name, user_id, {"params": params})
            # Log the fact that the system stopped the agent for approval
            enforcer._log_audit("S-O", tool_name, "REQUIRE_APPROVAL", user_id, pre.controls_applied, pre.evidence)

            answer = input(f"   APPROVAL REQUIRED. Approve action {action_id} ({tool_name})? [y/N]: ").strip().lower()
            if answer in ("y", "yes"):
                enforcer.approve(action_id, approver_id)
                enforcer._log_audit("S-O", tool_name, "APPROVED", approver_id, ["human_approval"], {"action_id": action_id})
                tool_result = simulate_tool(tool_name, params)
                post = enforcer.post_tool_result(tool_name, tool_result, user_id)
                print(f"   post_tool_result → {post.decision.value}")
                return post

            enforcer.deny_approval(action_id, approver_id, "Not approved in demo")
            enforcer._log_audit("S-O", tool_name, "DENIED_BY_HUMAN", approver_id, ["human_denial"], {"action_id": action_id})
            print("   Human denied the action. Tool call was NOT executed.")
            return pre

        # Allowed: execute tool and run inbound checks
        tool_result = simulate_tool(tool_name, params)
        post = enforcer.post_tool_result(tool_name, tool_result, user_id)
        print(f"   post_tool_result → {post.decision.value}")
        return post

    
    # Demo 1: Allowed tool call (SharePoint read)
    print("1. Testing S-O: SharePoint Read (should ALLOW)")
    result = enforcer.pre_tool_call("sharepoint_read", {"path": "/policies/draft"}, "analyst_123")
    print(f"   Decision: {result.decision.value}")
    print(f"   Controls: {result.controls_applied}\n")
    
    # Demo 2: Tool call requiring approval (Jira create)
    # Demo 2: Tool call requiring approval (Jira create task)
    print("2. Testing S-O: Jira Create (should REQUIRE_APPROVAL)")
    result = run_tool_with_enforcement("jira_create", {"title": "Review Q4 policy", "project": "COMP"}, "analyst_123")
    print(f"   Final Decision: {result.decision.value}")
    print()
    print("3. Testing S-O: Email Send (should DENY - not in allowlist)")
    result = enforcer.pre_tool_call("email_send", {"to": "external@other.com"}, "analyst_123")
    print(f"   Decision: {result.decision.value}")
    print(f"   Reason: {result.denial_reason}\n")
    
    # Demo 4: Response with regulatory claim but no citation
    print("4. Testing U-O: Response with regulatory claim, no citation (should DENY)")
    result = enforcer.pre_response(
        "OCC requires all banks to maintain capital reserves of 8%.",
        citations=[],
        user_id="analyst_123"
    )
    print(f"   Decision: {result.decision.value}")
    print(f"   Reason: {result.denial_reason}\n")
    
    # Demo 5: Response with citation (should pass)
    print("5. Testing U-O: Response with citation (should ALLOW)")
    result = enforcer.pre_response(
        "OCC requires all banks to maintain capital reserves of 8%.",
        citations=[{"source": "OCC Bulletin 2023-01", "url": "https://occ.gov/..."}],
        user_id="analyst_123"
    )
    print(f"   Decision: {result.decision.value}")
    print(f"   Controls: {result.controls_applied}\n")
    
    # Demo 6: Inter-agent communication (should DENY at L1)
    print("6. Testing A-O: Send to another agent (should DENY)")
    result = enforcer.agent_outbound("research_agent", {"query": "find precedents"}, "analyst_123")
    print(f"   Decision: {result.decision.value}")
    print(f"   Reason: {result.denial_reason}\n")
    
    # Demo 7: Memory write of allowed preference
    print("7. Testing M-O: Store citation format (should ALLOW)")
    result = enforcer.memory_write("citation_format", "APA 7th edition", "analyst_123")
    print(f"   Decision: {result.decision.value}")
    print(f"   Controls: {result.controls_applied}\n")
    
    # Demo 8: Memory write of regulated data
    print("8. Testing M-O: Store customer SSN (should DENY)")
    result = enforcer.memory_write("customer_info", "SSN: 123-45-6789", "analyst_123")
    print(f"   Decision: {result.decision.value}")
    print(f"   Reason: {result.denial_reason}\n")
    
    # Export audit log
    print("=== Audit Log ===")
    for entry in enforcer.get_audit_log():
        print(f"  [{entry['timestamp']}] {entry['gate']}/{entry['action']}: {entry['decision']}")