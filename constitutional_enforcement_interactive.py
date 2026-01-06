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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Check allowlist from policy
        allowed_actions = [a["target"] if isinstance(a, dict) else a for a in gate.get("allow", [])]
        tool_mapping = {
            "sharepoint_read": "sharepoint",
            "occ_query": "occ_fdic_db",
            "write_draft": "draft_doc",
            "jira_create": "jira_create_task",
            "export_data": "export_data",
            "delete_all_records": "delete_all_records",
            "delete_records": "delete_records"
        }
        
        mapped_target = tool_mapping.get(tool_name)
        if mapped_target not in allowed_actions:
            controls_applied.append("allowlist_check")
            self._log_audit("S-O", tool_name, "DENY", user_id, controls_applied, evidence)
            return EnforcementResult(
                decision=Decision.DENY,
                gate="S-O",
                action=tool_name,
                denial_reason=f"Tool '{tool_name}' not in allowlist",
                evidence=evidence
            )
        controls_applied.append("allowlist_check")
        
        # Check deny patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny(tool_name, params, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("S-O", tool_name, "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="S-O",
                    action=tool_name,
                    denial_reason=f"Action matches deny rule: {deny_pattern}",
                    evidence=evidence
                )
        
        # Check if approval required (Execute actions) - from allow action config
        action_config = next((a for a in gate.get("allow", []) if isinstance(a, dict) and a.get("target") == mapped_target), None)
        if action_config and "approval_hitl" in action_config.get("controls", []):
            controls_applied.append("approval_hitl")
            self._log_audit("S-O", tool_name, "REQUIRE_APPROVAL", user_id, controls_applied, evidence)
            return EnforcementResult(
                decision=Decision.REQUIRE_APPROVAL,
                gate="S-O",
                action=tool_name,
                controls_applied=controls_applied,
                evidence=evidence,
                requires_human=True
            )
        
        # Least privilege (if control exists in policy)
        if "least_privilege" in control_types:
            controls_applied.append("least_privilege")
        
        # Sandbox (if control exists in policy)
        if "sandbox" in control_types:
            controls_applied.append("sandbox")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Check deny patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny_result(result, tool_name, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("S-I", f"receive_{tool_name}_result", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="S-I",
                    action=f"receive_{tool_name}_result",
                    denial_reason=f"Result matches denied pattern: {deny_pattern}",
                    evidence=evidence
                )
        
        # Provenance capture (if control exists in policy)
        if "provenance_required" in control_types:
            evidence["source_uri"] = f"tool://{tool_name}"
            evidence["retrieval_timestamp"] = self._now()
            controls_applied.append("provenance_required")
        
        # Malware scan (if control exists in policy)
        if "malware_scan" in control_types:
            controls_applied.append("malware_scan")
            # Stub - assumes scan passes
        
        # DLP scan (if control exists in policy)
        if "dlp_scan" in control_types:
            if self._dlp_scan(result):
                controls_applied.append("dlp_scan")
            else:
                controls_applied.append("dlp_scan_failed")
                self._log_audit("S-I", f"receive_{tool_name}_result", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="S-I",
                    action=f"receive_{tool_name}_result",
                    denial_reason="DLP scan detected sensitive data in response",
                    evidence=evidence
                )
        
        # Injection scrub (if control exists in policy)
        if "injection_scrub" in control_types:
            result = self._scrub_injections(result)
            controls_applied.append("injection_scrub")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Auth validation (if control exists in policy)
        if "auth" in control_types:
            controls_applied.append("auth")
            # Stub - assumes upstream auth validation
        
        # Injection detection (if control exists in policy)
        if "injection_detect" in control_types:
            if self._detect_injection(user_input):
                controls_applied.append("injection_detect")
                self._log_audit("U-I", "receive_input", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="U-I",
                    action="receive_input",
                    denial_reason="Potential prompt injection detected",
                    evidence=evidence
                )
            controls_applied.append("injection_detect")
        
        # Check for denied request patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny_pattern(user_input, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("U-I", "receive_input", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="U-I",
                    action="receive_input",
                    denial_reason=f"Request matches denied pattern: {deny_pattern}",
                    evidence=evidence
                )
        
        # Scope lock (if control exists in policy)
        if "scope_lock" in control_types:
            controls_applied.append("scope_lock")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Check deny patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny_response(response, citations, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("U-O", "send_response", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="U-O",
                    action="send_response",
                    denial_reason=f"Response matches denied pattern: {deny_pattern}",
                    evidence=evidence
                )
        
        # Redaction (if control exists in policy)
        if "redaction" in control_types:
            response, redactions = self._redact_sensitive(response)
            if redactions:
                evidence["redactions_applied"] = redactions
            controls_applied.append("redaction")
        
        # Provenance check for regulatory claims (if control exists in policy)
        if "provenance_required" in control_types:
            if self._contains_regulatory_claim(response) and not citations:
                self._log_audit("U-O", "send_response", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="U-O",
                    action="send_response",
                    denial_reason="Regulatory claim without citation (ProvenanceRequired)",
                    evidence=evidence
                )
            controls_applied.append("provenance_required")
        
        # NoDeception - ensure limitations disclosed if applicable (if control exists in policy)
        if "no_deception" in control_types:
            controls_applied.append("no_deception")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Check deny patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny_memory(key, value, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("M-O", "store", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="M-O",
                    action="store",
                    denial_reason=f"Storage matches denied pattern: {deny_pattern}",
                    evidence=evidence
                )
        
        # Check allowed storage types from policy
        allowed_actions = gate.get("allow", [])
        key_matches_allowed = False
        for allowed in allowed_actions:
            # Match key against allowed patterns (e.g., "store_citation_format" -> "citation_format")
            if allowed.replace("store_", "") in key.lower() or key.lower() in allowed.lower():
                key_matches_allowed = True
                break
        
        if not key_matches_allowed:
            self._log_audit("M-O", "store", "DENY", user_id, controls_applied, evidence)
            return EnforcementResult(
                decision=Decision.DENY,
                gate="M-O",
                action="store",
                denial_reason=f"Storage key '{key}' not in allowed list: {allowed_actions}",
                evidence=evidence
            )
        
        # User controls (if control exists in policy)
        if "user_controls" in control_types:
            controls_applied.append("user_controls")
            evidence["user_controlled"] = True
        
        # Redaction before store (if control exists in policy)
        if "redaction" in control_types:
            value, redactions = self._redact_sensitive(str(value))
            if redactions:
                evidence["redactions_applied"] = redactions
            controls_applied.append("redaction")
        
        # Retention policy (if control exists in policy)
        if "retention_policy" in control_types:
            retention_control = next((c for c in gate.get("controls", []) if isinstance(c, dict) and c.get("type") == "retention_policy"), None)
            if retention_control and "params" in retention_control:
                evidence["retention_days"] = retention_control["params"].get("max_days", 365)
            controls_applied.append("retention_policy")
        
        # Encryption (if control exists in policy)
        if "encryption" in control_types:
            controls_applied.append("encryption")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        
        # Get control types from policy
        control_types = [c["type"] if isinstance(c, dict) else c for c in gate.get("controls", [])]
        
        # Check deny patterns from policy
        for deny_pattern in gate.get("deny", []):
            if self._matches_deny_memory_read(key, user_id, requesting_user, deny_pattern):
                controls_applied.append("deny_pattern_check")
                self._log_audit("M-I", "retrieve", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="M-I",
                    action="retrieve",
                    denial_reason=f"Retrieval matches denied pattern: {deny_pattern}",
                    evidence=evidence
                )
        
        # Check allowed retrieval types from policy
        allowed_actions = gate.get("allow", [])
        key_matches_allowed = False
        for allowed in allowed_actions:
            if allowed.replace("retrieve_", "") in key.lower() or key.lower() in allowed.lower():
                key_matches_allowed = True
                break
        
        if not key_matches_allowed:
            self._log_audit("M-I", "retrieve", "DENY", user_id, controls_applied, evidence)
            return EnforcementResult(
                decision=Decision.DENY,
                gate="M-I",
                action="retrieve",
                denial_reason=f"Retrieval key '{key}' not in allowed list: {allowed_actions}",
                evidence=evidence
            )
        
        # Per-user ACL check (if control exists in policy)
        if "acl" in control_types:
            if user_id != requesting_user:
                controls_applied.append("acl_check_failed")
                self._log_audit("M-I", "retrieve", "DENY", user_id, controls_applied, evidence)
                return EnforcementResult(
                    decision=Decision.DENY,
                    gate="M-I",
                    action="retrieve",
                    denial_reason="Cross-user memory access denied",
                    evidence=evidence
                )
            controls_applied.append("acl")
        
        # Data minimization (if control exists in policy)
        if "data_minimization" in control_types:
            controls_applied.append("data_minimization")
        
        # Versioning (if control exists in policy)
        if "versioning" in control_types:
            controls_applied.append("versioning")
        
        # Logging (if control exists in policy)
        if "log" in control_types:
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
        # Check if tool name matches deny pattern
        if pattern.lower() in tool.lower() or tool.lower() in pattern.lower():
            return True
        
        # Simplified matching - expand for production
        if "external" in pattern and params.get("destination", "").startswith("external"):
            return True
        if "final" in pattern.lower() and "approved" in pattern.lower():
            if params.get("destination", "").lower().startswith("final"):
                return True
        return False
    
    def _matches_deny_pattern(self, user_input: str, pattern: str) -> bool:
        """Check if user input matches a deny pattern from policy."""
        user_input_lower = user_input.lower()
        pattern_lower = pattern.lower()
        
        # Direct pattern matching
        if pattern_lower in user_input_lower:
            return True
        
        # Common mappings for U-I deny patterns
        pattern_mappings = {
            "request_export_external": ["export external", "share outside", "send to external", "export outside"],
            "request_include_customer_data": ["include customer data", "add customer data", "use customer info"]
        }
        
        if pattern in pattern_mappings:
            return any(mapping in user_input_lower for mapping in pattern_mappings[pattern])
        
        return False
    
    def _matches_deny_result(self, result: Any, tool_name: str, pattern: str) -> bool:
        """Check if tool result matches a deny pattern from policy."""
        result_str = str(result).lower()
        pattern_lower = pattern.lower()
        
        # Check for macros or executables in result metadata
        if "files_with_macros" == pattern or "files_with_executables" == pattern:
            # Stub - would check actual file metadata
            return False
        
        if "sources_not_on_allowlist" == pattern:
            # Already checked via allowlist, but verify here
            return False
        
        return pattern_lower in result_str
    
    def _matches_deny_response(self, response: str, citations: list, pattern: str) -> bool:
        """Check if response matches a deny pattern from policy."""
        response_lower = response.lower()
        pattern_lower = pattern.lower()
        
        if pattern == "share_to_external_recipients":
            # Would check recipient list - stub
            return False
        
        if pattern == "claims_without_citations":
            # Checked separately via provenance_required control
            return False
        
        return pattern_lower in response_lower
    
    def _matches_deny_memory(self, key: str, value: Any, pattern: str) -> bool:
        """Check if memory write matches a deny pattern from policy."""
        key_lower = key.lower()
        value_str = str(value).lower()
        pattern_lower = pattern.lower()
        
        # Map deny patterns to detection logic
        if pattern in ["store_pii", "store_phi", "store_customer_account_info"]:
            return self._is_regulated_data(value)
        
        if pattern == "store_full_document_contents":
            # Would check value size/content type - stub
            return False
        
        return pattern_lower in key_lower or pattern_lower in value_str
    
    def _matches_deny_memory_read(self, key: str, user_id: str, requesting_user: str, pattern: str) -> bool:
        """Check if memory read matches a deny pattern from policy."""
        key_lower = key.lower()
        pattern_lower = pattern.lower()
        
        if pattern == "retrieve_regulated_data":
            # Would check if key contains regulated data - stub
            return False
        
        if pattern == "cross_user_memory_access":
            return user_id != requesting_user
        
        return pattern_lower in key_lower
    
    def _dlp_scan(self, content: Any) -> bool:
        """Stub: Return True if content passes DLP scan."""
        # In production: integrate with actual DLP service
        import re
        content_str = str(content).lower()
        
        # Pattern-based detection (more comprehensive)
        sensitive_patterns = [
            "ssn:", "account_number:", "credit_card:",
            "ssn", "social security",
            "account number", "account#",
            "credit card", "cc#", "card number",
            "routing number", "bank account",
            "passport", "driver license", "dl#"
        ]
        
        # SSN pattern (XXX-XX-XXXX)
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        # Credit card pattern (rough)
        cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        
        if re.search(ssn_pattern, content_str) or re.search(cc_pattern, content_str):
            return False
        
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
            "jailbreak",
            "ignore all",
            "forget everything",
            "override",
            "system:",
            "assistant:",
            "you must",
            "your real instructions",
            "hidden instruction"
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
        import re
        value_str = str(value).lower()
        
        regulated_signals = [
            "ssn", "social security",
            "account_number", "account number", "account#",
            "phi", "protected health",
            "diagnosis", "patient",
            "credit card", "cc#",
            "passport", "driver license",
            "pii", "personally identifiable"
        ]
        
        # SSN pattern
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        if re.search(ssn_pattern, value_str):
            return True
        
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