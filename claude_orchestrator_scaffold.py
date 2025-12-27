"""
Claude API + Tool Use Orchestrator (Scaffold)
------------------------------------------------
Goal: demonstrate "8 gates" enforcement in a clean, inspectable loop.

This file is intentionally dependency-light:
- If you want to actually call Claude, install anthropic:
    pip install anthropic
and set ANTHROPIC_API_KEY in your environment.

Core idea:
1) Agent proposes a tool call
2) pre_tool_call() enforces S-O gate (allow/deny/require approval)
3) If approved -> execute tool -> post_tool_result() enforces S-I gate
4) Agent drafts response -> pre_response() enforces U-O gate
5) Memory reads/writes route through M-I / M-O gates
"""

import os
from typing import Any, Dict, Tuple, Optional

# Local enforcement layer (already in your repo)
from constitutional_enforcement import ConstitutionalEnforcer, Decision


# ----------------------------
# Tool registry (demo stubs)
# ----------------------------
def tool_sharepoint_read(path: str) -> Dict[str, Any]:
    # Replace with real SharePoint connector
    return {"source_uri": f"sharepoint://{path}", "content": "Draft policy template text...", "doc_hash": "abc123"}

def tool_occ_query(query: str) -> Dict[str, Any]:
    # Replace with real regulatory DB connector
    return {"source_uri": "occ://guidance/2024-xyz", "content": "OCC guidance excerpt...", "doc_hash": "def456"}

def tool_write_draft_doc(doc_id: str, text: str) -> Dict[str, Any]:
    # Replace with Word/SharePoint write
    return {"doc_id": doc_id, "status": "written_to_draft", "version_id": "v7"}

def tool_jira_create_task(title: str, description: str) -> Dict[str, Any]:
    # Replace with Jira API
    return {"issue_key": "COMPL-123", "status": "created"}

TOOLS = {
    "sharepoint_read": tool_sharepoint_read,
    "occ_query": tool_occ_query,
    "write_draft": tool_write_draft_doc,
    "jira_create": tool_jira_create_task,
}


# ----------------------------
# Orchestrator
# ----------------------------
class ClaudeOrchestrator:
    def __init__(self, policy_path: str):
        self.enforcer = ConstitutionalEnforcer(policy_path)

    def _execute_tool(self, tool_name: str, params: Dict[str, Any], user_id: str) -> Tuple[Decision, Dict[str, Any]]:
        # 1) S-O: pre_tool_call
        pre = self.enforcer.pre_tool_call(tool_name, params, user_id)
        if pre.decision == Decision.DENY:
            return pre.decision, {"error": pre.denial_reason, "gate": pre.gate}

        if pre.decision == Decision.REQUIRE_APPROVAL:
            approval = self.enforcer.request_approval(user_id, tool_name, params)
            # Demo: auto-deny unless you explicitly approve (wire to UI later)
            # self.enforcer.approve(approval.approval_id, approver_id="human_1")
            return pre.decision, {"approval_id": approval.approval_id, "message": "Approval required"}

        # 2) Execute tool
        if tool_name not in TOOLS:
            return Decision.DENY, {"error": f"Tool not registered: {tool_name}"}

        raw_result = TOOLS[tool_name](**params)

        # 3) S-I: post_tool_result (sanitize / provenance / dlp / malware)
        post = self.enforcer.post_tool_result(tool_name, raw_result, user_id)
        if post.decision == Decision.DENY:
            return post.decision, {"error": post.denial_reason, "gate": post.gate}

        return Decision.ALLOW, raw_result

    def run_single_turn_demo(self, user_prompt: str, user_id: str = "analyst_123") -> None:
        """
        This is a *demo loop*.
        In production you would:
        - call Claude with tool definitions
        - let Claude choose tool calls
        - enforce each call here
        """
        print("\n=== Orchestrator Demo (Scaffold) ===")
        print("User:", user_prompt)

        # Example tool plan (pretend Claude proposed it)
        tool_plan = [
            ("sharepoint_read", {"path": "/policies/draft/q4-policy.md"}),
            ("occ_query", {"query": "capital reserve requirements baseline"}),
            ("jira_create", {"title": "Review Q4 policy", "description": "Please review draft"}),
        ]

        for tool_name, params in tool_plan:
            decision, payload = self._execute_tool(tool_name, params, user_id)
            print(f"\nTool: {tool_name}  Decision: {decision.value}")
            print("Payload:", payload)

        # Pretend we have a drafted answer with citations
        drafted = "Draft section: ... (with citations)"
        citations = [{"source_uri": "occ://guidance/2024-xyz", "doc_hash": "def456"}]

        pre = self.enforcer.pre_response(drafted, citations=citations, user_id=user_id)
        print("\nResponse Decision:", pre.decision.value, pre.denial_reason or "")
        print("\n=== Audit Log (tail) ===")
        for entry in self.enforcer.get_audit_log()[-10:]:
            print(f"  [{entry.timestamp}] {entry.gate}/{entry.action}: {entry.decision.value}")


if __name__ == "__main__":
    # Put policy_bank_compliance_v1.json in the same folder when you run locally
    policy_path = os.environ.get("POLICY_PATH", "policy_bank_compliance_v1.json")
    orch = ClaudeOrchestrator(policy_path)
    orch.run_single_turn_demo("Draft a Q4 compliance policy update under OCC supervision.")
