"""
Soft Ontology Manager - Handles organization-specific documentation integration
Manages document uploads, text extraction, and policy conflict resolution
"""

import io
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import json
import streamlit as st
from openai import OpenAI


class SoftOntologyManager:
    """Manages soft ontology documents and their integration with hard ontology baseline"""
    
    def __init__(self):
        self.documents: List[Dict[str, Any]] = []
        self.extracted_rules: List[Dict[str, Any]] = []
        self.conflict_resolutions: List[Dict[str, Any]] = []
        self.document_analyses: Dict[str, Dict[str, Any]] = {}  # Store analysis results by document_id
        self.generated_policies: Dict[str, str] = {}  # Store generated policy file paths by document_id
        self._last_api_key_error: Optional[str] = None
    
    def add_document(self, file_name: str, file_content: bytes, file_type: str) -> Dict[str, Any]:
        """Add a document to the soft ontology collection"""
        document = {
            "id": f"doc_{len(self.documents)}_{datetime.utcnow().timestamp()}",
            "name": file_name,
            "type": file_type,
            "upload_date": datetime.utcnow().isoformat() + "Z",
            "size": len(file_content),
            "content": file_content,
            "extracted_text": None,
            "status": "uploaded"
        }
        self.documents.append(document)
        return document
    
    def remove_document(self, document_id: str) -> bool:
        """Remove a document from the collection"""
        initial_count = len(self.documents)
        self.documents = [doc for doc in self.documents if doc["id"] != document_id]
        return len(self.documents) < initial_count
    
    def extract_text(self, document_id: str) -> Optional[str]:
        """Extract text from a document based on its type"""
        document = next((doc for doc in self.documents if doc["id"] == document_id), None)
        if not document:
            return None
        
        file_type = document["type"].lower()
        content = document["content"]
        
        try:
            if file_type == "text/plain" or file_type.endswith(".txt"):
                text = content.decode('utf-8')
            elif file_type == "application/pdf" or file_type.endswith(".pdf"):
                # Basic PDF text extraction - in production, use PyPDF2 or pdfplumber
                text = f"[PDF content from {document['name']} - PDF parsing not fully implemented]"
            elif file_type.endswith(".docx") or "wordprocessingml" in file_type:
                # Basic DOCX extraction - in production, use python-docx
                text = f"[DOCX content from {document['name']} - DOCX parsing not fully implemented]"
            elif file_type.endswith(".md") or "markdown" in file_type:
                text = content.decode('utf-8')
            else:
                text = f"[Unsupported file type: {file_type}]"
            
            document["extracted_text"] = text
            document["status"] = "extracted"
            return text
        except Exception as e:
            document["status"] = f"error: {str(e)}"
            return None
    
    def _get_openai_client(self) -> Optional[OpenAI]:
        """Get OpenAI client using Streamlit secrets"""
        api_key = None
        error_details = []
        
        # Method 1: Try [openai].api_key
        try:
            if hasattr(st, 'secrets') and st.secrets:
                if "openai" in st.secrets:
                    openai_secret = st.secrets["openai"]
                    # Try dict-like access (works for both dict and Streamlit secret objects)
                    try:
                        api_key = openai_secret.get("api_key") if hasattr(openai_secret, 'get') else openai_secret["api_key"]
                        if api_key:
                            error_details.append(f"Found key via [openai].api_key (length: {len(api_key)})")
                    except (KeyError, TypeError, AttributeError) as e:
                        error_details.append(f"Could not access api_key from [openai] section: {str(e)}")
        except Exception as e:
            error_details.append(f"Error accessing [openai].api_key: {str(e)}")
        
        # Method 2: Try top-level OPENAI_API_KEY
        if not api_key:
            try:
                if hasattr(st, 'secrets') and st.secrets:
                    api_key = st.secrets.get("OPENAI_API_KEY")
                    if api_key:
                        error_details.append(f"Found key via OPENAI_API_KEY (length: {len(api_key)})")
            except Exception as e:
                error_details.append(f"Error accessing OPENAI_API_KEY: {str(e)}")
        
        # Method 3: Try environment variable as last resort
        if not api_key:
            try:
                import os
                api_key = os.environ.get("OPENAI_API_KEY")
                if api_key:
                    error_details.append(f"Found key via environment variable (length: {len(api_key)})")
            except Exception as e:
                error_details.append(f"Error accessing environment variable: {str(e)}")
        
        # Validate API key
        if not api_key:
            # Store error details for debugging
            self._last_api_key_error = "No API key found. " + " | ".join(error_details) if error_details else "Checked all sources."
            return None
        
        # Check for placeholder keys
        if api_key.startswith("sk-your-") or (api_key.startswith("sk-proj-") and len(api_key) < 50):
            self._last_api_key_error = f"Placeholder or invalid API key detected (starts with 'sk-your-' or 'sk-proj-' with length < 50)"
            return None
        
        # Validate key format (should start with sk- and be reasonable length)
        if not api_key.startswith("sk-"):
            self._last_api_key_error = f"API key doesn't start with 'sk-' (format may be invalid)"
            return None
        
        if len(api_key) < 20:
            self._last_api_key_error = f"API key too short (length: {len(api_key)}, expected at least 20 characters)"
            return None
        
        # Try to create the client
        try:
            client = OpenAI(api_key=api_key)
            # Clear any previous errors
            if hasattr(self, '_last_api_key_error'):
                delattr(self, '_last_api_key_error')
            return client
        except Exception as e:
            self._last_api_key_error = f"Failed to create OpenAI client: {str(e)}"
            return None
    
    def parse_policy_rules(self, document_id: str, use_openai: bool = True) -> List[Dict[str, Any]]:
        """
        Parse policy-relevant information from extracted text using OpenAI.
        Falls back to simple keyword matching if OpenAI is unavailable.
        """
        document = next((doc for doc in self.documents if doc["id"] == document_id), None)
        if not document or not document.get("extracted_text"):
            return []
        
        text = document["extracted_text"]
        document_name = document.get("name", "Unknown")
        
        # Heavily prioritize OpenAI - try it first if enabled
        if use_openai:
            rules = self._parse_with_openai(text, document_id, document_name)
            if rules and len(rules) > 0:
                # Store extracted rules
                for rule in rules:
                    # Check if rule already exists (by text content to avoid duplicates)
                    existing_rule = next(
                        (r for r in self.extracted_rules if r.get("text") == rule.get("text") and r.get("source_document") == document_id),
                        None
                    )
                    if not existing_rule:
                        self.extracted_rules.append(rule)
                return rules
            # If OpenAI returned empty but was requested, still try keywords as fallback
            # but log that OpenAI was attempted
        
        # Fallback to simple keyword-based extraction
        return self._parse_with_keywords(text, document_id)
    
    def _parse_with_openai(self, text: str, document_id: str, document_name: str) -> List[Dict[str, Any]]:
        """Parse policy rules using OpenAI with structured output"""
        client = self._get_openai_client()
        if not client:
            # Return empty list to trigger fallback
            return []
        
        # Define the JSON schema for structured output
        schema = {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule_id": {
                                "type": "string",
                                "description": "Unique identifier for the rule (e.g., 'RETENTION_001')"
                            },
                            "rule_text": {
                                "type": "string",
                                "description": "The exact text or paraphrased statement of the policy rule"
                            },
                            "rule_type": {
                                "type": "string",
                                "enum": ["data_retention", "access_control", "compliance", "security", "privacy", "operational", "other"],
                                "description": "Category of the policy rule"
                            },
                            "key_requirements": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific requirements or constraints extracted from the rule"
                            },
                            "time_periods": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Any time periods mentioned (e.g., '5 years', '30 days')"
                            },
                            "confidence": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                                "description": "Confidence score for rule extraction (0.0 to 1.0)"
                            },
                            "context": {
                                "type": "string",
                                "description": "Additional context or scope for the rule"
                            }
                        },
                        "required": ["rule_id", "rule_text", "rule_type", "confidence"]
                    }
                }
            },
            "required": ["rules"]
        }
        
        # Truncate text if too long (keep last 15000 chars to preserve context)
        text_to_analyze = text if len(text) <= 15000 else text[-15000:]
        
        prompt = f"""Analyze the following organizational policy document and extract all policy rules, requirements, and compliance statements.

Document Name: {document_name}

Text Content:
{text_to_analyze}

Instructions:
1. Identify ALL policy rules, compliance requirements, data retention policies, access controls, security requirements, and operational procedures
2. Extract specific requirements including:
   - Time periods (e.g., "5 years", "30 days", "7-year retention")
   - Data types and classifications
   - Access levels and permissions
   - Constraints and restrictions
   - Compliance obligations
3. For each rule, provide:
   - A clear, concise rule_text (exact quote or paraphrased statement)
   - Appropriate rule_type categorization
   - Key requirements as a list
   - Any time periods mentioned
   - Confidence score (0.0-1.0) based on how explicit and clear the rule is
   - Context if needed to understand the rule's scope
4. Only extract rules that are clearly stated - avoid inferring rules that aren't explicitly mentioned
5. Be thorough - extract all relevant policy statements, not just a few

Return a JSON object with this exact structure:
{{
  "rules": [
    {{
      "rule_id": "RETENTION_001",
      "rule_text": "Customer data must be retained for 5 years",
      "rule_type": "data_retention",
      "key_requirements": ["5 year retention", "customer data"],
      "time_periods": ["5 years"],
      "confidence": 0.95,
      "context": "Applies to all customer data"
    }}
  ]
}}"""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",  # Using GPT-4o for better structured output support
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert policy analyst specializing in extracting structured policy rules from organizational documents. Your task is to identify and extract ALL policy rules, requirements, and compliance statements. Be thorough and extract every relevant policy statement you find. Extract only explicit, clearly stated rules and requirements."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.2,  # Lower temperature for more consistent, thorough extraction
                max_tokens=4000
            )
            
            result = json.loads(response.choices[0].message.content)
            extracted_rules = result.get("rules", [])
            
            if not extracted_rules:
                # No rules found - return empty to trigger fallback
                return []
            
            # Transform OpenAI response to our rule format
            rules = []
            for idx, rule_data in enumerate(extracted_rules):
                # Validate required fields
                if not rule_data.get("rule_text"):
                    continue  # Skip invalid rules
                
                rule = {
                    "id": f"soft_rule_{len(self.extracted_rules) + len(rules)}",
                    "source_document": document_id,
                    "source_document_name": document_name,
                    "text": rule_data.get("rule_text", ""),
                    "rule_type": rule_data.get("rule_type", "other"),
                    "key_requirements": rule_data.get("key_requirements", []),
                    "time_periods": rule_data.get("time_periods", []),
                    "context": rule_data.get("context", ""),
                    "extracted_date": datetime.utcnow().isoformat() + "Z",
                    "confidence": float(rule_data.get("confidence", 0.7)),
                    "extraction_method": "openai_gpt4o"
                }
                rules.append(rule)
            
            return rules
            
        except json.JSONDecodeError as e:
            # JSON parsing error - log and return empty
            return []
        except Exception as e:
            # Other OpenAI errors - return empty to trigger fallback
            return []
    
    def _parse_with_keywords(self, text: str, document_id: str) -> List[Dict[str, Any]]:
        """Fallback: Simple keyword-based rule extraction"""
        rules = []
        lines = text.split('\n')
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ["retention", "retain", "policy", "compliance", "regulation"]):
                rule = {
                    "id": f"soft_rule_{len(self.extracted_rules) + len(rules)}",
                    "source_document": document_id,
                    "text": line.strip(),
                    "rule_type": "other",
                    "key_requirements": [],
                    "time_periods": [],
                    "context": "",
                    "extracted_date": datetime.utcnow().isoformat() + "Z",
                    "confidence": 0.5,  # Lower confidence for keyword-based extraction
                    "extraction_method": "keyword_matching"
                }
                rules.append(rule)
        
        # Store extracted rules
        for rule in rules:
            if rule not in self.extracted_rules:
                self.extracted_rules.append(rule)
        
        return rules
    
    def detect_conflicts(self, hard_ontology_rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect conflicts between hard ontology and soft ontology rules"""
        conflicts = []
        
        for soft_rule in self.extracted_rules:
            # Simple conflict detection - in production, use semantic similarity
            soft_text = soft_rule.get("text", "").lower()
            hard_text = str(hard_ontology_rule).lower()
            
            # Check for conflicting time periods (e.g., "5-year" vs "7-year")
            if "year" in soft_text or "retention" in soft_text:
                conflicts.append({
                    "id": f"conflict_{len(conflicts)}",
                    "hard_ontology_rule": hard_ontology_rule,
                    "soft_ontology_rule": soft_rule,
                    "conflict_type": "retention_period",
                    "detected_date": datetime.utcnow().isoformat() + "Z"
                })
        
        return conflicts
    
    def resolve_conflict(self, conflict_id: str, resolution: str, resolution_notes: str = "") -> bool:
        """Record a conflict resolution decision"""
        conflict = next((c for c in self.conflict_resolutions if c.get("id") == conflict_id), None)
        if conflict:
            conflict["resolution"] = resolution
            conflict["resolution_notes"] = resolution_notes
            conflict["resolved_date"] = datetime.utcnow().isoformat() + "Z"
            return True
        
        # If conflict not in resolutions list, add it
        resolution_record = {
            "id": conflict_id,
            "resolution": resolution,
            "resolution_notes": resolution_notes,
            "resolved_date": datetime.utcnow().isoformat() + "Z"
        }
        self.conflict_resolutions.append(resolution_record)
        return True
    
    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get all active soft ontology rules (non-conflicting or resolved)"""
        active_rules = []
        
        for rule in self.extracted_rules:
            # Check if rule has unresolved conflicts
            has_conflict = any(
                c.get("soft_ontology_rule", {}).get("id") == rule.get("id")
                for c in self.conflict_resolutions
                if c.get("resolution") != "use_soft_ontology"
            )
            
            if not has_conflict:
                active_rules.append(rule)
        
        return active_rules
    
    def analyze_document_intent(self, document_id: str) -> Optional[Dict[str, Any]]:
        """
        Analyze document to understand intent, objectives, and policy context using LLM.
        Returns structured analysis with intent, objectives, policy_type, key_requirements, etc.
        """
        document = next((doc for doc in self.documents if doc["id"] == document_id), None)
        if not document or not document.get("extracted_text"):
            return None
        
        # Check if already analyzed
        if document_id in self.document_analyses:
            return self.document_analyses[document_id]
        
        client = self._get_openai_client()
        if not client:
            return None
        
        text = document["extracted_text"]
        document_name = document.get("name", "Unknown")
        
        # Truncate text if too long (keep last 20000 chars to preserve context)
        text_to_analyze = text if len(text) <= 20000 else text[-20000:]
        
        prompt = f"""Analyze the following organizational policy document to understand its intent, objectives, and policy context.

Document Name: {document_name}

Text Content:
{text_to_analyze}

Your task is to provide a comprehensive analysis of this document that will be used to generate a governance policy. Analyze:

1. **Intent**: What is the primary purpose and intent of this document? What is it trying to achieve?
2. **Objectives**: What are the main goals, objectives, and desired outcomes?
3. **Policy Context**: What type of policy or compliance framework does this relate to? (e.g., data retention, access control, security, privacy, operational compliance)
4. **Key Requirements**: What are the specific requirements, constraints, and obligations mentioned?
5. **Compliance Frameworks**: Are there any regulatory frameworks, standards, or compliance requirements referenced? (e.g., OCC, FDIC, GDPR, HIPAA, SOX)
6. **Scope**: What is the scope of application? (e.g., all data, specific data types, specific operations)
7. **Risk Level**: What is the overall risk level or sensitivity? (low, medium, high, critical)

Return a JSON object with this exact structure:
{{
  "intent": "Clear statement of the document's primary purpose and what it aims to achieve",
  "objectives": ["Objective 1", "Objective 2", "Objective 3"],
  "policy_type": "data_retention|access_control|compliance|security|privacy|operational|other",
  "key_requirements": ["Requirement 1", "Requirement 2", "Requirement 3"],
  "compliance_frameworks": ["Framework 1", "Framework 2"],
  "scope": "Description of what this policy applies to",
  "risk_level": "low|medium|high|critical",
  "summary": "Brief 2-3 sentence summary of the document's purpose and key points"
}}"""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert policy analyst specializing in understanding organizational documents and extracting their intent, objectives, and policy context. Your analysis will be used to generate governance policies, so be thorough and accurate."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
                max_tokens=2000
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return None
            
            result = json.loads(response.choices[0].message.content)
            
            # Store analysis
            analysis = {
                "document_id": document_id,
                "document_name": document_name,
                "analyzed_date": datetime.utcnow().isoformat() + "Z",
                "intent": result.get("intent", ""),
                "objectives": result.get("objectives", []),
                "policy_type": result.get("policy_type", "other"),
                "key_requirements": result.get("key_requirements", []),
                "compliance_frameworks": result.get("compliance_frameworks", []),
                "scope": result.get("scope", ""),
                "risk_level": result.get("risk_level", "medium"),
                "summary": result.get("summary", "")
            }
            
            self.document_analyses[document_id] = analysis
            return analysis
            
        except json.JSONDecodeError:
            return None
        except Exception:
            return None
    
    def generate_policy_from_document(self, document_id: str, baseline_policy_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Generate a complete policy JSON from document analysis and extracted rules.
        Uses LLM to create a full policy structure based on document intent and requirements.
        """
        document = next((doc for doc in self.documents if doc["id"] == document_id), None)
        if not document:
            return None
        
        # Get or perform analysis
        analysis = self.document_analyses.get(document_id)
        if not analysis:
            analysis = self.analyze_document_intent(document_id)
            if not analysis:
                return None
        
        # Get extracted rules for this document
        document_rules = [rule for rule in self.extracted_rules if rule.get("source_document") == document_id]
        
        client = self._get_openai_client()
        if not client:
            return None
        
        # Load baseline policy as template if provided
        baseline_template = {}
        if baseline_policy_path:
            try:
                import os
                if os.path.exists(baseline_policy_path):
                    with open(baseline_policy_path, 'r') as f:
                        baseline_template = json.load(f)
            except Exception:
                pass
        
        # Prepare context for policy generation
        analysis_summary = f"""
Document Analysis:
- Intent: {analysis.get('intent', 'N/A')}
- Objectives: {', '.join(analysis.get('objectives', []))}
- Policy Type: {analysis.get('policy_type', 'other')}
- Key Requirements: {', '.join(analysis.get('key_requirements', []))}
- Compliance Frameworks: {', '.join(analysis.get('compliance_frameworks', []))}
- Scope: {analysis.get('scope', 'N/A')}
- Risk Level: {analysis.get('risk_level', 'medium')}
- Summary: {analysis.get('summary', 'N/A')}
"""
        
        extracted_rules_text = ""
        if document_rules:
            extracted_rules_text = "\nExtracted Rules:\n"
            for rule in document_rules[:10]:  # Limit to first 10 rules
                extracted_rules_text += f"- {rule.get('text', '')} (Type: {rule.get('rule_type', 'other')})\n"
        
        # Create policy generation prompt
        prompt = f"""Generate a complete governance policy JSON based on the following document analysis and extracted rules.

{analysis_summary}

{extracted_rules_text}

Generate a complete policy JSON that follows this structure (use the baseline policy as a template but adapt it based on the document analysis):

Required Structure:
{{
  "policy_id": "unique_policy_id_based_on_document",
  "policy_version": "1.0.0",
  "created": "YYYY-MM-DD",
  "description": "Policy description based on document intent and objectives",
  "dials": {{
    "autonomy": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "personalization": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "memory": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "inter_agent": {{"level": "L1-L3", "label": "...", "description": "..."}}
  }},
  "gates": {{
    "U-I": {{"name": "User Inbound", "direction": "user_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "U-O": {{"name": "User Outbound", "direction": "agent_to_user", "allow": [...], "controls": [...], "deny": [...]}},
    "S-I": {{"name": "System Inbound", "direction": "system_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "S-O": {{"name": "System Outbound", "direction": "agent_to_system", "allow": [...], "controls": [...], "deny": [...]}},
    "M-I": {{"name": "Memory Inbound", "direction": "memory_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "M-O": {{"name": "Memory Outbound", "direction": "agent_to_memory", "allow": [...], "controls": [...], "deny": [...]}},
    "A-I": {{"name": "Agent Inbound", "direction": "other_agent_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "A-O": {{"name": "Agent Outbound", "direction": "agent_to_other_agent", "allow": [...], "controls": [...], "deny": [...]}}
  }},
  "overlays_enabled": [],
  "overlays": {{}},
  "rules": [
    {{
      "rule_id": "R-XXX",
      "baseline": false,
      "enabled": true,
      "description": "Rule description based on document requirements",
      "severity": "deny|escalate|allow",
      "policy_clause_ref": "§X.X",
      "applies_to_gate": "U-I|U-O|S-I|S-O|M-I|M-O|A-I|A-O",
      "applies_to_control": "control_name"
    }}
  ]
}}

Instructions:
1. Create a policy_id based on the document name (sanitized, lowercase, underscores)
2. Set appropriate dial levels based on risk_level and policy_type (higher risk = more restrictive)
3. Map document requirements to appropriate gates:
   - Data retention requirements → M-O (Memory Outbound) with retention_policy controls
   - Access control requirements → U-I, S-O gates
   - Security requirements → S-I, S-O gates with appropriate controls
   - Privacy requirements → U-O, M-O gates with redaction controls
4. Create rules based on extracted rules and key requirements from analysis
5. Set severity appropriately: "deny" for critical restrictions, "escalate" for approval requirements, "allow" for permissions
6. Ensure all 8 gates are present with appropriate allow/controls/deny arrays
7. Make rules specific and actionable based on the document content
8. Include all required fields in rules

Return ONLY valid JSON, no markdown formatting, no code blocks."""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert policy engineer specializing in creating governance policies from organizational documents. Generate complete, valid JSON policy structures that map document requirements to appropriate gates, controls, and rules. Always return valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=8000
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return None
            
            policy_json = json.loads(response.choices[0].message.content)
            
            # Validate and ensure required fields exist
            if not policy_json.get("policy_id"):
                # Generate policy_id from document name
                doc_name = document.get("name", "generated_policy")
                policy_id = doc_name.lower().replace(" ", "_").replace(".", "_").replace("-", "_")
                policy_id = ''.join(c for c in policy_id if c.isalnum() or c == '_')[:50]
                policy_json["policy_id"] = policy_id
            
            if not policy_json.get("policy_version"):
                policy_json["policy_version"] = "1.0.0"
            
            if not policy_json.get("created"):
                policy_json["created"] = datetime.utcnow().strftime("%Y-%m-%d")
            
            # Ensure all gates exist
            required_gates = ["U-I", "U-O", "S-I", "S-O", "M-I", "M-O", "A-I", "A-O"]
            if "gates" not in policy_json:
                policy_json["gates"] = {}
            
            for gate_id in required_gates:
                if gate_id not in policy_json["gates"]:
                    policy_json["gates"][gate_id] = {
                        "name": f"{gate_id} Gate",
                        "direction": "unknown",
                        "allow": [],
                        "controls": [],
                        "deny": []
                    }
            
            # Ensure rules array exists
            if "rules" not in policy_json:
                policy_json["rules"] = []
            
            # Ensure overlays exist
            if "overlays_enabled" not in policy_json:
                policy_json["overlays_enabled"] = []
            if "overlays" not in policy_json:
                policy_json["overlays"] = {}
            
            return policy_json
            
        except json.JSONDecodeError as e:
            return None
        except Exception:
            return None
    
    def analyze_text_intent(self, text: str, text_name: str = "Input Text") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Analyze text directly to understand intent, objectives, and policy context using LLM.
        Returns structured analysis with intent, objectives, policy_type, key_requirements, etc.
        Returns tuple: (analysis_dict, error_message)
        """
        if not text or not text.strip():
            return None, "No text provided"
        
        # Use a session key for text-based analysis
        text_key = f"text_{hash(text[:100])}"
        
        # Check if already analyzed
        if text_key in self.document_analyses:
            return self.document_analyses[text_key], None
        
        client = self._get_openai_client()
        if not client:
            error_msg = getattr(self, '_last_api_key_error', None) or "OpenAI API key not found. Please configure your API key in `.streamlit/secrets.toml`"
            return None, error_msg
        
        # Truncate text if too long (keep last 20000 chars to preserve context)
        text_to_analyze = text if len(text) <= 20000 else text[-20000:]
        
        prompt = f"""Analyze the following organizational policy document to understand its intent, objectives, and policy context.

Document Name: {text_name}

Text Content:
{text_to_analyze}

Your task is to provide a comprehensive analysis of this document that will be used to generate a governance policy. Analyze:

1. **Intent**: What is the primary purpose and intent of this document? What problem is it trying to solve or what goal is it trying to achieve?

2. **Objectives**: List the main objectives or goals that this document aims to accomplish. Provide 3-5 specific objectives.

3. **Policy Type**: Categorize this as one of: data_retention, access_control, security, privacy, compliance, operational, financial, or other.

4. **Key Requirements**: Extract the most important requirements, constraints, or rules mentioned in the document. List 5-10 key requirements.

5. **Compliance Frameworks**: Identify any compliance frameworks, standards, or regulations mentioned (e.g., GDPR, HIPAA, SOC2, PCI-DSS, ISO 27001, etc.). If none are mentioned, return an empty array.

6. **Scope**: What is the scope of this policy? Who or what does it apply to? (e.g., "All employees", "Customer data", "Production systems", etc.)

7. **Risk Level**: Assess the risk level as: critical, high, medium, or low based on the sensitivity and impact of the requirements.

8. **Summary**: Provide a 2-3 sentence summary of the document's purpose and key points.

Return your analysis as a JSON object with the following structure:
{{
  "intent": "string describing the primary intent",
  "objectives": ["objective1", "objective2", "objective3"],
  "policy_type": "data_retention|access_control|security|privacy|compliance|operational|financial|other",
  "key_requirements": ["requirement1", "requirement2", "requirement3"],
  "compliance_frameworks": ["framework1", "framework2"],
  "scope": "string describing scope",
  "risk_level": "critical|high|medium|low",
  "summary": "2-3 sentence summary"
}}

Return ONLY valid JSON, no markdown formatting, no code blocks."""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert policy analyst specializing in understanding organizational documents and extracting their intent, objectives, and policy requirements. Always return valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
                max_tokens=2000
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return None, "No response from OpenAI API"
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Store analysis with text key
            self.document_analyses[text_key] = analysis
            return analysis, None
            
        except json.JSONDecodeError as e:
            return None, f"Failed to parse JSON response: {str(e)}"
        except Exception as e:
            return None, f"OpenAI API error: {str(e)}"
    
    def generate_policy_from_text(self, text: str, baseline_policy_path: Optional[str] = None, text_name: str = "Input Text") -> Optional[Dict[str, Any]]:
        """
        Generate a complete policy JSON from text analysis.
        Uses LLM to create a full policy structure based on text intent and requirements.
        """
        if not text or not text.strip():
            return None
        
        text_key = f"text_{hash(text[:100])}"
        
        # Get or perform analysis
        analysis = self.document_analyses.get(text_key)
        if not analysis:
            analysis, error_msg = self.analyze_text_intent(text, text_name)
            if not analysis:
                return None
        
        # Get extracted rules for this text (if any)
        document_rules = [rule for rule in self.extracted_rules if rule.get("source_document") == text_key]
        
        client = self._get_openai_client()
        if not client:
            return None
        
        # Load baseline policy as template if provided
        baseline_template = {}
        if baseline_policy_path:
            try:
                import os
                if os.path.exists(baseline_policy_path):
                    with open(baseline_policy_path, 'r') as f:
                        baseline_template = json.load(f)
            except Exception:
                pass
        
        # Prepare context for policy generation
        analysis_summary = f"""
Document Analysis:
- Intent: {analysis.get('intent', 'N/A')}
- Objectives: {', '.join(analysis.get('objectives', []))}
- Policy Type: {analysis.get('policy_type', 'other')}
- Key Requirements: {', '.join(analysis.get('key_requirements', []))}
- Compliance Frameworks: {', '.join(analysis.get('compliance_frameworks', []))}
- Scope: {analysis.get('scope', 'N/A')}
- Risk Level: {analysis.get('risk_level', 'medium')}
- Summary: {analysis.get('summary', 'N/A')}
"""
        
        extracted_rules_text = ""
        if document_rules:
            extracted_rules_text = "\nExtracted Rules:\n"
            for rule in document_rules[:10]:  # Limit to first 10 rules
                extracted_rules_text += f"- {rule.get('text', '')} (Type: {rule.get('rule_type', 'other')})\n"
        
        # Create policy generation prompt
        prompt = f"""Generate a complete governance policy JSON based on the following document analysis and extracted rules.

{analysis_summary}

{extracted_rules_text}

Generate a complete policy JSON that follows this structure (use the baseline policy as a template but adapt it based on the document analysis):

Required Structure:
{{
  "policy_id": "unique_policy_id_based_on_document",
  "policy_version": "1.0.0",
  "created": "YYYY-MM-DD",
  "description": "Policy description based on document intent and objectives",
  "dials": {{
    "autonomy": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "personalization": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "memory": {{"level": "L1-L3", "label": "...", "description": "..."}},
    "inter_agent": {{"level": "L1-L3", "label": "...", "description": "..."}}
  }},
  "gates": {{
    "U-I": {{"name": "User Inbound", "direction": "user_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "U-O": {{"name": "User Outbound", "direction": "agent_to_user", "allow": [...], "controls": [...], "deny": [...]}},
    "S-I": {{"name": "System Inbound", "direction": "system_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "S-O": {{"name": "System Outbound", "direction": "agent_to_system", "allow": [...], "controls": [...], "deny": [...]}},
    "M-I": {{"name": "Memory Inbound", "direction": "memory_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "M-O": {{"name": "Memory Outbound", "direction": "agent_to_memory", "allow": [...], "controls": [...], "deny": [...]}},
    "A-I": {{"name": "Agent Inbound", "direction": "other_agent_to_agent", "allow": [...], "controls": [...], "deny": [...]}},
    "A-O": {{"name": "Agent Outbound", "direction": "agent_to_other_agent", "allow": [...], "controls": [...], "deny": [...]}}
  }},
  "overlays_enabled": [],
  "overlays": {{}},
  "rules": [
    {{
      "rule_id": "R-XXX",
      "baseline": false,
      "enabled": true,
      "description": "Rule description based on document requirements",
      "severity": "deny|escalate|allow",
      "policy_clause_ref": "§X.X",
      "applies_to_gate": "U-I|U-O|S-I|S-O|M-I|M-O|A-I|A-O",
      "applies_to_control": "control_name"
    }}
  ]
}}

Instructions:
1. Create a policy_id based on the text name (sanitized, lowercase, underscores)
2. Set appropriate dial levels based on risk_level and policy_type (higher risk = more restrictive)
3. Map document requirements to appropriate gates:
   - Data retention requirements → M-O (Memory Outbound) with retention_policy controls
   - Access control requirements → U-I, S-O gates
   - Security requirements → S-I, S-O gates with appropriate controls
   - Privacy requirements → U-O, M-O gates with redaction controls
4. Create rules based on extracted rules and key requirements from analysis
5. Set severity appropriately: "deny" for critical restrictions, "escalate" for approval requirements, "allow" for permissions
6. Ensure all 8 gates are present with appropriate allow/controls/deny arrays
7. Make rules specific and actionable based on the document content
8. Include all required fields in rules

Return ONLY valid JSON, no markdown formatting, no code blocks."""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert policy engineer specializing in creating governance policies from organizational documents. Generate complete, valid JSON policy structures that map document requirements to appropriate gates, controls, and rules. Always return valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.2,
                max_tokens=8000
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return None
            
            policy_json = json.loads(response.choices[0].message.content)
            
            # Validate and ensure required fields exist
            if not policy_json.get("policy_id"):
                # Generate policy_id from text name
                policy_id = text_name.lower().replace(" ", "_").replace(".", "_").replace("-", "_")
                policy_id = ''.join(c for c in policy_id if c.isalnum() or c == '_')[:50]
                policy_json["policy_id"] = policy_id
            
            if not policy_json.get("policy_version"):
                policy_json["policy_version"] = "1.0.0"
            
            if not policy_json.get("created"):
                policy_json["created"] = datetime.utcnow().strftime("%Y-%m-%d")
            
            # Ensure all gates exist
            required_gates = ["U-I", "U-O", "S-I", "S-O", "M-I", "M-O", "A-I", "A-O"]
            if "gates" not in policy_json:
                policy_json["gates"] = {}
            
            for gate_id in required_gates:
                if gate_id not in policy_json["gates"]:
                    policy_json["gates"][gate_id] = {
                        "name": f"{gate_id} Gate",
                        "direction": "unknown",
                        "allow": [],
                        "controls": [],
                        "deny": []
                    }
            
            # Ensure rules array exists
            if "rules" not in policy_json:
                policy_json["rules"] = []
            
            # Ensure overlays exist
            if "overlays_enabled" not in policy_json:
                policy_json["overlays_enabled"] = []
            if "overlays" not in policy_json:
                policy_json["overlays"] = {}
            
            # Automatically save the policy to the project folder
            saved_path = self.save_generated_policy_from_text(text_key, policy_json)
            if saved_path:
                # Store the saved path in the policy_json for reference
                policy_json["_saved_path"] = saved_path
            
            return policy_json
            
        except json.JSONDecodeError as e:
            return None
        except Exception:
            return None
    
    def save_generated_policy(self, document_id: str, policy_json: Dict[str, Any]) -> Optional[str]:
        """Save generated policy to a JSON file and return the file path"""
        import os
        
        policy_id = policy_json.get("policy_id", f"generated_policy_{document_id}")
        parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        policy_filename = f"{policy_id}.json"
        policy_path = os.path.join(parent_dir, policy_filename)
        
        try:
            with open(policy_path, 'w') as f:
                json.dump(policy_json, f, indent=2)
            
            # Store the file path
            self.generated_policies[document_id] = policy_path
            return policy_path
        except Exception:
            return None
    
    def save_generated_policy_from_text(self, text_key: str, policy_json: Dict[str, Any]) -> Optional[str]:
        """Save generated policy from text to a JSON file in the project root directory and return the file path"""
        import os
        
        policy_id = policy_json.get("policy_id", f"generated_policy_{text_key}")
        # Get project root directory (go up 2 levels from app/soft_ontology_manager.py to reach root)
        current_file = os.path.abspath(__file__)  # app/soft_ontology_manager.py
        app_dir = os.path.dirname(current_file)   # app/
        root_dir = os.path.dirname(app_dir)       # project root
        
        policy_filename = f"{policy_id}.json"
        policy_path = os.path.join(root_dir, policy_filename)
        
        try:
            # Ensure the directory exists
            os.makedirs(root_dir, exist_ok=True)
            
            # Save the policy JSON file
            with open(policy_path, 'w', encoding='utf-8') as f:
                json.dump(policy_json, f, indent=2, ensure_ascii=False)
            
            # Store the file path
            self.generated_policies[text_key] = policy_path
            return policy_path
        except Exception as e:
            # Log the error for debugging
            import traceback
            print(f"Error saving policy file: {str(e)}")
            print(traceback.format_exc())
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert manager state to dictionary for serialization"""
        return {
            "documents": [
                {k: v for k, v in doc.items() if k != "content"}  # Exclude binary content
                for doc in self.documents
            ],
            "extracted_rules": self.extracted_rules,
            "conflict_resolutions": self.conflict_resolutions,
            "active_rules_count": len(self.get_active_rules()),
            "document_analyses": self.document_analyses,
            "generated_policies": self.generated_policies
        }
