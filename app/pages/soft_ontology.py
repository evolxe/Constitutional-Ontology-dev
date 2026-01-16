"""
Soft Ontology Page - Create and manage organization-specific documentation integration
"""

import streamlit as st
import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soft_ontology_manager import SoftOntologyManager


# Page configuration
st.set_page_config(
    page_title="Soft Ontology",
    page_icon="📄",
    layout="wide"
)

# Initialize session state for soft ontology manager
if "soft_ontology_manager" not in st.session_state:
    st.session_state.soft_ontology_manager = SoftOntologyManager()

manager = st.session_state.soft_ontology_manager

st.title("📄 Soft Ontology Management")
st.caption("Input organizational policy text to generate governance policies")

# ============================================================================
# POLICY GENERATION WORKFLOW SECTION (at top)
# ============================================================================
st.markdown("### Policy Generation Workflow")
st.caption("Generate governance policies from analyzed text")

# Initialize logging session state
if "soft_ontology_logs" not in st.session_state:
    st.session_state.soft_ontology_logs = []

# Initialize session state for text input
if "input_text" not in st.session_state:
    st.session_state.input_text = ""

if "text_analysis" not in st.session_state:
    st.session_state.text_analysis = None

if "generated_policy_path" not in st.session_state:
    st.session_state.generated_policy_path = None

if "text_key" not in st.session_state:
    st.session_state.text_key = None

def add_log(message: str, level: str = "info"):
    """Add a log entry to the logging section"""
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "level": level,  # info, success, warning, error
        "message": message
    }
    st.session_state.soft_ontology_logs.append(log_entry)
    # Keep only last 50 log entries
    if len(st.session_state.soft_ontology_logs) > 50:
        st.session_state.soft_ontology_logs = st.session_state.soft_ontology_logs[-50:]

# Logging Section at the top
st.markdown("---")
with st.expander("🔍 Debug Logging", expanded=False):
    st.caption("View step-by-step operation logs for debugging")
    
    if st.button("Clear Logs", key="clear_logs"):
        st.session_state.soft_ontology_logs = []
        st.rerun()
    
    if st.session_state.soft_ontology_logs:
        # Show logs in reverse order (newest first)
        for log in reversed(st.session_state.soft_ontology_logs[-20:]):  # Show last 20
            level = log.get("level", "info")
            timestamp = log.get("timestamp", "")
            message = log.get("message", "")
            
            if level == "success":
                st.success(f"[{timestamp}] {message}")
            elif level == "warning":
                st.warning(f"[{timestamp}] {message}")
            elif level == "error":
                st.error(f"[{timestamp}] {message}")
            else:
                st.info(f"[{timestamp}] {message}")
    else:
        st.info("No logs yet. Operations will be logged here.")

st.markdown("---")

# ============================================================================
# 1. INPUT TEXT SECTION
# ============================================================================
st.markdown("### Input Text")
st.caption("Enter or paste organizational policy text to analyze and generate policies")

input_text = st.text_area(
    "Policy Text Input",
    value=st.session_state.input_text,
    height=300,
    help="Enter the text content of your organizational policy, SOP, or compliance document",
    key="policy_text_input"
)

if input_text:
    st.session_state.input_text = input_text
    # Generate a key for this text
    st.session_state.text_key = f"text_{hash(input_text[:100])}"
else:
    st.session_state.input_text = ""
    st.session_state.text_key = None

# Analyze Text Intent button - directly below text area
if st.button("🔍 Analyze Text Intent", type="primary", use_container_width=True):
    if not st.session_state.input_text or not st.session_state.input_text.strip():
        st.warning("Please enter some text in the text area above before analyzing.")
    else:
        with st.spinner("Analyzing text with LLM..."):
            try:
                add_log("Starting LLM analysis for input text", "info")
                
                # First, test if we can get the client
                test_client = manager._get_openai_client()
                if not test_client:
                    error_msg = getattr(manager, '_last_api_key_error', None) or "OpenAI API key not found"
                    add_log(f"API key check failed - {error_msg}", "error")
                    st.error(f"❌ API Key Issue: {error_msg}")
                    
                    # Show detailed diagnostics
                    with st.expander("🔧 API Key Diagnostics", expanded=True):
                        st.markdown("**Checking API key sources:**")
                        
                        # Check secrets
                        try:
                            if hasattr(st, 'secrets') and st.secrets:
                                if "openai" in st.secrets:
                                    openai_sec = st.secrets["openai"]
                                    if isinstance(openai_sec, dict) and "api_key" in openai_sec:
                                        key_val = openai_sec["api_key"]
                                        key_len = len(key_val) if key_val else 0
                                        key_preview = key_val[:10] + "..." if key_val and len(key_val) > 10 else key_val
                                        st.success(f"✓ Found [openai].api_key (length: {key_len}, starts with: {key_preview})")
                                    else:
                                        st.warning("✗ [openai].api_key not found in secrets")
                                else:
                                    st.warning("✗ [openai] section not found in secrets")
                                
                                if "OPENAI_API_KEY" in st.secrets:
                                    key_val = st.secrets["OPENAI_API_KEY"]
                                    key_len = len(key_val) if key_val else 0
                                    st.success(f"✓ Found OPENAI_API_KEY (length: {key_len})")
                                else:
                                    st.info("ℹ OPENAI_API_KEY not found in secrets (this is OK if using [openai].api_key)")
                            else:
                                st.error("✗ st.secrets is not available")
                        except Exception as e:
                            st.error(f"✗ Error checking secrets: {str(e)}")
                        
                        # Check environment
                        import os
                        env_key = os.environ.get("OPENAI_API_KEY")
                        if env_key:
                            st.success(f"✓ Found OPENAI_API_KEY in environment (length: {len(env_key)})")
                        else:
                            st.info("ℹ OPENAI_API_KEY not in environment (this is OK if using secrets)")
                        
                        st.markdown("---")
                        st.markdown("""
                        **To fix:**
                        1. Ensure `.streamlit/secrets.toml` exists in your project root
                        2. Add your API key:
                        ```toml
                        [openai]
                        api_key = "sk-your-actual-key-here"
                        ```
                        3. Restart the Streamlit app (secrets are loaded at startup)
                        """)
                else:
                    # Client exists, proceed with analysis
                    analysis, error_msg = manager.analyze_text_intent(st.session_state.input_text, "Input Text")
                    if analysis:
                        intent = analysis.get("intent", "N/A")
                        policy_type = analysis.get("policy_type", "other")
                        risk_level = analysis.get("risk_level", "medium")
                        add_log(f"Analysis complete - Intent: {intent[:100]}... | Type: {policy_type} | Risk: {risk_level}", "success")
                        st.session_state.text_analysis = analysis
                        st.success("Text analyzed successfully!")
                        st.rerun()
                    else:
                        error_message = error_msg or "No results returned. Check OpenAI API key."
                        add_log(f"Analysis failed - {error_message}", "error")
                        st.error(f"Failed to analyze text: {error_message}")
                        if "API key" in error_message:
                            st.info("""
                            **To configure OpenAI API key:**
                            1. Create or edit `.streamlit/secrets.toml` file in your project root
                            2. Add your API key:
                            ```toml
                            [openai]
                            api_key = "sk-your-actual-key-here"
                            ```
                            3. Restart the Streamlit app
                            """)
            except Exception as e:
                add_log(f"Error during analysis: {str(e)}", "error")
                st.error(f"Error during analysis: {str(e)}")
                st.info("Please ensure OpenAI API key is configured correctly in `.streamlit/secrets.toml`")

st.markdown("---")

# ============================================================================
# 2. POLICY GENERATION WORKFLOW SECTION
# ============================================================================

if st.session_state.text_analysis:
    # Show analysis results if available
    st.markdown("#### Text Analysis Results")
    with st.expander("View Analysis", expanded=True):
        col_a1, col_a2 = st.columns(2)
        
        with col_a1:
            st.markdown("**Intent:**")
            st.info(st.session_state.text_analysis.get("intent", "N/A"))
            
            st.markdown("**Objectives:**")
            objectives = st.session_state.text_analysis.get("objectives", [])
            if objectives:
                for obj in objectives:
                    st.write(f"• {obj}")
            else:
                st.write("None specified")
        
        with col_a2:
            st.markdown("**Policy Type:**")
            st.write(st.session_state.text_analysis.get("policy_type", "other").replace("_", " ").title())
            
            st.markdown("**Risk Level:**")
            risk_level = st.session_state.text_analysis.get("risk_level", "medium")
            if risk_level == "critical":
                st.error(risk_level.upper())
            elif risk_level == "high":
                st.warning(risk_level.upper())
            else:
                st.info(risk_level.upper())
        
        st.markdown("**Key Requirements:**")
        requirements = st.session_state.text_analysis.get("key_requirements", [])
        if requirements:
            for req in requirements:
                st.write(f"• {req}")
        else:
            st.write("None specified")
        
        st.markdown("**Compliance Frameworks:**")
        frameworks = st.session_state.text_analysis.get("compliance_frameworks", [])
        if frameworks:
            st.write(", ".join(frameworks))
        else:
            st.write("None specified")
        
        st.markdown("**Summary:**")
        st.write(st.session_state.text_analysis.get("summary", "N/A"))
    
    # Generate Policy button
    if st.button("⚙️ Generate Policy", type="primary", use_container_width=True):
        with st.spinner("Generating policy with LLM (this may take a minute)..."):
            try:
                add_log("Starting policy generation from input text", "info")
                # Get baseline policy path
                parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                baseline_path = os.path.join(parent_dir, "policy_bank_compliance_baseline.json")
                
                if os.path.exists(baseline_path):
                    add_log(f"Using baseline policy template: {os.path.basename(baseline_path)}", "info")
                else:
                    add_log(f"Baseline policy not found at {baseline_path}, generating without template", "warning")
                
                policy_json = manager.generate_policy_from_text(st.session_state.input_text, baseline_path, "Input Text")
                if policy_json:
                    policy_id = policy_json.get("policy_id", "unknown")
                    rules_count = len(policy_json.get("rules", []))
                    gates_count = len(policy_json.get("gates", {}))
                    add_log(f"Policy JSON generated - ID: {policy_id}, Rules: {rules_count}, Gates: {gates_count}", "success")
                    
                    # Policy is automatically saved during generation
                    # Get the saved path from the policy_json or from manager
                    if st.session_state.text_key:
                        policy_path = manager.generated_policies.get(st.session_state.text_key)
                    else:
                        # Fallback: use policy_id as key
                        policy_path = manager.generated_policies.get(policy_id)
                    
                    # Also check if path was stored in policy_json
                    if not policy_path:
                        policy_path = policy_json.get("_saved_path")
                    
                    if policy_path and os.path.exists(policy_path):
                        add_log(f"Policy automatically saved to file: {os.path.basename(policy_path)}", "success")
                        st.success(f"✅ Policy generated and saved successfully: `{os.path.basename(policy_path)}`")
                        st.session_state.generated_policy_path = policy_path
                        st.session_state.generated_policy_filename = os.path.basename(policy_path)
                        st.rerun()
                    else:
                        # Try to save manually as fallback
                        if st.session_state.text_key:
                            policy_path = manager.save_generated_policy_from_text(st.session_state.text_key, policy_json)
                        else:
                            policy_path = manager.save_generated_policy_from_text(policy_id, policy_json)
                        
                        if policy_path:
                            add_log(f"Policy saved to file: {os.path.basename(policy_path)}", "success")
                            st.success(f"✅ Policy generated and saved successfully: `{os.path.basename(policy_path)}`")
                            st.session_state.generated_policy_path = policy_path
                            st.session_state.generated_policy_filename = os.path.basename(policy_path)
                            st.rerun()
                        else:
                            add_log("Failed to save policy to file. Check file permissions.", "error")
                            st.error("Policy generated but failed to save. Please check file permissions.")
                else:
                    add_log("Policy generation failed - No policy JSON returned. Check OpenAI API key.", "error")
                    st.error("Failed to generate policy. Please check OpenAI API key and try again.")
                    st.info("This could be due to: invalid API key, rate limits, or network issues.")
            except Exception as e:
                add_log(f"Error during policy generation: {str(e)}", "error")
                st.error(f"Error during policy generation: {str(e)}")
                st.info("Please ensure OpenAI API key is configured correctly in `.streamlit/secrets.toml`")
    
    # Show generated policy status
    if st.session_state.generated_policy_path and os.path.exists(st.session_state.generated_policy_path):
        st.markdown("#### Generated Policy")
        policy_filename = os.path.basename(st.session_state.generated_policy_path)
        
        st.success(f"✅ Policy generated and saved: `{policy_filename}`")
        st.info(f"📁 Saved to: `{st.session_state.generated_policy_path}`")
        
        col_open, col_view, col_download = st.columns(3)
        
        with col_open:
            if st.button("📝 Open in Policy Editor", type="primary", use_container_width=True):
                add_log(f"Opening policy '{policy_filename}' in policy editor", "info")
                # Set the selected policy in session state
                st.session_state.editor_selected_policy = policy_filename
                # Add flag to indicate this is a newly generated policy
                st.session_state.policy_just_generated = True
                st.switch_page("pages/policy_editor.py")
        
        with col_view:
            if st.button("👁️ Preview Policy", use_container_width=True):
                try:
                    with open(st.session_state.generated_policy_path, 'r', encoding='utf-8') as f:
                        policy_data = json.load(f)
                    st.json(policy_data)
                except Exception as e:
                    st.error(f"Failed to load policy: {str(e)}")
        
        with col_download:
            try:
                with open(st.session_state.generated_policy_path, 'r', encoding='utf-8') as f:
                    policy_json_data = f.read()
                
                st.download_button(
                    label="💾 Download JSON",
                    data=policy_json_data,
                    file_name=policy_filename,
                    mime="application/json",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"Failed to prepare download: {str(e)}")
else:
    st.info("Please analyze text first using the '🔍 Analyze Text Intent' button above to begin policy generation.")

