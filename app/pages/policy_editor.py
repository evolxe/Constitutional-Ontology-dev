"""
Policy Editor Page - Individual policy editing and gate modification
"""

import streamlit as st
import os
import sys
import json
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from constitutional_enforcement_interactive import ConstitutionalEnforcer


# Page configuration
st.set_page_config(
    page_title="Policy Editor",
    page_icon="⚙️",
    layout="wide"
)

st.title("⚙️ Policy Editor")
st.caption("Edit policy JSON directly with auto-formatting")

st.markdown("---")

# Policy selection
st.markdown("### Select Policy to Edit")

def get_policy_files():
    """Get all JSON policy files from root directory"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    policy_files = []
    if os.path.exists(parent_dir):
        for file in os.listdir(parent_dir):
            if file.endswith('.json') and os.path.isfile(os.path.join(parent_dir, file)):
                policy_files.append(file)
    return sorted(policy_files)

def load_policy_json(policy_filename: str) -> Optional[Dict[str, Any]]:
    """Load a policy file as JSON dictionary"""
    parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    policy_path = os.path.join(parent_dir, policy_filename)
    try:
        with open(policy_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None

policy_files = get_policy_files()

if not policy_files:
    st.error("No policy JSON files found in root directory")
    st.stop()

# Get current selection or default to first file
current_policy = st.session_state.get("editor_selected_policy", policy_files[0] if policy_files else None)
selected_policy = st.selectbox(
    "Select Policy File",
    options=policy_files,
    index=policy_files.index(current_policy) if current_policy in policy_files else 0,
    key="editor_policy_selector"
)

if selected_policy != st.session_state.get("editor_selected_policy"):
    st.session_state.editor_selected_policy = selected_policy
    st.rerun()

# Load policy
policy = load_policy_json(selected_policy)

if not policy:
    st.error(f"Failed to load policy file: {selected_policy}")
    st.stop()

st.markdown("---")

# Initialize session state for JSON editor
if "editor_json_content" not in st.session_state or st.session_state.get("editor_selected_policy") != selected_policy:
    # Format JSON with proper indentation when loading
    st.session_state.editor_json_content = json.dumps(policy, indent=2)
    st.session_state.editor_selected_policy = selected_policy

# JSON Editor Section
st.markdown("### JSON Editor")
st.caption("Edit the policy JSON directly. Formatting is automatically maintained.")

# If we just reset, clear the widget key to force it to use the new value
if st.session_state.get("just_reset", False):
    # Delete the widget key to force reset
    if "json_editor_text" in st.session_state:
        del st.session_state.json_editor_text
    # Use the session state content directly
    current_content = st.session_state.editor_json_content
else:
    # Use session state, but allow widget to maintain its own state
    current_content = st.session_state.editor_json_content

# Get the current JSON content from session state
json_content = st.text_area(
    "Policy JSON",
    value=current_content,
    height=600,
    key="json_editor_text",
    help="Edit the JSON directly. The formatting will be preserved when you save."
)

# Update session state when content changes (but not if we just reset)
if not st.session_state.get("just_reset", False) and json_content != st.session_state.editor_json_content:
    st.session_state.editor_json_content = json_content

st.markdown("---")

# Save/Export section
st.markdown("### Save Changes")

col_save1, col_save2, col_save3 = st.columns(3)

def save_policy_json():
    """Save the edited JSON to file with auto-formatting"""
    try:
        # Parse and validate JSON
        parsed_json = json.loads(json_content)
        
        # Re-format with proper indentation
        formatted_json = json.dumps(parsed_json, indent=2)
        
        # Save to file
        parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        policy_path = os.path.join(parent_dir, selected_policy)
        
        with open(policy_path, 'w') as f:
            f.write(formatted_json)
        
        # Update session state with formatted version
        st.session_state.editor_json_content = formatted_json
        
        return True, formatted_json
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"
    except Exception as e:
        return False, f"Failed to save policy: {str(e)}"

with col_save1:
    if st.button("💾 Save to File", type="primary"):
        success, result = save_policy_json()
        if success:
            st.success(f"Policy saved to {selected_policy}")
            st.rerun()
        else:
            st.error(result)

with col_save2:
    if st.button("📥 Export as JSON"):
        try:
            # Parse and format JSON for export
            parsed_json = json.loads(json_content)
            policy_json = json.dumps(parsed_json, indent=2)
            policy_id = parsed_json.get("policy_id", "policy")
            policy_version = parsed_json.get("policy_version", "v1")
            
            st.download_button(
                label="Download Policy JSON",
                data=policy_json,
                file_name=f"policy_{policy_id}_{policy_version}.json",
                mime="application/json"
            )
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {str(e)}")
        except Exception as e:
            st.error(f"Failed to export: {str(e)}")

with col_save3:
    if st.button("🔄 Reset Changes"):
        # Always reload from file, regardless of current editor content errors
        try:
            # Read raw file content first
            parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            policy_path = os.path.join(parent_dir, selected_policy)
            
            with open(policy_path, 'r') as f:
                file_content = f.read()
            
            # Try to parse and format, but if it fails, use raw content
            try:
                policy = json.loads(file_content)
                # Format it nicely
                formatted_content = json.dumps(policy, indent=2)
            except json.JSONDecodeError:
                # If file itself has JSON errors, use raw content
                formatted_content = file_content
                st.warning("File contains JSON errors, but content has been reset from file")
            
            # Update session state - the text_area will use this value on rerun
            st.session_state.editor_json_content = formatted_content
            st.session_state.just_reset = True  # Flag to indicate we just reset
            
            st.success("Changes reset to original file")
            st.markdown(
                '<div style="background-color: #fff3cd; color: #856404; padding: 1rem; border-radius: 0.25rem; border: 1px solid #ffeaa7; margin-top: 1rem;">'
                '<strong>⚠️ Page refresh required:</strong> Please refresh the page for the changes to take effect in the editor.'
                '</div>',
                unsafe_allow_html=True
            )
            st.rerun()
        except FileNotFoundError:
            st.error(f"Policy file not found: {selected_policy}")
        except Exception as e:
            st.error(f"Failed to reload policy: {str(e)}")

# JSON Validation Status
st.markdown("---")
# Only validate if we haven't just reset (skip validation during reset to avoid showing file errors)
if not st.session_state.get("just_reset", False):
    # Validate the current editor content
    try:
        json.loads(json_content)
        st.success("✓ Valid JSON")
    except json.JSONDecodeError as e:
        st.error(f"✗ Invalid JSON: {str(e)}")
        st.caption("Please fix JSON syntax errors before saving.")
else:
    # Just reset - clear the flag and show highlighted refresh message
    st.session_state.just_reset = False
    st.markdown(
        '<div style="background-color: #fff3cd; color: #856404; padding: 1rem; border-radius: 0.25rem; border: 1px solid #ffeaa7; margin-top: 1rem;">'
        '<strong>⚠️ Page refresh required:</strong> Please refresh the page for the changes to take effect in the editor.'
        '</div>',
        unsafe_allow_html=True
    )

# Navigation
st.markdown("---")
if st.button("← Back to Main Dashboard"):
    st.switch_page("app.py")
