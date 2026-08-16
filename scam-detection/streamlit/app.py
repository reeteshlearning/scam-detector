import sys
from pathlib import Path

# Add the project root directory to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

import streamlit as st

# set_page_config must be called before any other Streamlit commands
# Some older/typed Streamlit versions may not expose this in stubs.
st.set_page_config(page_title="Scam Detection App", layout="wide")  # type: ignore[attr-defined]

# Older or typed Streamlit builds may not define `container` in the stubs.
# Use `getattr` so the app remains compatible.
_container_factory = getattr(st, "container", None)
if _container_factory is None:
    _container_factory = getattr(st, "empty", None)
if _container_factory is None:
    class _CompatContainer:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __getattr__(self, _name):
            return lambda *args, **kwargs: None

    _container_factory = lambda: _CompatContainer()


# The compatibility container is used as a fallback throughout the app. Ensure it
# is always callable even if older Streamlit builds expose a ``None`` value.
def _safe_container_factory():
    if _container_factory is not None:
        return _container_factory

    class _CompatContainer:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def __getattr__(self, _name):
            return lambda *args, **kwargs: None

    return lambda: _CompatContainer()

import pandas as pd
from pipeline.scam_detector.detector import ScamDetector

# Some type stubs do not expose certain Streamlit methods on the module.
markdown_fn = getattr(st, "markdown", None)
if markdown_fn is None:
    markdown_fn = getattr(st, "write", None)

error_fn = getattr(st, "error", None)
if error_fn is None:
    error_fn = getattr(st, "write", None)

success_fn = getattr(st, "success", None)
if success_fn is None:
    success_fn = getattr(st, "write", None)

warning_fn = getattr(st, "warning", None)
if warning_fn is None:
    warning_fn = getattr(st, "write", None)

subheader_fn = getattr(st, "subheader", None)
if subheader_fn is None:
    subheader_fn = getattr(st, "write", None)

write_fn = getattr(st, "write", None)
if write_fn is None:
    write_fn = lambda *args, **kwargs: None

if markdown_fn is not None:
    markdown_fn(
        """
        <h1 style='margin: 0; padding: 0;'>Scam Detection System</h1>
        """,
        unsafe_allow_html=True,
    )

# Some older or typed Streamlit versions do not expose `text_area` in the stubs.
# Use a compatibility wrapper so type-checkers and runtime stay happy.
def _text_area_compat(label, **kwargs):
    fn = getattr(st, "text_area", None)
    if fn is not None:
        return fn(label, **kwargs)

    fn = getattr(st, "textarea", None)
    if fn is not None:
        return fn(label, **kwargs)

    text_input_fn = getattr(st, "text_input", None)
    if text_input_fn is not None:
        return text_input_fn(label, **kwargs)

    return ""


def _columns_compat(n, **kwargs):
    fn = getattr(st, "columns", None)
    if fn is not None:
        return fn(n, **kwargs)

    return tuple(_container_factory() for _ in range(n))


# Initialize detector
detector = ScamDetector()

# Tab layout
# `st.tabs` is not available in some older Streamlit versions, and static type
# stubs may not expose it. Use getattr so the app remains compatible.
tabs_fn = getattr(st, "tabs", None)
columns_fn = getattr(st, "columns", None)

if tabs_fn is not None:
    try:
        tab1, tab2 = tabs_fn(["Single Message", "Dataset Evaluation"])
    except Exception:
        tab1 = _container_factory()
        tab2 = _container_factory()
else:
    warning_fn = getattr(st, "write", None)
    if warning_fn is not None:
        warning_fn("This Streamlit version does not support tabs; using a fallback layout.")

    if columns_fn is not None:
        left_col, right_col = columns_fn(2)
    else:
        container_fn = getattr(st, "container", None)
        if container_fn is None:
            container_fn = getattr(st, "empty", None)
        if container_fn is not None:
            left_col, right_col = container_fn(), container_fn()
        else:
            left_col = right_col = _container_factory()

    left_container_fn = getattr(left_col, "container", None)
    right_container_fn = getattr(right_col, "container", None)

    if left_container_fn is not None:
        tab1 = left_container_fn()
    else:
        tab1 = left_col if hasattr(left_col, "__enter__") else _container_factory()

    if right_container_fn is not None:
        tab2 = right_container_fn()
    else:
        tab2 = right_col if hasattr(right_col, "__enter__") else _container_factory()

# Guard against any non-context-manager object being returned by custom wrappers.
class _DefaultContainer:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def _ensure_context_manager(obj):
    if hasattr(obj, "__enter__") and hasattr(obj, "__exit__"):
        return obj
    return _DefaultContainer()


tab1 = _ensure_context_manager(tab1)
tab2 = _ensure_context_manager(tab2)

# ----------- Single Message Analysis ----------
with tab1:
    if markdown_fn is not None:
        markdown_fn("### Analyze a Single Message")
    user_input = _text_area_compat(
        "Enter the message to analyze:",
        height=150,
        placeholder="Example: Congratulations! You've won $1000. Click here to claim...",
    )

    button_fn = getattr(st, "button", None)
    spinner_fn = getattr(st, "spinner", None)
    
    if button_fn is not None and button_fn("Analyze Message", type="primary"):
        if user_input.strip():
            if spinner_fn is not None:
                with spinner_fn("Analyzing message..."):
                    try:
                        result = detector.detect(user_input)
                        
                        # Display results
                        col1, col2 = _columns_compat(2)
                        
                        with col1:
                            subheader_fn("Classification Result")
                            label = result.get("label", "Unknown")
                            
                            if label == "Scam":
                                error_fn(f"🚨 **{label}**")
                            elif label == "Not Scam":
                                success_fn(f"✅ **{label}**")
                            else:
                                warning_fn(f"⚠️ **{label}**")
                        
                        with col2:
                            subheader_fn("Intent")
                            write_fn(result.get("intent", "Could not determine"))
                        
                        subheader_fn("Reasoning")
                        write_fn(result.get("reasoning", "No reasoning provided"))
                        
                        subheader_fn("Risk Factors")
                        risk_factors = result.get("risk_factors", [])
                        if risk_factors:
                            for factor in risk_factors:
                                st.write(f"• {factor}")
                        else:
                            st.write("No specific risk factors identified.")
                            
                    except Exception as e:
                        st.error(f"Error during analysis: {str(e)}")
            else:
                try:
                try:
                    result = detector.detect(user_input)
                    
                    # Display results
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("Classification Result")
                        label = result.get("label", "Unknown")
                        
                        if label == "Scam":
                            st.error(f"🚨 **{label}**")
                        elif label == "Not Scam":
                            st.success(f"✅ **{label}**")
                        else:
                            st.warning(f"⚠️ **{label}**")
                    
                    with col2:
                        st.subheader("Intent")
                        st.write(result.get("intent", "Could not determine"))
                    
                    st.subheader("Reasoning")
                    st.write(result.get("reasoning", "No reasoning provided"))
                    
                    st.subheader("Risk Factors")
                    risk_factors = result.get("risk_factors", [])
                    if risk_factors:
                        for factor in risk_factors:
                            st.write(f"• {factor}")
                    else:
                        st.write("No specific risk factors identified.")
                        
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")
        else:
            st.warning("Please enter a message to analyze.")

# ----------- Dataset Evaluation ----------
with tab2:
    st.header("Dataset Evaluation")
    
    uploaded_file = st.file_uploader("Upload a CSV file for batch analysis", type="csv")
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.write(f"Loaded dataset with {len(df)} rows")
            st.write("Sample data:")
            st.dataframe(df.head())
            
            # Find text column
            text_columns = ["text", "message_text", "message"]
            text_col = None
            for col in text_columns:
                if col in df.columns:
                    text_col = col
                    break
            
            if text_col:
                st.write(f"Using '{text_col}' as text column")
                
                # Limit for demo purposes
                max_rows = min(len(df), 10)
                if st.button(f"Analyze First {max_rows} Messages"):
                    with st.spinner(f"Analyzing {max_rows} messages..."):
                        messages = df[text_col].head(max_rows).tolist()
                        results = detector.detect_batch(messages)
                        
                        # Create results dataframe
                        results_df = pd.DataFrame(results)
                        
                        st.subheader("Analysis Results")
                        st.dataframe(results_df)
                        
                        # Summary statistics
                        label_counts = results_df['label'].value_counts()
                        st.subheader("Summary")
                        st.bar_chart(label_counts)
                        
            else:
                st.error(f"Could not find text column. Expected one of: {text_columns}")
                
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")
