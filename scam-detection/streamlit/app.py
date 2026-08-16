import sys
from pathlib import Path

# Add scam-detection directory to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.scam_detector.detector import ScamDetector

import pandas as pd
import streamlit as st


# ============================================================
# Page Configuration
# ============================================================

st.set_page_config(
    page_title="Scam Detection System",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# Detector
# ============================================================

@st.cache_resource
def get_detector() -> ScamDetector:
    return ScamDetector()


detector = get_detector()


# ============================================================
# Helper Functions
# ============================================================

def display_classification(label: str) -> None:
    """Display classification using appropriate Streamlit status."""

    if label == "Scam":
        st.error(f"🚨 {label}")

    elif label == "Not Scam":
        st.success(f"✅ {label}")

    else:
        st.warning(f"⚠️ {label}")


def find_text_column(df: pd.DataFrame) -> str | None:
    """Find the first supported message/text column."""

    supported_columns = [
        "text",
        "message_text",
        "message",
    ]

    for column in supported_columns:
        if column in df.columns:
            return column

    return None


# ============================================================
# Header
# ============================================================

st.title("🛡️ Scam Detection System")

st.markdown(
    """
    Analyze messages for potentially scammy, manipulative,
    or deceptive intent using an AI-powered detection system.
    """
)


# ============================================================
# Tabs
# ============================================================

single_tab, dataset_tab = st.tabs(
    [
        "📩 Single Message",
        "📊 Dataset Evaluation",
    ]
)


# ============================================================
# Single Message Analysis
# ============================================================

with single_tab:

    st.subheader("Analyze a Single Message")

    user_input = st.text_area(
        "Enter the message to analyze:",
        height=150,
        placeholder=(
            "Example: Congratulations! "
            "You've won $1000. Click here to claim..."
        ),
    )

    if st.button(
        "Analyze Message",
        type="primary",
        use_container_width=True,
    ):

        if not user_input.strip():
            st.warning("Please enter a message to analyze.")

        else:

            with st.spinner("Analyzing message..."):

                try:
                    result = detector.detect(user_input)

                except Exception as exc:
                    st.error(
                        "Unable to analyze the message. "
                        "Please try again."
                    )

                    # Log actual error in production
                    st.exception(exc)

                else:

                    label = result.get(
                        "label",
                        "Uncertain",
                    )

                    intent = result.get(
                        "intent",
                        "Could not determine",
                    )

                    reasoning = result.get(
                        "reasoning",
                        "No reasoning provided",
                    )

                    risk_factors = result.get(
                        "risk_factors",
                        [],
                    )

                    # ----------------------------------------
                    # Classification
                    # ----------------------------------------

                    st.subheader("Classification Result")

                    display_classification(label)

                    # ----------------------------------------
                    # Intent
                    # ----------------------------------------

                    st.subheader("Intent")

                    st.write(intent)

                    # ----------------------------------------
                    # Reasoning
                    # ----------------------------------------

                    st.subheader("Reasoning")

                    st.write(reasoning)

                    # ----------------------------------------
                    # Risk Factors
                    # ----------------------------------------

                    st.subheader("Risk Factors")

                    if risk_factors:

                        for factor in risk_factors:
                            st.write(f"• {factor}")

                    else:
                        st.write(
                            "No specific risk factors identified."
                        )


# ============================================================
# Dataset Evaluation
# ============================================================

with dataset_tab:

    st.subheader("Dataset Evaluation")

    uploaded_file = st.file_uploader(
        "Upload a CSV file for batch analysis",
        type=["csv"],
    )

    if uploaded_file is not None:

        try:
            df = pd.read_csv(uploaded_file)

        except Exception as exc:
            st.error("Unable to read the uploaded CSV file.")
            st.exception(exc)

        else:

            st.success(
                f"Dataset loaded successfully: {len(df)} rows"
            )

            st.write("Sample data:")

            st.dataframe(
                df.head(),
                use_container_width=True,
            )

            # ----------------------------------------
            # Find text column
            # ----------------------------------------

            text_col = find_text_column(df)

            if text_col is None:

                st.error(
                    "Could not find a message column."
                )

                st.info(
                    "Expected one of: "
                    "`text`, `message_text`, `message`"
                )

            else:

                st.info(
                    f"Using `{text_col}` as the message column."
                )

                # ----------------------------------------
                # Number of rows
                # ----------------------------------------

                max_rows = min(len(df), 10)

                rows_to_analyze = st.number_input(
                    "Number of messages to analyze",
                    min_value=1,
                    max_value=max_rows,
                    value=max_rows,
                    step=1,
                )

                # ----------------------------------------
                # Batch Analysis
                # ----------------------------------------

                if st.button(
                    f"Analyze {rows_to_analyze} Messages",
                    type="primary",
                ):

                    messages = (
                        df[text_col]
                        .head(rows_to_analyze)
                        .fillna("")
                        .astype(str)
                        .tolist()
                    )

                    # Remove empty messages
                    messages = [
                        message.strip()
                        for message in messages
                        if message.strip()
                    ]

                    if not messages:

                        st.warning(
                            "No valid messages found."
                        )

                    else:

                        with st.spinner(
                            f"Analyzing {len(messages)} messages..."
                        ):

                            try:

                                results = detector.detect_batch(
                                    messages
                                )

                                results_df = pd.DataFrame(
                                    results
                                )

                            except Exception as exc:

                                st.error(
                                    "Batch analysis failed."
                                )

                                st.exception(exc)

                            else:

                                # ----------------------------
                                # Results
                                # ----------------------------

                                st.subheader(
                                    "Analysis Results"
                                )

                                st.dataframe(
                                    results_df,
                                    use_container_width=True,
                                )

                                # ----------------------------
                                # Summary
                                # ----------------------------

                                if (
                                    "label" in
                                    results_df.columns
                                ):

                                    st.subheader(
                                        "Classification Summary"
                                    )

                                    label_counts = (
                                        results_df["label"]
                                        .value_counts()
                                    )

                                    st.bar_chart(
                                        label_counts
                                    )

## (.venv) PS D:\RK_CodingNinja\CN_Code Assgnment\Session9 Spam Detector\scam-detector\scam-detection> python -m streamlit run streamlit/app.py

## python -m streamlit run streamlit/app.py