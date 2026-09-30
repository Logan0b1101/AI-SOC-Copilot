import json
from pathlib import Path

import ollama
import streamlit as st

from risk_engine import calculate_risk
from mitre_rules import validate_alert
from audit_logger import save_audit_log

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# FIND ALERT FILES
# ============================================================

alert_folder = Path("alerts")
alert_files = sorted(alert_folder.glob("*.json"))


# ============================================================
# DASHBOARD HEADER
# ============================================================

st.title("🛡️ AI SOC Copilot")

st.caption(
    "AI-assisted security alert triage with deterministic "
    "risk scoring and MITRE ATT&CK validation"
)


# ============================================================
# CHECK FOR ALERTS
# ============================================================

if not alert_files:

    st.error("No alert files were found in the alerts folder.")
    st.stop()


# ============================================================
# ALERT SELECTOR
# ============================================================

selected_file = st.selectbox(
    "Select a security alert",
    alert_files,
    format_func=lambda file: file.stem
)


# ============================================================
# LOAD ALERT
# ============================================================

with open(selected_file, "r") as file:
    alert = json.load(file)


# ============================================================
# DETERMINISTIC ANALYSIS
# ============================================================

risk = calculate_risk(alert)

mitre = validate_alert(alert)


# ============================================================
# SECURITY ALERT SUMMARY
# ============================================================

st.header("Security Alert")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Alert ID",
        alert.get("alert_id", "Unknown")
    )

with col2:
    st.metric(
        "Severity",
        alert.get("severity", "Unknown").upper()
    )

with col3:
    st.metric(
        "Risk Score",
        risk["score"]
    )

with col4:
    st.metric(
        "Source",
        alert.get("source", "Unknown")
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.header("Risk Assessment")

risk_level = risk["risk_level"]

if risk_level == "CRITICAL":

    st.error(
        f"Risk Level: {risk_level}"
    )

elif risk_level == "HIGH":

    st.warning(
        f"Risk Level: {risk_level}"
    )

elif risk_level == "MEDIUM":

    st.info(
        f"Risk Level: {risk_level}"
    )

else:

    st.success(
        f"Risk Level: {risk_level}"
    )


# ============================================================
# RISK FACTORS
# ============================================================

st.subheader("Risk Factors")

for reason in risk["reasons"]:

    st.write(
        "•",
        reason
    )


# ============================================================
# MITRE ATT&CK VALIDATION
# ============================================================

st.header("MITRE ATT&CK Validation")

if mitre:

    st.success(
        f"{mitre['technique']} — {mitre['name']}"
    )

else:

    st.info(
        "No deterministic MITRE mapping found for this alert."
    )


# ============================================================
# ALERT DETAILS
# ============================================================

st.header("Alert Details")

st.write(
    "**Event:**",
    alert.get("event_type", "Unknown")
)

st.write(
    "**User:**",
    alert.get("user", "Unknown")
)

st.write(
    "**Host:**",
    alert.get("host", "Unknown")
)

st.write(
    "**Timestamp:**",
    alert.get("timestamp", "Unknown")
)

st.write("**Description:**")

st.write(
    alert.get("description", "Unknown")
)


# ============================================================
# AI SECURITY ANALYSIS
# ============================================================

st.header("AI Security Analysis")


if st.button(
    "🔍 Analyze with Local AI",
    type="primary"
):

    with st.spinner(
        "Local AI is analyzing the security alert..."
    ):

        # ----------------------------------------------------
        # AI PROMPT
        # ----------------------------------------------------

        prompt = f"""
You are a cybersecurity SOC analyst assistant.

Analyze the following security alert.

SECURITY ALERT:

{json.dumps(alert, indent=2)}

Return ONLY valid JSON.

Use exactly this structure:

{{
    "threat_category": "",
    "mitre_attack": "",
    "explanation": "",
    "indicators": [],
    "investigation_steps": [],
    "recommended_response": "",
    "confidence": "Low | Medium | High"
}}

IMPORTANT RULES:

1. Use ONLY evidence present in the alert.

2. Do NOT invent evidence.

3. Do NOT assume an attack occurred if the evidence does not prove it.

4. If there is not enough evidence, use "Unknown".

5. Do NOT guess MITRE ATT&CK technique IDs.

6. Only provide a MITRE ATT&CK technique when the alert clearly supports it.

7. If the MITRE technique is uncertain, return:
"Unknown"

8. Do not execute commands.

9. Do not recommend destructive actions without human approval.

10. Keep the explanation concise and suitable for a SOC analyst.

11. The response MUST be valid JSON.

12. Do not use Markdown code fences.

13. Do not add any text before or after the JSON.
"""


        # ----------------------------------------------------
        # CALL LOCAL OLLAMA MODEL
        # ----------------------------------------------------

        response = ollama.chat(
            model="llama3.2:3b",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )


        ai_text = response["message"]["content"]


    # ========================================================
    # CLEAN AI RESPONSE
    # ========================================================

    cleaned = ai_text.strip()


    # Remove Markdown code fences if the model adds them

    if cleaned.startswith("```"):

        lines = cleaned.splitlines()

        if len(lines) >= 2:

            lines = lines[1:]

        if lines and lines[-1].strip() == "```":

            lines = lines[:-1]

        cleaned = "\n".join(lines).strip()


    # ========================================================
    # PARSE AI JSON
    # ========================================================

    ai = None

    try:

        ai = json.loads(cleaned)

    except json.JSONDecodeError:

        # Try a simple repair if the model forgot
        # the final closing brace.

        if (
            cleaned.startswith("{")
            and not cleaned.endswith("}")
        ):

            try:

                ai = json.loads(
                    cleaned + "}"
                )

            except json.JSONDecodeError:

                ai = None


    # ========================================================
    # DISPLAY AI RESULT
    # ========================================================

    if ai is None:

        st.warning(
            "The AI returned malformed JSON. "
            "The raw output is shown below."
        )

        st.code(
            ai_text,
            language="text"
        )


    else:

        # ----------------------------------------------------
        # THREAT CATEGORY
        # ----------------------------------------------------

        st.subheader("Threat Category")

        st.info(
            ai.get(
                "threat_category",
                "Unknown"
            )
        )


        # ----------------------------------------------------
        # AI MITRE RESULT
        # ----------------------------------------------------

        st.subheader("AI MITRE ATT&CK Assessment")

        ai_mitre = ai.get(
            "mitre_attack",
            "Unknown"
        )

        st.write(
            ai_mitre
        )


        # ----------------------------------------------------
        # EXPLANATION
        # ----------------------------------------------------

        st.subheader("Explanation")

        st.write(
            ai.get(
                "explanation",
                "Unknown"
            )
        )


        # ----------------------------------------------------
        # INDICATORS
        # ----------------------------------------------------

        st.subheader("Indicators")

        indicators = ai.get(
            "indicators",
            []
        )

        if indicators:

            for indicator in indicators:

                st.write(
                    "•",
                    indicator
                )

        else:

            st.write(
                "No indicators identified."
            )


        # ----------------------------------------------------
        # INVESTIGATION STEPS
        # ----------------------------------------------------

        st.subheader(
            "Investigation Steps"
        )

        investigation_steps = ai.get(
            "investigation_steps",
            []
        )

        if investigation_steps:

            for step in investigation_steps:

                st.write(
                    "•",
                    step
                )

        else:

            st.write(
                "No investigation steps provided."
            )


        # ----------------------------------------------------
        # RECOMMENDED RESPONSE
        # ----------------------------------------------------

        st.subheader(
            "Recommended Response"
        )

        st.write(
            ai.get(
                "recommended_response",
                "Unknown"
            )
        )


        # ----------------------------------------------------
        # AI CONFIDENCE
        # ----------------------------------------------------

        st.subheader(
            "AI Confidence"
        )

        confidence = ai.get(
            "confidence",
            "Unknown"
        )

        st.write(
            confidence
        )


        # ====================================================
        # AI VS DETERMINISTIC MITRE VALIDATION
        # ====================================================

        st.subheader(
            "Validation Status"
        )


        if mitre:

            expected_technique = mitre[
                "technique"
            ]

            # Convert AI response to lowercase
            # for easier comparison.

            ai_mitre_lower = str(
                ai_mitre
            ).lower()

            expected_lower = (
                expected_technique.lower()
            )


            if expected_lower in ai_mitre_lower:

                st.success(
                    "✅ AI MITRE mapping agrees "
                    "with the deterministic rule."
                )

                st.write(
                    f"Validated technique: "
                    f"{mitre['technique']} — "
                    f"{mitre['name']}"
                )


            else:

                st.warning(
                    "⚠️ AI MITRE mapping differs "
                    "from the deterministic rule."
                )

                st.write(
                    f"Expected deterministic mapping: "
                    f"{mitre['technique']} — "
                    f"{mitre['name']}"
                )

                st.write(
                    f"AI result: {ai_mitre}"
                )

                st.write(
                    "Analyst review is required."
                )


        else:

            st.info(
                "No deterministic MITRE rule exists "
                "for this alert. AI MITRE output should "
                "be treated as unverified."
            )


# ============================================================
# ANALYST DECISION
# ============================================================

st.header("Analyst Decision")

st.warning(
    "⚠️ AI recommendations are advisory. "
    "A human analyst must validate the findings "
    "before taking response actions."
)


# Create a unique session key for each alert
status_key = f"status_{alert['alert_id']}"


# Set initial status
if status_key not in st.session_state:

    st.session_state[status_key] = "New"


# Status selector
status = st.selectbox(
    "Investigation Status",
    [
        "New",
        "Investigating",
        "Closed"
    ],
    index=[
        "New",
        "Investigating",
        "Closed"
    ].index(st.session_state[status_key])
)


# Update status
st.session_state[status_key] = status


# Display current status
if status == "New":

    st.info("🔵 Alert is new and has not been investigated yet.")

elif status == "Investigating":

    st.warning("🟠 Alert is currently under investigation.")

elif status == "Closed":

    st.success("🟢 Alert investigation is closed.")


# Analyst notes
st.subheader("Analyst Notes")

notes = st.text_area(
    "Add investigation notes",
    placeholder=(
        "Example: Reviewed endpoint logs and "
        "confirmed suspicious PowerShell activity."
    )
)


# Save investigation decision
if st.button("Save Investigation"):

    save_audit_log(alert, risk, mitre, status, notes)

    st.success(
        f"{alert['alert_id']} investigation saved."
    )

    st.write("Status:", status)

    if notes.strip():

        st.write("Notes:", notes)

    else:

        st.write("Notes: No notes added.")