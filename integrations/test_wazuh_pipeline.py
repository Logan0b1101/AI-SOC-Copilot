import json
import ollama

from integrations.wazuh_adapter import convert_wazuh_alert
from risk_engine import calculate_risk
from mitre_rules import validate_alert


# ---------------------------------------------------------
# Simulated Wazuh alert
# ---------------------------------------------------------

wazuh_alert = {
    "id": "1760012345.123456",
    "timestamp": "2026-09-30T23:30:00+0200",

    "rule": {
        "level": 12,
        "description": "Suspicious PowerShell command detected"
    },

    "agent": {
        "name": "WIN-CLIENT-01"
    },

    "data": {
        "srcuser": "employee01"
    }
}


# ---------------------------------------------------------
# Convert Wazuh alert
# ---------------------------------------------------------

alert = convert_wazuh_alert(wazuh_alert)


print("\n===== WAZUH ALERT =====")
print(json.dumps(alert, indent=4))


# ---------------------------------------------------------
# Risk analysis
# ---------------------------------------------------------

risk = calculate_risk(alert)


print("\n===== RISK ASSESSMENT =====")
print("Risk Score:", risk["score"])
print("Risk Level:", risk["risk_level"])

print("\nReasons:")

for reason in risk["reasons"]:
    print("-", reason)


# ---------------------------------------------------------
# MITRE validation
# ---------------------------------------------------------

mitre = validate_alert(alert)


print("\n===== MITRE VALIDATION =====")

if mitre:

    print(
        "Technique:",
        mitre["technique"]
    )

    print(
        "Name:",
        mitre["name"]
    )

else:

    print(
        "No deterministic MITRE mapping found."
    )


# ---------------------------------------------------------
# Local AI analysis
# ---------------------------------------------------------

prompt = f"""
You are a cybersecurity SOC analyst assistant.

Analyze this Wazuh security alert:

{json.dumps(alert, indent=2)}

Return ONLY valid JSON:

{{
    "threat_category": "",
    "explanation": "",
    "indicators": [],
    "investigation_steps": [],
    "recommended_response": "",
    "confidence": "Low | Medium | High"
}}

Rules:

- Use only evidence present in the alert.
- Do not invent evidence.
- Do not guess MITRE ATT&CK techniques.
- If information is insufficient, use "Unknown".
- Do not execute commands.
- Do not recommend destructive actions without human approval.
"""


response = ollama.chat(
    model="llama3.2:3b",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ]
)


ai_result = response["message"]["content"]


print("\n===== LOCAL AI ANALYSIS =====")
print(ai_result)


print("\n===== PIPELINE COMPLETE =====")
print("Wazuh → Adapter → Risk Engine → MITRE → Local AI")