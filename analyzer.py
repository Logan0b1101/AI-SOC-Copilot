import json
import ollama

from mitre_rules import validate_alert


# Read the security alert
with open("alerts/sample_alert.json", "r") as file:
    alert = json.load(file)


# Validate MITRE ATT&CK mapping using deterministic rules
validated_mitre = validate_alert(alert)

if validated_mitre:
    print("\n===== DETERMINISTIC MITRE VALIDATION =====")
    print("Technique:", validated_mitre["technique"])
    print("Name:", validated_mitre["name"])


# Ask the AI for a structured security assessment
prompt = f"""
You are a SOC analyst assistant.

Analyze the following security alert:

{json.dumps(alert, indent=2)}

Return ONLY valid JSON using exactly this structure:

{{
    "severity": "Low | Medium | High | Critical",
    "threat_category": "",
    "mitre_attack": "",
    "explanation": "",
    "indicators": [],
    "investigation_steps": [],
    "recommended_response": "",
    "confidence": "Low | Medium | High"
}}

Do not execute commands.
Do not invent evidence that is not present in the alert.
If there is insufficient information for a field, say "Unknown".
"""


# Send the alert to the local AI
response = ollama.chat(
    model="llama3.2:3b",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ]
)


# Get the AI response
ai_result = response["message"]["content"]
# Compare AI MITRE mapping with deterministic validation
if validated_mitre:
    expected_technique = validated_mitre["technique"]

    if expected_technique not in ai_result:
        print("\n===== VALIDATION WARNING =====")
        print("⚠️ AI MITRE mapping may be incorrect.")
        print("Expected:", expected_technique)
        print("AI result requires analyst review.")
    else:
        print("\n===== VALIDATION PASSED =====")
        print("AI MITRE mapping matches the deterministic rule.")

# Display the result
print("\n===== STRUCTURED SOC ANALYSIS =====\n")
print(ai_result)

from risk_engine import calculate_risk

risk = calculate_risk(alert)

print("\n===== DETERMINISTIC RISK ASSESSMENT =====")
print("Risk Score:", risk["score"])
print("Risk Level:", risk["risk_level"])

print("\nReasons:")
for reason in risk["reasons"]:
    print("-", reason)