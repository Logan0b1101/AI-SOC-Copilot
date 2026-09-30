import json
import ollama


# 1. Read the security alert
with open("alerts/sample_alert.json", "r") as file:
    alert = json.load(file)


# 2. Create an instruction for the AI
prompt = f"""
You are a SOC analyst assistant.

Analyze this security alert:

{json.dumps(alert, indent=2)}

Give me:

1. What happened?
2. Why could it be dangerous?
3. Risk level: Low, Medium, or High
4. What indicators should an analyst investigate?
5. What should the analyst do next?
6. Relevant MITRE ATT&CK technique, if applicable.

Do not execute any commands.
Only provide analysis and recommendations.
"""


# 3. Send the alert to our local AI
response = ollama.chat(
    model="llama3.2:3b",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ]
)


# 4. Display the AI analysis
print("\n===== AI SOC ANALYSIS =====\n")
print(response["message"]["content"])