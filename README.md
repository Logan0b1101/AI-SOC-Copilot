# 🛡️ AI SOC Copilot

## Local LLM-Assisted Security Alert Triage & Investigation

AI SOC Copilot is a cybersecurity prototype that assists SOC analysts with security alert triage, deterministic risk assessment, MITRE ATT&CK validation, AI-assisted investigation, and audit logging.

The project uses a local Large Language Model (LLM) through Ollama, so security alert data does not need to be sent to a cloud AI API.

---

## 🎯 Project Objective

Security Operations Centers can receive large numbers of alerts from endpoints, identity systems, and SIEM platforms.

AI SOC Copilot is designed to help an analyst:

- Understand security alerts faster
- Calculate an explainable risk score
- Validate MITRE ATT&CK mappings using deterministic rules
- Generate AI-assisted investigation steps
- Record analyst investigation decisions
- Maintain an audit trail
- Prepare alerts for integration with SIEM platforms such as Wazuh

The AI is used as an assistant and is not treated as the final authority.

---

# 🏗️ Architecture

<img width="1160" height="1356" alt="1" src="https://github.com/user-attachments/assets/83b4a109-8a4b-4ade-87a4-49f52b312621" />

1. Wazuh-Compatible Alert Ingestion

The project includes an adapter for converting Wazuh-style security alerts into the normalized format used by the SOC Copilot.

Example input:

{
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

The adapter converts this into:

{
    "alert_id": "1760012345.123456",
    "timestamp": "2026-09-30T23:30:00+0200",
    "source": "Wazuh",
    "event_type": "Suspicious PowerShell command detected",
    "severity": "critical",
    "user": "employee01",
    "host": "WIN-CLIENT-01",
    "description": "Suspicious PowerShell command detected"
}

This creates a normalized internal alert format that can be processed by the rest of the platform.

2. Explainable Risk Engine

The risk engine calculates a project-specific risk score using deterministic rules.

The current implementation considers factors such as:

Alert severity
PowerShell activity
File download activity
External IP communication

Example scoring logic:

Critical severity       +40
High severity           +30
Medium severity         +20
Low / unknown           +5

PowerShell activity     +25
File download           +20
External IP             +15

The resulting score is mapped to:

70+     → CRITICAL
50–69   → HIGH
30–49   → MEDIUM
<30     → LOW
Example

A critical PowerShell alert involving a file download from an external IP could receive:

40  Critical severity
25  PowerShell activity
20  File download
15  External IP
------------------
100 Risk Score

The scoring system is intentionally transparent so an analyst can understand why an alert received its risk classification.

Note: The scoring model is a project-specific heuristic and is not intended to represent an industry-standard risk score.

3. MITRE ATT&CK Validation

The project includes deterministic MITRE ATT&CK mappings for supported alert patterns.

Current examples include:

Alert Pattern	MITRE Technique	Technique Name
PowerShell activity	T1059.001	PowerShell
Suspicious login	T1078	Valid Accounts
Malware download	T1105	Ingress Tool Transfer

The important design principle is that the LLM is not trusted to invent MITRE ATT&CK technique IDs.

The platform performs deterministic validation and compares the AI-generated interpretation with the project's predefined mapping.

If there is a mismatch, the dashboard highlights the discrepancy for analyst review.

4. Local AI Analysis

The project uses a local LLM through Ollama.

Current model:

Llama 3.2 3B

The model is used to assist with:

Threat categorization
Alert explanation
Indicator identification
Investigation suggestions
Recommended response actions
Analyst-oriented summaries
Confidence estimation

Example AI output structure:

{
    "threat_category": "Credential Access",
    "mitre": "T1078",
    "explanation": "The alert indicates repeated authentication failures followed by a successful login from an unfamiliar location.",
    "indicators": [
        "Multiple failed login attempts",
        "Successful login",
        "Unfamiliar location"
    ],
    "investigation_steps": [
        "Review authentication logs",
        "Verify the user's recent login locations",
        "Check for additional suspicious activity"
    ],
    "recommended_response": [
        "Validate the login with the user",
        "Review the affected account",
        "Escalate if unauthorized activity is confirmed"
    ],
    "confidence": "medium"
}
5. Human-in-the-Loop Security

The system does not automatically execute destructive response actions.

Instead:

Alert
  ↓
Automated deterministic analysis
  ↓
AI-assisted investigation
  ↓
Human analyst review
  ↓
Analyst decision

The analyst can:

Review the alert
Review risk scoring
Review MITRE validation
Review AI analysis
Change investigation status
Add investigation notes
Save the investigation record

Available statuses:

New
Investigating
Closed

This approach reduces the risk of an LLM directly taking an incorrect containment or remediation action.

6. Audit Logging

Investigation actions are stored in:

logs/audit_log.json

The audit record contains information such as:

{
    "timestamp": "2026-09-30T23:45:00",
    "alert_id": "ALERT-001",
    "event_type": "Suspicious PowerShell",
    "risk_score": 90,
    "risk_level": "CRITICAL",
    "mitre": {
        "technique": "T1059.001",
        "name": "PowerShell"
    },
    "status": "Investigating",
    "analyst_notes": "Reviewed PowerShell activity and external connection."
}

This provides a basic investigation trail and makes analyst decisions traceable.

🖥️ Dashboard

The application is built using Streamlit.

The dashboard allows an analyst to:

Select a security alert
Review the raw alert information
View deterministic risk analysis
View MITRE ATT&CK validation
Run local AI analysis
Review AI-generated investigation guidance
Compare AI MITRE output with deterministic validation
Set investigation status
Add analyst notes
Save the investigation to the audit log
📂 Project Structure
AI-SOC-Copilot/
│
├── app.py
│
├── analyzer.py
├── analyzer_v1_working.py
├── risk_engine.py
├── mitre_rules.py
├── audit_logger.py
│
├── alerts/
│   ├── sample_alert.json
│   ├── suspicious_login.json
│   └── malware_download.json
│
├── integrations/
│   ├── __init__.py
│   ├── wazuh_adapter.py
│   ├── test_wazuh_adapter.py
│   └── test_wazuh_pipeline.py
│
├── logs/
│   └── audit_log.json
│
├── docs/
│   └── architecture.png
│
├── README.md
│
├── .gitignore
└── .env
Important

The following local files/directories are intentionally excluded from Git:

.venv/
.env
.vscode/
__pycache__/

The .env file should never contain credentials that are committed to the repository.

⚙️ Technology Stack
Component	Technology
Programming Language	Python 3.12
Dashboard	Streamlit
Local LLM Runtime	Ollama
AI Model	Llama 3.2 3B
Alert Integration	Wazuh-compatible adapter
Detection Logic	Python
Risk Engine	Custom deterministic rules
Threat Mapping	MITRE ATT&CK
Logging	JSON
Testing	Python
Version Control	Git / GitHub
🚀 Installation
Prerequisites

Install:

Python 3.12+
Git
Ollama

Verify Python:

python --version

Example:

Python 3.12.7

Verify Ollama:

ollama --version
🤖 Configure Ollama

Download the required local model:

ollama pull llama3.2:3b

Verify the model:

ollama list

You should see:

llama3.2:3b

You can also test the model directly:

ollama run llama3.2:3b
🐍 Create Python Virtual Environment

From the project directory:

python -m venv .venv

Activate it on Windows:

.venv\Scripts\activate.bat

You should see:

(.venv)

at the beginning of your terminal prompt.

📦 Install Dependencies

Install the required Python packages:

pip install streamlit ollama
▶️ Run the Application

From the project root:

streamlit run app.py

Streamlit will start the local dashboard.

Open the local address shown in the terminal.

🧪 Testing
Test Wazuh Adapter

From the project root:

python integrations/test_wazuh_adapter.py

Expected output:

Converted SOC Alert:
{
    ...
}
Test Wazuh Pipeline

Run:

python integrations/test_wazuh_pipeline.py

The pipeline tests the flow:

Wazuh Alert
     ↓
Wazuh Adapter
     ↓
Risk Engine
     ↓
MITRE Validation
     ↓
Local AI
🔎 Example Security Scenarios

The project contains sample alerts for different security situations.

Scenario 1 — Suspicious PowerShell
Event:
Suspicious PowerShell

Activity:
PowerShell attempted to download a file
from an external IP address.

The system can identify:

High/critical severity
PowerShell activity
File download
External IP communication
MITRE ATT&CK mapping
Investigation recommendations
Scenario 2 — Suspicious Login
Event:
Suspicious Login

Activity:
Multiple failed login attempts were followed
by a successful login from an unfamiliar location.

The system can assist the analyst with:

Authentication investigation
Account validation
Login history review
MITRE mapping
Recommended investigation steps
Scenario 3 — Malware Download
Event:
Malware Download

Activity:
A Windows endpoint downloaded an executable
from an external IP address.

The system can identify:

Critical severity
Download activity
External IP communication
MITRE ATT&CK mapping
Investigation guidance
🔐 Security Design

AI SOC Copilot follows several security-oriented design principles.

1. Local AI

The LLM runs locally using Ollama.

This avoids sending security alert data to a third-party cloud AI API during normal operation.

2. Deterministic Controls

Important security classifications such as risk scoring and supported MITRE mappings are handled by deterministic logic.

3. AI Validation

AI-generated MITRE information is compared against deterministic validation rules.

4. Human Approval

The AI does not directly execute containment or destructive remediation actions.

5. Explainability

The risk engine provides reasons for its score rather than producing an opaque classification.

6. Auditability

Analyst status and notes are recorded in an audit log.

7. Secret Protection

Local environment files such as:

.env

are excluded from Git.

🧠 Why Use a Local LLM?

Traditional AI integrations often require cloud API access and usage-based billing.

This project demonstrates that an AI-assisted SOC workflow can also be prototyped using a locally hosted model.

Advantages include:

No API usage fees
Local processing
Greater control over alert data
Offline-capable AI experimentation
Easy development and testing
Suitable for security research and prototypes

The local model is intentionally treated as an assistant, not an authoritative security decision-maker.

⚠️ Limitations

This project is a prototype and should not be considered a production SOC platform.

Current limitations include:
Wazuh integration is currently adapter-based rather than a live Wazuh deployment.
Risk scoring uses project-specific heuristics.
MITRE mappings cover selected sample alert patterns.
Local LLM output can contain incorrect or incomplete interpretations.
No automated endpoint isolation or remediation is implemented.
No production database is used.
Audit logs are stored as JSON.
No authentication or role-based access control is currently implemented.
The local Llama model has significantly fewer capabilities than larger enterprise models.
Detection coverage is limited to the implemented rules and sample scenarios.

Security analysts should validate AI-generated recommendations before taking response actions.


