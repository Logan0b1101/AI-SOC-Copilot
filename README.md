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

```text
                  Security Alert
                        │
                        ▼
              ┌──────────────────┐
              │ Alert Input      │
              │ JSON / Wazuh     │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Wazuh Adapter   │
              │ Normalization    │
              └────────┬─────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │      Security Analysis       │
        │                              │
        │  Risk Engine                 │
        │  MITRE Validation            │
        └──────────────┬───────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Local AI         │
              │ Ollama           │
              │ Llama 3.2 3B     │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Analyst Review   │
              │ Status + Notes   │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Audit Logging    │
              └──────────────────┘