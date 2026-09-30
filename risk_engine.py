def calculate_risk(alert):
    score = 0
    reasons = []

    severity = alert.get("severity", "").lower()
    event_type = alert.get("event_type", "").lower()
    description = alert.get("description", "").lower()

    # Base severity
    if severity == "critical":
        score += 40
        reasons.append("Alert severity is critical")

    elif severity == "high":
        score += 30
        reasons.append("Alert severity is high")

    elif severity == "medium":
        score += 20
        reasons.append("Alert severity is medium")

    else:
        score += 5
        reasons.append("Alert severity is low or unknown")

    # Suspicious PowerShell
    if "powershell" in event_type or "powershell" in description:
        score += 25
        reasons.append("Suspicious PowerShell activity detected")

    # External download
    if "download" in description:
        score += 20
        reasons.append("File download activity detected")

    # External IP
    if "external ip" in description:
        score += 15
        reasons.append("Connection to an external IP was observed")

    # Determine final risk
    if score >= 70:
        risk_level = "CRITICAL"

    elif score >= 50:
        risk_level = "HIGH"

    elif score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }