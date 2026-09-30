import json
from datetime import datetime


LOG_FILE = "logs/audit_log.json"


def save_audit_log(alert, risk, mitre, status, notes):

    try:
        with open(LOG_FILE, "r") as file:
            logs = json.load(file)

    except FileNotFoundError:
        logs = []

    entry = {
        "timestamp": datetime.now().isoformat(),

        "alert_id": alert.get(
            "alert_id",
            "Unknown"
        ),

        "event_type": alert.get(
            "event_type",
            "Unknown"
        ),

        "risk_score": risk.get(
            "score",
            0
        ),

        "risk_level": risk.get(
            "risk_level",
            "Unknown"
        ),

        "mitre": mitre if mitre else "Unknown",

        "status": status,

        "analyst_notes": notes
    }

    logs.append(entry)

    with open(LOG_FILE, "w") as file:
        json.dump(
            logs,
            file,
            indent=4
        )