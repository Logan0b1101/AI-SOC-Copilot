def convert_wazuh_alert(wazuh_alert):
    """
    Convert a Wazuh alert into the format
    used by AI SOC Copilot.
    """

    rule = wazuh_alert.get("rule", {})
    agent = wazuh_alert.get("agent", {})
    data = wazuh_alert.get("data", {})

    alert = {
        "alert_id": str(
            wazuh_alert.get(
                "id",
                "UNKNOWN"
            )
        ),

        "timestamp": wazuh_alert.get(
            "timestamp",
            "Unknown"
        ),

        "source": "Wazuh",

        "event_type": rule.get(
            "description",
            "Unknown"
        ),

        "severity": get_severity(
            rule.get("level", 0)
        ),

        "user": data.get(
            "srcuser",
            data.get(
                "dstuser",
                "Unknown"
            )
        ),

        "host": agent.get(
            "name",
            "Unknown"
        ),

        "description": rule.get(
            "description",
            "Unknown"
        )
    }

    return alert


def get_severity(level):
    """
    Convert Wazuh rule levels into
    simple severity categories.
    """

    try:
        level = int(level)
    except (ValueError, TypeError):
        return "unknown"

    if level >= 12:
        return "critical"

    elif level >= 8:
        return "high"

    elif level >= 5:
        return "medium"

    else:
        return "low"