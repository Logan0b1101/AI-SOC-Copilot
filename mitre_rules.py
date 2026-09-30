# Deterministic MITRE ATT&CK validation rules

MITRE_RULES = {

    "powershell": {
        "technique": "T1059.001",
        "name": "PowerShell"
    },

    "suspicious_login": {
        "technique": "T1078",
        "name": "Valid Accounts"
    },

    "malware_download": {
        "technique": "T1105",
        "name": "Ingress Tool Transfer"
    }
}


def validate_alert(alert):

    event_type = alert.get(
        "event_type",
        ""
    ).lower()

    description = alert.get(
        "description",
        ""
    ).lower()

    text = event_type + " " + description


    # PowerShell
    if "powershell" in text:

        return MITRE_RULES["powershell"]


    # Suspicious login
    if (
        "suspicious login" in event_type
        and "successful login" in description
    ):

        return MITRE_RULES["suspicious_login"]


    # Malware download
    if (
        "malware download" in event_type
        and "downloaded an executable" in description
    ):

        return MITRE_RULES["malware_download"]


    # No deterministic mapping
    return None