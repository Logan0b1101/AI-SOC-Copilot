from wazuh_adapter import convert_wazuh_alert
from integrations.wazuh_adapter import convert_wazuh_alert


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


alert = convert_wazuh_alert(wazuh_alert)


print("Converted SOC Alert:")
print(alert)