events = [
    {
        "username": "admin",
        "ip": "10.10.10.1",
        "failed_attempts": 7,
        "severity": "HIGH",
        "locked": False
    },
    {
        "username": "guest",
        "ip": "192.168.1.19",
        "failed_attempts": 1,
        "severity": "LOW",
        "locked": False
    },
    {
        "username": "root",
        "ip": "185.220.101.4",
        "failed_attempts": 5,
        "severity": "HIGH",
        "locked": True
    }
]


def calculate_severity(event):
    if event["failed_attempts"] <= 2:
        return "LOW"
    elif event["failed_attempts"] <= 5:
        return "MEDIUM"
    else:
        return "HIGH"


def check_account_status(event):
    if event["locked"] == True:
        return "LOCKED"
    else:
        return "ACTIVE"


def analyze_event(event):
    severity = calculate_severity(event)
    account_status = check_account_status(event)
    return severity, account_status


def ip_reputation(ip):
    if ip == "185.220.101.4":
        return "SUSPICIOUS"
    elif ip == "10.10.10.1":
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def generate_alert(severity, account_status, ip_reputation):
    if severity == "HIGH" and account_status == "LOCKED":
        return "CRITICAL"
    elif severity == "HIGH" and ip_reputation == "SUSPICIOUS":
        return "CRITICAL"
    elif severity == "HIGH" and account_status == "ACTIVE" and ip_reputation == "CLEAN":
        return "URGENT"
    elif severity == "MEDIUM" and ip_reputation == "SUSPICIOUS":
        return "WARNING"
    else:
        return "INFO"


def report_summary(event):
    severity, account_status = analyze_event(event)

    ip_reputation_status = ip_reputation(event["ip"])

    alert_level = generate_alert(
        severity,
        account_status,
        ip_reputation_status
    )

    return severity, account_status, ip_reputation_status, alert_level


def main():

    low_counter = 0
    medium_counter = 0
    high_counter = 0

    for each_event in events:

        severity, account_status, ip_reputation_status, alert_level = report_summary(each_event)

        if severity == "LOW":
            low_counter += 1
        elif severity == "MEDIUM":
            medium_counter += 1
        elif severity == "HIGH":
            high_counter += 1

        print(
            "Username:", each_event["username"],
            "IP:", each_event["ip"],
            "Severity:", severity,
            "Account status:", account_status,
            "Alert Level:", alert_level,
            "Suspicious IP Status:", ip_reputation_status
        )

    print("Low:", low_counter)
    print("Medium:", medium_counter)
    print("High:", high_counter)


main()
