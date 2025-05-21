from datetime import datetime


def generate_report(findings=None):
    if findings is None:
        findings = []

    report = {
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }

    return report


