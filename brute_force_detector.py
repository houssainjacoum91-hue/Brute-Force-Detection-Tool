import re
import json
from collections import defaultdict

THRESHOLD = 5

def analyze_logs(file_path):
    ip_attempts = defaultdict(int)

    with open(file_path, "r") as file:
        for line in file:
            if "Failed login" in line:
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    ip = ip_match.group()
                    ip_attempts[ip] += 1

    report = {}

    for ip, count in ip_attempts.items():
        if count >= THRESHOLD:
            severity = "Medium"
            if count >= 10:
                severity = "High"

            report[ip] = {
                "failed_attempts": count,
                "severity": severity
            }

    with open("report.json", "w") as outfile:
        json.dump(report, outfile, indent=4)

    print("Report generated: report.json")

if __name__ == "__main__":
    analyze_logs("sample_logs.txt")
