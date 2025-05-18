import subprocess
import re
from collections import Counter

FAILED_LOGIN_PATTERN = r"Failed password for(?: invalid user)? .* from ([\d\.]+|::1)"
THRESHOLD = 5

def read_logs_from_journal():
    """Read SSH logs using journalctl."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "--no-pager"],
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError:
        print("Error reading logs from journalctl.")
        return []

def extract_failed_ips(log_lines, pattern):
    ips = []
    for line in log_lines:
        match = re.search(pattern, line)
        if match:
            ips.append(match.group(1))
    return ips

def alert_suspicious_ips(ip_list, threshold):
    ip_counts = Counter(ip_list)
    for ip, count in ip_counts.items():
        if count >= threshold:
            print(f"[ALERT] Suspicious activity from {ip}: {count} failed login attempts.")

def main():
    print("=== Log Monitoring & Threat Detection (journalctl) ===")
    logs = read_logs_from_journal()
    failed_ips = extract_failed_ips(logs, FAILED_LOGIN_PATTERN)
    alert_suspicious_ips(failed_ips, THRESHOLD)

if __name__ == "__main__":
    main()
