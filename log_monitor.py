import re
from collections import Counter

# Path to the Linux auth log file
LOG_FILE = "/var/log/auth.log"

# Pattern to detect failed SSH logins and extract IP
FAILED_LOGIN_PATTERN = r"Failed password for(?: invalid user)? .* from (\d+\.\d+\.\d+\.\d+)"

# Threshold for brute-force alert
THRESHOLD = 5

def read_logs(filepath):
    """Read log file and return lines."""
    try:
        with open(filepath, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Log file not found at: {filepath}")
        return []

def extract_failed_ips(log_lines, pattern):
    """Extract IPs from failed login attempts using regex."""
    ips = []
    for line in log_lines:
        match = re.search(pattern, line)
        if match:
            ips.append(match.group(1))
    return ips

def alert_suspicious_ips(ip_list, threshold):
    """Print alert if failed login attempts exceed threshold."""
    ip_counts = Counter(ip_list)
    for ip, count in ip_counts.items():
        if count >= threshold:
            print(f"[ALERT] Suspicious activity from {ip}: {count} failed login attempts.")

def main():
    print("=== Log Monitoring & Threat Detection ===")
    logs = read_logs(LOG_FILE)
    if not logs:
        return
    failed_ips = extract_failed_ips(logs, FAILED_LOGIN_PATTERN)
    alert_suspicious_ips(failed_ips, THRESHOLD)

if __name__ == "__main__":
    main()
