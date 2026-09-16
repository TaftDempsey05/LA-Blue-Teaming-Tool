import re
import sys
from collections import defaultdict
from datetime import datetime

# Tune these values for the organization being analyzed.
KNOWN_USERS = {"admin", "alice", "bob"}  # TODO: replace with expected users
SUSPICIOUS_START = 22                    # 10 PM
SUSPICIOUS_END = 6                       # 6 AM
SSH_FAIL_THRESHOLD = 3
SQL_PATTERNS = [
    r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table",
    r"--", r"xp_cmdshell", r"sleep\s*\("
]

def parse_log_line(line):
    """Convert one raw log line into a dictionary."""
    t = re.search(r"\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]?", line)
    u = re.search(r"User:\s*([^|]+)", line, re.I)
    ip = re.search(r"IP:\s*([^|]+)", line, re.I)
    status = re.search(r"Status:\s*([^|]+)", line, re.I)
    action = re.search(r"Action:\s*([^|]*)", line, re.I)
    if not (t and u):
        return None
    return {
        "timestamp": datetime.strptime(t.group(1), "%Y-%m-%d %H:%M:%S"),
        "username": u.group(1).strip(),
        "ip": ip.group(1).strip() if ip else "UNKNOWN",
        "status": status.group(1).strip().upper() if status else "UNKNOWN",
        "action": action.group(1).strip() if action else "",
        "raw": line.strip()
    }

def read_log(filename):
    records, skipped = [], 0
    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            record = parse_log_line(line)
            if record:
                records.append(record)
            else:
                skipped += 1
    return records, skipped

def count_login_attempts(records):
    counts = defaultdict(lambda: {"success": 0, "failed": 0})
    for r in records:
        if "login" in r["action"].lower() or "login" in r["raw"].lower():
            if r["status"] in {"SUCCESS", "SUCCESSFUL"}:
                counts[r["username"]]["success"] += 1
            elif r["status"] in {"FAIL", "FAILED", "FAILURE"}:
                counts[r["username"]]["failed"] += 1
    return counts

def validate_time(records):
    alerts = []
    for r in records:
        is_login = "login" in r["action"].lower() or "login" in r["raw"].lower()
        hour = r["timestamp"].hour
        if is_login and (hour >= SUSPICIOUS_START or hour < SUSPICIOUS_END):
            alerts.append(f'{r["username"]}: unusual login at {r["timestamp"]}')
    return alerts

def ssh_check(records):
    failed = defaultdict(int)
    alerts = []
    for r in records:
        if "ssh" not in r["raw"].lower():
            continue
        if r["status"] in {"FAIL", "FAILED", "FAILURE"}:
            failed[(r["username"], r["ip"])] += 1
        if r["timestamp"].hour >= SUSPICIOUS_START or r["timestamp"].hour < SUSPICIOUS_END:
            alerts.append(f'{r["username"]}: SSH at unusual time from {r["ip"]}')
    for (user, ip), total in failed.items():
        if total >= SSH_FAIL_THRESHOLD:
            alerts.append(f"{user}: {total} failed SSH attempts from {ip}")
    return alerts

def sql_check(records):
    alerts = []
    for r in records:
        if any(re.search(p, r["raw"], re.I) for p in SQL_PATTERNS):
            alerts.append(f'{r["username"]}: possible SQL injection -> {r["raw"]}')
    return alerts

def build_report(records, skipped):
    counts = count_login_attempts(records)
    users = defaultdict(list)
    for r in records:
        users[r["username"]].append(r)
    lines = ["=== AUTOMATED LOG ANALYSIS REPORT ===",
             f"Parsed: {len(records)} | Skipped: {skipped}", ""]
    for user, activity in sorted(users.items()):
        ips = sorted({r["ip"] for r in activity})
        actions = sorted({r["action"] or "(blank)" for r in activity})
        lines += [
            f"USER: {user}",
            f"  IP(s): {', '.join(ips)}",
            f"  Successful logins: {counts[user]['success']}",
            f"  Failed logins: {counts[user]['failed']}",
            f"  Actions: {', '.join(actions)}"
        ]
        if user not in KNOWN_USERS:
            lines.append("  ALERT: unknown user")
        lines.append("")
    alerts = validate_time(records) + ssh_check(records) + sql_check(records)
    lines.append("=== SUSPICIOUS ACTIVITY ===")
    lines += [f"- {a}" for a in alerts] if alerts else ["No rules were triggered."]
    return "\n".join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py Log_File.txt")
        return
    records, skipped = read_log(sys.argv[1])
    report = build_report(records, skipped)
    print(report)
    with open("analysis_report.txt", "w", encoding="utf-8") as file:
        file.write(report)
    print("\nSaved report to analysis_report.txt")

if __name__ == "__main__":
    main()

# ----- OPTIONAL ADVANCED DEEP-LEARNING EXTENSION -----
# Commented out so the starter code runs without TensorFlow.
# Autoencoder: learn common event patterns; high reconstruction error = anomaly.
# import numpy as np
# from tensorflow.keras import Sequential
# from tensorflow.keras.layers import Dense
#
# def deep_learning_anomalies(records):
#     X = np.array([
#         [r["timestamp"].hour / 23, r["timestamp"].weekday() / 6,
#          1 if r["status"] in {"FAIL", "FAILED", "FAILURE"} else 0,
#          1 if "ssh" in r["raw"].lower() else 0,
#          1 if any(re.search(p, r["raw"], re.I) for p in SQL_PATTERNS) else 0]
#         for r in records
#     ], dtype=float)
#     model = Sequential([Dense(3, activation="relu", input_shape=(5,)),
#                         Dense(2, activation="relu"), Dense(3, activation="relu"),
#                         Dense(5, activation="sigmoid")])
#     model.compile(optimizer="adam", loss="mse")
#     model.fit(X, X, epochs=30, batch_size=16, verbose=0)
#     rebuilt = model.predict(X, verbose=0)
#     scores = np.mean((X - rebuilt) ** 2, axis=1)
#     cutoff = np.percentile(scores, 95)
#     return [(records[i], scores[i]) for i in range(len(records))
#             if scores[i] >= cutoff]