#Got inspired seeing all the filepath manipulation options when viewing pythong libraries during class on 10/6/2026, 
# and decided to use OS to make sure the output files are always in the same DIR as the script, 
# also using OS to default to log_data.txt in the same DIR as the script if no input file is given.
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
import numpy as np
#from tensorflow.keras import Sequential
#from tensorflow.keras.layers import Dense
from keras.models import Sequential
from keras.layers import Dense

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

#Graph imports
import matplotlib
#use Agg so charts are saved to the PDF instead of opening interactive windows"
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
#needed so the text doesn't get cut off in the pdf
import textwrap

# Settings to tune per organization:
# KNOWN_USERS = valid usernames (anyone else is flagged)
# SUSPICIOUS_START/END = Ex.logins between 10 PM and 6 AM are unusual
# SSH_FAIL_THRESHOLD = # of failed SSH attempts per user/IP before alerting
# SQL_PATTERNS = regex patterns for common SQL injection tricks
KNOWN_USERS = {"admin", "tdempsey", "rflorian", "jsmith", "nhughes", "bwells"}  #Our organization's users.
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
    u = re.search(r"User=(\S+)", line, re.I)
    ip = re.search(r"src_ip=(\S+)", line, re.I)
    status = re.search(r"Status=(\S+)", line, re.I)
    action = re.search(r"action=(.*?)\s+status=", line, re.I)
   
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

def deep_learning_anomalies(records):
    X = np.array([
       [r["timestamp"].hour / 23, r["timestamp"].weekday() / 6,
        1 if r["status"] in {"FAIL", "FAILED", "FAILURE"} else 0,
        1 if "ssh" in r["raw"].lower() else 0,
        1 if any(re.search(p, r["raw"], re.I) for p in SQL_PATTERNS) else 0]
        for r in records
    ], dtype=float)
    model = Sequential([Dense(3, activation="relu", input_shape=(5,)),
                         Dense(2, activation="relu"), Dense(3, activation="relu"),
                         Dense(5, activation="sigmoid")])
    model.compile(optimizer="adam", loss="mse")
    model.fit(X, X, epochs=30, batch_size=16, verbose=0)
    rebuilt = model.predict(X, verbose=0)
    scores = np.mean((X - rebuilt) ** 2, axis=1)
    cutoff = np.percentile(scores, 95)
    return [(records[i], scores[i]) for i in range(len(records))
            if scores[i] >= cutoff]

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

    #Deep Learning Module
    anomalies = deep_learning_anomalies(records)
    lines.append("")
    lines.append("======Deep Learning Anomalies====")

    if anomalies:
        for record, score in anomalies:
            lines.append(
                f'-Anomaly Score: {score:.4f} -> {record["raw"]}'
            )
    else:
        lines.append("No Anomalies")
            
    return "\n".join(lines)

#Roberts matplotlib meltdown... Gotta change the analysis report to a pdf to hold the graphs.
#AI disclosure, VScode has an ai autocomplete function that writes a lot of the code for me, I just have to edit it to make it work. Not sure if this is allowed.
#Also online resources suggested textwrap for the text pages.
def graph_logins(records):
    counts = count_login_attempts(records)
    users = sorted(counts.keys())
    successes = [counts[u]["success"] for u in users]
    failures = [counts[u]["failed"] for u in users]

    x = np.arange(len(users))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.bar(x - width/2, successes, width, label='Successful Logins', color='green')
    ax.bar(x + width/2, failures, width, label='Failed Logins', color='red')

    ax.set_xlabel('Users')
    ax.set_ylabel('Number of Logins')
    ax.set_title('Login Attempts by Users')
    ax.set_xticks(x)
    ax.set_xticklabels(users, rotation=45)
    ax.legend()
    fig.tight_layout()
    return fig

def graph_events_per_ip(records):
    counts = defaultdict(int)
    for r in records:
        counts[r["ip"]] += 1
    ips = sorted(counts, key=counts.get)
    colors = ['steelblue' if ip.startswith("10.") else 'red' for ip in ips]
 
    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.barh(ips, [counts[ip] for ip in ips], color=colors)
    ax.set_xlabel('Number of Log Entries')
    ax.set_ylabel('Source IP')
    ax.set_title('Activity by Source IP (red = outside 10.x.x.x network)')
    fig.tight_layout()
    return fig

#hours outside the normal workday are highlighted in red, and the rest are blue.
def graph_hours(records):
    hours = [r["timestamp"].hour for r in records]
    counts = [hours.count(h) for h in range(24)]
    suspicious = [h for h in range(24) if h >= SUSPICIOUS_START or h < SUSPICIOUS_END]
    normal = [h for h in range(24) if h not in suspicious]

    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.bar(normal, [counts[h] for h in normal], color='blue', edgecolor='black', label='Normal Hours')
    ax.bar(suspicious, [counts[h] for h in suspicious], color='red', edgecolor='black', label='Suspicious Hours')
    ax.set_xlabel('Hour of the Day')
    ax.set_ylabel('Number of Log Entries')
    ax.set_title('Log Entries by Hour of the Day')
    ax.set_xticks(range(24))
    ax.legend()
    fig.tight_layout()
    return fig

def graph_alerts_by_user(records):
    categories = {
        "Unusual-hour login": validate_time(records),
        "SSH alert": ssh_check(records),
        "SQL injection": sql_check(records),
    }
    users = sorted({r["username"] for r in records})
    colors = ['orange', 'purple', 'red']

    fig, ax = plt.subplots(figsize=(8.5, 5))
    bottoms = [0] * len(users)
    for (label, alerts), color in zip(categories.items(), colors):
        values = [sum(1 for a in alerts if a.split(":")[0] == u) for u in users]
        ax.bar(users, values, bottom=bottoms, label=label, color=color)
        bottoms = [b + v for b, v in zip(bottoms, values)]

    ax.set_yticks(range(0, max(bottoms) + 1))
    ax.set_xlabel('Users')
    ax.set_ylabel('Number of Alerts')
    ax.set_title('Alerts by User')
    ax.legend()
    fig.tight_layout()
    return fig

#Textwrap makes sure the text fits on the page, without it the long text lines run off the page, also had a problem with matplotlib picking up $ as a math.
def add_text_pages(pdf, text, width=100, lines_per_page=75):
    text = text.replace("$", r"\$")
    wrapped = []
    for line in text.split("\n"):
        wrapped += textwrap.wrap(line, width=width, subsequent_indent="    ") or [""]
    for i in range(0, len(wrapped), lines_per_page):
        fig = plt.figure(figsize=(8.5, 11))
        fig.text(0.06, 0.96, "\n".join(wrapped[i:i + lines_per_page]),
                 family="monospace", fontsize=7.5, va="top")
        pdf.savefig(fig)
        plt.close(fig)

def save_pdf_report(records, report_text, filename="analysis_report.pdf"):
    with PdfPages(filename) as pdf:

        #Add the login attempts graph
        fig_logins = graph_logins(records)
        pdf.savefig(fig_logins)
        plt.close(fig_logins)

        #Add the log entries per IP graph
        fig_ips = graph_events_per_ip(records)
        pdf.savefig(fig_ips)
        plt.close(fig_ips)

        #Add the log entries by hour graph
        fig_hours = graph_hours(records)
        pdf.savefig(fig_hours)
        plt.close(fig_hours)

        #Add the log entries per user graph
        fig_alerts = graph_alerts_by_user(records)
        pdf.savefig(fig_alerts)
        plt.close(fig_alerts)

        #Add the text report pages
        add_text_pages(pdf, report_text)

def main():
    #default to log_data.txt in the same DIR as the script if no input file is given
    if len(sys.argv) < 2:
        log_path = os.path.join(BASE_DIR, "log_data.txt")
    else:
        log_path = sys.argv[1]
        #if the typed path doesn't exist, look next to the script instead
        if not os.path.exists(log_path):
            log_path = os.path.join(BASE_DIR, sys.argv[1])
    
    records, skipped = read_log(log_path)

    #stop early if nothing in the file could be parsed, preventing crashes.
    if not records:
        print(f"No valid log entries found in {log_path} ({skipped} lines skipped).")
        return
    report = build_report(records, skipped)
    print(report)

    #making the output files always in the same DIR as the script.
    txt_output_path = os.path.join(BASE_DIR, "analysis_report.txt")
    pdf_output_path = os.path.join(BASE_DIR, "analysis_report.pdf")

    #Save the text report and the PDF report with graphs
    with open(txt_output_path, "w", encoding="utf-8") as file:
        file.write(report)
    save_pdf_report(records, report, pdf_output_path)
    print(f"\nSaved report to {txt_output_path}, and report with graphs to {pdf_output_path}")

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