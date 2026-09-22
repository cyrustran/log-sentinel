#!/usr/bin/env python3
"""
Log Sentinel - an SSH authentication log analyzer.
Author: Phengtheu Tran

WHAT THIS TOOL DOES
-------------------
Linux records every login attempt, sudo command, and account change in an
authentication log (/var/log/auth.log on Ubuntu/Debian, /var/log/secure on
Red Hat/CentOS/Fedora). This tool reads that log and looks for patterns a
SOC (Security Operations Center) analyst would care about:

  1. Brute force        - one IP failing to log in many times, fast
  2. Possible compromise - an IP that failed many times and then SUCCEEDED
  3. Username enumeration - one IP trying lots of different usernames
  4. Post-login activity  - new accounts created and sudo (admin) commands

Each alert is tagged with a MITRE ATT&CK technique ID, the industry's shared
vocabulary for describing attacker behavior (https://attack.mitre.org).

HOW TO RUN IT
-------------
    python3 log_sentinel.py sample_auth.log
    python3 log_sentinel.py sample_auth.log --html report.html --json alerts.json
    python3 log_sentinel.py /var/log/auth.log --threshold 10 --window 120

Only uses Python's standard library, so there is nothing to install.
"""

# ---------------------------------------------------------------------------
# IMPORTS
# Every one of these ships with Python. Using only the standard library means
# anyone can run the tool without installing packages (and without having to
# trust third-party code, which matters in security).
# ---------------------------------------------------------------------------
import argparse                      # reads command-line flags like --threshold
import html                          # escapes text safely before putting it in HTML
import json                          # writes machine-readable output
import re                            # regular expressions: pattern matching on text
import sys                           # exit codes and checking if output is a terminal
from collections import defaultdict, deque   # handy data structures (explained below)
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# MITRE ATT&CK MAPPING
# A dictionary that maps our alert types to official technique IDs.
# Keeping this in one place means we only have to update it once.
# ---------------------------------------------------------------------------
ATTACK = {
    "brute_force": ("T1110", "Brute Force"),
    "compromise": ("T1078", "Valid Accounts"),
    "enumeration": ("T1110.003", "Brute Force: Password Spraying (many-username pattern)"),
    "new_account": ("T1136.001", "Create Account: Local Account"),
    "sudo": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo"),
}

# Severity levels, ordered so we can sort alerts from most to least serious.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ---------------------------------------------------------------------------
# REGULAR EXPRESSIONS (REGEX)
# A regex is a pattern that describes what text should look like. We use them
# to pull specific pieces (IP address, username, time) out of each log line.
#
# Quick regex cheat sheet for reading the patterns below:
#   \S+        one or more characters that are NOT whitespace (a "word")
#   \d{2}      exactly two digits
#   \s+        one or more spaces
#   .*         anything, any length
#   (?:...)    a group we don't need to capture
#   (?P<name>...)  a NAMED capture group: we can later grab it with m["name"]
#   ?          the thing before it is optional
#   ^ and $    start and end of the line
#
# re.compile() pre-builds the pattern once so it runs faster on every line.
# ---------------------------------------------------------------------------

# Every syslog line starts the same way: timestamp, hostname, program name.
# Example:  Sep 21 02:11:47 web01 sshd[3805]: Accepted password for deploy ...
# We support two timestamp styles:
#   classic:  "Sep 21 02:11:47"                   (older Ubuntu, most tutorials)
#   ISO 8601: "2026-09-21T02:11:47.123456+00:00"  (Ubuntu 24.04 and newer)
LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"      # classic timestamp
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)"          # OR ISO timestamp
    r"\s+(?P<host>\S+)"                                  # hostname, e.g. web01
    r"\s+(?P<proc>[\w\-.]+)(?:\[\d+\])?:"                # program, e.g. sshd[3805]
    r"\s+(?P<msg>.*)$"                                   # the rest of the message
)

# "Failed password for root from 203.0.113.45 port 47315 ssh2"
# "Failed password for invalid user admin from 192.0.2.77 port 51000 ssh2"
# The "invalid user" part appears when the username doesn't exist on the system.
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)

# "Accepted password for deploy from 198.51.100.23 port 58812 ssh2"
# "Accepted publickey for jordan from 10.0.0.5 port 50122 ssh2"
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)

# "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd ..."
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")

# "new user: name=sysupdate, UID=1002, ..."
NEWUSER_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")


# ---------------------------------------------------------------------------
# PARSING
# Turn raw text lines into structured "event" dictionaries that are easy to
# analyze. Lines we don't care about (like CRON jobs) are skipped.
# ---------------------------------------------------------------------------

def parse_timestamp(ts_text, year):
    """Convert a timestamp string into a Python datetime object.

    Classic syslog timestamps don't include the YEAR (a well-known annoyance),
    so the caller tells us which year to assume. Datetime objects let us do
    math like "how many seconds between these two events?".
    """
    if "T" in ts_text:
        # ISO format. fromisoformat() understands it directly. We drop the
        # timezone info so every timestamp is comparable to every other.
        return datetime.fromisoformat(ts_text).replace(tzinfo=None)
    # Classic format. " ".join(split()) collapses double spaces ("Sep  1").
    cleaned = " ".join(ts_text.split())
    return datetime.strptime(f"{year} {cleaned}", "%Y %b %d %H:%M:%S")


def parse_log(path, year):
    """Read the log file and return a list of event dictionaries."""
    events = []
    # "with open(...)" automatically closes the file when we're done.
    # errors="replace" means a weird/corrupted byte won't crash the tool.
    with open(path, encoding="utf-8", errors="replace") as f:
        # Looping over the file object reads ONE LINE AT A TIME instead of
        # loading the whole file into memory. Real logs can be gigabytes.
        for line_no, line in enumerate(f, start=1):
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue  # not a syslog-style line; ignore it

            try:
                ts = parse_timestamp(m["ts"], year)
            except ValueError:
                continue  # malformed timestamp; skip rather than crash

            proc, msg = m["proc"], m["msg"]
            base = {"time": ts, "line": line_no, "raw": line.strip()}

            # Check the message against each pattern we care about.
            if proc == "sshd":
                if fm := FAILED_RE.search(msg):          # := assigns AND tests
                    events.append({**base, "type": "failed",
                                   "user": fm["user"], "ip": fm["ip"]})
                elif am := ACCEPTED_RE.search(msg):
                    events.append({**base, "type": "accepted", "user": am["user"],
                                   "ip": am["ip"], "method": am["method"]})
            elif proc == "sudo":
                if sm := SUDO_RE.search(msg):
                    events.append({**base, "type": "sudo",
                                   "user": sm["user"], "cmd": sm["cmd"].strip()})
            elif proc == "useradd":
                if nm := NEWUSER_RE.search(msg):
                    events.append({**base, "type": "new_user", "user": nm["user"]})

    # Sort by time so every detection below can assume chronological order.
    events.sort(key=lambda e: e["time"])
    return events


# ---------------------------------------------------------------------------
# DETECTIONS
# Each function looks for one attack pattern and returns a list of alerts.
# Keeping detections separate makes them easy to test, tune, and extend.
# ---------------------------------------------------------------------------

def make_alert(kind, severity, title, detail, ip=None, user=None, time=None, evidence=None):
    """Build an alert in one consistent shape, with its ATT&CK tag attached."""
    tech_id, tech_name = ATTACK[kind]
    return {
        "type": kind,
        "severity": severity,
        "title": title,
        "detail": detail,
        "ip": ip,
        "user": user,
        "time": time.isoformat(sep=" ") if time else None,
        "mitre_id": tech_id,
        "mitre_name": tech_name,
        "evidence": evidence or [],   # a few raw log lines as proof
    }


def detect_brute_force(events, threshold, window_seconds):
    """Flag IPs with >= `threshold` failed logins inside any `window_seconds` span.

    HOW THE SLIDING WINDOW WORKS
    For each IP we keep a deque (a list that is fast to add to one end and
    remove from the other) of recent failure times. When a new failure
    arrives, we drop any times older than the window. Whatever is left is
    "failures in the last N seconds". If that count hits the threshold,
    it's a burst.

    Why a time window and not just a total count? A server on the internet
    gets random failed logins all day. 20 failures spread over a month is
    background noise; 20 failures in 60 seconds is an automated attack.
    """
    window = timedelta(seconds=window_seconds)
    recent = defaultdict(deque)   # ip -> deque of failure timestamps
    peak = {}                     # ip -> biggest burst we saw
    first_hit = {}                # ip -> when the burst first crossed the threshold
    stats = defaultdict(lambda: {"total": 0, "users": set(), "evidence": []})

    for e in events:
        if e["type"] != "failed":
            continue
        ip, q = e["ip"], recent[e["ip"]]
        q.append(e["time"])
        # Slide the window: pop old timestamps off the left side.
        while q and e["time"] - q[0] > window:
            q.popleft()

        s = stats[ip]
        s["total"] += 1
        s["users"].add(e["user"])
        if len(s["evidence"]) < 3:
            s["evidence"].append(e["raw"])

        if len(q) >= threshold:
            peak[ip] = max(peak.get(ip, 0), len(q))
            first_hit.setdefault(ip, e["time"])

    alerts = []
    for ip, burst in peak.items():
        s = stats[ip]
        alerts.append(make_alert(
            "brute_force", "HIGH",
            f"Brute-force attempt from {ip}",
            f"{burst} failed logins within {window_seconds}s "
            f"({s['total']} total). Usernames tried: {', '.join(sorted(s['users']))}.",
            ip=ip, time=first_hit[ip], evidence=s["evidence"],
        ))
    # Return the flagged IPs too, because the compromise check reuses them.
    return alerts, set(peak)


def detect_enumeration(events, min_usernames):
    """Flag IPs that tried many DIFFERENT usernames.

    This catches a slower, sneakier attacker who stays under the brute-force
    time window but guesses a long list of common account names
    (admin, test, oracle, postgres...) hoping one exists with a weak password.
    """
    users_by_ip = defaultdict(set)   # set = no duplicates, so len() = distinct names
    first_seen, evidence = {}, defaultdict(list)
    for e in events:
        if e["type"] == "failed":
            users_by_ip[e["ip"]].add(e["user"])
            first_seen.setdefault(e["ip"], e["time"])
            if len(evidence[e["ip"]]) < 3:
                evidence[e["ip"]].append(e["raw"])

    alerts, flagged = [], set()
    for ip, users in users_by_ip.items():
        if len(users) >= min_usernames:
            flagged.add(ip)
            alerts.append(make_alert(
                "enumeration", "MEDIUM",
                f"Username enumeration from {ip}",
                f"Tried {len(users)} different usernames: {', '.join(sorted(users))}.",
                ip=ip, time=first_seen[ip], evidence=evidence[ip],
            ))
    return alerts, flagged


def detect_compromise(events, suspicious_ips, min_prior_failures):
    """Flag SUCCESSFUL logins from IPs that were attacking us.

    This is the most important alert in the tool. Failed logins mean someone
    is knocking on the door; a success after many failures means the door
    may have opened. A real analyst would treat this as a probable incident.
    """
    failures_so_far = defaultdict(int)   # ip -> failed attempts seen up to this moment
    alerts, compromised_users = [], set()

    for e in events:   # chronological, so "so far" really means "before this login"
        if e["type"] == "failed":
            failures_so_far[e["ip"]] += 1
        elif e["type"] == "accepted":
            prior = failures_so_far[e["ip"]]
            if e["ip"] in suspicious_ips or prior >= min_prior_failures:
                compromised_users.add(e["user"])
                alerts.append(make_alert(
                    "compromise", "CRITICAL",
                    f"Possible account compromise: '{e['user']}' from {e['ip']}",
                    f"Successful {e['method']} login after {prior} failed attempts "
                    f"from the same IP. Treat as a likely breach and investigate.",
                    ip=e["ip"], user=e["user"], time=e["time"], evidence=[e["raw"]],
                ))
    return alerts, compromised_users


def detect_post_login_activity(events, compromised_users):
    """Flag new accounts and sudo commands.

    Attackers who get in often (a) create their own account so they can get
    back in later ("persistence") and (b) use sudo to gain admin rights.

    CORRELATION: sudo is normal for admins, so on its own it's LOW severity.
    But sudo by an account we just flagged as possibly compromised is HIGH.
    Linking events together like this is exactly what SIEM tools do.
    """
    alerts = []
    for e in events:
        if e["type"] == "new_user":
            alerts.append(make_alert(
                "new_account", "HIGH",
                f"New local account created: '{e['user']}'",
                "Attackers often create accounts for persistence. "
                "Verify this account was created by an authorized admin.",
                user=e["user"], time=e["time"], evidence=[e["raw"]],
            ))
        elif e["type"] == "sudo":
            risky = e["user"] in compromised_users
            alerts.append(make_alert(
                "sudo", "HIGH" if risky else "LOW",
                f"sudo used by '{e['user']}'" + (" (possibly compromised account)" if risky else ""),
                f"Command run as root: {e['cmd']}",
                user=e["user"], time=e["time"], evidence=[e["raw"]],
            ))
    return alerts


# ---------------------------------------------------------------------------
# OUTPUT: TERMINAL, JSON, HTML
# ---------------------------------------------------------------------------

# ANSI escape codes change text color in most terminals.
COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;91m",
          "MEDIUM": "\033[1;93m", "LOW": "\033[96m"}
RESET, DIM = "\033[0m", "\033[2m"


def print_report(alerts, event_count, use_color):
    """Print a readable summary to the terminal."""
    c = (lambda key: COLORS.get(key, "")) if use_color else (lambda key: "")
    reset = RESET if use_color else ""
    dim = DIM if use_color else ""

    print(f"\nLog Sentinel: parsed {event_count} relevant events, raised {len(alerts)} alerts\n")
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    print("  " + "   ".join(f"{c(s)}{s}: {counts[s]}{reset}" for s in SEVERITY_ORDER) + "\n")

    for a in alerts:
        print(f"{c(a['severity'])}[{a['severity']}]{reset} {a['title']}")
        print(f"    {a['detail']}")
        print(f"    {dim}{a['time']}  |  MITRE {a['mitre_id']} {a['mitre_name']}{reset}\n")


def write_json(alerts, path):
    """Save alerts as JSON, the format SIEMs and other tools can ingest."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated": datetime.now().isoformat(timespec="seconds"),
                   "alert_count": len(alerts), "alerts": alerts}, f, indent=2)


def write_html(alerts, path, source_name, event_count):
    """Save a styled HTML report you can open in a browser.

    SECURITY NOTE: usernames and other fields come straight from the log,
    which means an ATTACKER controls them. If someone tried to log in as
    the username "<script>...</script>", and we pasted that into HTML
    unescaped, their code would run in the analyst's browser (a Cross-Site
    Scripting / XSS attack). html.escape() converts < > & " into harmless
    text. Never trust log data.
    """
    esc = html.escape
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1

    cards = []
    for a in alerts:
        evidence = "\n".join(esc(line) for line in a["evidence"])
        cards.append(f"""
      <article class="alert sev-{a['severity'].lower()}">
        <div class="alert-head">
          <span class="badge">{a['severity']}</span>
          <h3>{esc(a['title'])}</h3>
        </div>
        <p>{esc(a['detail'])}</p>
        <p class="meta">{esc(a['time'] or '')} &nbsp;|&nbsp;
          <a href="https://attack.mitre.org/techniques/{a['mitre_id'].replace('.', '/')}/"
             target="_blank" rel="noopener">MITRE {a['mitre_id']}</a> {esc(a['mitre_name'])}</p>
        <details><summary>Evidence from the log</summary><pre>{evidence}</pre></details>
      </article>""")

    summary = "".join(
        f'<div class="count sev-{s.lower()}"><strong>{counts[s]}</strong><span>{s.title()}</span></div>'
        for s in SEVERITY_ORDER)

    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Sentinel report: {esc(source_name)}</title>
<style>
  :root {{ --bg:#eef1f4; --panel:#ffffff; --ink:#1c2530; --muted:#5b6876; --line:#d5dbe1;
          --crit:#b3261e; --high:#d9480f; --med:#b58100; --low:#2f6f8f; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#141a21; --panel:#1d252e; --ink:#e4e9ee; --muted:#9aa7b4; --line:#2e3944;
            --crit:#ff6b61; --high:#ff8a4c; --med:#f0c14b; --low:#6fb7d9; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
         font:16px/1.55 "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; }}
  main {{ max-width:880px; margin:0 auto; padding:40px 20px 64px; }}
  header h1 {{ margin:0 0 4px; font-size:1.9rem; letter-spacing:-0.01em; }}
  header p {{ margin:0; color:var(--muted); }}
  .counts {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:28px 0 32px; }}
  .count {{ background:var(--panel); border:1px solid var(--line); border-top:4px solid; padding:12px 14px; }}
  .count strong {{ display:block; font-size:1.8rem; line-height:1.1; }}
  .count span {{ color:var(--muted); font-size:.9rem; }}
  .sev-critical {{ --sev:var(--crit); }} .sev-high {{ --sev:var(--high); }}
  .sev-medium {{ --sev:var(--med); }}   .sev-low {{ --sev:var(--low); }}
  .count {{ border-top-color:var(--sev); }}
  .alert {{ background:var(--panel); border:1px solid var(--line); border-left:6px solid var(--sev);
           padding:16px 20px; margin-bottom:14px; }}
  .alert-head {{ display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }}
  .alert h3 {{ margin:0; font-size:1.08rem; }}
  .badge {{ background:var(--sev); color:#fff; font-size:.75rem; font-weight:700; padding:2px 8px; }}
  .alert p {{ margin:8px 0 0; }}
  .meta {{ color:var(--muted); font-size:.9rem; }}
  .meta a {{ color:inherit; }}
  details {{ margin-top:10px; }}
  summary {{ cursor:pointer; color:var(--muted); font-size:.9rem; }}
  pre {{ overflow-x:auto; background:var(--bg); padding:10px; font-size:.8rem; margin:8px 0 0; }}
  @media (max-width:560px) {{ .counts {{ grid-template-columns:repeat(2,1fr); }} }}
</style></head>
<body><main>
  <header>
    <h1>Log Sentinel report</h1>
    <p>Source: {esc(source_name)} &nbsp;|&nbsp; {event_count} relevant events &nbsp;|&nbsp;
       generated {datetime.now():%Y-%m-%d %H:%M}</p>
  </header>
  <section class="counts">{summary}</section>
  <section>{''.join(cards) or '<p>No suspicious activity found with the current thresholds.</p>'}</section>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# argparse turns flags like "--threshold 10" into variables, and builds the
# --help message for free. Try: python3 log_sentinel.py --help
# ---------------------------------------------------------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Detect brute force, account compromise, and suspicious "
                    "activity in Linux auth logs.")
    p.add_argument("logfile", help="path to auth.log (or /var/log/secure)")
    p.add_argument("--threshold", type=int, default=5,
                   help="failed logins within the window that count as brute force (default: 5)")
    p.add_argument("--window", type=int, default=60,
                   help="brute-force time window in seconds (default: 60)")
    p.add_argument("--min-usernames", type=int, default=5,
                   help="distinct usernames from one IP that count as enumeration (default: 5)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year to assume for classic timestamps, which omit it (default: this year)")
    p.add_argument("--json", metavar="PATH", help="also write alerts to a JSON file")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report")
    p.add_argument("--no-color", action="store_true", help="disable colored terminal output")
    return p


def main():
    args = build_arg_parser().parse_args()

    try:
        events = parse_log(args.logfile, args.year)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")
    except PermissionError:
        # Real auth logs are usually readable only by root. That's deliberate.
        sys.exit(f"Error: permission denied reading {args.logfile} (try sudo)")

    # Run every detection. Order matters: the compromise check needs to know
    # which IPs the brute-force and enumeration checks flagged.
    bf_alerts, bf_ips = detect_brute_force(events, args.threshold, args.window)
    en_alerts, en_ips = detect_enumeration(events, args.min_usernames)
    cp_alerts, bad_users = detect_compromise(events, bf_ips | en_ips, args.threshold)
    post_alerts = detect_post_login_activity(events, bad_users)

    # Most severe first; ties broken by time.
    alerts = sorted(bf_alerts + en_alerts + cp_alerts + post_alerts,
                    key=lambda a: (SEVERITY_ORDER[a["severity"]], a["time"] or ""))

    print_report(alerts, len(events), use_color=sys.stdout.isatty() and not args.no_color)
    if args.json:
        write_json(alerts, args.json)
        print(f"JSON written to {args.json}")
    if args.html:
        write_html(alerts, args.html, args.logfile, len(events))
        print(f"HTML report written to {args.html}")

    # Exit code 1 if anything HIGH or CRITICAL was found. This lets other
    # scripts or scheduled jobs react automatically, e.g.:
    #   python3 log_sentinel.py /var/log/auth.log || send-alert-email
    serious = any(a["severity"] in ("CRITICAL", "HIGH") for a in alerts)
    sys.exit(1 if serious else 0)


# This line means "only run main() when this file is executed directly",
# not when another script imports functions from it.
if __name__ == "__main__":
    main()
