# Log Sentinel

A Python tool that analyzes Linux SSH authentication logs and flags the activity a SOC analyst would investigate: brute-force attacks, likely account compromises, username enumeration, and suspicious post-login behavior. Every alert is mapped to a MITRE ATT&CK technique.

Built with only the Python standard library, so it runs anywhere Python 3.8+ is installed with nothing to install.

## Quick start

```bash
git clone https://github.com/<your-username>/log-sentinel.git
cd log-sentinel
python3 log_sentinel.py sample_auth.log --html report.html --json alerts.json
```

To analyze a real system (auth logs are root-only by design):

```bash
sudo python3 log_sentinel.py /var/log/auth.log      # Ubuntu / Debian
sudo python3 log_sentinel.py /var/log/secure        # RHEL / CentOS / Fedora
```

## What it detects

| Detection | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|
| Brute force | One IP reaches N failed logins inside a sliding time window | High | T1110 |
| Possible compromise | Successful login from an IP that was brute-forcing or enumerating | Critical | T1078 |
| Username enumeration | One IP tries N or more different usernames | Medium | T1110.003 |
| New local account | `useradd` creates an account (common persistence technique) | High | T1136.001 |
| sudo usage | Low by default; raised to High when run by a possibly compromised account | Low / High | T1548.003 |

## Example

The included `sample_auth.log` contains a day of simulated activity with three attacks mixed into normal traffic:

1. A fast brute-force attack against `root` that never succeeds.
2. A brute-force attack that succeeds against `deploy`, after which the attacker uses sudo to create a backdoor account (`sysupdate`) and adds it to the sudo group.
3. A slow enumeration attack that tries eight usernames over 40 minutes, staying under the brute-force window but caught by the enumeration rule.

It also contains a normal user who mistypes their password twice before logging in. The tool correctly does not flag this, because two failures stays under the threshold.

See `example_report.html` and `example_alerts.json` for the output. All sample IPs come from ranges reserved for documentation (RFC 5737), so they belong to no real system.

## Options

```
--threshold N      failed logins in the window that count as brute force (default 5)
--window SECONDS   brute-force time window (default 60)
--min-usernames N  distinct usernames from one IP that count as enumeration (default 5)
--year YYYY        year for classic syslog timestamps, which omit it (default: current year)
--json PATH        write alerts as JSON
--html PATH        write an HTML report
--no-color         plain terminal output
```

The tool exits with code 1 when any High or Critical alert is found, so it can drive automation:

```bash
python3 log_sentinel.py /var/log/auth.log || echo "Security alert!" | mail -s "Log Sentinel" admin@example.com
```

## Design decisions

**Sliding time window, not a total count.** Internet-facing servers receive failed logins constantly. A window separates automated bursts from background noise and one-off typos.

**Correlation between detections.** The compromise check reuses IPs flagged by the other detections, and sudo severity depends on whether the account was flagged as compromised. Linking events is what turns individual log lines into an incident story.

**Log data is treated as untrusted.** Usernames in failed-login lines are chosen by the attacker. The HTML report escapes all log-derived text to prevent cross-site scripting in the analyst's browser.

**Standard library only.** Easy to run on any server, and no third-party dependencies to audit.

## Limitations

- Analyzes logs after the fact rather than monitoring in real time.
- A patient attacker who spaces out attempts across many IPs can evade per-IP thresholds.
- Classic syslog timestamps have no year, so logs spanning New Year's need care.
- Currently parses only Linux auth logs, not Windows Event Logs or web server logs.

## Future improvements

- [ ] GeoIP / threat-intelligence enrichment for attacking IPs
- [ ] Real-time mode that follows the log as it grows (like `tail -f`)
- [ ] Windows Security Event Log support (event IDs 4625, 4624, 4720)
- [ ] Unit tests for each detection

## Author

Phengtheu Cyrus Tran, IT student concentrating in Cybersecurity

