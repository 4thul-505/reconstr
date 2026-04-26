"""
parser.py — Linux log parser for attack path reconstruction
Supports: auth.log, syslog
Improvements:
  - Timestamps parsed to datetime objects and sorted globally
  - Session tracking via PID/TTY extraction
  - Multi-pattern fallback so small format variations don't break silently
  - Delta analysis between events
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from collections import defaultdict

# ── Event dataclass ──────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    timestamp: str
    host: str
    source: str
    event_type: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    command: Optional[str] = None
    raw: str = ""
    severity: str = "info"
    mitre: str = ""
    # New fields
    dt: Optional[datetime] = None       # parsed datetime for sorting/delta
    session_id: Optional[str] = None    # PID or TTY-derived session key
    pid: Optional[str] = None
    attack_stage: str = ""              # Initial Access / Priv Esc / Persistence / Execution

# ── Timestamp parsing (supports multiple formats) ────────────────────────────

_TS_FORMATS = [
    "%b %d %H:%M:%S",      # Jan  5 10:22:01  (auth.log)
    "%b  %d %H:%M:%S",     # Jan  5 ...  (double-space day)
    "%Y-%m-%dT%H:%M:%S",   # ISO8601 syslog
    "%Y-%m-%d %H:%M:%S",   # journald export
]

def _parse_dt(ts: str) -> Optional[datetime]:
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            # auth.log has no year — assume current year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None

# ── Regex patterns ────────────────────────────────────────────────────────────
# Each tuple: (event_type, compiled_regex, extractor_fn)
# PID is captured where available for session correlation.

PATTERNS = [
    # SSH failed login
    (
        "ssh_fail",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssshd\[(\d+)\].*?Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4), "src_ip": m.group(5),
                   "severity": "warning", "mitre": "T1110 - Brute Force",
                   "attack_stage": "Initial Access"}
    ),
    # SSH accepted login
    (
        "ssh_success",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssshd\[(\d+)\].*?Accepted \S+ for (\S+) from ([\d.]+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4), "src_ip": m.group(5),
                   "severity": "critical", "mitre": "T1078 - Valid Accounts",
                   "attack_stage": "Initial Access"}
    ),
    # SSH session opened — capture PID for session correlation
    (
        "session_open",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssshd\[(\d+)\].*?session opened for user (\S+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4),
                   "severity": "warning", "mitre": "T1078 - Valid Accounts",
                   "attack_stage": "Initial Access"}
    ),
    # Sudo command
    (
        "sudo",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssudo\[(\d+)\]:\s+(\S+)\s.*?COMMAND=(.+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4), "command": m.group(5).strip(),
                   "severity": "critical", "mitre": "T1548.003 - Sudo and Sudo Caching",
                   "attack_stage": "Privilege Escalation"}
    ),
    # New user created
    (
        "new_user",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\suseradd\[(\d+)\].*?new user: name=(\S+),"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4),
                   "severity": "critical", "mitre": "T1136.001 - Local Account",
                   "attack_stage": "Persistence"}
    ),
    # Cron CMD execution
    (
        "cron_exec",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\sCRON\[(\d+)\]:\s+\(\w+\)\s+CMD\s+\((.+?)\)\s*$"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "command": re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', m.group(4)).strip(),
                   "severity": "critical", "mitre": "T1053.003 - Cron",
                   "attack_stage": "Persistence"}
    ),
    # Crontab modification
    (
        "cron_modify",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\scrontab\[(\d+)\]:\s+\((\S+)\)\s+(?:REPLACE|EDIT|ADD)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4),
                   "severity": "critical", "mitre": "T1053.003 - Cron",
                   "attack_stage": "Persistence"}
    ),
    # Usermod via sudo
    (
        "usermod",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssudo\[(\d+)\]:\s+(\S+)\s.*?COMMAND=.*?usermod\s+(.+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4), "command": f"usermod {m.group(5).strip()}",
                   "severity": "critical", "mitre": "T1098 - Account Manipulation",
                   "attack_stage": "Privilege Escalation"}
    ),
    # su (switch user)
    (
        "su",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\ssu\[(\d+)\].*?Successful su for (\S+) by (\S+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(5), "command": f"su → {m.group(4)}",
                   "severity": "critical", "mitre": "T1548 - Abuse Elevation Control",
                   "attack_stage": "Privilege Escalation"}
    ),
    # passwd change
    (
        "passwd_change",
        re.compile(r"(\w+\s+\d+\s[\d:]+)\s(\S+)\spasswd\[(\d+)\].*?password changed for (\S+)"),
        lambda m: {"timestamp": m.group(1), "host": m.group(2), "pid": m.group(3),
                   "user": m.group(4),
                   "severity": "critical", "mitre": "T1098 - Account Manipulation",
                   "attack_stage": "Persistence"}
    ),
]

# ── Fallback: extract what we can even if no pattern matches ─────────────────

_FALLBACK_TS   = re.compile(r"^(\w+\s+\d+\s[\d:]+)\s(\S+)\s(\S+)\[")
_FALLBACK_IP   = re.compile(r"from ([\d.]+)")
_FALLBACK_USER = re.compile(r"for (?:invalid user )?(\S+)")

def _try_fallback(line: str) -> Optional[LogEvent]:
    """Best-effort parse for lines that don't match any known pattern."""
    m = _FALLBACK_TS.match(line)
    if not m:
        return None
    ts, host, src = m.group(1), m.group(2), m.group(3)
    ip_m   = _FALLBACK_IP.search(line)
    usr_m  = _FALLBACK_USER.search(line)
    return LogEvent(
        timestamp=ts, host=host, source=src,
        event_type="unknown",
        user=usr_m.group(1) if usr_m else None,
        src_ip=ip_m.group(1) if ip_m else None,
        raw=line, severity="info", mitre="",
        dt=_parse_dt(ts),
    )

# ── Session correlation ───────────────────────────────────────────────────────

def _correlate_sessions(events: list[LogEvent]) -> list[LogEvent]:
    """
    Tie events to sessions using PID lineage.
    sshd PIDs at login become session anchors; subsequent sudo/cron under the
    same user within a short window inherit that session_id.
    """
    # Map pid → session_id (use the sshd/login PID as canonical session key)
    pid_to_session: dict[str, str] = {}
    # Map user → last active session
    user_last_session: dict[str, str] = {}

    for e in events:
        if e.event_type in ("ssh_success", "session_open") and e.pid:
            sid = f"session_{e.pid}"
            e.session_id = sid
            pid_to_session[e.pid] = sid
            if e.user:
                user_last_session[e.user] = sid

        elif e.event_type in ("sudo", "usermod", "su", "cron_exec", "cron_modify",
                               "new_user", "passwd_change"):
            # Inherit from pid map first, then from user's last known session
            if e.pid and e.pid in pid_to_session:
                e.session_id = pid_to_session[e.pid]
            elif e.user and e.user in user_last_session:
                e.session_id = user_last_session[e.user]

    return events

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_auth_log(filepath: str) -> list[LogEvent]:
    events = []

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            matched = False
            for event_type, pattern, extractor in PATTERNS:
                match = pattern.search(line)
                if match:
                    data = extractor(match)
                    dt = _parse_dt(data.get("timestamp", ""))
                    evt = LogEvent(
                        timestamp=data.get("timestamp", ""),
                        host=data.get("host", "unknown"),
                        source=event_type,
                        event_type=event_type,
                        user=data.get("user"),
                        src_ip=data.get("src_ip"),
                        command=data.get("command"),
                        raw=line,
                        severity=data.get("severity", "info"),
                        mitre=data.get("mitre", ""),
                        dt=dt,
                        pid=data.get("pid"),
                        attack_stage=data.get("attack_stage", ""),
                    )
                    events.append(evt)
                    matched = True
                    break

            # Soft fallback — keep unknown events for context but don't crash
            # (only fall back for lines that look like structured log lines)
            # Uncomment the block below to enable fallback parsing:
            # if not matched:
            #     fb = _try_fallback(line)
            #     if fb:
            #         events.append(fb)

    # Sort globally by parsed datetime, preserving original string order for ties
    events.sort(key=lambda e: (e.dt or datetime.min))

    # Session correlation pass
    events = _correlate_sessions(events)

    return events


# ── Detection rules ───────────────────────────────────────────────────────────

def run_detections(events: list[LogEvent]) -> list[dict]:
    """
    Rule engine that returns a list of alert dicts.
    Rules: brute_force, impossible_travel, privesc_chain, persistence_combo
    """
    from collections import Counter
    alerts = []

    # --- Rule 1: Brute Force (≥5 ssh_fail from same IP) ----------------------
    fail_by_ip: Counter = Counter(
        e.src_ip for e in events if e.event_type == "ssh_fail" and e.src_ip
    )
    for ip, cnt in fail_by_ip.items():
        if cnt >= 5:
            alerts.append({
                "rule": "brute_force",
                "severity": "critical",
                "description": f"Brute force: {ip} made {cnt} failed SSH attempts",
                "mitre": "T1110",
                "ip": ip,
            })

    # --- Rule 2: Impossible Travel (same user, multiple IPs in short window) --
    user_ips: dict[str, set] = defaultdict(set)
    for e in events:
        if e.event_type == "ssh_success" and e.user and e.src_ip:
            user_ips[e.user].add(e.src_ip)
    for user, ips in user_ips.items():
        if len(ips) > 1:
            alerts.append({
                "rule": "impossible_travel",
                "severity": "critical",
                "description": f"Impossible travel: user '{user}' logged in from {len(ips)} IPs: {', '.join(ips)}",
                "mitre": "T1078",
                "user": user,
                "ips": list(ips),
            })

    # --- Rule 3: Privilege Escalation chain (ssh_success → sudo/usermod) ------
    priv_users = {e.user for e in events if e.event_type in ("sudo", "usermod", "su")}
    login_users = {e.user for e in events if e.event_type == "ssh_success"}
    for user in priv_users & login_users:
        alerts.append({
            "rule": "privesc_chain",
            "severity": "critical",
            "description": f"Privilege escalation chain: '{user}' logged in then ran privileged commands",
            "mitre": "T1548",
            "user": user,
        })

    # --- Rule 4: Persistence combo (new_user + cron in same attack) -----------
    has_new_user = any(e.event_type == "new_user" for e in events)
    has_cron     = any(e.event_type in ("cron_exec", "cron_modify") for e in events)
    if has_new_user and has_cron:
        alerts.append({
            "rule": "persistence_combo",
            "severity": "critical",
            "description": "Persistence pattern: new user creation combined with cron modification detected",
            "mitre": "T1136 + T1053",
        })

    # --- Rule 5: Brute force then success (same IP) ---------------------------
    success_ips = {e.src_ip for e in events if e.event_type == "ssh_success" and e.src_ip}
    for ip in success_ips:
        if fail_by_ip.get(ip, 0) >= 3:
            alerts.append({
                "rule": "brute_then_success",
                "severity": "critical",
                "description": f"Brute force succeeded: {ip} had {fail_by_ip[ip]} failures then logged in",
                "mitre": "T1110 → T1078",
                "ip": ip,
            })

    return alerts


# ── Summarize ─────────────────────────────────────────────────────────────────

def summarize(events: list[LogEvent]) -> dict:
    from collections import Counter

    bf_counter = Counter(
        e.src_ip for e in events if e.event_type == "ssh_fail" and e.src_ip
    )
    detections = run_detections(events)

    # Time delta: first → last event
    dts = [e.dt for e in events if e.dt]
    span_seconds = (max(dts) - min(dts)).total_seconds() if len(dts) >= 2 else 0

    return {
        "total_events":    len(events),
        "event_types":     Counter(e.event_type for e in events),
        "unique_ips":      set(e.src_ip for e in events if e.src_ip),
        "users_seen":      set(e.user for e in events if e.user),
        "critical_events": [e for e in events if e.severity == "critical"],
        "brute_force_ips": bf_counter,
        "detections":      detections,
        "span_seconds":    span_seconds,
        "attack_stages":   list({e.attack_stage for e in events if e.attack_stage}),
        "sessions":        list({e.session_id for e in events if e.session_id}),
    }
