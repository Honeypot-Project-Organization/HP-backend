"""
MITRE ATT&CK mapping for honeypot activity.

HOW IT WORKS
  * Command text is split into segments (on ; && || |) and each segment is
    matched against the RULES below. A rule is a plain regular expression.
  * Some techniques are inferred from EVENTS instead of command text: a new
    connection, a failed login, a successful login (see EVENT_TECHNIQUES).
  * Results are stored as a list of technique IDs on commands, sessions and
    IPs (see routers/ingest.py), so MongoDB can count and filter them.
  * Only IDs are stored. Names, tactics and links come from CATALOG, so fixing
    a name here needs no data migration.

THESE ARE HEURISTIC MATCHES, NOT CONFIRMED TECHNIQUES. A command that looks
like discovery may be a bot replaying a script. The dashboard says so.

Technique IDs, names and tactics were checked against attack.mitre.org
(ATT&CK v19, April 2026) on 2026-11-02. ATT&CK renumbers things between
versions (v19 split Defense Evasion into Stealth and Defense Impairment and
moved T1562.* to T1685/T1686/T1690), so re-check them when you update.

CHANGING THE RULES: edit RULES / CATALOG, then increase RULES_VERSION and run
`python scripts/backfill.py` (add --rebuild-mitre once, while ingest is idle,
if you REMOVED or changed a rule and want old tags dropped).
"""
import re
from typing import Any, Dict, List, Optional, Tuple

RULES_VERSION = 1
MAX_TEXT = 4096       # ingest already caps command text at this length
MAX_SEGMENTS = 50
TECH_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
ATTACK_BASE = "https://attack.mitre.org/techniques/"

# basis: "event" = inferred from login/connection events, "command" = from command text.
CATALOG: Dict[str, Dict[str, Any]] = {
    # ---- event based
    "T1133": {"name": "External Remote Services", "tactics": ["Persistence", "Initial Access"], "basis": "event"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactics": ["Credential Access"], "basis": "event"},
    "T1078": {"name": "Valid Accounts", "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Stealth"], "basis": "event"},
    # ---- command based
    "T1082": {"name": "System Information Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1033": {"name": "System Owner/User Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1087.001": {"name": "Account Discovery: Local Account", "tactics": ["Discovery"], "basis": "command"},
    "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactics": ["Credential Access"], "basis": "command"},
    "T1069.001": {"name": "Permission Groups Discovery: Local Groups", "tactics": ["Discovery"], "basis": "command"},
    "T1016": {"name": "System Network Configuration Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1049": {"name": "System Network Connections Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1057": {"name": "Process Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1083": {"name": "File and Directory Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1018": {"name": "Remote System Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1046": {"name": "Network Service Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1124": {"name": "System Time Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1007": {"name": "System Service Discovery", "tactics": ["Discovery"], "basis": "command"},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ["Command and Control"], "basis": "command"},
    "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactics": ["Execution"], "basis": "command"},
    "T1059.006": {"name": "Command and Scripting Interpreter: Python", "tactics": ["Execution"], "basis": "command"},
    "T1222.002": {"name": "File and Directory Permissions Modification: Linux and Mac Permissions", "tactics": ["Defense Impairment"], "basis": "command"},
    "T1053.003": {"name": "Scheduled Task/Job: Cron", "tactics": ["Execution", "Persistence", "Privilege Escalation"], "basis": "command"},
    "T1098.004": {"name": "Account Manipulation: SSH Authorized Keys", "tactics": ["Persistence", "Privilege Escalation"], "basis": "command"},
    "T1098": {"name": "Account Manipulation", "tactics": ["Persistence", "Privilege Escalation"], "basis": "command"},
    "T1136.001": {"name": "Create Account: Local Account", "tactics": ["Persistence"], "basis": "command"},
    "T1543.002": {"name": "Create or Modify System Process: Systemd Service", "tactics": ["Persistence", "Privilege Escalation"], "basis": "command"},
    "T1037.004": {"name": "Boot or Logon Initialization Scripts: RC Scripts", "tactics": ["Persistence", "Privilege Escalation"], "basis": "command"},
    "T1070.003": {"name": "Indicator Removal: Clear Command History", "tactics": ["Stealth"], "basis": "command"},
    "T1070.004": {"name": "Indicator Removal: File Deletion", "tactics": ["Stealth"], "basis": "command"},
    "T1690": {"name": "Prevent Command History Logging", "tactics": ["Defense Impairment"], "basis": "command"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactics": ["Stealth"], "basis": "command"},
    "T1496.001": {"name": "Resource Hijacking: Compute Hijacking", "tactics": ["Impact"], "basis": "command"},
    "T1686": {"name": "Disable or Modify System Firewall", "tactics": ["Defense Impairment"], "basis": "command"},
    "T1685": {"name": "Disable or Modify Tools", "tactics": ["Defense Impairment"], "basis": "command"},
    "T1021.004": {"name": "Remote Services: SSH", "tactics": ["Lateral Movement"], "basis": "command"},
    "T1548.003": {"name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactics": ["Privilege Escalation"], "basis": "command"},
    "T1529": {"name": "System Shutdown/Reboot", "tactics": ["Impact"], "basis": "command"},
}

# Event-based techniques: where to count them. (collection, filter, time field, description)
EVENT_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1133": {"collection": "sessions", "filter": {}, "time": "start_time",
              "event": "cowrie.session.connect", "description": "Every new SSH/Telnet connection to the honeypot."},
    "T1110.001": {"collection": "auth_attempts", "filter": {"success": False}, "time": "timestamp",
                  "event": "cowrie.login.failed", "description": "Every failed login attempt (a guessed username/password)."},
    "T1078": {"collection": "auth_attempts", "filter": {"success": True}, "time": "timestamp",
              "event": "cowrie.login.success", "description": "Every login the honeypot accepted."},
}


def _cmd(names: str) -> str:
    """Segment starts with this command (optionally behind sudo / a path / busybox)."""
    return r"^(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:busybox\s+)?(?:\S*/)?(?:" + names + r")(?:\s|$)"


# (rule name, technique, regex, scope). scope "segment" = each ;/&&/||/| part, "full" = whole line.
RULES: List[Tuple[str, str, str, str]] = [
    ("sysinfo-commands", "T1082", _cmd(r"uname|lscpu|hostnamectl|lsb_release|nproc|dmidecode|free|uptime|hostname|arch"), "segment"),
    ("sysinfo-files", "T1082", r"/proc/(?:cpuinfo|meminfo|version)|/etc/(?:os-release|issue|lsb-release)", "segment"),
    ("user-discovery", "T1033", _cmd(r"whoami|id|w|who|last|lastlog|users|logname"), "segment"),
    ("passwd-file", "T1087.001", r"/etc/passwd\b|^(?:sudo\s+)?getent\s+passwd", "segment"),
    ("shadow-file", "T1003.008", r"/etc/shadow\b", "segment"),
    ("local-groups", "T1069.001", _cmd(r"groups") + r"|/etc/group\b|^(?:sudo\s+)?getent\s+group", "segment"),
    ("net-config", "T1016", _cmd(r"ifconfig|route|iwconfig") + r"|^(?:sudo\s+)?ip\s+(?:-\S+\s+)*(?:a|addr|address|l|link|r|route|n|neigh)\b|/etc/resolv\.conf", "segment"),
    ("net-connections", "T1049", _cmd(r"netstat|ss") + r"|^(?:sudo\s+)?lsof\s+.*-i\b", "segment"),
    ("process-discovery", "T1057", _cmd(r"ps|top|htop|pgrep|pstree"), "segment"),
    ("file-discovery", "T1083", _cmd(r"ls|ll|dir|find|locate|tree"), "segment"),
    ("remote-systems", "T1018", _cmd(r"ping|arp"), "segment"),
    ("service-scan", "T1046", _cmd(r"nmap|masscan|zmap") + r"|^(?:sudo\s+)?nc\s+.*-z\b", "segment"),
    ("time-discovery", "T1124", _cmd(r"date|hwclock|timedatectl"), "segment"),
    ("service-discovery", "T1007", r"^(?:sudo\s+)?systemctl\s+(?:list-units|list-unit-files|status)\b|^(?:sudo\s+)?service\s+--status-all|" + _cmd(r"chkconfig"), "segment"),
    ("download-tools", "T1105", _cmd(r"wget|curl|tftp|ftpget|ftp|sftp|scp"), "segment"),
    ("shell-run", "T1059.004", _cmd(r"sh|bash|dash|zsh|ash"), "segment"),
    ("pipe-to-shell", "T1059.004", r"\|\s*(?:sudo\s+)?(?:\S*/)?(?:ba|da|z)?sh\b", "full"),
    ("python-run", "T1059.006", _cmd(r"python[0-9.]*"), "segment"),
    ("permissions", "T1222.002", _cmd(r"chmod|chown|chgrp|chattr"), "segment"),
    ("cron", "T1053.003", _cmd(r"crontab") + r"|/etc/cron|/var/spool/cron", "segment"),
    ("ssh-keys", "T1098.004", r"authorized_keys", "segment"),
    ("password-change", "T1098", _cmd(r"passwd|chpasswd|usermod"), "segment"),
    ("create-user", "T1136.001", _cmd(r"useradd|adduser"), "segment"),
    ("systemd-persistence", "T1543.002", r"/etc/systemd/system|^(?:sudo\s+)?systemctl\s+(?:enable|daemon-reload)\b", "segment"),
    ("rc-scripts", "T1037.004", r"/etc/rc\.local|/etc/init\.d/", "segment"),
    ("history-clear", "T1070.003", r"^(?:sudo\s+)?history\s+-[cw]\b|\.bash_history", "segment"),
    ("file-delete", "T1070.004", _cmd(r"rm|shred|unlink"), "segment"),
    ("history-disable", "T1690", r"unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|set\s+\+o\s+history", "segment"),
    ("decode", "T1140", r"\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b|\buudecode\b|\bopenssl\s+enc\b.*\s-d\b", "segment"),
    ("miner", "T1496.001", r"xmrig|minerd|cpuminer|ethminer|stratum\+tcp|\bmonero\b", "full"),
    ("firewall-off", "T1686", r"\biptables\s+(?:-\S+\s+)*-[FXP]\b|\bufw\s+disable\b|^(?:sudo\s+)?systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|iptables)\b|^(?:sudo\s+)?service\s+(?:iptables|firewalld|ufw)\s+stop\b|\bnft\s+flush\b", "segment"),
    ("security-tools-off", "T1685", r"\bsetenforce\s+0\b|^(?:sudo\s+)?systemctl\s+(?:stop|disable)\s+(?:auditd|apparmor|rsyslog)\b|^(?:sudo\s+)?service\s+(?:auditd|apparmor|rsyslog)\s+stop\b|\bauditctl\s+-e\s+0\b", "segment"),
    ("outbound-ssh", "T1021.004", _cmd(r"ssh"), "segment"),
    ("sudo", "T1548.003", r"^sudo(?:\s|$)", "segment"),
    ("power", "T1529", _cmd(r"reboot|shutdown|poweroff|halt") + r"|^(?:sudo\s+)?init\s+[06]\b", "segment"),
]

_COMPILED = [(name, tech, pattern, scope, re.compile(pattern, re.IGNORECASE)) for name, tech, pattern, scope in RULES]
_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\|)\s*")


def _segments(text: str) -> List[str]:
    parts = [p.strip() for p in _SPLIT.split(text[:MAX_TEXT])]
    return [p for p in parts if p][:MAX_SEGMENTS]


def match_command(text: Optional[str]) -> List[Dict[str, str]]:
    """Every (technique, rule) that matches this command line."""
    if not isinstance(text, str) or not text.strip():
        return []
    text = text.strip()[:MAX_TEXT]
    segs = _segments(text)
    hits: List[Dict[str, str]] = []
    seen = set()
    for name, tech, _pattern, scope, rx in _COMPILED:
        targets = [text] if scope == "full" else segs
        if any(rx.search(t) for t in targets) and (name, tech) not in seen:
            seen.add((name, tech))
            hits.append({"technique": tech, "rule": name})
    return hits


def techniques_for_command(text: Optional[str]) -> List[str]:
    """Sorted, de-duplicated technique IDs for one command."""
    return sorted({h["technique"] for h in match_command(text)})


def technique_url(tid: str) -> str:
    """T1110.001 -> https://attack.mitre.org/techniques/T1110/001/"""
    return f"{ATTACK_BASE}{tid.replace('.', '/')}/"


def public_catalog() -> List[Dict[str, Any]]:
    return [
        {"id": tid, "name": c["name"], "tactics": c["tactics"], "basis": c["basis"], "url": technique_url(tid)}
        for tid, c in sorted(CATALOG.items())
    ]


def rules_for(tid: str) -> List[Dict[str, Any]]:
    """The rules that can produce this technique (shown on the detail page)."""
    if tid in EVENT_TECHNIQUES:
        e = EVENT_TECHNIQUES[tid]
        return [{"name": e["event"], "pattern": None, "scope": "event", "description": e["description"]}]
    return [{"name": n, "pattern": p, "scope": s, "description": None} for n, t, p, s in RULES if t == tid]
