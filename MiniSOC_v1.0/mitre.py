"""Small MITRE ATT&CK (Enterprise) subset relevant to web services, used for the coverage matrix.

The list is intentionally focused: techniques an internet-facing web/API service and its
hosts commonly face. Uncovered techniques show where new detections are needed.
"""
TACTICS = [
    ("TA0043", "Reconnaissance"), ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"), ("TA0011", "Command and Control"), ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]

TECHNIQUES = {
    "T1595.002": ("Vulnerability Scanning", "TA0043"),
    "T1595.003": ("Wordlist Scanning", "TA0043"),
    "T1190": ("Exploit Public-Facing Application", "TA0001"),
    "T1078": ("Valid Accounts", "TA0001"),
    "T1133": ("External Remote Services", "TA0001"),
    "T1059.001": ("PowerShell", "TA0002"),
    "T1059.004": ("Unix Shell", "TA0002"),
    "T1053.005": ("Scheduled Task", "TA0003"),
    "T1543.003": ("Windows Service", "TA0003"),
    "T1136": ("Create Account", "TA0003"),
    "T1505.003": ("Web Shell", "TA0003"),
    "T1098": ("Account Manipulation", "TA0004"),
    "T1078.003": ("Local Accounts", "TA0004"),
    "T1068": ("Exploitation for Privilege Escalation", "TA0004"),
    "T1070.001": ("Clear Windows Event Logs", "TA0005"),
    "T1562.008": ("Disable or Modify Cloud Logs", "TA0005"),
    "T1556.006": ("Multi-Factor Authentication", "TA0005"),
    "T1110": ("Brute Force", "TA0006"),
    "T1110.001": ("Password Guessing", "TA0006"),
    "T1110.003": ("Password Spraying", "TA0006"),
    "T1110.004": ("Credential Stuffing", "TA0006"),
    "T1003": ("OS Credential Dumping", "TA0006"),
    "T1539": ("Steal Web Session Cookie", "TA0006"),
    "T1621": ("MFA Request Generation", "TA0006"),
    "T1046": ("Network Service Discovery", "TA0007"),
    "T1087": ("Account Discovery", "TA0007"),
    "T1071": ("Application Layer Protocol", "TA0011"),
    "T1105": ("Ingress Tool Transfer", "TA0011"),
    "T1567": ("Exfiltration Over Web Service", "TA0010"),
    "T1530": ("Data from Cloud Storage", "TA0010"),
    "T1041": ("Exfiltration Over C2 Channel", "TA0010"),
    "T1496": ("Resource Hijacking", "TA0040"),
    "T1499": ("Endpoint Denial of Service", "TA0040"),
    "T1498": ("Network Denial of Service", "TA0040"),
    "T1485": ("Data Destruction", "TA0040"),
}


def technique_name(tid):
    return TECHNIQUES.get(tid.upper(), (tid, ""))[0]


def coverage(rules, tested=None):
    """Build a tactic -> technique matrix with covering rules."""
    tested = tested or set()
    by_tech = {}
    for rule in rules:
        for tid in rule.mitre:
            by_tech.setdefault(tid, []).append(rule)
            parent = tid.split(".")[0]
            if parent != tid:
                by_tech.setdefault(parent, [])
    matrix = []
    for tactic_id, tactic in TACTICS:
        cells = []
        for tid, (name, tac) in TECHNIQUES.items():
            if tac != tactic_id:
                continue
            covering = by_tech.get(tid, [])
            cells.append({"id": tid, "name": name, "rules": [r.id for r in covering],
                          "tested": tid in tested, "covered": bool(covering)})
        matrix.append({"id": tactic_id, "name": tactic, "techniques": cells,
                       "covered": sum(1 for c in cells if c["covered"]), "total": len(cells)})
    total = sum(t["total"] for t in matrix)
    covered = sum(t["covered"] for t in matrix)
    return {"matrix": matrix, "covered": covered, "total": total,
            "percent": round(100 * covered / total) if total else 0}
