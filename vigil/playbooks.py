"""Response playbooks, filled in with the entities from an alert."""

from __future__ import annotations

PLAYBOOKS: dict[str, dict[str, list[str]]] = {
    "recon": {
        "contain": [
            "Confirm with change management whether {host} has an approved scanning task",
            "If not approved, isolate {host} at the switch or EDR",
        ],
        "investigate": [
            "List the {targets} probed hosts and check which ports answered",
            "Pull process and logon history from {host} for the 30 minutes before the scan",
        ],
        "remediate": ["Re-image {host} if a scanning tool or implant is found"],
    },
    "brute_force": {
        "contain": [
            "Block {src} at the perimeter or rate-limit it on the login service",
            "Lock or force a reset for accounts that were guessed: {users}",
        ],
        "investigate": [
            "Check whether any guessed account logged in successfully after the failures",
            "Look for the same source in VPN, mail and SSO logs",
        ],
        "remediate": ["Enforce MFA on the targeted accounts", "Add lockout and velocity rules for {target}"],
    },
    "lateral_movement": {
        "contain": [
            "Disable the account {users} used to move between hosts",
            "Isolate {host} and the hosts it reached: {targets}",
        ],
        "investigate": [
            "Collect service installs, scheduled tasks and new binaries on the reached hosts",
            "Trace how {users} was obtained (brute force, credential dumping)",
        ],
        "remediate": ["Rotate credentials for the account and any cached admin credentials", "Restrict SMB/WinRM between workstations"],
    },
    "c2_beacon": {
        "contain": [
            "Block {dst} at the egress firewall and DNS resolver",
            "Isolate {host} before the operator notices",
        ],
        "investigate": [
            "Identify the process on {host} holding the connection to {dst}",
            "Search all hosts for traffic to {dst}",
        ],
        "remediate": ["Re-image {host}", "Add {dst} to threat-intel blocklists"],
    },
    "exfiltration": {
        "contain": [
            "Cut egress from {host} to {dst} immediately",
            "Preserve flow logs and disk images for forensics",
        ],
        "investigate": [
            "Estimate what was sent: {bytes_out} so far",
            "Identify the files staged on {host} before the transfer",
        ],
        "remediate": ["Start the breach-assessment process with legal and privacy", "Review DLP rules for this path"],
    },
    "anomaly": {
        "contain": ["Watch {host} closely; no known technique matched"],
        "investigate": [
            "Compare the flagged behaviour with {host}'s normal baseline",
            "Check whether the destination {dst} is known to threat intel",
        ],
        "remediate": ["If malicious, label the alert so the next model version learns the pattern"],
    },
}

PHASES = ("contain", "investigate", "remediate")


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return "n/a"


def render(threat: str, context: dict[str, str]) -> dict[str, list[str]]:
    book = PLAYBOOKS.get(threat, PLAYBOOKS["anomaly"])
    ctx = _Blank(context)
    return {phase: [step.format_map(ctx) for step in book[phase]] for phase in PHASES}
