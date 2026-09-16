"""Core data types shared by the simulator, feature pipeline and detection engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

LAYERS = ("network", "endpoint", "application")

# Classes the supervised model predicts. Order is the model's output order.
THREAT_CLASSES = (
    "benign",
    "recon",
    "brute_force",
    "lateral_movement",
    "c2_beacon",
    "exfiltration",
)

# "anomaly" is emitted by the unsupervised detector, never by the classifier.
ANOMALY = "anomaly"


@dataclass(slots=True)
class Event:
    """One raw telemetry record, before any feature engineering.

    `label`, `campaign` and `lookalike` are simulation ground truth. The feature
    pipeline never reads them; they exist only for training and scoring.
    """

    ts: float
    layer: str  # network | endpoint | application
    kind: str  # flow | auth | process | http
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    duration: float = 0.0
    user: str | None = None
    outcome: str | None = None  # auth: success | failure
    method: str | None = None
    path: str | None = None
    status: int | None = None
    process: str | None = None
    label: str = "benign"
    campaign: str | None = None
    lookalike: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def telemetry(self) -> dict[str, Any]:
        """The record as a sensor would report it, without ground truth."""
        d = self.to_dict()
        for k in ("label", "campaign", "lookalike"):
            d.pop(k, None)
        return d


@dataclass(frozen=True, slots=True)
class Technique:
    key: str
    title: str
    tactic: str
    stage: int  # position in the kill chain, 0 = unstaged
    severity: str
    mitre: tuple[tuple[str, str], ...]


TECHNIQUES: dict[str, Technique] = {
    "recon": Technique(
        "recon", "Internal network scan", "Discovery", 1, "medium",
        (("T1046", "Network Service Discovery"),),
    ),
    "brute_force": Technique(
        "brute_force", "Credential brute force", "Credential Access", 2, "high",
        (("T1110", "Brute Force"), ("T1110.003", "Password Spraying")),
    ),
    "lateral_movement": Technique(
        "lateral_movement", "Lateral movement", "Lateral Movement", 3, "critical",
        (("T1021.002", "SMB/Windows Admin Shares"), ("T1570", "Lateral Tool Transfer")),
    ),
    "c2_beacon": Technique(
        "c2_beacon", "Command-and-control beaconing", "Command and Control", 4, "high",
        (("T1071.001", "Web Protocols"), ("T1573", "Encrypted Channel")),
    ),
    "exfiltration": Technique(
        "exfiltration", "Data exfiltration", "Exfiltration", 5, "critical",
        (("T1041", "Exfiltration Over C2 Channel"), ("T1048", "Exfiltration Over Alternative Protocol")),
    ),
    ANOMALY: Technique(
        ANOMALY, "Anomalous behaviour", "Unclassified", 0, "medium",
        (),
    ),
}

KILL_CHAIN = ("Discovery", "Credential Access", "Lateral Movement", "Command and Control", "Exfiltration")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
