"""Turns scored events into analyst-facing alerts and cross-layer incidents."""

from __future__ import annotations

import itertools
import statistics
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

from . import playbooks
from .environment import Environment, is_internal
from .features import FeatureExtractor
from .model import Detector, Verdict
from .schema import ANOMALY, KILL_CHAIN, SEVERITY_RANK, TECHNIQUES, THREAT_CLASSES, Event

ALERT_MERGE_GAP = 900.0  # an alert absorbs new detections for 15 sim-minutes
ANOMALY_MIN_HITS = 5  # anomalous events from one source before an anomaly alert
ANOMALY_WINDOW = 300.0
INCIDENT_WINDOW = 1800.0  # max quiet gap between linked alerts
PIVOT_SLACK = 60.0
EXPLAIN_REFRESH = 0.1
CLOSED = ("resolved", "false_positive")
RANKED_SEVERITIES = sorted(SEVERITY_RANK, key=SEVERITY_RANK.get)


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_duration(s: float) -> str:
    return f"{s:.0f}s" if s < 120 else f"{s / 60:.1f} min"


def _lower(severity: str) -> str:
    return RANKED_SEVERITIES[max(0, SEVERITY_RANK[severity] - 1)]


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
@dataclass
class Alert:
    id: str
    threat: str
    detector: str
    entity: str
    hostname: str | None
    role: str
    first_seen: float
    last_seen: float
    confidence: float
    status: str = "open"
    severity: str = "medium"
    event_count: int = 0
    layers: Counter = field(default_factory=Counter)
    targets: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    users: Counter = field(default_factory=Counter)
    compromised_users: set[str] = field(default_factory=set)
    auth_failures: int = 0
    bytes_out: int = 0
    suspicious_processes: Counter = field(default_factory=Counter)
    beacon_times: deque = field(default_factory=lambda: deque(maxlen=32))
    explanation: list[dict] = field(default_factory=list)
    explained_at: float = -1.0
    class_probs: dict[str, float] = field(default_factory=dict)
    evidence: deque = field(default_factory=lambda: deque(maxlen=12))
    truth: Counter = field(default_factory=Counter)
    campaigns: set[str] = field(default_factory=set)
    incident_id: str | None = None
    notes: list[dict] = field(default_factory=list)
    revision: int = 0

    @property
    def technique(self):
        return TECHNIQUES[self.threat]

    @property
    def is_open(self) -> bool:
        return self.status not in CLOSED

    def absorb(self, e: Event, verdict: Verdict) -> None:
        self.event_count += 1
        self.last_seen = max(self.last_seen, e.ts)
        self.layers[e.layer] += 1
        if e.kind != "process":
            self.targets[e.dst_ip] += 1
        if e.dst_port:
            self.ports[e.dst_port] += 1
        if e.user:
            self.users[e.user] += 1
        if e.kind == "auth":
            if e.outcome == "failure":
                self.auth_failures += 1
            else:
                self.compromised_users.add(e.user or "?")
        if e.kind == "http" and e.status == 200 and e.path and "login" in e.path and e.user:
            self.compromised_users.add(e.user)
        if e.kind == "process":
            self.suspicious_processes[e.process or "?"] += 1
            if e.user:
                self.compromised_users.add(e.user)
        if not is_internal(e.dst_ip):
            self.bytes_out += e.bytes_out
        if e.kind == "flow":
            self.beacon_times.append((e.dst_ip, e.ts))
        self.confidence = max(self.confidence, verdict.confidence)
        self.evidence.append(e.telemetry())
        self.truth["malicious" if e.label != "benign" else "benign"] += 1
        if e.campaign:
            self.campaigns.add(e.campaign)

    # ----------------------------------------------------------- narrative
    def context(self) -> dict[str, str]:
        top_targets = [t for t, _ in self.targets.most_common(4)]
        external = [t for t, _ in self.targets.most_common() if not is_internal(t)]
        users = sorted(self.compromised_users) or [u for u, _ in self.users.most_common(3)]
        return {
            "src": self.entity,
            "host": f"{self.hostname} ({self.entity})" if self.hostname else self.entity,
            "targets": ", ".join(top_targets) + (f" +{len(self.targets) - 4} more" if len(self.targets) > 4 else ""),
            "target": top_targets[0] if top_targets else "the target",
            "users": ", ".join(users[:4]) or "unknown accounts",
            "dst": external[0] if external else (top_targets[0] if top_targets else "unknown"),
            "bytes_out": fmt_bytes(self.bytes_out),
        }

    def summary(self) -> str:
        c = self.context()
        n_targets = len(self.targets)
        if self.threat == "recon":
            return f"{c['host']} probed {n_targets} hosts across {len(self.ports)} ports with short, empty connections."
        if self.threat == "brute_force":
            extra = f" {len(self.compromised_users)} account(s) then logged in successfully." if self.compromised_users else ""
            return f"{self.auth_failures:,} failed logins against {len(self.users)} accounts from {c['host']}.{extra}"
        if self.threat == "lateral_movement" and not n_targets:
            procs = ", ".join(list(self.suspicious_processes)[:2]) or "remote tooling"
            return f"Remote execution on {c['host']} as {c['users']}: {procs}."
        if self.threat == "lateral_movement":
            procs = f" Remote execution seen: {', '.join(list(self.suspicious_processes)[:2])}." if self.suspicious_processes else ""
            return f"{c['users']} authenticated from {c['host']} to {n_targets} internal hosts over admin protocols.{procs}"
        if self.threat == "c2_beacon":
            gap = self.beacon_interval()
            timing = f" roughly every {fmt_duration(gap)}" if gap else ""
            return f"{c['host']} keeps calling back to {c['dst']}{timing} with near-constant payload sizes."
        if self.threat == "exfiltration":
            return f"{c['host']} has sent {c['bytes_out']} to {c['dst']}, a destination almost no other host uses."
        return f"{c['host']} behaves unlike anything in its baseline ({self.event_count} unusual events)."

    def beacon_interval(self) -> float | None:
        by_dst: dict[str, list[float]] = defaultdict(list)
        for dst, ts in self.beacon_times:
            by_dst[dst].append(ts)
        times = max(by_dst.values(), key=len, default=[])
        if len(times) < 3:
            return None
        return statistics.median(b - a for a, b in zip(times, times[1:]))

    def to_dict(self, full: bool = True) -> dict:
        t = self.technique
        d = {
            "id": self.id,
            "threat": self.threat,
            "title": t.title,
            "tactic": t.tactic,
            "stage": t.stage,
            "mitre": [{"id": i, "name": n} for i, n in t.mitre],
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "detector": self.detector,
            "status": self.status,
            "entity": self.entity,
            "hostname": self.hostname,
            "role": self.role,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "layers": sorted(self.layers),
            "summary": self.summary(),
            "incident_id": self.incident_id,
            "target_count": len(self.targets),
            "ground_truth": "malicious" if self.truth["malicious"] >= self.truth["benign"] else "benign",
            "revision": self.revision,
        }
        if full:
            d.update(
                targets=[{"ip": ip, "count": n} for ip, n in self.targets.most_common(10)],
                ports=[p for p, _ in self.ports.most_common(10)],
                users=[u for u, _ in self.users.most_common(10)],
                compromised_users=sorted(self.compromised_users),
                bytes_out=self.bytes_out,
                auth_failures=self.auth_failures,
                layer_counts=dict(self.layers),
                explanation=self.explanation,
                class_probs=self.class_probs,
                evidence=list(self.evidence),
                playbook=playbooks.render(self.threat, self.context()),
                notes=self.notes,
            )
        return d


class AlertManager:
    def __init__(self, detector: Detector, env: Environment, max_alerts: int = 2000):
        self.detector = detector
        self.env = env
        self.alerts: dict[str, Alert] = {}
        self._open: dict[tuple[str, str], Alert] = {}
        self._anomaly_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=ANOMALY_MIN_HITS * 4))
        self._ids = itertools.count(1)
        self.max_alerts = max_alerts
        # campaign id -> {stage label -> first detection time}
        self.detections: dict[str, dict[str, float]] = defaultdict(dict)

    def ingest(self, events: list[Event], X: np.ndarray, probs: np.ndarray, verdicts: list[Verdict | None]) -> set[str]:
        touched: set[str] = set()
        for i, (e, v) in enumerate(zip(events, verdicts)):
            if v is None:
                continue
            if v.threat == ANOMALY:
                hits = self._anomaly_hits[e.src_ip]
                hits.append(e.ts)
                recent = sum(1 for t in hits if t >= e.ts - ANOMALY_WINDOW)
                if recent < ANOMALY_MIN_HITS and (e.src_ip, ANOMALY) not in self._open:
                    continue
            alert = self._alert_for(e, v)
            alert.absorb(e, v)
            if alert.confidence - alert.explained_at >= EXPLAIN_REFRESH or not alert.explanation:
                alert.explanation = self.detector.explain(X[i], v.threat)
                alert.explained_at = alert.confidence
                alert.class_probs = {c: round(float(p), 3) for c, p in zip(THREAT_CLASSES, probs[i])}
            alert.severity = self._severity(alert)
            alert.revision += 1
            touched.add(alert.id)
            if e.campaign:
                self.detections[e.campaign].setdefault(e.label, e.ts)
        self._trim()
        return touched

    def _alert_for(self, e: Event, v: Verdict) -> Alert:
        key = (e.src_ip, v.threat)
        alert = self._open.get(key)
        if alert and alert.is_open and e.ts - alert.last_seen <= ALERT_MERGE_GAP:
            return alert
        alert = Alert(
            id=f"AL-{next(self._ids):05d}",
            threat=v.threat,
            detector=v.detector,
            entity=e.src_ip,
            hostname=self.env.hostname(e.src_ip),
            role=self.env.role_of(e.src_ip),
            first_seen=e.ts,
            last_seen=e.ts,
            confidence=v.confidence,
        )
        self.alerts[alert.id] = alert
        self._open[key] = alert
        return alert

    @staticmethod
    def _severity(alert: Alert) -> str:
        sev = alert.technique.severity
        if alert.detector == "supervised" and alert.confidence < 0.75:
            sev = _lower(sev)
        return sev

    def _trim(self) -> None:
        if len(self.alerts) <= self.max_alerts:
            return
        for aid in list(self.alerts)[: len(self.alerts) - self.max_alerts]:
            alert = self.alerts.pop(aid)
            if self._open.get((alert.entity, alert.threat)) is alert:
                del self._open[(alert.entity, alert.threat)]

    def set_status(self, alert_id: str, status: str, note: str | None, now: float) -> Alert:
        alert = self.alerts[alert_id]
        alert.status = status
        if note:
            alert.notes.append({"ts": now, "text": note, "status": status})
        alert.revision += 1
        return alert


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #
@dataclass
class Incident:
    id: str
    alert_ids: list[str]
    created_at: float
    status: str = "open"
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "status": self.status, "created_at": self.created_at,
                "alert_ids": self.alert_ids, **self.data}


class Correlator:
    """Groups alerts into incidents by walking an entity graph.

    Two alerts join when they share a host, an account that was used
    successfully, or an external endpoint, and happen within a few hours of
    each other. A lateral-movement alert also links its source to every host it
    reached, which is how a pivot chain across machines becomes one incident.
    """

    def __init__(self, env: Environment):
        self.env = env
        self.incidents: dict[str, Incident] = {}
        self._ids = itertools.count(1)

    @staticmethod
    def own_keys(a: Alert) -> set[str]:
        """What the alert's actor *is*: its source host and accounts it used successfully."""
        return {f"ip:{a.entity}"} | {f"user:{u}" for u in a.compromised_users}

    @staticmethod
    def reach_keys(a: Alert) -> set[str]:
        """What the actor touched in a way that matters for the story."""
        if a.threat == "lateral_movement":
            return {f"ip:{t}" for t, _ in a.targets.most_common(20)}
        if a.threat in ("exfiltration", "c2_beacon"):
            return {f"ip:{t}" for t, _ in a.targets.most_common(3) if not is_internal(t)}
        if a.threat == "brute_force" and a.compromised_users:
            return {f"ip:{t}" for t, _ in a.targets.most_common(3)}
        return set()

    def linked(self, a: Alert, b: Alert) -> bool:
        """Two alerts belong together when one actor pivots into the other
        (a's target is b's source), they share an identity, they share
        external attacker infrastructure, or the same technique hits the same
        target at the same time (a distributed attack)."""
        if b.first_seen - a.last_seen > INCIDENT_WINDOW or a.first_seen - b.last_seen > INCIDENT_WINDOW:
            return False
        own_a, own_b = self.own_keys(a), self.own_keys(b)
        reach_a, reach_b = self.reach_keys(a), self.reach_keys(b)
        if own_a & own_b:
            return True
        # A pivot is causal: the host that was reached acts after it was reached.
        if reach_a & own_b and b.last_seen >= a.first_seen - PIVOT_SLACK:
            return True
        if reach_b & own_a and a.last_seen >= b.first_seen - PIVOT_SLACK:
            return True
        shared = reach_a & reach_b
        if any(not is_internal(k[3:]) for k in shared):
            return True
        return bool(shared) and a.threat == b.threat and a.first_seen <= b.last_seen and b.first_seen <= a.last_seen

    def update(self, alerts: dict[str, Alert], now: float) -> set[str]:
        live = [a for a in alerts.values() if a.status != "false_positive" and a.last_seen >= now - 6 * 3600]
        parent = {a.id: a.id for a in live}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        # Only alerts that share at least one key can be linked, so bucket by key first.
        by_key: dict[str, list[Alert]] = defaultdict(list)
        for a in live:
            for k in self.own_keys(a) | self.reach_keys(a):
                by_key[k].append(a)
        for group in by_key.values():
            for i, a in enumerate(group):
                for b in group[i + 1:]:
                    if find(a.id) != find(b.id) and self.linked(a, b):
                        parent[find(b.id)] = find(a.id)

        components: dict[str, list[Alert]] = defaultdict(list)
        for a in live:
            components[find(a.id)].append(a)

        changed: set[str] = set()
        for members in components.values():
            if not self._qualifies(members):
                continue
            ids = {a.id for a in members}
            existing = sorted(
                (inc for inc in self.incidents.values() if ids & set(inc.alert_ids)),
                key=lambda inc: inc.created_at,
            )
            if existing:
                inc = existing[0]
                for dup in existing[1:]:
                    del self.incidents[dup.id]
                    changed.add(dup.id)
            else:
                inc = Incident(f"IN-{next(self._ids):04d}", [], now)
                self.incidents[inc.id] = inc
            data = self._describe(members)
            new_ids = sorted(ids)
            if new_ids != inc.alert_ids or data != inc.data:
                inc.alert_ids = new_ids
                inc.data = data
                changed.add(inc.id)
            for a in members:
                a.incident_id = inc.id
        return changed

    @staticmethod
    def _qualifies(members: list[Alert]) -> bool:
        threats = {a.threat for a in members}
        layers = set().union(*(a.layers for a in members))
        if len(members) >= 2 and (len(threats) >= 2 or len({a.entity for a in members}) >= 2):
            return True
        return any(len(a.layers) >= 2 and SEVERITY_RANK[a.severity] >= 2 for a in members) and len(layers) >= 2

    def _describe(self, members: list[Alert]) -> dict:
        members = sorted(members, key=lambda a: a.first_seen)
        stages: dict[str, dict] = {}
        for a in members:
            t = a.technique
            s = stages.setdefault(t.tactic, {"tactic": t.tactic, "threat": a.threat, "title": t.title,
                                              "stage": t.stage, "first_seen": a.first_seen, "alert_ids": []})
            s["alert_ids"].append(a.id)
        ordered = sorted(stages.values(), key=lambda s: (s["stage"] or 99, s["first_seen"]))
        tactics = [s["tactic"] for s in ordered]
        chain = [s for s in ordered if s["tactic"] in KILL_CHAIN]

        severity = max((a.severity for a in members), key=SEVERITY_RANK.get)
        if len(chain) >= 3:
            severity = "critical"
        elif len(chain) >= 2 and SEVERITY_RANK[severity] < 2:
            severity = "high"
        confidence = max(a.confidence for a in members)
        risk = min(100, round(confidence * (40 + 15 * SEVERITY_RANK[severity]) + 8 * max(0, len(chain) - 1)))

        entities = []
        for ip in dict.fromkeys(ip for a in members for ip in [a.entity]):
            entities.append({"ip": ip, "hostname": self.env.hostname(ip), "role": self.env.role_of(ip)})
        first = members[0]
        origin = first.hostname or first.entity
        if len(chain) >= 2:
            title = f"Multi-stage attack from {origin}: {' → '.join(s['tactic'] for s in chain)}"
        else:
            title = f"{first.technique.title} from {origin} across {len(set().union(*(a.layers for a in members)))} layers"

        story = [
            {"ts": a.first_seen, "alert_id": a.id, "threat": a.threat, "text": a.summary()}
            for a in members
        ]
        mitre = list(dict.fromkeys(f"{i} {n}" for a in members for i, n in a.technique.mitre))
        steps: dict[str, list[str]] = {p: [] for p in playbooks.PHASES}
        for a in sorted(members, key=lambda a: -SEVERITY_RANK[a.severity]):
            for phase, items in playbooks.render(a.threat, a.context()).items():
                for step in items:
                    if step not in steps[phase]:
                        steps[phase].append(step)
        return {
            "title": title,
            "severity": severity,
            "risk": risk,
            "confidence": round(confidence, 3),
            "first_seen": first.first_seen,
            "last_seen": max(a.last_seen for a in members),
            "tactics": tactics,
            "stages": ordered,
            "entities": entities,
            "users": sorted(set().union(*(a.compromised_users for a in members))),
            "layers": sorted(set().union(*(a.layers for a in members))),
            "mitre": mitre,
            "story": story,
            "playbook": {p: s[:6] for p, s in steps.items()},
            "alert_count": len(members),
        }


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class DetectionEngine:
    def __init__(self, detector: Detector, env: Environment):
        self.detector = detector
        self.env = env
        dcs = frozenset({env.dc.ip, env.servers[5].ip})
        self.extractor = FeatureExtractor(env.role_of, dcs)
        self.alerts = AlertManager(detector, env)
        self.correlator = Correlator(env)
        self.events_processed = 0
        self.flagged_events = 0
        self.last_verdicts: list[Verdict | None] = []

    def warmup(self, events: list[Event]) -> None:
        for e in events:
            self.extractor.update(e)

    def featurize(self, events: list[Event]) -> np.ndarray:
        return np.asarray([self.extractor.update(e) for e in events], dtype=np.float64)

    def process(self, events: list[Event], now: float | None = None) -> tuple[set[str], set[str]]:
        if not events:
            self.last_verdicts = []
            return set(), set()
        X = self.featurize(events)
        probs, _, verdicts = self.detector.score(X)
        self.last_verdicts = verdicts
        self.events_processed += len(events)
        self.flagged_events += sum(v is not None for v in verdicts)
        touched = self.alerts.ingest(events, X, probs, verdicts)
        incidents: set[str] = set()
        if touched:
            incidents = self.correlator.update(self.alerts.alerts, now if now is not None else events[-1].ts)
        return touched, incidents
