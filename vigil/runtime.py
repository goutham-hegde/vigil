"""The live engine: a simulated clock, ambient traffic, scenario injection and
an event feed the dashboard subscribes to."""

from __future__ import annotations

import asyncio
import heapq
import itertools
import json
import random
import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .detection import DetectionEngine
from .environment import Environment
from .model import Detector
from .schema import LAYERS, SEVERITY_RANK, TECHNIQUES, Event
from .simulator import SCENARIOS, Background, Campaign

TICK = 0.25
MAX_BATCH = 4000
SERIES_MINUTES = 90

SCENARIO_CATALOG: list[dict] = [
    {
        "id": "intrusion_chain",
        "name": "Full intrusion kill chain",
        "summary": "A phished workstation calls home, scans the network, sprays passwords at a server, "
                   "moves laterally with PsExec-style execution and stages data out through a server.",
        "stages": ["c2_beacon", "recon", "brute_force", "lateral_movement", "exfiltration"],
        "layers": ["network", "endpoint"],
        "duration_min": 35,
        "difficulty": "Advanced",
        "expectation": "One critical cross-layer incident covering every stage.",
    },
    {
        "id": "credential_stuffing",
        "name": "Credential stuffing",
        "summary": "A small botnet replays leaked passwords against the public login page and gets a few accounts in.",
        "stages": ["brute_force"],
        "layers": ["application", "endpoint"],
        "duration_min": 6,
        "difficulty": "Basic",
        "expectation": "High-severity brute-force alerts corroborated by app and auth logs.",
    },
    {
        "id": "c2_exfil",
        "name": "C2 implant and exfiltration",
        "summary": "A malicious launcher installs an implant that beacons on a jittered timer, then ships data out in chunks.",
        "stages": ["c2_beacon", "exfiltration"],
        "layers": ["endpoint", "network"],
        "duration_min": 45,
        "difficulty": "Intermediate",
        "expectation": "Beaconing caught from timing regularity, then an exfiltration alert in the same incident.",
    },
    {
        "id": "low_and_slow",
        "name": "Low-and-slow password guessing",
        "summary": "One guess every 15–60 seconds for over an hour, built to stay under per-minute lockout rules.",
        "stages": ["brute_force"],
        "layers": ["endpoint", "application"],
        "duration_min": 90,
        "difficulty": "Evasive",
        "expectation": "Detected from hour-long failure counts even though no 5-minute window looks unusual.",
    },
    {
        "id": "benign_noise",
        "name": "Benign look-alikes",
        "summary": "Nightly backup, a vulnerability scan, a load test, a forgotten password, a big cloud upload "
                   "and an admin's RDP session: each resembles an attack.",
        "stages": [],
        "layers": ["network", "endpoint", "application"],
        "duration_min": 25,
        "difficulty": "False-positive test",
        "expectation": "Few or no alerts. Each alert raised here is a false positive.",
    },
    {
        "id": "dns_tunnel",
        "name": "DNS tunnelling (held out)",
        "summary": "Data smuggled in DNS-sized packets straight to an attacker's name server. "
                   "The classifier never trained on this technique.",
        "stages": ["exfiltration"],
        "layers": ["network"],
        "duration_min": 12,
        "difficulty": "Novel",
        "expectation": "Tests generalisation: flagged as exfiltration, C2 or an anomaly.",
        "held_out": True,
    },
]


@dataclass
class SimulationRun:
    id: str
    scenario: str
    campaign: Campaign
    intensity: float
    started_at: float
    real_started_at: float
    status: str = "running"
    emitted: int = 0
    ended_at: float | None = None

    def to_dict(self, engine: DetectionEngine) -> dict:
        detections = engine.alerts.detections.get(self.campaign.id, {})
        alerts = [a for a in engine.alerts.alerts.values() if self.campaign.id in a.campaigns]
        stages = []
        for label, ts in self.campaign.stages.items():
            det = detections.get(label)
            stages.append({
                "threat": label,
                "title": TECHNIQUES[label].title,
                "tactic": TECHNIQUES[label].tactic,
                "started_at": ts,
                "detected_at": det,
                "time_to_detect": None if det is None else round(det - ts, 1),
            })
        first_stage = min(self.campaign.stages.values(), default=None)
        first_det = min(detections.values(), default=None)
        malicious = self.scenario != "benign_noise"
        return {
            "id": self.id,
            "campaign_id": self.campaign.id,
            "scenario": self.scenario,
            "name": next(s["name"] for s in SCENARIO_CATALOG if s["id"] == self.scenario),
            "status": self.status,
            "intensity": self.intensity,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "sim_start": self.campaign.start,
            "sim_end": self.campaign.end,
            "total_events": len(self.campaign.events),
            "emitted": self.emitted,
            "progress": round(self.emitted / max(1, len(self.campaign.events)), 3),
            "entities": self.campaign.entities[:8],
            "stages": stages,
            "alert_ids": [a.id for a in alerts],
            "incident_ids": sorted({a.incident_id for a in alerts if a.incident_id}),
            "false_alerts": len(alerts) if not malicious else 0,
            "time_to_detect": None if first_det is None or first_stage is None else round(first_det - first_stage, 1),
            "detected": bool(detections) if malicious else None,
        }


@dataclass
class _Bucket:
    minute: int
    layers: Counter = field(default_factory=Counter)
    alerts: Counter = field(default_factory=Counter)
    flagged: int = 0


class Runtime:
    def __init__(self, detector: Detector, env: Environment | None = None, speed: float = 30.0,
                 ambient: bool = True, feedback_path: Path | None = None, sim_start: float | None = None):
        self.detector = detector
        self.env = env or Environment()
        self.speed = speed
        self.ambient = ambient
        self.paused = False
        self.feedback_path = feedback_path
        self._sim_origin = sim_start or self._default_start()
        self._lock = threading.RLock()
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._run_ids = itertools.count(1)
        self._seq = itertools.count()
        self.rng = random.Random()
        self._reset_state()

    @staticmethod
    def _default_start() -> float:
        today = datetime.now(timezone.utc).replace(hour=9, minute=30, second=0, microsecond=0)
        return today.timestamp()

    def _reset_state(self) -> None:
        self.now = self._sim_origin
        self.engine = DetectionEngine(self.detector, self.env)
        self.background = Background(self.env, self.rng.randrange(1 << 30))
        self.pending: list[tuple[float, int, Event]] = []
        self.runs: dict[str, SimulationRun] = {}
        self.series: deque[_Bucket] = deque(maxlen=SERIES_MINUTES)
        self.layer_totals: Counter = Counter()
        self.recent: deque[dict] = deque(maxlen=60)
        self._eps: deque[tuple[float, int]] = deque(maxlen=40)
        self.engine.warmup(self._generate_warmup())

    def _generate_warmup(self) -> list[Event]:
        out: list[Event] = []
        t = self.now - 1800
        while t < self.now:
            out += self.background.generate(t, min(t + 300, self.now))
            t += 300
        return out

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        last = time.monotonic()
        last_tick = 0.0
        while True:
            await asyncio.sleep(TICK)
            now_real = time.monotonic()
            dt = now_real - last
            last = now_real
            messages = await asyncio.to_thread(self.step, dt)
            for kind, payload in messages:
                self.publish(kind, payload)
            if now_real - last_tick >= 1.0:
                last_tick = now_real
                self.publish("tick", self.overview())

    def step(self, dt: float) -> list[tuple[str, dict]]:
        """Advance simulated time by dt real seconds and process what happened."""
        with self._lock:
            if self.paused:
                self._eps.append((time.monotonic(), 0))
                return []
            start = self.now
            self.now += dt * self.speed
            if self.ambient:
                for e in self.background.generate(start, self.now):
                    self._push(e)
            batch: list[Event] = []
            while self.pending and self.pending[0][0] <= self.now and len(batch) < MAX_BATCH:
                batch.append(heapq.heappop(self.pending)[2])
            touched, incidents = self.engine.process(batch, self.now)
            self._eps.append((time.monotonic(), len(batch)))
            return self._record(batch, touched, incidents)

    def _push(self, e: Event) -> None:
        heapq.heappush(self.pending, (e.ts, next(self._seq), e))

    def _record(self, batch: list[Event], touched: set[str], incidents: set[str]) -> list[tuple[str, dict]]:
        verdicts = self.engine.last_verdicts
        by_run = Counter(e.campaign for e in batch if e.campaign)
        for e, v in zip(batch, verdicts):
            minute = int(e.ts // 60)
            if not self.series or self.series[-1].minute < minute:
                self.series.append(_Bucket(minute))
            bucket = self.series[-1] if self.series[-1].minute == minute else None
            if bucket:
                bucket.layers[e.layer] += 1
                bucket.flagged += v is not None
            self.layer_totals[e.layer] += 1
        sample = batch[-24:] if len(batch) > 24 else batch
        flagged = [(e, v) for e, v in zip(batch, verdicts) if v is not None][-8:]
        for e, v in [*((e, None) for e in sample), *flagged]:
            self.recent.append({**e.telemetry(), "threat": v.threat if v else None})

        messages: list[tuple[str, dict]] = []
        alerts = self.engine.alerts.alerts
        for aid in touched:
            a = alerts.get(aid)
            if a is None:
                continue
            if a.revision == 1 and self.series:
                self.series[-1].alerts[a.severity] += 1
            messages.append(("alert", a.to_dict(full=False)))
        for iid in incidents:
            inc = self.engine.correlator.incidents.get(iid)
            messages.append(("incident", inc.to_dict() if inc else {"id": iid, "deleted": True}))

        for run in self.runs.values():
            if run.status != "running":
                continue
            run.emitted += by_run.get(run.campaign.id, 0)
            if run.emitted >= len(run.campaign.events):
                run.status = "completed"
                run.ended_at = self.now
            if by_run.get(run.campaign.id) or run.status == "completed" or touched:
                messages.append(("run", run.to_dict(self.engine)))
        if batch:
            messages.append(("telemetry", {"events": list(self.recent)[-20:]}))
        return messages

    # ---------------------------------------------------------------- pubsub
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, kind: str, payload: dict) -> None:
        msg = f"event: {kind}\ndata: {json.dumps(payload, default=str)}\n\n"
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # A client that stops reading gets dropped rather than stalling everyone.
                self._subscribers.discard(q)

    def publish_threadsafe(self, kind: str, payload: dict) -> None:
        if self._loop:
            self._loop.call_soon_threadsafe(self.publish, kind, payload)

    # ------------------------------------------------------------- commands
    def launch(self, scenario: str, intensity: float = 1.0) -> dict:
        if scenario not in SCENARIOS:
            raise KeyError(scenario)
        with self._lock:
            campaign = SCENARIOS[scenario](self.env, self.rng, self.now + 3, intensity=intensity)
            for e in campaign.events:
                self._push(e)
            run = SimulationRun(f"RUN-{next(self._run_ids):03d}", scenario, campaign, intensity, self.now, time.time())
            self.runs[run.id] = run
            data = run.to_dict(self.engine)
        self.publish_threadsafe("run", data)
        return data

    def stop_run(self, run_id: str) -> dict:
        with self._lock:
            run = self.runs[run_id]
            if run.status == "running":
                self.pending = [p for p in self.pending if p[2].campaign != run.campaign.id]
                heapq.heapify(self.pending)
                run.status = "stopped"
                run.ended_at = self.now
            data = run.to_dict(self.engine)
        self.publish_threadsafe("run", data)
        return data

    def ingest(self, events: list[Event]) -> int:
        with self._lock:
            for e in events:
                self._push(e)
        return len(events)

    def update_settings(self, speed: float | None = None, ambient: bool | None = None, paused: bool | None = None) -> dict:
        with self._lock:
            if speed is not None:
                self.speed = speed
            if ambient is not None:
                self.ambient = ambient
            if paused is not None:
                self.paused = paused
            data = self.settings()
        self.publish_threadsafe("settings", data)
        return data

    def settings(self) -> dict:
        return {"speed": self.speed, "ambient": self.ambient, "paused": self.paused}

    def reset(self) -> None:
        with self._lock:
            self._reset_state()
        self.publish_threadsafe("reset", {"now": self.now})

    def set_alert_status(self, alert_id: str, status: str, note: str | None) -> dict:
        with self._lock:
            alert = self.engine.alerts.set_status(alert_id, status, note, self.now)
            self.engine.correlator.update(self.engine.alerts.alerts, self.now)
            data = alert.to_dict()
        if self.feedback_path:
            self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "alert_id": alert_id, "status": status, "note": note, "threat": data["threat"],
                "detector": data["detector"], "confidence": data["confidence"], "entity": data["entity"],
                "explanation": data["explanation"], "evidence": data["evidence"][-5:],
            }
            with self.feedback_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        self.publish_threadsafe("alert", {k: v for k, v in data.items() if k in _SUMMARY_KEYS})
        return data

    # ----------------------------------------------------------------- views
    def alerts(self) -> list[dict]:
        with self._lock:
            return [a.to_dict(full=False) for a in reversed(self.engine.alerts.alerts.values())]

    def alert(self, alert_id: str) -> dict:
        with self._lock:
            return self.engine.alerts.alerts[alert_id].to_dict()

    def incidents(self) -> list[dict]:
        with self._lock:
            return sorted((i.to_dict() for i in self.engine.correlator.incidents.values()),
                          key=lambda d: -d["last_seen"])

    def incident(self, incident_id: str) -> dict:
        with self._lock:
            inc = self.engine.correlator.incidents[incident_id].to_dict()
            alerts = self.engine.alerts.alerts
            inc["alerts"] = [alerts[a].to_dict(full=False) for a in inc["alert_ids"] if a in alerts]
            return inc

    def list_runs(self) -> list[dict]:
        with self._lock:
            return [r.to_dict(self.engine) for r in reversed(self.runs.values())]

    def events_per_second(self) -> float:
        cutoff = time.monotonic() - 5
        recent = [(t, n) for t, n in self._eps if t >= cutoff]
        if len(recent) < 2:
            return 0.0
        return sum(n for _, n in recent[1:]) / max(recent[-1][0] - recent[0][0], 1e-6)

    def overview(self) -> dict:
        with self._lock:
            alerts = list(self.engine.alerts.alerts.values())
            open_alerts = [a for a in alerts if a.is_open]
            incidents = [i for i in self.engine.correlator.incidents.values() if i.status == "open"]
            ttds = [r.to_dict(self.engine)["time_to_detect"] for r in self.runs.values() if r.scenario != "benign_noise"]
            ttds = [t for t in ttds if t is not None]
            entities: dict[str, dict] = {}
            for a in open_alerts:
                d = entities.setdefault(a.entity, {"ip": a.entity, "hostname": a.hostname, "role": a.role,
                                                   "alerts": 0, "severity": "low", "score": 0.0})
                d["alerts"] += 1
                d["score"] += a.confidence * (1 + SEVERITY_RANK[a.severity])
                if SEVERITY_RANK[a.severity] > SEVERITY_RANK[d["severity"]]:
                    d["severity"] = a.severity
            total_events = self.engine.events_processed
            return {
                "now": self.now,
                **self.settings(),
                "events_total": total_events,
                "events_per_second": round(self.events_per_second(), 1),
                "flagged_events": self.engine.flagged_events,
                "layer_totals": {layer: self.layer_totals.get(layer, 0) for layer in LAYERS},
                "alerts_total": len(alerts),
                "alerts_open": len(open_alerts),
                "open_by_severity": dict(Counter(a.severity for a in open_alerts)),
                "open_by_threat": dict(Counter(a.threat for a in open_alerts)),
                "alerts_by_status": dict(Counter(a.status for a in alerts)),
                "incidents_open": len(incidents),
                "critical_incidents": sum(1 for i in incidents if i.data.get("severity") == "critical"),
                "events_per_alert": round(total_events / len(alerts)) if alerts else None,
                "median_time_to_detect": round(statistics.median(ttds), 1) if ttds else None,
                "active_runs": sum(1 for r in self.runs.values() if r.status == "running"),
                "top_entities": sorted(entities.values(), key=lambda d: -d["score"])[:6],
                "model_version": self.detector.meta.get("version"),
                "series": [
                    {"t": b.minute * 60, **{layer: b.layers.get(layer, 0) for layer in LAYERS},
                     "flagged": b.flagged, "alerts": sum(b.alerts.values()),
                     **{f"alerts_{s}": b.alerts.get(s, 0) for s in SEVERITY_RANK}}
                    for b in self.series
                ],
            }


_SUMMARY_KEYS = {
    "id", "threat", "title", "tactic", "stage", "mitre", "severity", "confidence", "detector", "status", "entity",
    "hostname", "role", "first_seen", "last_seen", "event_count", "layers", "summary", "incident_id",
    "target_count", "ground_truth", "revision",
}
