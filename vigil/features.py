"""Streaming feature extraction.

`FeatureExtractor.update(event)` folds one raw event into per-entity state and
returns that entity's feature vector at that moment. Training replays simulated
telemetry through this same class, so the model trains on exactly the features
it will see when scoring live.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Callable

from .environment import ADMIN_PORTS, is_internal
from .schema import Event

SHORT_WINDOW = 300.0  # 5 min
LONG_WINDOW = 3600.0  # 1 h
PAIR_WINDOW = 1800.0  # 30 min
PAIR_HISTORY = 16
CLEANUP_EVERY = 20_000

SUSPICIOUS_TOKENS = (
    "-enc", "javascript:", "mshta", "regsvr32", "psexesvc", "wsmprovhost", "whoami", "wmic", "call create",
)


def suspicious_process(name: str | None) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return any(tok in lowered for tok in SUSPICIOUS_TOKENS)


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    label: str
    kind: str  # bool | count | ratio | bytes | seconds | number


def _spec(name: str, label: str, kind: str) -> FeatureSpec:
    return FeatureSpec(name, label, kind)


FEATURES: tuple[FeatureSpec, ...] = (
    _spec("ev_network", "Event is a network flow", "bool"),
    _spec("ev_endpoint", "Event is endpoint telemetry", "bool"),
    _spec("ev_application", "Event is an application log", "bool"),
    _spec("ev_admin_port", "Targets an admin port (SMB/RDP/SSH/WinRM)", "bool"),
    _spec("ev_dst_external", "Destination is outside the network", "bool"),
    _spec("ev_bytes_out", "Bytes sent in this event", "bytes"),
    _spec("ev_bytes_in", "Bytes received in this event", "bytes"),
    _spec("ev_duration", "Connection duration", "seconds"),
    _spec("ev_auth_failure", "Event is a failed login", "bool"),
    _spec("ev_http_4xx", "HTTP client error", "bool"),
    _spec("ev_login_path", "Request hits a login endpoint", "bool"),
    _spec("ev_proc_suspicious", "Suspicious process command line", "bool"),
    _spec("w_events", "Events from source (5 min)", "count"),
    _spec("w_flows", "Network flows from source (5 min)", "count"),
    _spec("w_uniq_dst", "Distinct destinations (5 min)", "count"),
    _spec("w_uniq_ports", "Distinct destination ports (5 min)", "count"),
    _spec("w_small_flow_ratio", "Share of tiny probe-like flows (5 min)", "ratio"),
    _spec("w_admin_port_ratio", "Share of flows to admin ports (5 min)", "ratio"),
    _spec("w_external_ratio", "Share of traffic leaving the network (5 min)", "ratio"),
    _spec("w_bytes_out", "Bytes sent by source (5 min)", "bytes"),
    _spec("w_bytes_in", "Bytes received by source (5 min)", "bytes"),
    _spec("w_out_in_skew", "Upload/download skew, log ratio (5 min)", "number"),
    _spec("w_auth_failures", "Failed logins (5 min)", "count"),
    _spec("w_auth_failure_ratio", "Failed share of logins (5 min)", "ratio"),
    _spec("w_uniq_users", "Distinct accounts used (5 min)", "count"),
    _spec("w_remote_logons", "Successful logons to non-DC hosts (5 min)", "count"),
    _spec("w_http", "HTTP requests (5 min)", "count"),
    _spec("w_http_4xx_ratio", "HTTP client-error share (5 min)", "ratio"),
    _spec("w_login_ratio", "Share of requests to login endpoints (5 min)", "ratio"),
    _spec("w_uniq_paths", "Distinct URL paths (5 min)", "count"),
    _spec("w_suspicious_procs", "Suspicious process launches (5 min)", "count"),
    _spec("h_auth_failures", "Failed logins (1 h)", "count"),
    _spec("h_uniq_failed_users", "Distinct accounts with failed logins (1 h)", "count"),
    _spec("h_external_bytes_out", "Bytes sent outside the network (1 h)", "bytes"),
    _spec("p_count", "Connections to this destination (30 min)", "count"),
    _spec("p_interval_mean", "Mean gap between connections to destination", "seconds"),
    _spec("p_interval_cv", "Timing irregularity to destination (CV)", "number"),
    _spec("p_size_cv", "Payload size variation to destination (CV)", "number"),
    _spec("dst_prevalence", "Internal hosts that ever contacted destination", "count"),
    _spec("src_workstation", "Source is a workstation", "bool"),
    _spec("src_server", "Source is a server", "bool"),
    _spec("src_infra", "Source is sanctioned IT tooling", "bool"),
    _spec("src_external", "Source is on the internet", "bool"),
    _spec("off_hours", "Outside business hours", "bool"),
)
FEATURE_NAMES = tuple(f.name for f in FEATURES)
N_FEATURES = len(FEATURES)
LOG_KINDS = frozenset({"count", "bytes", "seconds"})


def display_value(spec: FeatureSpec, x: float) -> str:
    """Turn a (possibly log-scaled) feature value back into readable text."""
    if spec.kind == "bool":
        return "yes" if x >= 0.5 else "no"
    if spec.kind == "ratio":
        return f"{x * 100:.0f}%"
    if spec.kind == "number":
        return f"{x:.2f}"
    raw = math.expm1(x)
    if spec.kind == "count":
        return f"{raw:,.0f}"
    if spec.kind == "seconds":
        return f"{raw:.1f}s" if raw < 120 else f"{raw / 60:.1f}m"
    for unit in ("B", "KB", "MB", "GB"):
        if raw < 1024:
            return f"{raw:.0f} {unit}" if unit == "B" else f"{raw:.1f} {unit}"
        raw /= 1024
    return f"{raw:.1f} TB"


_L = math.log1p

# Numeric accumulators kept per rolling window.
_N, _FLOW, _AUTH, _AUTH_FAIL, _REMOTE, _HTTP, _HTTP4XX, _LOGIN, _SUSP, _BOUT, _BIN, _EXT, _ADMIN, _SMALL = range(14)


class RollingWindow:
    """Sums and distinct-counts over a sliding time window, updated in O(1) amortised."""

    __slots__ = ("span", "q", "sums", "uniq")

    def __init__(self, span: float, n_sums: int, n_keys: int):
        self.span = span
        self.q: deque[tuple[float, tuple[float, ...], tuple]] = deque()
        self.sums = [0.0] * n_sums
        self.uniq: list[dict] = [{} for _ in range(n_keys)]

    def add(self, ts: float, nums: tuple[float, ...], keys: tuple) -> None:
        self.q.append((ts, nums, keys))
        sums = self.sums
        for i, v in enumerate(nums):
            sums[i] += v
        for d, k in zip(self.uniq, keys):
            if k is not None:
                d[k] = d.get(k, 0) + 1

    def evict(self, now: float) -> None:
        q = self.q
        cutoff = now - self.span
        sums = self.sums
        while q and q[0][0] < cutoff:
            _, nums, keys = q.popleft()
            for i, v in enumerate(nums):
                sums[i] -= v
            for d, k in zip(self.uniq, keys):
                if k is not None:
                    c = d[k] - 1
                    if c:
                        d[k] = c
                    else:
                        del d[k]


class _EntityState:
    __slots__ = ("short", "long", "last_seen")

    def __init__(self) -> None:
        self.short = RollingWindow(SHORT_WINDOW, 14, 4)  # keys: dst, port, user, path
        self.long = RollingWindow(LONG_WINDOW, 2, 1)  # sums: auth_fail, ext_bytes_out; keys: failed user
        self.last_seen = 0.0


def _cv(values: list[float]) -> float:
    n = len(values)
    mean = sum(values) / n
    if mean <= 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(var) / mean


class FeatureExtractor:
    def __init__(self, role_of: Callable[[str], str], domain_controllers: frozenset[str] = frozenset()):
        self.role_of = role_of
        self.domain_controllers = domain_controllers
        self.entities: dict[str, _EntityState] = {}
        self.pairs: dict[tuple[str, str], deque[tuple[float, int]]] = {}
        self.prevalence: dict[str, set[str]] = {}
        self._roles: dict[str, tuple[float, float, float, float]] = {}
        self._since_cleanup = 0

    def _role_vec(self, ip: str) -> tuple[float, float, float, float]:
        vec = self._roles.get(ip)
        if vec is None:
            role = self.role_of(ip)
            vec = (
                float(role == "workstation"),
                float(role in ("server", "internal-unknown")),
                float(role == "infra"),
                float(role == "external"),
            )
            self._roles[ip] = vec
        return vec

    def update(self, e: Event) -> list[float]:
        ts = e.ts
        state = self.entities.get(e.src_ip)
        if state is None:
            state = self.entities[e.src_ip] = _EntityState()
        state.last_seen = ts

        is_flow = e.kind == "flow"
        is_auth = e.kind == "auth"
        is_http = e.kind == "http"
        auth_fail = is_auth and e.outcome == "failure"
        remote_logon = is_auth and e.outcome == "success" and e.dst_ip not in self.domain_controllers
        http_4xx = is_http and e.status is not None and 400 <= e.status < 500
        login = is_http and e.path is not None and "login" in e.path
        susp = e.kind == "process" and suspicious_process(e.process)
        ext = not is_internal(e.dst_ip)
        admin = e.dst_port in ADMIN_PORTS
        small = is_flow and e.bytes_out < 100 and e.duration < 0.05

        state.short.add(ts, (
            1.0, float(is_flow), float(is_auth), float(auth_fail), float(remote_logon), float(is_http),
            float(http_4xx), float(login), float(susp), float(e.bytes_out), float(e.bytes_in),
            float(ext and e.kind != "process"), float(is_flow and admin), float(small),
        ), (
            e.dst_ip if e.kind != "process" else None,
            e.dst_port if is_flow else None,
            e.user if is_auth else None,
            e.path,
        ))
        state.short.evict(ts)
        state.long.add(ts, (float(auth_fail), float(e.bytes_out) if ext else 0.0),
                       (e.user if auth_fail else None,))
        state.long.evict(ts)

        # Per source→destination timing, the beaconing signal.
        p_count, p_mean, p_cv, p_size_cv = 0.0, 0.0, 1.0, 1.0
        if is_flow:
            key = (e.src_ip, e.dst_ip)
            hist = self.pairs.get(key)
            if hist is None:
                hist = self.pairs[key] = deque(maxlen=PAIR_HISTORY)
            hist.append((ts, e.bytes_out))
            while hist and hist[0][0] < ts - PAIR_WINDOW:
                hist.popleft()
            p_count = float(len(hist))
            if len(hist) >= 4:
                times = [h[0] for h in hist]
                gaps = [b - a for a, b in zip(times, times[1:])]
                p_mean = sum(gaps) / len(gaps)
                p_cv = _cv(gaps) if p_mean > 0 else 0.0
                p_size_cv = _cv([float(h[1]) for h in hist])

        prevalence = 0
        if e.kind in ("flow", "http"):
            seen = self.prevalence.get(e.dst_ip)
            if seen is None:
                seen = self.prevalence[e.dst_ip] = set()
            if len(seen) < 64 and is_internal(e.src_ip):
                seen.add(e.src_ip)
            prevalence = len(seen)

        s = state.short.sums
        n = s[_N]
        flows = s[_FLOW]
        auths = s[_AUTH]
        https = s[_HTTP]
        u_dst, u_port, u_user, u_path = (len(d) for d in state.short.uniq)
        role = self._role_vec(e.src_ip)
        hour = (ts % 86400) / 3600

        self._since_cleanup += 1
        if self._since_cleanup >= CLEANUP_EVERY:
            self.cleanup(ts)

        return [
            float(is_flow), float(e.layer == "endpoint"), float(e.layer == "application"),
            float(admin and e.kind != "process"), float(ext and e.kind != "process"),
            _L(e.bytes_out), _L(e.bytes_in), _L(e.duration),
            float(auth_fail), float(http_4xx), float(login), float(susp),
            _L(n), _L(flows), _L(u_dst), _L(u_port),
            s[_SMALL] / flows if flows else 0.0,
            s[_ADMIN] / flows if flows else 0.0,
            s[_EXT] / n if n else 0.0,
            _L(s[_BOUT]), _L(s[_BIN]), _L(s[_BOUT]) - _L(s[_BIN]),
            _L(s[_AUTH_FAIL]), s[_AUTH_FAIL] / auths if auths else 0.0, _L(u_user),
            _L(s[_REMOTE]),
            _L(https), s[_HTTP4XX] / https if https else 0.0, s[_LOGIN] / https if https else 0.0, _L(u_path),
            _L(s[_SUSP]),
            _L(state.long.sums[0]), _L(len(state.long.uniq[0])), _L(state.long.sums[1]),
            _L(p_count), _L(p_mean), p_cv, p_size_cv,
            _L(prevalence),
            *role,
            float(not (8 <= hour < 19)),
        ]

    def cleanup(self, now: float) -> None:
        """Drop state for entities and pairs that have gone quiet."""
        self._since_cleanup = 0
        stale = now - LONG_WINDOW
        for ip in [ip for ip, st in self.entities.items() if st.last_seen < stale]:
            del self.entities[ip]
        pair_stale = now - PAIR_WINDOW
        for key in [k for k, h in self.pairs.items() if not h or h[-1][0] < pair_stale]:
            del self.pairs[key]
        if len(self.prevalence) > 200_000:
            for dst in [d for d, s in self.prevalence.items() if len(s) <= 1]:
                del self.prevalence[dst]
