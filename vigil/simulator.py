"""Telemetry simulator: benign background traffic plus attack campaigns.

Every generator emits *raw* events (flows, auth records, process launches, HTTP
logs). Windowed behaviour such as "failed logins in the last five minutes" is
never written into the events; the feature pipeline has to derive it, exactly as
it would from real sensors.
"""

from __future__ import annotations

import math
import random
import uuid
from dataclasses import dataclass, field
from typing import Callable

from .environment import SCAN_PORTS, Asset, Environment
from .schema import Event

BENIGN_PROCESSES = (
    "chrome.exe", "msedge.exe", "outlook.exe", "teams.exe", "excel.exe", "winword.exe",
    "code.exe", "slack.exe", "explorer.exe", "onedrive.exe", "zoom.exe", "svchost.exe",
)
ADMIN_PROCESSES = ("powershell.exe", "mmc.exe", "mstsc.exe", "cmd.exe")
MALICIOUS_LAUNCHERS = (
    "rundll32.exe javascript:", "powershell.exe -nop -w hidden -enc", "mshta.exe http",
    "regsvr32.exe /s /i:http",
)
REMOTE_EXEC_PROCESSES = ("psexesvc.exe", "wsmprovhost.exe", "cmd.exe /c whoami /all", "wmic.exe process call create")
APP_PATHS = ("/", "/dashboard", "/api/orders", "/api/search", "/api/profile", "/static/app.js", "/api/reports", "/health")


def _lognormal(rng: random.Random, mu: float, sigma: float, lo: int = 1) -> int:
    return max(lo, int(rng.lognormvariate(mu, sigma)))


def business_factor(ts: float) -> float:
    hour = (ts % 86400) / 3600
    return 1.0 if 8 <= hour < 19 else 0.3


# --------------------------------------------------------------------------- #
# Background
# --------------------------------------------------------------------------- #
class Background:
    """Benign traffic for the whole organisation. Stateless between chunks, so
    it can be generated for any [t0, t1) window, live or offline."""

    WS_RATE = 1 / 25  # events per second per workstation, business hours
    SERVER_RATE = 1 / 12
    CUSTOMER_RATE = 0.8  # public web requests per second, business hours
    MONITOR_PERIOD = 15.0

    def __init__(self, env: Environment, seed: int = 0):
        self.env = env
        self.rng = random.Random(seed)
        prng = random.Random(seed + 1)
        self.sync_schedule = [
            (ws, prng.choice((60.0, 120.0, 300.0)), prng.uniform(0, 300), prng.choice(env.popular_external))
            for ws in env.sync_clients
        ]
        self.monitor_phase = {s.ip: prng.uniform(0, self.MONITOR_PERIOD) for s in env.servers}
        self.customers = [
            (env.attacker_ip(prng) if prng.random() < 0.3 else env.long_tail_external(prng), f"cust{i:04d}")
            for i in range(600)
        ]
        self._devs = {a.ip for a in env.developers}
        self._admins = {a.ip for a in env.admins}

    def generate(self, t0: float, t1: float, scale: float = 1.0) -> list[Event]:
        if t1 <= t0:
            return []
        out: list[Event] = []
        rng = self.rng
        env = self.env
        factor = business_factor(t0) * scale

        for ws in env.workstations:
            t = t0
            rate = self.WS_RATE * factor
            while True:
                t += rng.expovariate(rate)
                if t >= t1:
                    break
                out.append(self._workstation_event(ws, t))

        for srv in env.servers:
            t = t0
            rate = self.SERVER_RATE * max(factor, 0.5)
            while True:
                t += rng.expovariate(rate)
                if t >= t1:
                    break
                out.append(self._server_event(srv, t))

        t = t0
        while True:
            t += rng.expovariate(self.CUSTOMER_RATE * factor)
            if t >= t1:
                break
            out.extend(self._customer_events(t))

        for ws, period, phase, dst in self.sync_schedule:
            k = math.ceil((t0 - phase) / period)
            while (t := phase + k * period + rng.uniform(-2, 2)) < t1:
                if t >= t0:
                    out.append(Event(t, "network", "flow", ws.ip, dst, 443,
                                     rng.randint(300, 650), rng.randint(300, 900),
                                     rng.uniform(0.1, 0.4), lookalike=True))
                k += 1

        mon = env.monitor
        for srv in env.servers:
            phase = self.monitor_phase[srv.ip]
            k = math.ceil((t0 - phase) / self.MONITOR_PERIOD)
            while (t := phase + k * self.MONITOR_PERIOD) < t1:
                out.append(Event(t + rng.uniform(0, 0.3), "network", "flow", mon.ip, srv.ip, 9100,
                                 rng.randint(150, 260), rng.randint(2000, 9000), rng.uniform(0.01, 0.05)))
                k += 1

        out.sort(key=lambda e: e.ts)
        return out

    def _workstation_event(self, ws: Asset, t: float) -> Event:
        rng = self.rng
        env = self.env
        r = rng.random()
        if ws.ip in self._admins and r < 0.04:
            srv = rng.choice(env.servers)
            if rng.random() < 0.5:
                return Event(t, "endpoint", "auth", ws.ip, srv.ip, 3389, user=f"adm-{ws.owner}", outcome="success")
            return Event(t, "network", "flow", ws.ip, srv.ip, rng.choice((3389, 5985)),
                         _lognormal(rng, 9, 1), _lognormal(rng, 11, 1), rng.uniform(5, 120))
        if ws.ip in self._devs and r < 0.05:
            srv = rng.choice(env.servers[7:9])
            return Event(t, "network", "flow", ws.ip, srv.ip, 22,
                         _lognormal(rng, 8, 1), _lognormal(rng, 9, 1), rng.uniform(1, 60))
        if r < 0.025:
            # Attachments, cloud sync, the odd file-sharing site: big uploads are normal.
            dst = rng.choice(env.popular_external) if rng.random() < 0.75 else env.long_tail_external(rng)
            return Event(t, "network", "flow", ws.ip, dst, 443,
                         _lognormal(rng, 14.0, 1.4), _lognormal(rng, 8.0, 1.0), rng.uniform(2, 90))
        if r < 0.32:
            return Event(t, "network", "flow", ws.ip, rng.choice(env.popular_external), 443,
                         _lognormal(rng, 6.8, 1.0), _lognormal(rng, 9.5, 1.6), rng.expovariate(0.5))
        if r < 0.44:
            return Event(t, "network", "flow", ws.ip, env.long_tail_external(rng), rng.choice((80, 443, 443)),
                         _lognormal(rng, 6.5, 1.0), _lognormal(rng, 9.0, 1.8), rng.expovariate(0.5))
        if r < 0.62:
            return Event(t, "network", "flow", ws.ip, env.resolver.ip, 53,
                         rng.randint(55, 110), rng.randint(80, 320), rng.uniform(0.005, 0.05))
        if r < 0.76:
            srv = rng.choice((env.web, env.servers[7], env.servers[10], env.servers[11]))
            path = rng.choice(APP_PATHS)
            method = "GET"
            status = rng.choices((200, 304, 404, 500), (90, 5, 4, 1))[0]
            if rng.random() < 0.05:
                path, method = "/login", "POST"
                status = 200 if rng.random() < 0.93 else 401
            return Event(t, "application", "http", ws.ip, srv.ip, 443,
                         rng.randint(300, 2200), _lognormal(rng, 8, 1.2), rng.uniform(0.02, 0.8),
                         user=ws.owner, method=method, path=path, status=status)
        if r < 0.83:
            dc = rng.choice((env.dc, env.servers[5]))
            ok = rng.random() < 0.96
            return Event(t, "endpoint", "auth", ws.ip, dc.ip, 88, user=ws.owner,
                         outcome="success" if ok else "failure")
        if r < 0.90:
            fs = rng.choice((env.file_server, env.servers[6]))
            return Event(t, "network", "flow", ws.ip, fs.ip, 445,
                         _lognormal(rng, 7.2, 1.4), _lognormal(rng, 9.5, 2.0), rng.uniform(0.1, 10))
        if ws.ip in self._admins and rng.random() < 0.3:
            # IT scripts really do use encoded PowerShell now and then.
            proc = "powershell.exe -ExecutionPolicy Bypass -enc" if rng.random() < 0.1 else rng.choice(ADMIN_PROCESSES)
        else:
            proc = rng.choice(BENIGN_PROCESSES)
        return Event(t, "endpoint", "process", ws.ip, ws.ip, user=ws.owner, process=proc)

    def _customer_events(self, t: float) -> list[Event]:
        """Internet users of the public web app, including their typos."""
        rng = self.rng
        web = self.env.web.ip
        ip, user = self.customers[min(int(rng.paretovariate(1.2)) - 1, len(self.customers) - 1)]
        if rng.random() < 0.12:
            failures = rng.choices((0, 1, 2, 3), (70, 18, 8, 4))[0]
            out = []
            for k in range(failures + 1):
                ok = k == failures
                ts = t + k * rng.uniform(3, 15)
                out.append(Event(ts, "application", "http", ip, web, 443, rng.randint(350, 620),
                                 rng.randint(2000, 9000) if ok else rng.randint(150, 320), rng.uniform(0.05, 0.4),
                                 user=user, method="POST", path=rng.choice(("/login", "/api/auth/login")),
                                 status=200 if ok else 401))
                out.append(Event(ts + 0.02, "endpoint", "auth", ip, web, 443, user=user,
                                 outcome="success" if ok else "failure"))
            return out
        status = rng.choices((200, 304, 404, 403), (88, 6, 5, 1))[0]
        return [Event(t, "application", "http", ip, web, 443, rng.randint(300, 1500), _lognormal(rng, 9, 1.4),
                      rng.uniform(0.02, 0.9), method="GET", path=rng.choice(APP_PATHS), status=status)]

    def _server_event(self, srv: Asset, t: float) -> Event:
        rng = self.rng
        env = self.env
        r = rng.random()
        if srv.hostname.startswith(("web", "api", "hr", "erp")) and r < 0.6:
            return Event(t, "network", "flow", srv.ip, env.db.ip, 5432,
                         rng.randint(200, 1500), _lognormal(rng, 8.5, 1.5), rng.uniform(0.002, 0.2))
        if srv.hostname.startswith("dc") and r < 0.6:
            peer = env.servers[5] if srv is env.dc else env.dc
            return Event(t, "network", "flow", srv.ip, peer.ip, rng.choice((389, 445, 135)),
                         _lognormal(rng, 8, 1), _lognormal(rng, 8, 1), rng.uniform(0.01, 1))
        if srv.hostname.startswith("mail") and r < 0.6:
            return Event(t, "network", "flow", srv.ip, rng.choice(env.popular_external), 25,
                         _lognormal(rng, 9, 1.5), rng.randint(200, 900), rng.uniform(0.2, 3))
        if r < 0.8:
            return Event(t, "network", "flow", srv.ip, env.resolver.ip, 53,
                         rng.randint(55, 110), rng.randint(80, 320), rng.uniform(0.005, 0.05))
        return Event(t, "endpoint", "process", srv.ip, srv.ip, user="system",
                     process=rng.choice(("svchost.exe", "sqlservr.exe", "w3wp.exe", "lsass.exe", "taskhostw.exe")))


# --------------------------------------------------------------------------- #
# Campaigns
# --------------------------------------------------------------------------- #
@dataclass
class Campaign:
    id: str
    scenario: str
    start: float
    events: list[Event]
    entities: list[str] = field(default_factory=list)

    @property
    def end(self) -> float:
        return self.events[-1].ts if self.events else self.start

    @property
    def stages(self) -> dict[str, float]:
        """First event time of each malicious stage."""
        first: dict[str, float] = {}
        for e in self.events:
            if e.label != "benign" and e.label not in first:
                first[e.label] = e.ts
        return dict(sorted(first.items(), key=lambda kv: kv[1]))


class _Builder:
    def __init__(self, scenario: str, rng: random.Random, lookalike: bool = False):
        self.id = f"sim_{uuid.UUID(int=rng.getrandbits(128)).hex[:8]}"
        self.scenario = scenario
        self.rng = rng
        self.lookalike = lookalike
        self.events: list[Event] = []
        self.entities: list[str] = []

    def add(self, label: str, *args, **kwargs) -> None:
        e = Event(*args, **kwargs)
        e.label = label
        e.campaign = self.id
        e.lookalike = self.lookalike
        self.events.append(e)

    def build(self, start: float) -> Campaign:
        self.events.sort(key=lambda e: e.ts)
        return Campaign(self.id, self.scenario, start, self.events, list(dict.fromkeys(self.entities)))


def _beacon(b: _Builder, src: str, dst: str, t0: float, t1: float, label: str = "c2_beacon") -> None:
    rng = b.rng
    period = rng.uniform(30, 120)
    jitter = rng.uniform(0.03, 0.2)
    size = rng.randint(180, 600)
    t = t0
    while t < t1:
        b.add(label, t, "network", "flow", src, dst, rng.choice((443, 443, 8443)),
              int(size * rng.uniform(0.9, 1.1)), rng.randint(150, 1800), rng.uniform(0.05, 0.6))
        t += period * (1 + rng.uniform(-jitter, jitter))


def _foothold(b: _Builder, victim: Asset, t: float) -> None:
    """Half the time the implant arrives via a visible malicious launcher; otherwise
    the attacker used stolen credentials and endpoint telemetry shows nothing."""
    if b.rng.random() < 0.5:
        b.add("c2_beacon", t, "endpoint", "process", victim.ip, victim.ip, user=victim.owner,
              process=b.rng.choice(MALICIOUS_LAUNCHERS))


def _scan(b: _Builder, src: str, targets: list[str], t0: float, label: str, rate: float, ports: list[int]) -> float:
    rng = b.rng
    probes = [(tgt, p) for tgt in targets for p in ports]
    rng.shuffle(probes)
    t = t0
    for tgt, port in probes:
        t += rng.expovariate(rate)
        opened = rng.random() < 0.15
        b.add(label, t, "network", "flow", src, tgt, port,
              rng.randint(40, 74) if not opened else rng.randint(120, 400),
              0 if not opened else rng.randint(60, 600), rng.uniform(0.0, 0.03))
    return t


def scenario_intrusion_chain(env: Environment, rng: random.Random, start: float, intensity: float = 1.0) -> Campaign:
    """Phishing foothold → C2 → internal scan → password spray → lateral movement → exfiltration."""
    b = _Builder("intrusion_chain", rng)
    victim = rng.choice(env.workstations)
    c2 = env.attacker_ip(rng)
    b.entities += [victim.ip, c2]

    _foothold(b, victim, start)

    t = start + rng.uniform(120, 300)
    targets = [h.ip for h in rng.sample(env.internal_hosts(), int(rng.randint(25, 70) * intensity))]
    ports = rng.sample(SCAN_PORTS, rng.randint(4, 9))
    t = _scan(b, victim.ip, targets, t, "recon", rng.uniform(4, 25) * intensity, ports)

    t += rng.uniform(60, 180)
    target = rng.choice((env.dc, env.servers[5], env.file_server))
    sprayed = rng.sample(env.users, rng.randint(10, 40)) + env.service_accounts
    account = rng.choice(sprayed)
    rate = rng.uniform(0.5, 5) * intensity
    for _ in range(int(rng.randint(80, 400) * intensity)):
        t += rng.expovariate(rate)
        b.add("brute_force", t, "endpoint", "auth", victim.ip, target.ip, rng.choice((88, 445)),
              user=rng.choice(sprayed), outcome="failure")
        if rng.random() < 0.3:
            b.add("brute_force", t + 0.01, "network", "flow", victim.ip, target.ip, 445,
                  rng.randint(300, 700), rng.randint(200, 500), rng.uniform(0.01, 0.2))
    t += rng.uniform(1, 5)
    b.add("brute_force", t, "endpoint", "auth", victim.ip, target.ip, 445, user=account, outcome="success")
    b.entities.append(target.ip)

    t += rng.uniform(60, 240)
    pool = [h for h in env.internal_hosts() if h.ip != victim.ip]
    stager = rng.choice([env.file_server, env.servers[6], env.db, env.servers[11]])
    hops = [h for h in rng.sample(pool, rng.randint(4, 12)) if h is not stager]
    hops[0] = stager
    for hop in hops:
        t += rng.uniform(10, 60)
        b.add("lateral_movement", t, "endpoint", "auth", victim.ip, hop.ip, 445, user=account, outcome="success")
        b.add("lateral_movement", t + 0.5, "network", "flow", victim.ip, hop.ip, 445,
              rng.randint(150_000, 2_500_000), rng.randint(2_000, 20_000), rng.uniform(1, 8))
        b.add("lateral_movement", t + 2, "network", "flow", victim.ip, hop.ip, rng.choice((135, 5985)),
              rng.randint(500, 4000), rng.randint(500, 4000), rng.uniform(0.2, 3))
        b.add("lateral_movement", t + 4, "endpoint", "process", hop.ip, hop.ip, user=account,
              process=rng.choice(REMOTE_EXEC_PROCESSES))
        b.entities.append(hop.ip)

    t += rng.uniform(120, 400)
    drop = rng.choice((c2, env.attacker_ip(rng)))
    for _ in range(rng.randint(15, 60)):
        t += rng.uniform(5, 40)
        b.add("exfiltration", t, "network", "flow", stager.ip, drop, 443,
              rng.randint(2_000_000, 60_000_000), rng.randint(2_000, 30_000), rng.uniform(5, 60))
    b.entities.append(drop)

    _beacon(b, victim.ip, c2, start + rng.uniform(5, 30), t)
    return b.build(start)


def scenario_credential_stuffing(env: Environment, rng: random.Random, start: float, intensity: float = 1.0) -> Campaign:
    """External bots replay leaked credentials against the web login."""
    b = _Builder("credential_stuffing", rng)
    bots = [env.attacker_ip(rng) for _ in range(rng.randint(1, 4))]
    b.entities += bots + [env.web.ip]
    usernames = rng.sample(env.users, 30) + [f"user{rng.randint(1000, 9999)}" for _ in range(60)]
    t = start
    rate = rng.uniform(2, 12) * intensity
    for _ in range(int(rng.randint(300, 1500) * intensity)):
        t += rng.expovariate(rate)
        bot = rng.choice(bots)
        user = rng.choice(usernames)
        b.add("brute_force", t, "application", "http", bot, env.web.ip, 443,
              rng.randint(350, 620), rng.randint(150, 320), rng.uniform(0.05, 0.4),
              user=user, method="POST", path=rng.choice(("/login", "/api/auth/login")), status=401)
        if rng.random() < 0.6:
            b.add("brute_force", t + 0.02, "endpoint", "auth", bot, env.web.ip, 443, user=user, outcome="failure")
    for _ in range(rng.randint(1, 5)):
        t += rng.uniform(1, 20)
        bot = rng.choice(bots)
        user = rng.choice(usernames[:30])
        b.add("brute_force", t, "application", "http", bot, env.web.ip, 443, rng.randint(350, 620),
              rng.randint(2000, 9000), 0.2, user=user, method="POST", path="/login", status=200)
        b.add("brute_force", t + 0.02, "endpoint", "auth", bot, env.web.ip, 443, user=user, outcome="success")
    return b.build(start)


def scenario_c2_exfil(env: Environment, rng: random.Random, start: float, intensity: float = 1.0) -> Campaign:
    """An implant beacons home on a jittered timer, then stages data out in chunks."""
    b = _Builder("c2_exfil", rng)
    victim = rng.choice(env.workstations)
    c2 = env.attacker_ip(rng)
    b.entities += [victim.ip, c2]
    _foothold(b, victim, start)
    beacon_end = start + rng.uniform(20, 50) * 60 / max(intensity, 0.5)
    _beacon(b, victim.ip, c2, start + 5, beacon_end)
    t = beacon_end
    for _ in range(int(rng.randint(20, 80) * intensity)):
        t += rng.uniform(15, 90)
        b.add("exfiltration", t, "network", "flow", victim.ip, c2, 443,
              rng.randint(500_000, 15_000_000), rng.randint(500, 5_000), rng.uniform(2, 30))
    _beacon(b, victim.ip, c2, beacon_end + 3, t)
    return b.build(start)


def scenario_low_and_slow(env: Environment, rng: random.Random, start: float, intensity: float = 1.0) -> Campaign:
    """A patient password guesser that stays under per-minute rate limits."""
    b = _Builder("low_and_slow", rng)
    t = start
    end = start + rng.uniform(60, 120) * 60 / max(intensity, 0.5)
    users = rng.sample(env.users, 8) + env.service_accounts
    if rng.random() < 0.5:
        src = env.attacker_ip(rng)
        b.entities += [src, env.web.ip]
        while t < end:
            t += rng.uniform(15, 60)
            user = rng.choice(users)
            b.add("brute_force", t, "application", "http", src, env.web.ip, 443, rng.randint(350, 620),
                  rng.randint(150, 320), 0.2, user=user, method="POST", path="/login", status=401)
            b.add("brute_force", t + 0.02, "endpoint", "auth", src, env.web.ip, 443, user=user, outcome="failure")
    else:
        src = rng.choice(env.workstations).ip
        b.entities += [src, env.dc.ip]
        while t < end:
            t += rng.uniform(15, 60)
            b.add("brute_force", t, "endpoint", "auth", src, env.dc.ip, 88, user=rng.choice(users), outcome="failure")
    return b.build(start)


def scenario_dns_tunnel(env: Environment, rng: random.Random, start: float, intensity: float = 1.0) -> Campaign:
    """Data smuggled out in DNS-sized packets straight to an attacker's resolver.

    Never used for training: this is the unseen technique the anomaly detector
    has to catch on its own.
    """
    b = _Builder("dns_tunnel", rng)
    victim = rng.choice(env.workstations)
    ns = env.attacker_ip(rng)
    b.entities += [victim.ip, ns]
    t = start
    end = start + rng.uniform(8, 15) * 60
    rate = rng.uniform(4, 15) * intensity
    while t < end:
        t += rng.expovariate(rate)
        b.add("exfiltration", t, "network", "flow", victim.ip, ns, 53,
              rng.randint(120, 255), rng.randint(60, 200), rng.uniform(0.005, 0.08))
    return b.build(start)


# ----------------------------------------------------------- benign look-alikes
def _backup_job(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    for fs in (env.file_server, env.servers[6]):
        t += rng.uniform(1, 10)
        b.add("benign", t, "network", "flow", env.backup.ip, fs.ip, 445,
              rng.randint(2000, 9000), rng.randint(50_000_000, 400_000_000), rng.uniform(60, 300))
    for _ in range(rng.randint(20, 120)):
        t += rng.uniform(10, 30)
        b.add("benign", t, "network", "flow", env.backup.ip, env.offsite_backup, 22,
              rng.randint(20_000_000, 400_000_000), rng.randint(5_000, 50_000), rng.uniform(20, 120))
    return t


def _vuln_scan(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    targets = [h.ip for h in rng.sample(env.internal_hosts(), rng.randint(40, 120))]
    return _scan(b, env.scanner.ip, targets, t, "benign", rng.uniform(10, 40), rng.sample(SCAN_PORTS, rng.randint(6, 12)))


def _load_test(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    dev = rng.choice(env.developers)
    end = t + rng.uniform(120, 360)
    rate = rng.uniform(5, 30)
    path = rng.choice(("/api/search", "/health", "/api/orders"))
    while t < end:
        t += rng.expovariate(rate)
        b.add("benign", t, "application", "http", dev.ip, env.servers[7].ip, 443, rng.randint(300, 900),
              rng.randint(500, 6000), rng.uniform(0.01, 0.3), user=dev.owner, method="GET", path=path,
              status=429 if rng.random() < 0.05 else 200)
    return t


def _forgotten_password(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    ws = rng.choice(env.workstations)
    for _ in range(rng.randint(4, 12)):
        t += rng.uniform(4, 20)
        b.add("benign", t, "endpoint", "auth", ws.ip, env.dc.ip, 88, user=ws.owner, outcome="failure")
    b.add("benign", t + rng.uniform(30, 120), "endpoint", "auth", ws.ip, env.dc.ip, 88, user=ws.owner, outcome="success")
    return t


def _cloud_upload(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    ws = rng.choice(env.workstations)
    dst = rng.choice(env.popular_external[:5])
    for _ in range(rng.randint(3, 10)):
        t += rng.uniform(5, 40)
        b.add("benign", t, "network", "flow", ws.ip, dst, 443,
              rng.randint(10_000_000, 200_000_000), rng.randint(2_000, 20_000), rng.uniform(10, 90))
    return t


def _admin_rdp(b: _Builder, env: Environment, t: float) -> float:
    rng = b.rng
    admin = rng.choice(env.admins)
    b.add("benign", t, "endpoint", "process", admin.ip, admin.ip, user=admin.owner, process="mstsc.exe")
    for srv in rng.sample(env.servers, rng.randint(4, 9)):
        t += rng.uniform(60, 300)
        b.add("benign", t, "endpoint", "auth", admin.ip, srv.ip, 3389, user=f"adm-{admin.owner}", outcome="success")
        b.add("benign", t + 1, "network", "flow", admin.ip, srv.ip, 3389,
              rng.randint(20_000, 400_000), rng.randint(500_000, 20_000_000), rng.uniform(60, 900))
    return t


LOOKALIKES: dict[str, Callable[[_Builder, Environment, float], float]] = {
    "backup_job": _backup_job,
    "vuln_scan": _vuln_scan,
    "load_test": _load_test,
    "forgotten_password": _forgotten_password,
    "cloud_upload": _cloud_upload,
    "admin_rdp": _admin_rdp,
}


def scenario_benign_noise(env: Environment, rng: random.Random, start: float, intensity: float = 1.0,
                          behaviours: list[str] | None = None) -> Campaign:
    """Legitimate activity that resembles attacks. Should raise no alerts."""
    b = _Builder("benign_noise", rng, lookalike=True)
    names = behaviours or list(LOOKALIKES)
    t = start
    for name in names:
        LOOKALIKES[name](b, env, t)
        t += rng.uniform(20, 90)
    return b.build(start)


SCENARIOS: dict[str, Callable[..., Campaign]] = {
    "intrusion_chain": scenario_intrusion_chain,
    "credential_stuffing": scenario_credential_stuffing,
    "c2_exfil": scenario_c2_exfil,
    "low_and_slow": scenario_low_and_slow,
    "benign_noise": scenario_benign_noise,
    "dns_tunnel": scenario_dns_tunnel,
}

# Scenarios the supervised model trains on. dns_tunnel is held out on purpose.
TRAINING_SCENARIOS = ("intrusion_chain", "credential_stuffing", "c2_exfil", "low_and_slow", "benign_noise")
