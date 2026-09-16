"""A simulated organisation: hosts, roles, users and the outside internet.

The asset inventory stands in for a CMDB. Detection is allowed to use a host's
role (workstation / server / infra tooling), as a real SOC would.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass

INTERNAL_NET = ipaddress.ip_network("10.0.0.0/8")

ADMIN_PORTS = frozenset({22, 135, 139, 445, 3389, 5985, 5986})
SCAN_PORTS = (21, 22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080)

FIRST_NAMES = (
    "aarav", "maya", "liam", "zoe", "noah", "ira", "kabir", "emma", "arjun", "leah",
    "omar", "nina", "rohan", "sara", "dev", "ana", "yusuf", "tara", "eli", "priya",
)


@dataclass(frozen=True, slots=True)
class Asset:
    ip: str
    hostname: str
    role: str  # workstation | server | infra
    owner: str | None = None


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in INTERNAL_NET
    except ValueError:
        return False


class Environment:
    def __init__(self, seed: int = 7, n_workstations: int = 120):
        rng = random.Random(seed)
        self.assets: dict[str, Asset] = {}

        self.users: list[str] = []
        self.workstations: list[Asset] = []
        for i in range(n_workstations):
            user = f"{FIRST_NAMES[i % len(FIRST_NAMES)]}.{i:03d}"
            ip = f"10.20.{i // 250}.{i % 250 + 10}"
            ws = Asset(ip, f"ws-{i:04d}", "workstation", user)
            self.users.append(user)
            self.workstations.append(ws)
        self.admins = rng.sample(self.workstations, 4)
        self.developers = rng.sample(self.workstations, 10)
        self.sync_clients = rng.sample(self.workstations, n_workstations // 3)

        def server(ip: str, name: str) -> Asset:
            return Asset(ip, name, "server")

        self.dc = server("10.10.0.10", "dc-01")
        self.resolver = server("10.10.0.2", "dns-01")
        self.file_server = server("10.10.1.20", "file-01")
        self.web = server("10.10.2.30", "web-01")
        self.db = server("10.10.2.40", "db-01")
        self.servers = [
            self.dc, self.resolver, self.file_server, self.web, self.db,
            server("10.10.0.11", "dc-02"),
            server("10.10.1.21", "file-02"),
            server("10.10.2.31", "api-01"),
            server("10.10.2.32", "api-02"),
            server("10.10.3.10", "mail-01"),
            server("10.10.3.20", "hr-app"),
            server("10.10.3.30", "erp-01"),
        ]

        self.backup = Asset("10.10.5.20", "backup-01", "infra")
        self.scanner = Asset("10.10.5.30", "vulnscan-01", "infra")
        self.monitor = Asset("10.10.5.40", "monitor-01", "infra")
        self.infra = [self.backup, self.scanner, self.monitor]

        for a in (*self.workstations, *self.servers, *self.infra):
            self.assets[a.ip] = a

        self.service_accounts = ["svc_backup", "svc_sql", "svc_deploy", "administrator"]

        # Popular SaaS/CDN endpoints that many hosts talk to.
        self.popular_external = [
            f"{a}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            for a in rng.choices((13, 20, 34, 52, 104, 142, 151, 172), k=40)
        ]
        self.offsite_backup = "198.51.100.25"

    # ---------------------------------------------------------------- lookups
    def role_of(self, ip: str) -> str:
        asset = self.assets.get(ip)
        if asset:
            return asset.role
        return "internal-unknown" if is_internal(ip) else "external"

    def hostname(self, ip: str) -> str | None:
        asset = self.assets.get(ip)
        return asset.hostname if asset else None

    def internal_hosts(self) -> list[Asset]:
        return [*self.workstations, *self.servers]

    # ------------------------------------------------------------- randomness
    @staticmethod
    def long_tail_external(rng: random.Random) -> str:
        """A web destination few hosts ever contact."""
        first = rng.choice((23, 31, 37, 46, 62, 77, 81, 89, 93, 95, 109, 176, 178, 193, 212))
        return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    @staticmethod
    def attacker_ip(rng: random.Random) -> str:
        first = rng.choice((5, 45, 80, 91, 103, 141, 146, 154, 162, 185, 188, 194, 195, 213))
        return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
