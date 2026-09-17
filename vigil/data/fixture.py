"""A tiny synthetic dataset in LANL's exact file format, for tests and CI.

    python -m vigil.data.fixture --out tmp/lanl_tiny

Six days, a few dozen users and computers, habitual user->host logons, machine
account traffic, and a red-team campaign from day 2 on: a new attacker host
logs on with stolen user credentials to hosts those users never touched. The
redteam file lists those logons, as LANL's does, plus one row with no matching
auth event and one logon that appears twice (both occur in the real data).

It only has to exercise ingestion, labels, splits and the model plumbing. The
numbers it produces mean nothing.
"""

from __future__ import annotations

import argparse
import gzip
import random
from pathlib import Path

DAY = 86400


def write_fixture(out: Path, seed: int = 7, days: int = 6, users: int = 40, comps: int = 60) -> Path:
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    auth, proc, flows, dns, red = [], [], [], [], []
    servers = [f"C{i}" for i in range(comps - 10, comps)]
    home = {f"U{u}": f"C{u + 1}" for u in range(users)}
    usual = {u: rng.sample(servers, 3) for u in home}

    for d in range(days):
        base = d * DAY
        for u, h in home.items():
            for _ in range(rng.randint(30, 60)):
                t = base + rng.randint(8 * 3600, 18 * 3600)
                dst = rng.choice(usual[u] + [h])
                kind = rng.choice(["Kerberos", "Kerberos", "NTLM"])
                ok = "Success" if rng.random() > 0.02 else "Fail"
                auth.append((t, f"{u}@DOM1", f"{u}@DOM1", h, dst, kind, "Network", "LogOn", ok))
            # Occasional legitimate first-time access: the hard negatives.
            if rng.random() < 0.15:
                t = base + rng.randint(8 * 3600, 18 * 3600)
                auth.append((t, f"{u}@DOM1", f"{u}@DOM1", h, rng.choice(servers), "Kerberos", "Network", "LogOn",
                             "Success"))
        for c in range(1, comps + 1):
            for hr in range(0, 24, 3):
                t = base + hr * 3600 + rng.randint(0, 3599)
                auth.append((t, f"C{c}$@DOM1", f"C{c}$@DOM1", f"C{c}", "C1", "Kerberos", "Network", "LogOn", "Success"))
                proc.append((t, f"C{c}$@DOM1", f"C{c}", f"P{rng.randint(1, 20)}", "Start"))
                flows.append((t, rng.randint(0, 30), f"C{c}", f"N{rng.randint(1, 999)}", rng.choice(servers), "445",
                               6, rng.randint(1, 50), rng.randint(60, 90000)))
                dns.append((t, f"C{c}", rng.choice(servers)))
            if rng.random() < 0.3:
                t = base + rng.randint(0, DAY - 1)
                auth.append((t, "ANONYMOUS LOGON@C586", "ANONYMOUS LOGON@C586", f"C{c}", "C586", "NTLM", "Network",
                             "LogOn", "Success"))

    attacker = "C999"
    victims = [f"U{u}" for u in rng.sample(range(users), 6)]
    for d in range(2, days):
        for _ in range(8):
            t = d * DAY + rng.randint(0, DAY - 1)
            u = rng.choice(victims)
            dst = f"C{rng.randint(1, comps)}"
            row = (t, f"{u}@DOM1", f"{u}@DOM1", attacker, dst, "NTLM", "Network", "LogOn", "Success")
            auth.append(row)
            red.append((t, f"{u}@DOM1", attacker, dst))
            proc.append((t + 2, f"{u}@DOM1", dst, "P999", "Start"))
    dup = red[0]
    auth.append((dup[0], dup[1], dup[1], dup[2], dup[3], "NTLM", "Network", "LogOn", "Success"))
    red.append((3 * DAY + 5, "U0@DOM1", attacker, "C404"))  # no matching auth event

    for name, rows in (("auth", auth), ("proc", proc), ("flows", flows), ("dns", dns), ("redteam", red)):
        rows.sort(key=lambda r: r[0])
        with gzip.open(out / f"{name}.txt.gz", "wt", newline="\n") as f:
            for r in rows:
                f.write(",".join(map(str, r)) + "\n")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    print(write_fixture(a.out, a.seed))
