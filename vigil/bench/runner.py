"""Run one benchmark experiment and record everything needed to trust the result.

    python -m vigil.bench run first_seen_edge --config configs/lanl.yaml [--seed 1] [--set k=v ...]

Each run lives in `runs/<experiment>__<data>__<hash>/`, where the hash covers
the experiment parameters, the data and eval config and the seed. The folder
holds the resolved config, `meta.json` (git SHA, versions, timings), one
stratified score file per evaluation split, and `metrics.json`. A folder with
`metrics.json` is complete and is skipped unless `--force`; any other existing
folder is resumed, and the experiment can pick up from `ctx.checkpoint_dir`.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import pyarrow as pa
import yaml

from ..data.lanl import REPO, connect, data_paths
from .experiment import EXPERIMENTS, Context, Experiment
from .metrics import evaluate
from .scores import ScoreSink

log = logging.getLogger("vigil.bench")
RUNS = REPO / "runs"


class PowerError(RuntimeError):
    pass


def power_status() -> tuple[bool | None, int | None]:
    """(on_battery, percent) on Windows; (None, None) elsewhere or if unknown."""
    if sys.platform != "win32":
        return None, None

    class SYSTEM_POWER_STATUS(ctypes.Structure):
        _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                    ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                    ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]

    s = SYSTEM_POWER_STATUS()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s)):
        return None, None
    on_battery = {0: True, 1: False}.get(s.ACLineStatus)
    pct = None if s.BatteryLifePercent == 255 else int(s.BatteryLifePercent)
    return on_battery, pct


def check_power(force: bool, min_percent: int = 60) -> None:
    on_battery, pct = power_status()
    if not on_battery:
        return
    msg = f"running on battery ({pct}%): the CPU throttles hard, so long jobs crawl"
    if force:
        log.warning(msg)
    elif pct is None or pct < min_percent:
        raise PowerError(msg + f"; plug in, or pass --force-power (refusing below {min_percent}%)")
    else:
        log.warning(msg)


def git_sha() -> str | None:
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO,
                               capture_output=True, text=True).stdout.strip()
        return sha.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return None


def run_id(experiment: str, cfg: dict, params: dict, seed: int) -> str:
    blob = json.dumps({"data": cfg["data"], "eval": cfg["eval"], "params": params, "seed": seed}, sort_keys=True)
    return f"{experiment}__{cfg['name']}__{hashlib.sha1(blob.encode()).hexdigest()[:8]}"


_LABEL = re.compile(r"\blabel\b", re.IGNORECASE)


_LOG_EVERY = 20_000_000  # events between progress lines on the single-query path


def _stream(ctx: Context, exp: Experiment, sink: ScoreSink, a: int, b: int, split: str = "") -> None:
    """Score days [a, b) into `sink`, logging progress as it goes.

    Scoring the test window takes hours and used to log nothing between its
    start and its end, so a slow run was indistinguishable from a hung one.
    Cost per day grows with the day index — the novelty and history features
    join against cumulative tables — so the estimate below is deliberately
    based on days already done rather than on a fixed rate, and it drifts
    optimistic early on.
    """
    t0 = time.monotonic()
    tag = f"{exp.name} {split}".strip()
    sql = exp.score_sql(ctx)
    base = ctx.events_sql()
    if sql is not None:
        joins, expr = sql
        if _LABEL.search(joins) or _LABEL.search(expr):
            raise ValueError(f"{exp.name}: scoring SQL must not reference the label")
        query = f"""
            SELECT e.key, e.day, hash(e.src_user) AS cluster, e.label, ({expr})::DOUBLE AS score
            FROM ({base}) e {joins}
            WHERE e.day >= {a} AND e.day < {b}
        """
        reader = ctx.con.execute(query).to_arrow_reader(1 << 20)
        next_log = _LOG_EVERY
        for batch in reader:
            sink.add(batch["key"], batch["score"], batch["label"], batch["day"], batch["cluster"])
            if sink.n_seen >= next_log:
                log.info("%s: %.0fM events, %.1f min elapsed", tag, sink.n_seen / 1e6,
                         (time.monotonic() - t0) / 60)
                next_log += _LOG_EVERY
        return
    joins, extra = exp.batch_columns(ctx) or ("", "")
    if _LABEL.search(joins) or _LABEL.search(extra):
        raise ValueError(f"{exp.name}: batch SQL must not reference the label")
    extra = f", {extra}" if extra else ""
    ndays = b - a
    for i, day in enumerate(range(a, b), start=1):
        reader = ctx.con.execute(
            f"SELECT e.*, hash(e.src_user) AS cluster {extra} FROM ({base}) e {joins} WHERE e.day = {day} ORDER BY e.key"
        ).to_arrow_reader(1 << 18)
        for batch in reader:
            tbl = pa.Table.from_batches([batch])
            label = tbl["label"].to_numpy()
            cluster = tbl["cluster"].to_numpy()
            features = tbl.drop_columns(["label", "cluster"])
            scores = np.asarray(exp.score_batch(ctx, features), dtype=float)
            if len(scores) != tbl.num_rows:
                raise ValueError(f"{exp.name}: returned {len(scores)} scores for {tbl.num_rows} rows")
            sink.add(tbl["key"].to_numpy(), scores, label, tbl["day"].to_numpy(), cluster)
        done = time.monotonic() - t0
        log.info("%s: day %d (%d/%d), %.0fM events, %.1f min elapsed, ~%.0f min left",
                 tag, day, i, ndays, sink.n_seen / 1e6, done / 60, done / i * (ndays - i) / 60)


def recompute(run_dir: Path) -> dict:
    """Re-evaluate a finished run from its score files, without scoring anything again.

    Used when a metric definition changes: the scores are the expensive part and
    they do not depend on how they are summarised.
    """
    import pyarrow.parquet as pq

    cfg = yaml.safe_load((run_dir / "config.yaml").read_text())
    results = json.loads((run_dir / "metrics.json").read_text())
    ev = cfg["eval"]
    for split in list(results):
        path = run_dir / f"scores_{split}.parquet"
        if not path.exists():
            continue
        t = pq.read_table(path)
        res = evaluate(t["label"].to_numpy(), t["score"].to_numpy(), t["weight"].to_numpy(),
                       t["day"].to_numpy(), t["cluster"].to_numpy() if ev.get("cluster") else None,
                       n_boot=ev.get("n_boot", 500), seed=cfg.get("seed", 0))
        res.update({k: results[split][k] for k in ("events_scored", "days", "seconds") if k in results[split]})
        results[split] = res
    (run_dir / "metrics.json").write_text(json.dumps(results, indent=1))
    return results


def run(experiment: str, cfg: dict, params: dict | None = None, seed: int | None = None, force: bool = False,
        force_power: bool = False, runs_dir: Path = RUNS) -> Path:
    if experiment not in EXPERIMENTS:
        raise KeyError(f"unknown experiment {experiment!r}; known: {sorted(EXPERIMENTS)}")
    if not cfg["data"].get("splits"):
        raise ValueError("config has no data.splits; fix them from the data card first")
    params = {**cfg.get("experiments", {}).get(experiment, {}), **(params or {})}
    seed = cfg.get("seed", 0) if seed is None else seed
    run_dir = runs_dir / run_id(experiment, cfg, params, seed)
    if (run_dir / "metrics.json").exists() and not force:
        log.info("%s: complete, skipping (use --force to rerun)", run_dir.name)
        return run_dir
    check_power(force_power)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "config.yaml").write_text(yaml.safe_dump({**cfg, "experiment": experiment, "params": params,
                                                          "seed": seed}, sort_keys=False))
    meta = {"experiment": experiment, "data": cfg["name"], "seed": seed, "git": git_sha(),
            "supervised": EXPERIMENTS[experiment].supervised,
            "python": platform.python_version(), "duckdb": duckdb.__version__, "numpy": np.__version__,
            "host": platform.node(), "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "power": power_status()}

    _, pqd, derived = data_paths(cfg)
    con = connect(pqd, derived=derived)
    ctx = Context(cfg, con, run_dir, seed, log)
    exp = EXPERIMENTS[experiment](params)
    np.random.seed(seed)

    t0 = time.monotonic()
    exp.fit(ctx)
    meta["fit_seconds"] = round(time.monotonic() - t0, 1)

    ev = cfg["eval"]
    results = {}
    for split in ev["splits"]:
        a, b = ctx.splits[split]
        t1 = time.monotonic()
        sink = ScoreSink(ev["per_day_top"], ev["sample_rate"])
        _stream(ctx, exp, sink, a, b, split)
        tbl = sink.save(run_dir / f"scores_{split}.parquet")
        cluster = tbl["cluster"].to_numpy() if ev.get("cluster") else None
        res = evaluate(tbl["label"].to_numpy(), tbl["score"].to_numpy(), tbl["weight"].to_numpy(),
                       tbl["day"].to_numpy(), cluster, n_boot=ev.get("n_boot", 500), seed=seed)
        res["events_scored"] = sink.n_seen
        res["days"] = [a, b]
        res["seconds"] = round(time.monotonic() - t1, 1)
        results[split] = res
        m = res["metrics"]
        log.info("%s %s: AP %.4f  ROC-AUC %.4f  recall@100/day %.3f  (%d events, %d positive)", experiment, split,
                 m["ap"]["value"], m["roc_auc"]["value"], m["recall@100/day"]["value"], sink.n_seen,
                 res["n_positive"])
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=1))
    (run_dir / "metrics.json").write_text(json.dumps(results, indent=1))
    return run_dir
