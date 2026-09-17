"""LANL "Comprehensive, Multi-Source Cyber-Security Events" ingestion.

    python -m vigil.data.lanl ingest                 # raw .gz -> day-partitioned Parquet (long, run once)
    python -m vigil.data.lanl profile                # writes docs/data/LANL_DATA_CARD.md
    python -m vigil.data.lanl build --config configs/lanl.yaml   # derived tables (hourly edges, ...)

The raw files (auth, proc, flows, dns, redteam) stay gzipped under
VIGIL_LANL_RAW (default C:/data/lanl); they are never decompressed to disk and
never committed. Ingestion streams each file once, adds `key` (the row's index
in its source file, a stable unique id used for sampling and joins) and writes
zstd Parquet partitioned by day under VIGIL_LANL_PARQUET (default
<raw>/parquet). Everything after that is DuckDB SQL over the Parquet files.

Time is in seconds from the start of the collection; `day = time // 86400`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time as _time
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq
import yaml

REPO = Path(__file__).resolve().parents[2]
DAY = 86400
HOUR = 3600

_s, _i64 = pa.string(), pa.int64()
SCHEMAS: dict[str, list[tuple[str, pa.DataType]]] = {
    "auth": [("time", _i64), ("src_user", _s), ("dst_user", _s), ("src_comp", _s), ("dst_comp", _s),
             ("auth_type", _s), ("logon_type", _s), ("orientation", _s), ("success", _s)],
    "proc": [("time", _i64), ("user", _s), ("comp", _s), ("process", _s), ("action", _s)],
    "flows": [("time", _i64), ("duration", _i64), ("src_comp", _s), ("src_port", _s), ("dst_comp", _s),
              ("dst_port", _s), ("protocol", pa.int32()), ("packets", _i64), ("bytes", _i64)],
    "dns": [("time", _i64), ("src_comp", _s), ("resolved", _s)],
    "redteam": [("time", _i64), ("user", _s), ("src_comp", _s), ("dst_comp", _s)],
}
TABLES = tuple(SCHEMAS)

# Which authentications count as events to score. Red-team rows are all
# human (U...) accounts; computer accounts (C...$) and ANONYMOUS/SYSTEM
# logons are machine traffic.
USER_FILTERS = {
    "all": "TRUE",
    "human": "src_user LIKE 'U%'",
}


def raw_dir() -> Path:
    return Path(os.environ.get("VIGIL_LANL_RAW", "C:/data/lanl"))


def parquet_dir(raw: Path | None = None) -> Path:
    env = os.environ.get("VIGIL_LANL_PARQUET")
    return Path(env) if env else (raw or raw_dir()) / "parquet"


# ---------------------------------------------------------------- ingestion

def ingest_table(table: str, raw: Path, out: Path, block_mb: int = 64, log=print) -> int:
    """Stream `<raw>/<table>.txt.gz` into `<out>/<table>/day=N/part-0.parquet`.

    Writes into a staging directory and renames it at the end, so an
    interrupted run leaves no half-written table behind. Returns the row count.
    """
    src = raw / f"{table}.txt.gz"
    if not src.exists():
        raise FileNotFoundError(src)
    final = out / table
    stage = out / f"{table}.partial"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    names = [n for n, _ in SCHEMAS[table]]
    reader = pacsv.open_csv(
        pa.input_stream(str(src), compression="gzip"),
        read_options=pacsv.ReadOptions(column_names=names, block_size=block_mb << 20),
        convert_options=pacsv.ConvertOptions(column_types=dict(SCHEMAS[table]), strings_can_be_null=False),
    )
    schema = pa.schema([("key", pa.uint64()), *SCHEMAS[table]])
    writers: dict[int, pq.ParquetWriter] = {}
    n = 0
    t0 = last = _time.monotonic()
    try:
        for batch in reader:
            tbl = pa.Table.from_batches([batch])
            tbl = tbl.add_column(0, "key", pa.array(range(n, n + tbl.num_rows), type=pa.uint64()))
            n += tbl.num_rows
            days = pc.divide(tbl["time"], DAY)
            for d in pc.unique(days).to_pylist():
                part = tbl.filter(pc.equal(days, d)).cast(schema)
                if d not in writers:
                    path = stage / f"day={d}" / "part-0.parquet"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    writers[d] = pq.ParquetWriter(path, schema, compression="zstd")
                writers[d].write_table(part)
            now = _time.monotonic()
            if now - last > 30:
                log(f"  {table}: {n:,} rows, {n / (now - t0):,.0f} rows/s")
                last = now
    finally:
        for w in writers.values():
            w.close()
    if final.exists():
        shutil.rmtree(final)
    stage.rename(final)
    (final / "_INGESTED.json").write_text(json.dumps({"rows": n, "seconds": round(_time.monotonic() - t0, 1),
                                                      "source_bytes": src.stat().st_size}))
    return n


def ingest(tables, raw: Path, out: Path, force: bool = False, log=print) -> dict[str, int]:
    done = {}
    for t in tables:
        marker = out / t / "_INGESTED.json"
        if marker.exists() and not force:
            log(f"{t}: already ingested ({json.loads(marker.read_text())['rows']:,} rows), skipping")
            continue
        log(f"{t}: ingesting {raw / (t + '.txt.gz')}")
        done[t] = ingest_table(t, raw, out, log=log)
        log(f"{t}: {done[t]:,} rows")
    return done


# ---------------------------------------------------------------- querying

def connect(pq_dir: Path, threads: int | None = None, memory_limit: str = "6GB",
            derived: Path | None = None) -> duckdb.DuckDBPyConnection:
    """DuckDB connection with a view per ingested table (plus derived tables when given)."""
    con = duckdb.connect()
    con.execute(f"SET memory_limit='{memory_limit}'")
    con.execute("SET preserve_insertion_order=false")
    if threads:
        con.execute(f"SET threads={int(threads)}")
    for t in TABLES:
        if (pq_dir / t / "_INGESTED.json").exists():
            glob = (pq_dir / t / "*" / "*.parquet").as_posix()
            con.execute(f"CREATE VIEW {t} AS SELECT * FROM read_parquet('{glob}', hive_partitioning=true)")
    if (pq_dir / "redteam" / "_INGESTED.json").exists():
        con.execute("""
            CREATE VIEW redteam_keys AS
            SELECT DISTINCT time, "user" AS src_user, src_comp, dst_comp FROM redteam
        """)
    if derived is not None:
        for d in sorted(p for p in derived.glob("*") if p.is_dir() and (p / "_BUILT.json").exists()):
            glob = (d / "**" / "*.parquet").as_posix()
            con.execute(f"CREATE VIEW {d.name} AS SELECT * FROM read_parquet('{glob}', hive_partitioning=true)")
    return con


def auth_events_sql(user_filter: str = "human") -> str:
    """Scorable authentications with the red-team label attached.

    Models never see this relation directly: the runner selects the label
    separately from the columns it hands to a model.
    """
    return f"""
        SELECT a.*, a.time // {HOUR} AS hour, (r.src_user IS NOT NULL) AS label
        FROM (SELECT * FROM auth WHERE {USER_FILTERS[user_filter]}) a
        LEFT JOIN redteam_keys r
          ON a.time = r.time AND a.src_user = r.src_user AND a.src_comp = r.src_comp AND a.dst_comp = r.dst_comp
    """


# ---------------------------------------------------------------- derived tables

def build_derived(con: duckdb.DuckDBPyConnection, derived: Path, force: bool = False, log=print) -> None:
    """Hourly per-edge authentication counts over the whole collection.

    One row per (hour, user, src, dst, auth type, logon type, orientation,
    outcome). The novelty features and the graph model read this instead of
    the billion raw events. Built one day at a time to bound memory.
    """
    out = derived / "auth_edges_hourly"
    if "auth" not in {r[0] for r in con.execute("SELECT view_name FROM duckdb_views()").fetchall()}:
        raise RuntimeError("auth is not ingested yet; run `python -m vigil.data.lanl ingest` first")
    if (out / "_BUILT.json").exists() and not force:
        log("auth_edges_hourly: already built, skipping")
        return
    if out.exists():
        shutil.rmtree(out)
    days = [r[0] for r in con.execute("SELECT DISTINCT day FROM auth ORDER BY day").fetchall()]
    total = 0
    for d in days:
        path = out / f"day={d}" / "part-0.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        con.execute(f"""
            COPY (
                SELECT time // {HOUR} AS hour, src_user, src_comp, dst_comp, auth_type, logon_type,
                       orientation, success, count(*)::INTEGER AS n
                FROM auth WHERE day = {d}
                GROUP BY ALL ORDER BY hour
            ) TO '{path.as_posix()}' (FORMAT parquet, COMPRESSION zstd)
        """)
        rows = con.execute(f"SELECT count(*) FROM read_parquet('{path.as_posix()}')").fetchone()[0]
        total += rows
        log(f"  auth_edges_hourly day {d}: {rows:,} rows")
    (out / "_BUILT.json").write_text(json.dumps({"rows": total, "days": len(days)}))


# ---------------------------------------------------------------- profile / data card

@dataclass
class Profile:
    per_day: dict[str, dict[int, int]]
    redteam: dict
    user_mix: list[dict]
    ingested: dict[str, dict]

    def to_json(self) -> dict:
        return {"per_day": {t: {str(k): v for k, v in d.items()} for t, d in self.per_day.items()},
                "redteam": self.redteam, "user_mix": self.user_mix, "ingested": self.ingested}


def profile(con: duckdb.DuckDBPyConnection, pq_dir: Path, log=print) -> Profile:
    present = [t for t in TABLES if (pq_dir / t / "_INGESTED.json").exists()]
    per_day = {}
    for t in present:
        log(f"profile: counting {t}")
        per_day[t] = dict(con.execute(f"SELECT day, count(*) FROM {t} GROUP BY day ORDER BY day").fetchall())
    ingested = {t: json.loads((pq_dir / t / "_INGESTED.json").read_text()) for t in present}

    rt: dict = {}
    if "redteam" in present:
        rt["rows"] = con.execute("SELECT count(*) FROM redteam").fetchone()[0]
        rt["distinct_rows"] = con.execute("SELECT count(*) FROM redteam_keys").fetchone()[0]
        rt["users"] = con.execute('SELECT count(DISTINCT "user") FROM redteam').fetchone()[0]
        rt["src_comps"] = sorted(r[0] for r in con.execute("SELECT DISTINCT src_comp FROM redteam").fetchall())
        rt["dst_comps"] = con.execute("SELECT count(DISTINCT dst_comp) FROM redteam").fetchone()[0]
        rt["first_time"], rt["last_time"] = con.execute("SELECT min(time), max(time) FROM redteam").fetchone()
        rt["non_human_users"] = con.execute("""SELECT count(*) FROM redteam WHERE "user" NOT LIKE 'U%'""").fetchone()[0]
        if "auth" in present:
            log("profile: matching red-team rows to auth events")
            matches = con.execute("""
                SELECT r.time, r.src_user, r.src_comp, r.dst_comp, count(a.time) AS n,
                       count(*) FILTER (WHERE a.success = 'Success') AS n_success
                FROM redteam_keys r
                LEFT JOIN (SELECT * FROM auth WHERE day IN (SELECT DISTINCT time // 86400 FROM redteam)) a
                  ON a.time = r.time AND a.src_user = r.src_user AND a.src_comp = r.src_comp
                 AND a.dst_comp = r.dst_comp
                GROUP BY ALL
            """).fetchall()
            ns = [m[4] for m in matches]
            rt["match_histogram"] = {"0": sum(n == 0 for n in ns), "1": sum(n == 1 for n in ns),
                                     "2+": sum(n >= 2 for n in ns)}
            rt["matched_auth_events"] = sum(ns)
            rt["matched_success_events"] = sum(m[5] for m in matches)
            rt["unmatched"] = [list(m[:4]) for m in matches if m[4] == 0][:50]
            rt["auth_types"] = dict(con.execute("""
                SELECT a.auth_type || ' / ' || a.logon_type, count(*) FROM auth a
                JOIN redteam_keys r ON a.time = r.time AND a.src_user = r.src_user
                 AND a.src_comp = r.src_comp AND a.dst_comp = r.dst_comp
                WHERE a.day IN (SELECT DISTINCT time // 86400 FROM redteam)
                GROUP BY 1 ORDER BY 2 DESC LIMIT 10
            """).fetchall())
    user_mix = []
    if "auth" in present:
        log("profile: auth user mix")
        rows = con.execute("""
            SELECT day,
                   count(*) FILTER (WHERE src_user LIKE 'U%') AS human,
                   count(*) FILTER (WHERE src_user LIKE '%$@%') AS computer,
                   count(*) FILTER (WHERE src_user LIKE 'ANONYMOUS%') AS anonymous,
                   count(*) AS total,
                   count(DISTINCT src_user) FILTER (WHERE src_user LIKE 'U%') AS human_users
            FROM auth GROUP BY day ORDER BY day
        """).fetchall()
        user_mix = [dict(zip(("day", "human", "computer", "anonymous", "total", "human_users"), r)) for r in rows]
    return Profile(per_day, rt, user_mix, ingested)


def render_card(p: Profile, splits: dict | None) -> str:
    L = ["# LANL multi-source dataset: data card", "",
         "Generated by `python -m vigil.data.lanl profile` from the local Parquet copy. Do not edit by hand.", "",
         "Source: Los Alamos National Laboratory, *Comprehensive, Multi-Source Cyber-Security Events* "
         "(Kent, 2015), csr.lanl.gov/data/cyber1. The data is not redistributed with this repository.", "",
         "## Volumes", "", "| table | rows | days | first day | last day |", "|---|---:|---:|---:|---:|"]
    for t, d in p.per_day.items():
        L.append(f"| {t} | {sum(d.values()):,} | {len(d)} | {min(d)} | {max(d)} |")
    rt = p.redteam
    if rt:
        L += ["", "## Red team", "",
              f"* {rt['rows']} rows ({rt['distinct_rows']} distinct), {rt['users']} users, "
              f"{rt['dst_comps']} destination computers, source computers {', '.join(rt['src_comps'])}.",
              f"* Time span: {rt['first_time']:,} s to {rt['last_time']:,} s "
              f"(day {rt['first_time'] // DAY} to day {rt['last_time'] // DAY}).",
              f"* Rows whose user is not a human (`U...`) account: {rt['non_human_users']}."]
        if "match_histogram" in rt:
            h = rt["match_histogram"]
            L += [f"* Matching to auth events on (time, user, source, destination): {h['1']} rows match exactly one "
                  f"event, {h['2+']} match several (exact duplicates in the log), {h['0']} match none. "
                  f"{rt['matched_auth_events']:,} auth events are labelled red team "
                  f"({rt['matched_success_events']:,} successful).",
                  "", "Top auth/logon types among labelled events:", "",
                  "| auth type / logon type | events |", "|---|---:|"]
            L += [f"| {k} | {v:,} |" for k, v in rt["auth_types"].items()]
            if rt["unmatched"]:
                L += ["", "Unmatched red-team rows (first 50): " + "; ".join(",".join(map(str, u)) for u in rt["unmatched"])]
        if "redteam" in p.per_day:
            L += ["", "Red-team rows per day:", "", "| day | rows |", "|---:|---:|"]
            L += [f"| {d} | {n} |" for d, n in p.per_day["redteam"].items()]
    if p.user_mix:
        L += ["", "## Authentication mix per day", "",
              "| day | total | human (U) | computer ($) | anonymous | human users | red-team rows |",
              "|---:|---:|---:|---:|---:|---:|---:|"]
        rtd = p.per_day.get("redteam", {})
        for m in p.user_mix:
            L.append(f"| {m['day']} | {m['total']:,} | {m['human']:,} | {m['computer']:,} | {m['anonymous']:,} "
                     f"| {m['human_users']:,} | {rtd.get(m['day'], 0)} |")
    L += ["", "## Evaluation splits", ""]
    if splits:
        L += ["Half-open day ranges `[start, end)`. Strictly temporal; no row-level random splits. Red-team events "
              "inside the training range are removed before any model is fitted.", "",
              "| split | days | red-team rows |", "|---|---|---:|"]
        rtd = p.per_day.get("redteam", {})
        for name, (a, b) in splits.items():
            L.append(f"| {name} | {a}–{b - 1} | {sum(v for k, v in rtd.items() if a <= k < b)} |")
    else:
        L.append("Not fixed yet.")
    return "\n".join(L) + "\n"


def load_config(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m vigil.data.lanl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_in = sub.add_parser("ingest")
    p_in.add_argument("--tables", nargs="+", default=list(TABLES), choices=TABLES)
    p_in.add_argument("--force", action="store_true")
    p_in.add_argument("--config", type=Path, default=REPO / "configs" / "lanl.yaml")
    p_pr = sub.add_parser("profile")
    p_pr.add_argument("--config", type=Path, default=REPO / "configs" / "lanl.yaml")
    p_pr.add_argument("--out", type=Path, default=REPO / "docs" / "data" / "LANL_DATA_CARD.md")
    p_bu = sub.add_parser("build")
    p_bu.add_argument("--config", type=Path, default=REPO / "configs" / "lanl.yaml")
    p_bu.add_argument("--force", action="store_true")
    for p in (p_in, p_pr, p_bu):
        p.add_argument("--raw", type=Path, default=None)
        p.add_argument("--parquet", type=Path, default=None)
    args = ap.parse_args(argv)

    cfg = (load_config(args.config) if getattr(args, "config", None) else None) or {}
    data = cfg.get("data", {})
    raw, pqd, derived = data_paths(cfg)
    raw, pqd = args.raw or raw, args.parquet or pqd
    log = lambda m: print(m, file=sys.stderr, flush=True)  # noqa: E731

    if args.cmd == "ingest":
        ingest(args.tables, raw, pqd, force=args.force, log=log)
    elif args.cmd == "profile":
        con = connect(pqd)
        prof = profile(con, pqd, log=log)
        derived.mkdir(parents=True, exist_ok=True)
        (derived / "profile.json").write_text(json.dumps(prof.to_json(), indent=1))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_card(prof, data.get("splits")), encoding="utf-8")
        log(f"wrote {args.out}")
    elif args.cmd == "build":
        build_derived(connect(pqd), derived, force=args.force, log=log)


def data_paths(cfg: dict) -> tuple[Path, Path, Path]:
    """(raw, parquet, derived) directories for a benchmark config; relative paths are repo-relative."""
    data = cfg.get("data", {})

    def resolve(v: str | None, default: Path) -> Path:
        if not v:
            return default
        p = Path(v)
        return p if p.is_absolute() else REPO / p

    raw = resolve(data.get("raw"), raw_dir())
    pqd = resolve(data.get("parquet"), parquet_dir(raw))
    derived = resolve(data.get("derived"), REPO / "data" / "lanl" / cfg.get("name", "lanl"))
    return raw, pqd, derived


if __name__ == "__main__":
    main()
