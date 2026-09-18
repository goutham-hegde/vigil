"""Causal per-authentication features for LANL, computed in DuckDB.

Scoring protocol: events are scored in hourly batches, so a feature may use
everything that happened up to the end of the event's hour, and nothing later.
(A SOC running an hourly job has exactly that information.)

Novelty ("has this user ever touched this host?") and history ("how many users
have ever logged on to this host?") come from first-seen tables. The minimum
hour of an edge over the whole collection is still causal when compared with
the event's own hour, since that minimum is set by the past. The running
counts are cumulative sums over first-seen hours, looked up with an ASOF join
at the event's hour.

`tests/test_bench_features.py` checks the protocol: deleting all later days
must leave every feature of earlier days unchanged.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import duckdb

from ..data.lanl import HOUR, USER_FILTERS

# Categorical vocabularies are fixed here rather than learned, so feature codes
# never depend on which days were loaded. Unknown values map to 0.
AUTH_TYPES = ["Kerberos", "NTLM", "Negotiate", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "?"]
LOGON_TYPES = ["Network", "Service", "Batch", "Interactive", "Unlock", "RemoteInteractive", "CachedInteractive",
               "NewCredentials", "NetworkCleartext", "?"]
ORIENTATIONS = ["LogOn", "LogOff", "TGS", "TGT", "AuthMap", "ScreenLock", "ScreenUnlock"]


@dataclass(frozen=True)
class Feature:
    name: str
    sql: str
    group: str
    categorical: bool = False


def _code(col: str, vocab: list[str]) -> str:
    cases = " ".join(f"WHEN '{v}' THEN {i + 1}" for i, v in enumerate(vocab))
    return f"(CASE {col} {cases} ELSE 0 END)"


def _log(x: str) -> str:
    return f"ln(1 + coalesce({x}, 0))"


def _since(first: str) -> str:
    return f"ln(1 + (e.hour - {first}))"


FEATURES: list[Feature] = [
    # The event itself.
    Feature("auth_type_code", _code("e.auth_type", AUTH_TYPES), "event", True),
    Feature("logon_type_code", _code("e.logon_type", LOGON_TYPES), "event", True),
    Feature("orientation_code", _code("e.orientation", ORIENTATIONS), "event", True),
    Feature("failed", "(e.success <> 'Success')::INT", "event"),
    Feature("is_local", "(e.src_comp = e.dst_comp)::INT", "event"),
    Feature("other_dst_user", "(e.dst_user <> e.src_user)::INT", "event"),
    Feature("hour_of_day", "(e.hour % 24)", "event"),
    # Novelty: first time for this user / computer pair.
    Feature("new_user_dst", "(e.hour = fud.first_hour)::INT", "novelty"),
    Feature("since_user_dst", _since("fud.first_hour"), "novelty"),
    Feature("new_user_src", "(e.hour = fus.first_hour)::INT", "novelty"),
    Feature("since_user_src", _since("fus.first_hour"), "novelty"),
    Feature("new_src_dst", "(e.hour = fsd.first_hour)::INT", "novelty"),
    Feature("since_src_dst", _since("fsd.first_hour"), "novelty"),
    Feature("since_src_seen", _since("fsc.first_hour"), "novelty"),
    Feature("since_dst_seen", _since("fdc.first_hour"), "novelty"),
    Feature("since_user_seen", _since("fu.first_hour"), "novelty"),
    # History: how established the endpoints are.
    Feature("dst_users", _log("cdu.cum"), "history"),
    Feature("src_users", _log("csu.cum"), "history"),
    Feature("user_dsts", _log("cud.cum"), "history"),
    Feature("user_srcs", _log("cus.cum"), "history"),
    Feature("dst_user_share", "coalesce(cdu.cum, 0) / greatest(coalesce(cud.cum, 0), 1)", "history"),
    # The user's activity in this hour.
    Feature("user_hour_events", _log("uh.n_events"), "user_hour"),
    Feature("user_hour_dsts", _log("uh.n_dst"), "user_hour"),
    Feature("user_hour_srcs", _log("uh.n_src"), "user_hour"),
    Feature("user_hour_fails", _log("uh.n_fail"), "user_hour"),
    Feature("user_hour_ntlm", "coalesce(uh.n_ntlm / uh.n_events, 0)", "user_hour"),
    Feature("user_hour_new_dsts", _log("uh.n_new_dst"), "user_hour"),
    Feature("user_hour_new_srcs", _log("uh.n_new_src"), "user_hour"),
    # Host context from the other sensors (this hour).
    Feature("src_proc_starts", _log("hs.proc_starts"), "host_proc"),
    Feature("src_proc_new", _log("hs.proc_new"), "host_proc"),
    Feature("dst_proc_starts", _log("hd.proc_starts"), "host_proc"),
    Feature("dst_proc_new", _log("hd.proc_new"), "host_proc"),
    Feature("src_flows_out", _log("hs.flows_out"), "host_flow"),
    Feature("src_bytes_out", _log("hs.bytes_out"), "host_flow"),
    Feature("src_out_ports", _log("hs.out_ports"), "host_flow"),
    Feature("src_out_peers", _log("hs.out_peers"), "host_flow"),
    Feature("dst_flows_in", _log("hd.flows_in"), "host_flow"),
    Feature("dst_bytes_in", _log("hd.bytes_in"), "host_flow"),
    Feature("src_dns", _log("hs.dns_n"), "host_dns"),
    Feature("src_dns_names", _log("hs.dns_names"), "host_dns"),
]
FEATURE_NAMES = tuple(f.name for f in FEATURES)
GROUPS = tuple(dict.fromkeys(f.group for f in FEATURES))

# The features that carry the NTLM confound. Every labelled red-team event is
# NTLM/Network against a 3.3% benign base rate, so these three alone are worth
# ROC-AUC ~0.98 (see the `ntlm_only` baseline). They span two groups, so an
# ablation has to name them individually: pass them as `drop` to a FeatureModel.
PROTOCOL_FEATURES = ("auth_type_code", "logon_type_code", "user_hour_ntlm")

JOINS = """
    LEFT JOIN feat_first_user_dst fud ON fud.src_user = e.src_user AND fud.dst_comp = e.dst_comp
    LEFT JOIN feat_first_user_src fus ON fus.src_user = e.src_user AND fus.src_comp = e.src_comp
    LEFT JOIN feat_first_src_dst fsd ON fsd.src_comp = e.src_comp AND fsd.dst_comp = e.dst_comp
    LEFT JOIN feat_first_src fsc ON fsc.src_comp = e.src_comp
    LEFT JOIN feat_first_dst fdc ON fdc.dst_comp = e.dst_comp
    LEFT JOIN feat_first_user fu ON fu.src_user = e.src_user
    LEFT JOIN feat_user_hour uh ON uh.src_user = e.src_user AND uh.hour = e.hour
    LEFT JOIN feat_host_hour hs ON hs.comp = e.src_comp AND hs.hour = e.hour
    LEFT JOIN feat_host_hour hd ON hd.comp = e.dst_comp AND hd.hour = e.hour
    ASOF LEFT JOIN feat_cum_dst_users cdu ON cdu.dst_comp = e.dst_comp AND e.hour >= cdu.hour
    ASOF LEFT JOIN feat_cum_src_users csu ON csu.src_comp = e.src_comp AND e.hour >= csu.hour
    ASOF LEFT JOIN feat_cum_user_dsts cud ON cud.src_user = e.src_user AND e.hour >= cud.hour
    ASOF LEFT JOIN feat_cum_user_srcs cus ON cus.src_user = e.src_user AND e.hour >= cus.hour
"""


def select_list(features=FEATURES) -> str:
    return ",\n".join(f"({f.sql})::DOUBLE AS {f.name}" for f in features)


def _edges(user_filter: str) -> str:
    return f"(SELECT * FROM auth_edges_hourly WHERE {USER_FILTERS[user_filter]})"


def _first(key: str) -> str:
    return f"SELECT {key}, min(hour) AS first_hour FROM {{edges}} GROUP BY ALL"


def _cum(first_table: str, entity: str) -> str:
    return f"""
        SELECT {entity}, first_hour AS hour,
               sum(count(*)) OVER (PARTITION BY {entity} ORDER BY first_hour)::DOUBLE AS cum
        FROM {first_table} GROUP BY {entity}, first_hour
    """


# Tables over the auth edge table, in build order (later ones read earlier ones).
AUTH_TABLES = {
    "feat_first_user_dst": _first("src_user, dst_comp"),
    "feat_first_user_src": _first("src_user, src_comp"),
    "feat_first_src_dst": _first("src_comp, dst_comp"),
    "feat_first_src": _first("src_comp"),
    "feat_first_dst": _first("dst_comp"),
    "feat_first_user": _first("src_user"),
    "feat_cum_dst_users": _cum("feat_first_user_dst", "dst_comp"),
    "feat_cum_user_dsts": _cum("feat_first_user_dst", "src_user"),
    "feat_cum_src_users": _cum("feat_first_user_src", "src_comp"),
    "feat_cum_user_srcs": _cum("feat_first_user_src", "src_user"),
    "feat_user_hour": """
        WITH base AS (
            SELECT src_user, hour, sum(n)::DOUBLE AS n_events,
                   count(DISTINCT dst_comp)::DOUBLE AS n_dst, count(DISTINCT src_comp)::DOUBLE AS n_src,
                   (sum(n) FILTER (WHERE success <> 'Success'))::DOUBLE AS n_fail,
                   (sum(n) FILTER (WHERE auth_type = 'NTLM'))::DOUBLE AS n_ntlm
            FROM {edges} GROUP BY ALL),
        nd AS (SELECT src_user, first_hour AS hour, count(*)::DOUBLE AS n FROM feat_first_user_dst GROUP BY ALL),
        ns AS (SELECT src_user, first_hour AS hour, count(*)::DOUBLE AS n FROM feat_first_user_src GROUP BY ALL)
        SELECT base.*, coalesce(nd.n, 0) AS n_new_dst, coalesce(ns.n, 0) AS n_new_src
        FROM base
        LEFT JOIN nd USING (src_user, hour)
        LEFT JOIN ns USING (src_user, hour)
    """,
}


def _host_parts(present: set[str]) -> list[str]:
    parts = []
    if "proc" in present:
        parts.append(f"""
            SELECT comp, hour, count(*) FILTER (WHERE action = 'Start') AS proc_starts,
                   count(DISTINCT process) FILTER (WHERE is_new) AS proc_new
            FROM (
                SELECT p.comp, p.time // {HOUR} AS hour, p.action, p.process,
                       (p.time // {HOUR} = f.first_hour) AS is_new
                FROM proc p JOIN feat_first_proc f ON f.comp = p.comp AND f.process = p.process
            ) GROUP BY ALL
        """)
    if "flows" in present:
        parts.append(f"""
            SELECT src_comp AS comp, time // {HOUR} AS hour, count(*) AS flows_out, sum(bytes) AS bytes_out,
                   count(DISTINCT dst_port) AS out_ports, count(DISTINCT dst_comp) AS out_peers
            FROM flows GROUP BY ALL
        """)
        parts.append(f"""
            SELECT dst_comp AS comp, time // {HOUR} AS hour, count(*) AS flows_in, sum(bytes) AS bytes_in
            FROM flows GROUP BY ALL
        """)
    if "dns" in present:
        parts.append(f"""
            SELECT src_comp AS comp, time // {HOUR} AS hour, count(*) AS dns_n, count(DISTINCT resolved) AS dns_names
            FROM dns GROUP BY ALL
        """)
    return parts


HOST_COLUMNS = ["proc_starts", "proc_new", "flows_out", "bytes_out", "out_ports", "out_peers", "flows_in",
                "bytes_in", "dns_n", "dns_names"]


def _views(con) -> set[str]:
    return {r[0] for r in con.execute("SELECT view_name FROM duckdb_views() WHERE NOT internal").fetchall()}


def _copy(con, sql: str, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    con.execute(f"COPY ({sql}) TO '{path.as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
    return con.execute(f"SELECT count(*) FROM read_parquet('{path.as_posix()}')").fetchone()[0]


def _register(con, name: str, path: Path) -> None:
    con.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM read_parquet('{path.as_posix()}')")


def build_feature_tables(con: duckdb.DuckDBPyConnection, derived: Path, user_filter: str = "human",
                         force: bool = False, log=print) -> None:
    """Materialise every feature lookup table under `<derived>/features/` (idempotent)."""
    build_host_tables(con, derived, force=force, log=log)
    build_auth_tables(con, derived, user_filter, force=force, log=log)


def build_auth_tables(con: duckdb.DuckDBPyConnection, derived: Path, user_filter: str = "human",
                      force: bool = False, log=print) -> None:
    """The tables derived from authentications. Needs `auth_edges_hourly`."""
    out = derived / "features"
    marker = out / "_AUTH_BUILT.json"
    if marker.exists() and not force:
        log("auth features: already built, skipping")
        _register_dir(con, out)
        return
    if "auth_edges_hourly" not in _views(con):
        raise RuntimeError("auth_edges_hourly is missing; run `python -m vigil.data.lanl build` after ingesting auth")
    out.mkdir(parents=True, exist_ok=True)
    rows = {}
    edges = _edges(user_filter)
    for name, sql in AUTH_TABLES.items():
        rows[name] = _copy(con, sql.format(edges=edges), out / f"{name}.parquet")
        _register(con, name, out / f"{name}.parquet")
        log(f"  {name}: {rows[name]:,} rows")
    marker.write_text(json.dumps({"rows": rows, "user_filter": user_filter}))


def build_host_tables(con: duckdb.DuckDBPyConnection, derived: Path, force: bool = False, log=print) -> None:
    """Per-computer hourly context from proc, flows and DNS. Independent of auth, so it can be built first."""
    out = derived / "features"
    marker = out / "_HOST_BUILT.json"
    if marker.exists() and not force:
        log("host features: already built, skipping")
        _register_dir(con, out)
        return
    out.mkdir(parents=True, exist_ok=True)
    present = _views(con)
    rows = {}
    if "proc" in present:
        rows["feat_first_proc"] = _copy(
            con, f"SELECT comp, process, min(time) // {HOUR} AS first_hour FROM proc GROUP BY ALL",
            out / "feat_first_proc.parquet")
        _register(con, "feat_first_proc", out / "feat_first_proc.parquet")
        log(f"  feat_first_proc: {rows['feat_first_proc']:,} rows")
    parts = _host_parts(present)
    cols = ", ".join(f"sum({c})::DOUBLE AS {c}" for c in HOST_COLUMNS)
    if parts:
        # Union the per-sensor aggregates with NULL padding, then fold to one row per (comp, hour).
        padded = []
        for p in parts:
            have = _columns(con, p)
            sel = ", ".join(c if c in have else f"NULL AS {c}" for c in HOST_COLUMNS)
            padded.append(f"SELECT comp, hour, {sel} FROM ({p})")
        host_sql = f"SELECT comp, hour, {cols} FROM ({' UNION ALL '.join(padded)}) GROUP BY ALL"
    else:
        nulls = ", ".join(f"NULL::DOUBLE AS {c}" for c in HOST_COLUMNS)
        host_sql = f"SELECT NULL::VARCHAR AS comp, NULL::BIGINT AS hour, {nulls} LIMIT 0"
    rows["feat_host_hour"] = _copy(con, host_sql, out / "feat_host_hour.parquet")
    _register(con, "feat_host_hour", out / "feat_host_hour.parquet")
    log(f"  feat_host_hour: {rows['feat_host_hour']:,} rows (sensors: {sorted(present & {'proc', 'flows', 'dns'})})")
    marker.write_text(json.dumps({"rows": rows, "sensors": sorted(present & {"proc", "flows", "dns"})}))


def _columns(con, sql: str) -> set[str]:
    return {d[0] for d in con.execute(f"SELECT * FROM ({sql}) LIMIT 0").description}


def register_feature_tables(con: duckdb.DuckDBPyConnection, derived: Path) -> None:
    out = derived / "features"
    if not (out / "_AUTH_BUILT.json").exists():
        raise RuntimeError(f"feature tables not built under {out}; run `python -m vigil.data.lanl build`")
    _register_dir(con, out)


def _register_dir(con: duckdb.DuckDBPyConnection, out: Path) -> None:
    for p in sorted(out.glob("*.parquet")):
        _register(con, p.stem, p)


def features_sql(events_sql: str, where: str, features=FEATURES) -> str:
    """Events joined to their features. `events_sql` must expose alias-able columns of auth_events."""
    return f"""
        SELECT e.*, {select_list(features)}
        FROM ({events_sql}) e
        {JOINS}
        WHERE {where}
    """
