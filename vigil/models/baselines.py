"""Reference scorers every learned model has to beat.

* `random`: a sanity check. Its AUC must come out near 0.5 and its AP near the
  positive rate, or the evaluation is broken.
* `first_seen_edge`: the classic LANL heuristic. Lateral movement means a user
  logging on to a host they have never touched, often from a host they have
  never used. It is a strong baseline on this data and is reported as such.
* `ntlm_only`: not a detector but a control. Every labelled red-team event in
  this collection is NTLM/Network, so "is it NTLM" alone is a near-perfect
  ranker by AUC. Any model whose AUC does not clear it has shown nothing.
"""

from __future__ import annotations

from ..bench.experiment import Context, Experiment, register


@register("random")
class RandomScore(Experiment):
    def score_sql(self, ctx: Context):
        return "", f"hash(e.key, {int(ctx.seed)}) / 18446744073709551616.0"


@register("ntlm_only")
class NtlmOnly(Experiment):
    """Score = 1 if the logon is NTLM, else 0. A confound control, not a detector.

    Every one of the 702 labelled events is NTLM/Network while only ~3.3% of
    benign human logons are, so this one-line rule ranks almost every red-team
    event above almost every benign one. Its AUC is therefore the floor that a
    real model has to beat before its own AUC means anything, and it is the
    reason the headline metrics here are AP and recall at an alert budget: the
    rule flags ~196k events a day, so it is worthless to an analyst despite the
    AUC. Reported, never tuned.
    """

    def score_sql(self, ctx: Context):
        return "", "(e.auth_type = 'NTLM')::INT"


@register("first_seen_edge")
class FirstSeenEdge(Experiment):
    """Score = 2·[user→dst first seen this hour] + [user from src first seen this hour] + edge recency.

    `first_hour` is the minimum over the whole collection, but comparing it with
    the event's own hour is still causal: the event itself happened in that
    hour, so the minimum is set by the past and present only. The recency term
    1/(2 + hours since the edge first appeared) orders the ties.
    """

    def fit(self, ctx: Context) -> None:
        edges = f"(SELECT * FROM auth_edges_hourly WHERE {ctx.user_filter_sql})"
        ctx.con.execute(f"""
            CREATE OR REPLACE TEMP TABLE fse_dst AS
            SELECT src_user, dst_comp, min(hour) AS first_hour FROM {edges} GROUP BY ALL
        """)
        ctx.con.execute(f"""
            CREATE OR REPLACE TEMP TABLE fse_src AS
            SELECT src_user, src_comp, min(hour) AS first_hour FROM {edges} GROUP BY ALL
        """)

    def score_sql(self, ctx: Context):
        joins = """
            JOIN fse_dst fd ON fd.src_user = e.src_user AND fd.dst_comp = e.dst_comp
            JOIN fse_src fs ON fs.src_user = e.src_user AND fs.src_comp = e.src_comp
        """
        expr = """
            2 * (e.hour = fd.first_hour)::INT + (e.hour = fs.first_hour)::INT
            + 1.0 / (2 + e.hour - fd.first_hour)
        """
        return joins, expr
