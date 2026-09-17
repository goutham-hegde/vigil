"""Combining the detectors into one score.

The models disagree by design: the heuristic knows about first contact, the GBM
knows about feature combinations, the graph knows who belongs where, and the
GRU knows each user's habits. Fusion is worth doing only if the combination
beats every member, which the ablation table in the report has to show.

Raw scores are not comparable (log-likelihoods, cosine distances, tree
outputs), so each member's score is turned into its rank within a reference
sample: the empirical CDF, giving every model a number in [0, 1]. Then:

* `ensemble_mean` averages those ranks. It uses no labels at all.
* `ensemble_stack` fits a logistic regression on the *validation* window and is
  therefore marked as having seen labels. Judge it on the test window only.

Members are run in one process, so each event is scored by every model without
storing intermediate score files.
"""

from __future__ import annotations

import numpy as np
import pyarrow as pa

from ..bench.experiment import EXPERIMENTS, Context, Experiment, register

DEFAULT_MEMBERS = ["first_seen_edge", "gbm_density_ratio", "graph_embed"]
QUANTILES = 1001


class _Member:
    """One model inside the ensemble, with its score turned into a rank."""

    def __init__(self, name: str, params: dict):
        self.name = name
        self.model = EXPERIMENTS[name](params)
        self.quantiles: np.ndarray | None = None

    def score(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        sql = self.model.score_sql(ctx)
        if sql is None:
            return np.asarray(self.model.score_batch(ctx, batch), dtype=float)
        joins, expr = sql
        # Evaluate the member's SQL over this batch, keeping the batch's order.
        idx = pa.table({"_row": np.arange(batch.num_rows)}).column("_row")
        view = batch.append_column("_row", idx)
        ctx.con.register("_ensemble_batch", view)
        try:
            out = ctx.con.execute(f"""
                SELECT ({expr})::DOUBLE AS score FROM _ensemble_batch e {joins} ORDER BY e._row
            """).to_arrow_table()
        finally:
            ctx.con.unregister("_ensemble_batch")
        return out["score"].to_numpy(zero_copy_only=False)

    def rank(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        s = self.score(ctx, batch)
        if self.quantiles is None:
            raise RuntimeError(f"{self.name}: not calibrated")
        return np.searchsorted(self.quantiles, s, side="right") / len(self.quantiles)


class BaseEnsemble(Experiment):
    def __init__(self, params=None):
        super().__init__(params)
        members = self.params.get("members") or DEFAULT_MEMBERS
        member_params = self.params.get("member_params") or {}
        unknown = set(members) - set(EXPERIMENTS)
        if unknown:
            raise ValueError(f"unknown ensemble members {sorted(unknown)}")
        self.members = [_Member(m, member_params.get(m, {})) for m in members]

    def batch_columns(self, ctx: Context):
        """The union of what the members need, with duplicate joins and columns removed."""
        joins, selects = [], []
        for m in self.members:
            extra = m.model.batch_columns(ctx)
            if not extra:
                continue
            j, s = extra
            if j.strip() and j.strip() not in joins:
                joins.append(j.strip())
            for col in _split_columns(s):
                if col not in selects:
                    selects.append(col)
        return "\n".join(joins), ", ".join(selects)

    def fit(self, ctx: Context) -> None:
        for m in self.members:
            ctx.log.info("ensemble: fitting %s", m.name)
            m.model.fit(ctx)
        sample = self._reference_sample(ctx, "train").drop_columns(["label"])
        for m in self.members:
            s = m.score(ctx, sample)
            m.quantiles = np.quantile(s[np.isfinite(s)], np.linspace(0, 1, QUANTILES))
            ctx.log.info("ensemble: calibrated %s on %d events", m.name, sample.num_rows)
        self._reset_stateful(ctx)

    def _reset_stateful(self, ctx: Context) -> None:
        """Calibration scores events out of order, which is meaningless for a model that
        carries per-user state, so rewind those members to the end of the training window."""
        for m in self.members:
            warm_up = getattr(m.model, "_warm_up", None)
            if warm_up is not None:
                warm_up(ctx)

    def _reference_sample(self, ctx: Context, split: str, n: int | None = None) -> pa.Table:
        """A deterministic slice of a split, with every column the members need."""
        n = n or int(self.params.get("calibration_sample", 200_000))
        a, b = ctx.splits[split]
        joins, extra = self.batch_columns(ctx)
        extra = f", {extra}" if extra else ""
        total = ctx.con.execute(
            f"SELECT count(*) FROM ({ctx.events_sql()}) WHERE day >= {a} AND day < {b}").fetchone()[0]
        cut = max(1, min(1_000_000, int(1_000_000 * n / max(total, 1))))
        return ctx.con.execute(f"""
            SELECT e.* {extra} FROM ({ctx.events_sql()}) e {joins}
            WHERE e.day >= {a} AND e.day < {b} AND (hash(e.key) % 1000000) < {cut}
            ORDER BY e.key
        """).to_arrow_table()

    def ranks(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        return np.column_stack([m.rank(ctx, batch) for m in self.members])


@register("ensemble_mean")
class EnsembleMean(BaseEnsemble):
    """Unsupervised fusion: the mean of the members' rank-normalised scores."""

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        weights = np.asarray(self.params.get("weights") or [1.0] * len(self.members), dtype=float)
        if len(weights) != len(self.members):
            raise ValueError("weights must have one entry per member")
        return self.ranks(ctx, batch) @ (weights / weights.sum())


@register("ensemble_stack")
class EnsembleStack(BaseEnsemble):
    """Logistic stacking fitted on the validation window; test numbers only."""

    supervised = True

    def fit(self, ctx: Context) -> None:
        from sklearn.linear_model import LogisticRegression

        super().fit(ctx)
        val = self._reference_sample(ctx, "val", int(self.params.get("stack_sample", 400_000)))
        y = val["label"].to_numpy(zero_copy_only=False).astype(int)
        if y.sum() == 0:
            raise ValueError("ensemble_stack: the validation window has no red-team events to fit on")
        X = self.ranks(ctx, val.drop_columns(["label"]))
        self._reset_stateful(ctx)
        self.meta = LogisticRegression(max_iter=1000, class_weight="balanced").fit(X, y)
        ctx.log.info("ensemble_stack: weights %s",
                     dict(zip([m.name for m in self.members], np.round(self.meta.coef_[0], 3))))

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        return self.meta.decision_function(self.ranks(ctx, batch))


def _split_columns(select: str) -> list[str]:
    """Split a SQL select list on top-level commas (expressions contain their own)."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(select):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(select[start:i].strip())
            start = i + 1
    tail = select[start:].strip()
    return [c for c in [*out, tail] if c]
