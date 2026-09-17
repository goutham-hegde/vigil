"""Tabular models on the causal auth features (`auth_features.py`).

* `iforest`: IsolationForest fitted on a sample of benign training events.
  Fully unsupervised; the score is how easy an event is to isolate.
* `gbm_supervised`: LightGBM trained on the training window *with* its
  red-team labels. It shows how far features alone can go when attacks of the
  same kind have been seen before. The report marks it as an upper bound.

Both accept `groups` (the feature groups to use, for ablations) and
`train_sample` (how many benign training events to fit on).
"""

from __future__ import annotations

import lightgbm as lgb
import numpy as np
import pyarrow as pa
from sklearn.ensemble import IsolationForest

from ..bench.experiment import Context, Experiment, register
from .auth_features import FEATURES, GROUPS, JOINS, select_list

_HASH_MOD = 1_000_000


class FeatureModel(Experiment):
    def __init__(self, params=None):
        super().__init__(params)
        groups = self.params.get("groups") or list(GROUPS)
        unknown = set(groups) - set(GROUPS)
        if unknown:
            raise ValueError(f"unknown feature groups {sorted(unknown)}; known: {GROUPS}")
        self.features = [f for f in FEATURES if f.group in groups]

    def batch_columns(self, ctx: Context):
        return JOINS, select_list(self.features)

    def matrix(self, tbl: pa.Table) -> np.ndarray:
        return np.column_stack([tbl[f.name].to_numpy(zero_copy_only=False) for f in self.features]).astype(np.float32)

    def sample(self, ctx: Context, events_sql: str, n: int, keep_positive: bool = False) -> pa.Table:
        """About `n` events from `events_sql`, chosen by a hash of the row key (deterministic)."""
        total = ctx.con.execute(f"SELECT count(*) FROM ({events_sql})").fetchone()[0]
        if total == 0:
            raise ValueError(f"{self.name}: the training window has no events")
        cut = max(1, min(_HASH_MOD, int(_HASH_MOD * n / total)))
        keep = f"(hash(e.key, {ctx.seed}) % {_HASH_MOD}) < {cut}"
        if keep_positive:
            keep = f"(e.label OR {keep})"
        extra = ", e.label" if keep_positive else ""
        tbl = ctx.con.execute(f"""
            SELECT {select_list(self.features)} {extra}
            FROM ({events_sql}) e {JOINS}
            WHERE {keep}
        """).to_arrow_table()
        ctx.log.info("%s: %d training rows sampled from %d", self.name, tbl.num_rows, total)
        return tbl


@register("iforest")
class IForest(FeatureModel):
    def fit(self, ctx: Context) -> None:
        X = self.matrix(self.sample(ctx, ctx.train_events_sql(), int(self.params.get("train_sample", 500_000))))
        self.model = IsolationForest(
            n_estimators=int(self.params.get("n_estimators", 200)),
            max_samples=int(self.params.get("max_samples", 4096)),
            random_state=ctx.seed, n_jobs=-1,
        ).fit(X)

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        return -self.model.score_samples(self.matrix(batch))


@register("gbm_density_ratio")
class GBMDensityRatio(FeatureModel):
    """An unsupervised GBM: no labels anywhere, on training or test.

    Trick from Hastie et al. (ESL 14.2.4). Take the benign training events as
    class 1, and manufacture class 0 by shuffling each feature column
    independently, which keeps every marginal but destroys the joint
    structure. A classifier separating the two learns
    log p_real(x) / p_independent(x), so a *low* value means a combination of
    feature values that normal activity does not produce. The anomaly score is
    the negative of it.

    This is the honest counterpart to `gbm_supervised`: same features, same
    trees, no knowledge of any attack.
    """

    def fit(self, ctx: Context) -> None:
        X = self.matrix(self.sample(ctx, ctx.train_events_sql(), int(self.params.get("train_sample", 1_000_000))))
        rng = np.random.default_rng(ctx.seed)
        fake = np.column_stack([rng.permutation(X[:, j]) for j in range(X.shape[1])])
        data = np.vstack([X, fake])
        y = np.concatenate([np.ones(len(X)), np.zeros(len(fake))])
        categorical = [i for i, f in enumerate(self.features) if f.categorical]
        dset = lgb.Dataset(data, y, feature_name=[f.name for f in self.features],
                           categorical_feature=categorical, free_raw_data=False)
        params = {
            "objective": "binary",
            "learning_rate": float(self.params.get("learning_rate", 0.1)),
            "num_leaves": int(self.params.get("num_leaves", 63)),
            "min_child_samples": int(self.params.get("min_child_samples", 50)),
            "feature_fraction": 0.8, "bagging_fraction": 0.8, "bagging_freq": 1,
            "seed": ctx.seed, "deterministic": True, "num_threads": 0, "verbose": -1,
        }
        self.booster = lgb.train(params, dset, num_boost_round=int(self.params.get("rounds", 200)))
        self.booster.save_model(str(ctx.run_dir / f"{self.name}.txt"))

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        return -self.booster.predict(self.matrix(batch), raw_score=True)


@register("gbm_supervised")
class GBMSupervised(FeatureModel):
    supervised = True

    def fit(self, ctx: Context) -> None:
        tbl = self.sample(ctx, ctx.train_labeled_sql(), int(self.params.get("train_sample", 2_000_000)),
                          keep_positive=True)
        y = tbl["label"].to_numpy(zero_copy_only=False).astype(int)
        if y.sum() == 0:
            raise ValueError(f"{self.name}: the training window has no red-team events to learn from")
        X = self.matrix(tbl)
        categorical = [i for i, f in enumerate(self.features) if f.categorical]
        data = lgb.Dataset(X, y, feature_name=[f.name for f in self.features], categorical_feature=categorical,
                           free_raw_data=False)
        params = {
            "objective": "binary",
            "learning_rate": float(self.params.get("learning_rate", 0.05)),
            "num_leaves": int(self.params.get("num_leaves", 31)),
            "min_child_samples": int(self.params.get("min_child_samples", 20)),
            "feature_fraction": 0.8, "bagging_fraction": 0.8, "bagging_freq": 1,
            "scale_pos_weight": float(self.params.get("scale_pos_weight", 10.0)),
            "seed": ctx.seed, "deterministic": True, "num_threads": 0, "verbose": -1,
        }
        self.booster = lgb.train(params, data, num_boost_round=int(self.params.get("rounds", 300)))
        self.booster.save_model(str(ctx.run_dir / f"{self.name}.txt"))

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        return self.booster.predict(self.matrix(batch), raw_score=True)
