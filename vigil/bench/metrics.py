"""Detection metrics with bootstrap confidence intervals.

Every metric accepts per-row weights. Two things need them:

* LANL test windows hold hundreds of millions of benign events, so a score file
  keeps every red-team event, the exact top of each day, and a hash sample of
  the rest weighted by 1/rate (see `ScoreSink`). Weighted metrics on that file
  estimate the metrics on the full stream.
* The bootstrap resamples whole clusters (users by default) by drawing a count
  per cluster and multiplying it into the weights. The rows never move, so the
  scores are sorted once and each draw is a few cumulative sums.

The calibration helpers used by `vigil.train` also live here.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..model import softmax

BUDGETS = (50, 100, 500)  # alerts per day
FPRS = (1e-3, 1e-4)


@dataclass(slots=True)
class Ranked:
    """Rows sorted by descending score, with everything weight-independent precomputed.

    The bootstrap re-runs every metric hundreds of times with new weights but the
    same rows, so the sort order, the tie boundaries and the per-day grouping are
    computed once here. Each draw is then a handful of cumulative sums.
    """

    y: np.ndarray  # bool
    w: np.ndarray  # float
    day: np.ndarray  # int
    last_of_tie: np.ndarray  # bool: True where the next row has a lower score
    day_order: np.ndarray  # groups rows by day, keeping the score order within each day
    day_first: np.ndarray  # index of the first row of each row's day, in day_order space
    y_by_day: np.ndarray  # y[day_order], cached
    tie_starts: np.ndarray  # start index of each (day, score) tie group, in day_order space
    tie_day_first: np.ndarray  # day_first at each tie group's start

    @classmethod
    def build(cls, y, score, weight=None, day=None) -> Ranked:
        score = np.asarray(score, dtype=float)
        order = np.argsort(-score, kind="stable")
        s = score[order]
        last = np.ones(len(s), dtype=bool)
        last[:-1] = s[:-1] != s[1:]
        w = np.ones(len(s)) if weight is None else np.asarray(weight, dtype=float)[order]
        d = np.zeros(len(s), dtype=np.int64) if day is None else np.asarray(day)[order]
        y = np.asarray(y, dtype=bool)[order]
        day_order = np.argsort(d, kind="stable")
        sorted_days = d[day_order]
        day_first = np.searchsorted(sorted_days, sorted_days, side="left")
        # Tie groups: same day and same score. A coarse scorer puts thousands of
        # events on one score, and which of them an analyst would see first is
        # not decided by the model, so the budget metric averages over that.
        by_day_score = s[day_order]
        new_group = np.ones(len(day_order), dtype=bool)
        new_group[1:] = (sorted_days[1:] != sorted_days[:-1]) | (by_day_score[1:] != by_day_score[:-1])
        tie_starts = np.flatnonzero(new_group)
        return cls(y, w, d, last, day_order, day_first, y[day_order], tie_starts, day_first[tie_starts])


def _curve(r: Ranked, w: np.ndarray):
    """Cumulative weighted TP and FP at each distinct threshold."""
    tp = np.cumsum(np.where(r.y, w, 0.0))[r.last_of_tie]
    fp = np.cumsum(np.where(r.y, 0.0, w))[r.last_of_tie]
    return tp, fp


def average_precision(r: Ranked, w: np.ndarray | None = None) -> float:
    return _ap(*_curve(r, r.w if w is None else w))


def _ap(tp: np.ndarray, fp: np.ndarray) -> float:
    if tp[-1] <= 0:
        return float("nan")
    precision = tp / np.maximum(tp + fp, 1e-300)
    recall_step = np.diff(np.concatenate([[0.0], tp])) / tp[-1]
    return float(np.sum(recall_step * precision))


def roc_auc(r: Ranked, w: np.ndarray | None = None) -> float:
    return _auc(*_curve(r, r.w if w is None else w))


def _auc(tp: np.ndarray, fp: np.ndarray) -> float:
    if tp[-1] <= 0 or fp[-1] <= 0:
        return float("nan")
    tpr = np.concatenate([[0.0], tp / tp[-1]])
    fpr = np.concatenate([[0.0], fp / fp[-1]])
    return float(np.trapezoid(tpr, fpr))


def tpr_at_fpr(r: Ranked, target: float, w: np.ndarray | None = None) -> float:
    """Highest TPR among thresholds whose FPR does not exceed `target`."""
    return _tpr_at_fpr(*_curve(r, r.w if w is None else w), target)


def _tpr_at_fpr(tp: np.ndarray, fp: np.ndarray, target: float) -> float:
    if tp[-1] <= 0 or fp[-1] <= 0:
        return float("nan")
    ok = fp / fp[-1] <= target
    return float((tp[ok] / tp[-1]).max()) if ok.any() else 0.0


def precision_at_k(r: Ranked, k: int, w: np.ndarray | None = None) -> float:
    """Weighted precision of the top `k` (weighted) rows."""
    w = r.w if w is None else w
    cw = np.cumsum(w)
    top = cw <= k
    total = w[top].sum()
    return float(w[top & r.y].sum() / total) if total > 0 else float("nan")


def recall_at_budget(r: Ranked, per_day: int, w: np.ndarray | None = None) -> float:
    """Expected share of positive weight inside each day's top `per_day` alerts.

    This is the SOC view: a team works a fixed number of alerts a day, highest
    score first. Events tied on the same score are in no model-determined
    order, so when a tie group straddles the budget the metric takes the
    expectation over random orderings within it: the group contributes the
    fraction of itself that fits. A coarse scorer that puts 5,000 events on one
    score and has 100 slots therefore gets credit for 100/5,000 of the
    positives in that group, rather than all or none depending on row order.
    """
    w = r.w if w is None else w
    pos_total = w[r.y].sum()
    if pos_total <= 0:
        return float("nan")
    ww = w[r.day_order]
    cw = np.cumsum(ww)
    starts = r.tie_starts
    group_w = np.add.reduceat(ww, starts)
    pos_w = np.add.reduceat(np.where(r.y_by_day, ww, 0.0), starts)
    day_before = np.where(r.tie_day_first > 0, cw[np.maximum(r.tie_day_first - 1, 0)], 0.0)
    before_group = cw[starts] - ww[starts] - day_before  # weight ranked above this group, within its day
    share = np.clip((per_day - before_group) / np.maximum(group_w, 1e-300), 0.0, 1.0)
    return float(np.sum(share * pos_w) / pos_total)


def point_metrics(r: Ranked, w: np.ndarray | None = None) -> dict[str, float]:
    """Every metric from one pass over the data: the curve is shared, not recomputed per metric."""
    w = r.w if w is None else w
    tp, fp = _curve(r, w)
    out = {"ap": _ap(tp, fp), "roc_auc": _auc(tp, fp)}
    for f in FPRS:
        out[f"tpr@fpr={f:g}"] = _tpr_at_fpr(tp, fp, f)
    for b in BUDGETS:
        out[f"recall@{b}/day"] = recall_at_budget(r, b, w)
    return out


def evaluate(y, score, weight=None, day=None, cluster=None, n_boot: int = 500, seed: int = 0,
             alpha: float = 0.05) -> dict:
    """Point estimates plus cluster-bootstrap percentile intervals.

    `cluster` is one id per row (for example the user); clusters are resampled
    with replacement. Draws with no positives are skipped for that metric.
    """
    y = np.asarray(y, dtype=bool)
    r = Ranked.build(y, score, weight, day)
    point = point_metrics(r)
    w = r.w
    pos = float(w[r.y].sum())
    result = {
        "n_rows": int(len(y)),
        "n_positive": int(y.sum()),
        "weighted_total": float(w.sum()),
        "positive_rate": pos / float(w.sum()) if len(y) else float("nan"),
        "metrics": {},
    }
    draws: dict[str, list[float]] = {k: [] for k in point}
    if cluster is not None and n_boot > 0:
        order = np.argsort(-np.asarray(score, dtype=float), kind="stable")
        _, cid = np.unique(np.asarray(cluster)[order], return_inverse=True)
        n_clusters = cid.max() + 1
        rng = np.random.default_rng(seed)
        for _ in range(n_boot):
            counts = rng.multinomial(n_clusters, np.full(n_clusters, 1.0 / n_clusters))
            bw = w * counts[cid]
            for k, v in point_metrics(r, bw).items():
                if not np.isnan(v):
                    draws[k].append(v)
    for k, v in point.items():
        entry = {"value": v}
        if len(draws[k]) >= 20:
            lo, hi = np.quantile(draws[k], [alpha / 2, 1 - alpha / 2])
            entry.update(lo=float(lo), hi=float(hi), n_boot=len(draws[k]))
        result["metrics"][k] = entry
    return result


# Calibration helpers, shared with vigil.train.

def fit_temperature(raw: np.ndarray, y: np.ndarray) -> float:
    best_t, best_nll = 1.0, np.inf
    for t in np.linspace(0.4, 4.0, 37):
        p = softmax(raw / t)
        nll = -np.mean(np.log(p[np.arange(len(y)), y] + 1e-12))
        if nll < best_nll:
            best_t, best_nll = float(t), nll
    return best_t


def expected_calibration_error(probs: np.ndarray, y: np.ndarray, bins: int = 15) -> float:
    conf = probs.max(axis=1)
    correct = probs.argmax(axis=1) == y
    ece = 0.0
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi)
        if m.any():
            ece += m.mean() * abs(conf[m].mean() - correct[m].mean())
    return float(ece)


def pick_threshold(p_mal: np.ndarray, is_mal: np.ndarray, beta: float = 0.5) -> float:
    """Threshold on P(malicious) maximising F-beta; beta < 1 favours precision."""
    best, best_score = 0.5, -1.0
    for t in np.linspace(0.2, 0.97, 78):
        pred = p_mal >= t
        tp = np.sum(pred & is_mal)
        if tp == 0:
            continue
        prec = tp / pred.sum()
        rec = tp / is_mal.sum()
        score = (1 + beta**2) * prec * rec / (beta**2 * prec + rec)
        if score > best_score:
            best, best_score = float(t), score
    return best
