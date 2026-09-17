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
    """Rows sorted by descending score, with tied scores marked."""

    y: np.ndarray  # bool
    w: np.ndarray  # float
    day: np.ndarray  # int
    last_of_tie: np.ndarray  # bool: True where the next row has a lower score

    @classmethod
    def build(cls, y, score, weight=None, day=None) -> Ranked:
        score = np.asarray(score, dtype=float)
        order = np.argsort(-score, kind="stable")
        s = score[order]
        last = np.ones(len(s), dtype=bool)
        last[:-1] = s[:-1] != s[1:]
        w = np.ones(len(s)) if weight is None else np.asarray(weight, dtype=float)[order]
        d = np.zeros(len(s), dtype=np.int64) if day is None else np.asarray(day)[order]
        return cls(np.asarray(y, dtype=bool)[order], w, d, last)


def _curve(r: Ranked, w: np.ndarray):
    """Cumulative weighted TP and FP at each distinct threshold."""
    tp = np.cumsum(np.where(r.y, w, 0.0))[r.last_of_tie]
    fp = np.cumsum(np.where(r.y, 0.0, w))[r.last_of_tie]
    return tp, fp


def average_precision(r: Ranked, w: np.ndarray | None = None) -> float:
    w = r.w if w is None else w
    tp, fp = _curve(r, w)
    if tp[-1] <= 0:
        return float("nan")
    precision = tp / np.maximum(tp + fp, 1e-300)
    recall_step = np.diff(np.concatenate([[0.0], tp])) / tp[-1]
    return float(np.sum(recall_step * precision))


def roc_auc(r: Ranked, w: np.ndarray | None = None) -> float:
    w = r.w if w is None else w
    tp, fp = _curve(r, w)
    if tp[-1] <= 0 or fp[-1] <= 0:
        return float("nan")
    tpr = np.concatenate([[0.0], tp / tp[-1]])
    fpr = np.concatenate([[0.0], fp / fp[-1]])
    return float(np.trapezoid(tpr, fpr))


def tpr_at_fpr(r: Ranked, target: float, w: np.ndarray | None = None) -> float:
    """Highest TPR among thresholds whose FPR does not exceed `target`."""
    w = r.w if w is None else w
    tp, fp = _curve(r, w)
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
    """Share of positive weight inside each day's top `per_day` alerts.

    This is the SOC view: an analyst team works a fixed number of alerts a day.
    A row is alerted when the weight ranked above it on its day, itself
    included, fits in the budget. Ties are broken by input order.
    """
    w = r.w if w is None else w
    pos_total = w[r.y].sum()
    if pos_total <= 0:
        return float("nan")
    order = np.argsort(r.day, kind="stable")  # stable keeps the score order within a day
    d, ww = r.day[order], w[order]
    cw = np.cumsum(ww)
    starts = np.searchsorted(d, d, side="left")
    before = np.where(starts > 0, cw[np.maximum(starts - 1, 0)], 0.0)
    alerted = (cw - before) <= per_day
    return float(ww[alerted & r.y[order]].sum() / pos_total)


def point_metrics(r: Ranked, w: np.ndarray | None = None) -> dict[str, float]:
    out = {"ap": average_precision(r, w), "roc_auc": roc_auc(r, w)}
    for f in FPRS:
        out[f"tpr@fpr={f:g}"] = tpr_at_fpr(r, f, w)
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
