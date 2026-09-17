"""Stratified score files for very large test windows.

A LANL test day holds millions of benign authentications. Keeping every score
is wasteful, while plain subsampling makes the "top 100 alerts a day" region
far too noisy. `ScoreSink` therefore keeps three strata:

* every row in its day's top `per_day_top` scores, with weight 1 (exact);
* every other positive, with weight 1 (exact, since positives are rare);
* the other negatives, sampled by a hash of the row key at `sample_rate`,
  with weight 1 / sample_rate.

Weighted metrics on the result estimate the metrics on the full stream and are
exact for alert budgets up to `per_day_top`. The sample depends only on the
row key, so every model is judged on the same random negatives.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

_HASH_SPACE = 1 << 32


def mix64(key: np.ndarray) -> np.ndarray:
    """splitmix64 finaliser: turns sequential or clustered keys into uniform bits."""
    z = np.asarray(key).astype(np.uint64, copy=True)
    with np.errstate(over="ignore"):
        z ^= z >> np.uint64(30)
        z *= np.uint64(0xBF58476D1CE4E5B9)
        z ^= z >> np.uint64(27)
        z *= np.uint64(0x94D049BB133111EB)
        z ^= z >> np.uint64(31)
    return z


def in_sample(key: np.ndarray, rate: float) -> np.ndarray:
    if rate >= 1.0:
        return np.ones(len(key), dtype=bool)
    return (mix64(key) & np.uint64(_HASH_SPACE - 1)) < np.uint64(int(rate * _HASH_SPACE))


COLUMNS = ("key", "score", "label", "day", "cluster")


class ScoreSink:
    def __init__(self, per_day_top: int = 2000, sample_rate: float = 0.01):
        self.per_day_top = per_day_top
        self.sample_rate = sample_rate
        self._top: dict[int, dict[str, np.ndarray]] = {}
        self._pos: list[dict[str, np.ndarray]] = []
        self._sample: list[dict[str, np.ndarray]] = []
        self.n_seen = 0

    def add(self, key, score, label, day, cluster) -> None:
        """Add a chunk. `key` must be a unique row id; `cluster` is the bootstrap unit (e.g. hashed user)."""
        cols = {
            "key": np.asarray(key).astype(np.uint64),
            "score": np.asarray(score, dtype=np.float64),
            "label": np.asarray(label, dtype=bool),
            "day": np.asarray(day, dtype=np.int32),
            "cluster": np.asarray(cluster).astype(np.uint64),
        }
        n = len(cols["key"])
        if any(len(v) != n for v in cols.values()):
            raise ValueError("ScoreSink.add: column lengths differ")
        if np.isnan(cols["score"]).any():
            raise ValueError("ScoreSink.add: NaN scores")
        self.n_seen += n
        self._pos.append(_take(cols, cols["label"]))
        self._sample.append(_take(cols, ~cols["label"] & in_sample(cols["key"], self.sample_rate)))
        for d in np.unique(cols["day"]):
            part = _take(cols, cols["day"] == d)
            if d in self._top:
                part = {k: np.concatenate([self._top[d][k], part[k]]) for k in COLUMNS}
            k = self.per_day_top
            if len(part["score"]) > k:
                # Keep everything tied with the k-th score, then order deterministically:
                # score descending, key ascending.
                kth = np.partition(part["score"], len(part["score"]) - k)[len(part["score"]) - k]
                part = _take(part, part["score"] >= kth)
                order = np.lexsort((part["key"], -part["score"]))[:k]
                part = _take(part, order)
            self._top[int(d)] = part

    def table(self) -> pa.Table:
        parts = [dict(v, weight=np.ones(len(v["key"]))) for v in self._top.values()]
        for chunk, w in ((self._pos, 1.0), (self._sample, 1.0 / self.sample_rate)):
            if not chunk:
                continue
            merged = {k: np.concatenate([c[k] for c in chunk]) for k in COLUMNS}
            keep = _not_in_top(merged, self._top)
            merged = _take(merged, keep)
            parts.append(dict(merged, weight=np.full(len(merged["key"]), w)))
        if not parts:
            return pa.table({k: pa.array([], type=t) for k, t in _SCHEMA.items()})
        data = {k: np.concatenate([p[k] for p in parts]) for k in (*COLUMNS, "weight")}
        return pa.table(data, schema=pa.schema(list(_SCHEMA.items())))

    def save(self, path: Path) -> pa.Table:
        t = self.table()
        pq.write_table(t, path, compression="zstd")
        return t


_SCHEMA = {"key": pa.uint64(), "score": pa.float64(), "label": pa.bool_(), "day": pa.int32(),
           "cluster": pa.uint64(), "weight": pa.float64()}


def _take(cols: dict[str, np.ndarray], idx) -> dict[str, np.ndarray]:
    return {k: v[idx] for k, v in cols.items()}


def _not_in_top(cols: dict[str, np.ndarray], top: dict[int, dict[str, np.ndarray]]) -> np.ndarray:
    """True for rows that are not already kept in their day's top stratum (keys are unique row ids)."""
    keep = np.ones(len(cols["key"]), dtype=bool)
    for d, t in top.items():
        m = cols["day"] == d
        if m.any():
            keep[m] = ~np.isin(cols["key"][m], t["key"])
    return keep
