"""The contract between the benchmark runner and a model.

A model subclasses `Experiment`, registers itself with `@register("name")`,
and scores authentication events in one of two ways:

* `score_sql(ctx)` returns `(joins, expression)`: SQL evaluated per event over
  the alias `e`. Heuristics use this, because it stays inside DuckDB.
* `score_batch(ctx, batch)` receives Arrow batches in time order, one day at a
  time, and returns one score per row. Stateful models use this, and
  `batch_columns(ctx)` can add SQL-computed columns (features) to each batch.

Either way the model never receives the label. The runner attaches the label
to the scores itself, rejects SQL that mentions it, and removes the column
from every batch before handing it over.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import duckdb
import numpy as np
import pyarrow as pa

from ..data.lanl import USER_FILTERS, auth_events_sql

EXPERIMENTS: dict[str, type[Experiment]] = {}


def register(name: str):
    def deco(cls):
        cls.name = name
        EXPERIMENTS[name] = cls
        return cls
    return deco


@dataclass
class Context:
    cfg: dict
    con: duckdb.DuckDBPyConnection
    run_dir: Path
    seed: int
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("vigil.bench"))

    @property
    def splits(self) -> dict[str, tuple[int, int]]:
        return {k: tuple(v) for k, v in self.cfg["data"]["splits"].items()}

    @property
    def user_filter(self) -> str:
        return self.cfg["data"].get("users", "human")

    @property
    def checkpoint_dir(self) -> Path:
        p = self.run_dir / "checkpoint"
        p.mkdir(exist_ok=True)
        return p

    def events_sql(self) -> str:
        """All scorable events, with the label column (runner use only)."""
        return auth_events_sql(self.user_filter)

    def train_labeled_sql(self, split: str = "train") -> str:
        """Events of a split *with* labels. Only for experiments marked `supervised`, which the report flags."""
        a, b = self.splits[split]
        return f"SELECT * FROM ({self.events_sql()}) WHERE day >= {a} AND day < {b}"

    def train_events_sql(self) -> str:
        """Training-window events with known red-team events removed; no label column."""
        a, b = self.splits["train"]
        return f"SELECT * EXCLUDE (label) FROM ({self.events_sql()}) WHERE day >= {a} AND day < {b} AND NOT label"

    @property
    def user_filter_sql(self) -> str:
        return USER_FILTERS[self.user_filter]


class Experiment:
    name: ClassVar[str] = ""
    supervised: ClassVar[bool] = False  # trained on earlier red-team labels (marked † in the report)

    def __init__(self, params: dict | None = None):
        self.params = params or {}

    def fit(self, ctx: Context) -> None:
        """Fit on the training window. Must not use labels."""

    def score_sql(self, ctx: Context) -> tuple[str, str] | None:
        return None

    def batch_columns(self, ctx: Context) -> tuple[str, str] | None:
        """Optional `(joins, select list)` over alias `e`, added to every batch passed to `score_batch`."""
        return None

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        raise NotImplementedError
