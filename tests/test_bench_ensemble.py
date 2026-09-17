"""Fusion: members are combined, and the combination is judged like any other model."""

import copy
import json

import numpy as np
import pytest

from vigil import models  # noqa: F401  (registers the experiments)
from vigil.bench import runner
from vigil.models.ensemble import _split_columns

MEMBERS = ["first_seen_edge", "iforest", "graph_embed"]
PARAMS = {"members": MEMBERS, "calibration_sample": 2000,
          "member_params": {"iforest": {"n_estimators": 50, "max_samples": 256}, "graph_embed": {"dim": 8}}}


@pytest.fixture
def cfg(lanl_fixture):
    c = copy.deepcopy(lanl_fixture[1])
    c["data"]["splits"]["train"] = [0, 2]
    c["eval"]["splits"] = ["test"]
    return c


def _metrics(out):
    return json.loads((out / "metrics.json").read_text())["test"]["metrics"]


def test_mean_ensemble_combines_members(cfg, tmp_path):
    out = runner.run("ensemble_mean", cfg, PARAMS, runs_dir=tmp_path, force_power=True)
    members = {m: _metrics(runner.run(m, cfg, PARAMS["member_params"].get(m, {}), runs_dir=tmp_path,
                                      force_power=True))["ap"]["value"] for m in MEMBERS}
    ap = _metrics(out)["ap"]["value"]
    assert ap > min(members.values())  # fusion beats the weakest member
    assert json.loads((out / "meta.json").read_text())["supervised"] is False


def test_stacked_ensemble_is_flagged_as_supervised(cfg, tmp_path):
    cfg["eval"]["splits"] = ["test"]
    out = runner.run("ensemble_stack", cfg, {**PARAMS, "stack_sample": 5000}, runs_dir=tmp_path, force_power=True)
    assert json.loads((out / "meta.json").read_text())["supervised"] is True
    assert _metrics(out)["ap"]["value"] > 0.3


def test_unknown_member_is_rejected(cfg, tmp_path):
    with pytest.raises(ValueError, match="unknown ensemble members"):
        runner.run("ensemble_mean", cfg, {"members": ["nope"]}, runs_dir=tmp_path, force_power=True)


def test_select_list_splits_on_top_level_commas():
    assert _split_columns("a, f(b, c), d") == ["a", "f(b, c)", "d"]
    assert _split_columns("") == []


def test_member_scores_match_standalone_scores(cfg, tmp_path):
    """A member scored inside the ensemble gets the same scores as when run alone."""
    import pyarrow.parquet as pq

    from vigil.bench.experiment import Context
    from vigil.data import lanl
    from vigil.models.ensemble import EnsembleMean

    _, pqd, derived = lanl.data_paths(cfg)
    ctx = Context(cfg, lanl.connect(pqd, derived=derived), tmp_path / "ens", 0)
    ctx.run_dir.mkdir(parents=True, exist_ok=True)
    ens = EnsembleMean(PARAMS)
    ens.fit(ctx)
    joins, extra = ens.batch_columns(ctx)
    batch = ctx.con.execute(f"""
        SELECT e.* EXCLUDE (label), {extra} FROM ({ctx.events_sql()}) e {joins}
        WHERE e.day = 4 ORDER BY e.key LIMIT 500
    """).to_arrow_table()
    inside = ens.members[0].score(ctx, batch)  # first_seen_edge, the SQL member

    alone = runner.run("first_seen_edge", cfg, runs_dir=tmp_path, force_power=True)
    scores = pq.read_table(alone / "scores_test.parquet")
    by_key = dict(zip(scores["key"].to_pylist(), scores["score"].to_pylist()))
    keys = batch["key"].to_pylist()
    common = [(i, k) for i, k in enumerate(keys) if k in by_key]
    assert len(common) > 50
    np.testing.assert_allclose([inside[i] for i, _ in common], [by_key[k] for _, k in common])
