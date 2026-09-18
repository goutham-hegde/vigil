"""The LANL feature pipeline is causal, and the tabular models run end to end."""

import copy
import gzip
import importlib.util

import numpy as np
import pyarrow as pa
import pytest
from conftest import build_lanl

from vigil.bench import runner
from vigil.data import lanl
from vigil.models.auth_features import FEATURE_NAMES, GROUPS, JOINS, features_sql, select_list


def _features(cfg, last_day):
    _, pqd, derived = lanl.data_paths(cfg)
    con = lanl.connect(pqd, derived=derived)
    sql = features_sql(lanl.auth_events_sql("human"), f"e.day <= {last_day}")
    return con.execute(f"SELECT key, {', '.join(FEATURE_NAMES)} FROM ({sql}) ORDER BY key").fetchnumpy()


def test_features_ignore_the_future(lanl_fixture, tmp_path):
    """Deleting days 4-5 from every sensor must not change any feature of days 0-3."""
    root, cfg = lanl_fixture
    raw = tmp_path / "raw"
    raw.mkdir()
    for t in lanl.TABLES:
        with gzip.open(root / "raw" / f"{t}.txt.gz", "rt") as src, gzip.open(raw / f"{t}.txt.gz", "wt") as dst:
            dst.writelines(line for line in src if int(line.split(",", 1)[0]) < 4 * 86400)
    cut = build_lanl(tmp_path, raw)
    full, part = _features(cfg, 3), _features(cut, 3)
    assert len(full["key"]) == len(part["key"]) > 1000
    assert np.array_equal(full["key"], part["key"])
    for name in FEATURE_NAMES:
        np.testing.assert_allclose(full[name], part[name], err_msg=name)
    # And the features actually vary: a constant column would pass the test above trivially.
    assert sum(np.std(full[n]) > 0 for n in FEATURE_NAMES) >= len(FEATURE_NAMES) - 3


def test_red_team_events_look_novel(lanl_fixture):
    _, cfg = lanl_fixture
    _, pqd, derived = lanl.data_paths(cfg)
    con = lanl.connect(pqd, derived=derived)
    sql = features_sql(lanl.auth_events_sql("human"), "TRUE")
    red, benign = (con.execute(f"SELECT avg(since_user_src) FROM ({sql}) WHERE label = {v}").fetchone()[0]
                   for v in ("true", "false"))
    assert red < benign  # the attacker host is new for every stolen account


def test_feature_sql_never_mentions_label():
    assert "label" not in (JOINS + select_list()).lower()


# torch is only needed for the sequence model; it is not a runtime dependency of
# the engine, so CI can run everything else without it.
requires_torch = pytest.mark.skipif(importlib.util.find_spec("torch") is None, reason="torch is not installed")


@pytest.mark.parametrize("experiment,params", [
    ("iforest", {"n_estimators": 50, "max_samples": 256}),
    ("iforest", {"n_estimators": 50, "max_samples": 256, "groups": ["event", "novelty"]}),
    ("gbm_supervised", {"rounds": 30, "min_child_samples": 2}),
    ("gbm_density_ratio", {"rounds": 30, "min_child_samples": 5}),
    ("graph_embed", {"dim": 8}),
    pytest.param("sequence_gru", {"hidden": 16, "layers": 1, "window": 8, "epochs": 1, "batch": 16,
                                  "max_users": 50}, marks=requires_torch),
])
def test_models_run(lanl_fixture, tmp_path, experiment, params):
    _, cfg = lanl_fixture
    cfg = copy.deepcopy(cfg)
    cfg["data"]["splits"]["train"] = [0, 4]  # the supervised model needs red-team days to learn from
    cfg["eval"]["splits"] = ["test"]
    out = runner.run(experiment, cfg, params, runs_dir=tmp_path, force_power=True)
    import json
    m = json.loads((out / "metrics.json").read_text())["test"]["metrics"]
    assert 0 <= m["ap"]["value"] <= 1
    if experiment == "gbm_supervised":
        assert m["ap"]["value"] > 0.5
        assert json.loads((out / "meta.json").read_text())["supervised"] is True


def test_unknown_feature_group_is_rejected():
    from vigil.models.gbm import IForest
    with pytest.raises(ValueError, match="unknown feature groups"):
        IForest({"groups": ["nope"]})
    assert "novelty" in GROUPS


@pytest.fixture(scope="module")
def fitted_gru(lanl_fixture, tmp_path_factory):
    """A tiny trained sequence model, plus a context to score with."""
    pytest.importorskip("torch")
    from vigil.bench.experiment import Context
    from vigil.models.sequence import SequenceGRU

    _, cfg = lanl_fixture
    cfg = copy.deepcopy(cfg)
    cfg["data"]["splits"]["train"] = [0, 4]
    _, pqd, derived = lanl.data_paths(cfg)
    ctx = Context(cfg, lanl.connect(pqd, derived=derived), tmp_path_factory.mktemp("gru"), 0)
    exp = SequenceGRU({"hidden": 16, "layers": 1, "window": 8, "epochs": 1, "batch": 16, "max_users": 50})
    exp.fit(ctx)
    return exp, ctx


@requires_torch
def test_sequence_scores_depend_only_on_the_past(fitted_gru):
    exp, ctx = fitted_gru
    sql = lanl.auth_events_sql("human")
    user = ctx.con.execute(f"SELECT src_user FROM ({sql}) WHERE day = 4 GROUP BY 1 "
                           "HAVING count(*) > 5 ORDER BY 1 LIMIT 1").fetchone()[0]
    tbl = ctx.con.execute(f"SELECT * EXCLUDE (label) FROM ({sql}) WHERE day = 4 AND src_user = '{user}' "
                          "ORDER BY key LIMIT 6").to_arrow_table()

    def score(t):
        exp.state, exp.last = {}, {}  # same starting point both times
        return exp.score_batch(ctx, t)

    before = score(tbl)
    changed = tbl.set_column(tbl.schema.get_field_index("dst_comp"), "dst_comp",
                             pa.array(tbl["dst_comp"].to_pylist()[:-1] + ["C_ELSEWHERE"]))
    after = score(changed)
    np.testing.assert_array_equal(before[:-1], after[:-1])  # earlier events unaffected by a later change
    assert before[-1] != after[-1]  # the changed event itself does move


def test_drop_removes_named_features_without_disturbing_the_rest():
    """The NTLM-confound ablation must remove exactly three features and reorder nothing.

    A fitted model reads its columns positionally, so a `drop` that resequenced
    the survivors would silently score against the wrong features.
    """
    from vigil.models.auth_features import PROTOCOL_FEATURES
    from vigil.models.gbm import FeatureModel

    full = [f.name for f in FeatureModel({}).features]
    assert full == list(FEATURE_NAMES)  # the default is every feature, unablated

    ablated = [f.name for f in FeatureModel({"drop": list(PROTOCOL_FEATURES)}).features]
    assert set(full) - set(ablated) == set(PROTOCOL_FEATURES)
    assert ablated == [n for n in full if n not in PROTOCOL_FEATURES]

    # The confound spans two groups, which is why `groups` alone cannot isolate it.
    from vigil.models.auth_features import FEATURES
    assert len({f.group for f in FEATURES if f.name in PROTOCOL_FEATURES}) > 1

    with pytest.raises(ValueError, match="unknown features to drop"):
        FeatureModel({"drop": ["not_a_feature"]})
