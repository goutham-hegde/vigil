"""The LANL feature pipeline is causal, and the tabular models run end to end."""

import copy
import gzip

import numpy as np
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


@pytest.mark.parametrize("experiment,params", [
    ("iforest", {"n_estimators": 50, "max_samples": 256}),
    ("iforest", {"n_estimators": 50, "max_samples": 256, "groups": ["event", "novelty"]}),
    ("gbm_supervised", {"rounds": 30, "min_child_samples": 2}),
])
def test_tabular_models_run(lanl_fixture, tmp_path, experiment, params):
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
