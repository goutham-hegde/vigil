import numpy as np
import pytest
from sklearn.metrics import average_precision_score, roc_auc_score

from vigil.bench.metrics import Ranked, average_precision, evaluate, recall_at_budget, roc_auc
from vigil.bench.scores import ScoreSink, in_sample


def _data(n=4000, seed=0, ties=True):
    rng = np.random.default_rng(seed)
    y = rng.random(n) < 0.05
    s = rng.normal(size=n) + 1.5 * y
    if ties:
        s = np.round(s, 1)
    w = rng.uniform(0.5, 3.0, size=n)
    return y, s, w


@pytest.mark.parametrize("weighted", [False, True])
def test_ap_and_auc_match_sklearn(weighted):
    y, s, w = _data()
    w = w if weighted else None
    r = Ranked.build(y, s, w)
    assert average_precision(r) == pytest.approx(average_precision_score(y, s, sample_weight=w), abs=1e-9)
    assert roc_auc(r) == pytest.approx(roc_auc_score(y, s, sample_weight=w), abs=1e-9)


def test_recall_at_budget_counts_each_day_separately():
    y = np.array([1, 0, 0, 1, 1, 0, 0, 1], dtype=bool)
    s = np.array([9, 8, 7, 6, 9, 8, 7, 1], dtype=float)
    day = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    r = Ranked.build(y, s, day=day)
    assert recall_at_budget(r, 1) == pytest.approx(2 / 4)  # top of each day is a positive
    assert recall_at_budget(r, 3) == pytest.approx(2 / 4)
    assert recall_at_budget(r, 4) == pytest.approx(1.0)


def test_random_scores_give_chance_level():
    rng = np.random.default_rng(1)
    y = rng.random(200_000) < 0.01
    res = evaluate(y, rng.random(len(y)), n_boot=0)
    assert res["metrics"]["roc_auc"]["value"] == pytest.approx(0.5, abs=0.02)
    assert res["metrics"]["ap"]["value"] == pytest.approx(y.mean(), rel=0.2)


def test_bootstrap_interval_brackets_point_estimate():
    y, s, _ = _data(seed=2)
    cluster = np.arange(len(y)) % 97
    res = evaluate(y, s, cluster=cluster, n_boot=200)
    for k in ("ap", "roc_auc"):
        m = res["metrics"][k]
        assert m["lo"] <= m["value"] <= m["hi"]
        assert m["hi"] - m["lo"] > 0


def test_score_sink_is_exact_without_sampling():
    y, s, _ = _data(n=3000, ties=False)
    day = np.arange(len(y)) // 1000
    sink = ScoreSink(per_day_top=100, sample_rate=1.0)
    for chunk in np.array_split(np.arange(len(y)), 7):
        sink.add(chunk, s[chunk], y[chunk], day[chunk], chunk % 13)
    t = sink.table()
    assert t.num_rows == len(y)
    assert len(np.unique(t["key"].to_numpy())) == len(y)
    assert np.all(t["weight"].to_numpy() == 1)


def test_score_sink_sampling_keeps_top_exact_and_estimates_ap():
    y, s, _ = _data(n=200_000, seed=3, ties=False)
    day = np.arange(len(y)) // 20_000
    keys = np.arange(len(y))
    sink = ScoreSink(per_day_top=50, sample_rate=0.1)
    for chunk in np.array_split(keys, 11):
        sink.add(chunk, s[chunk], y[chunk], day[chunk], chunk % 101)
    t = sink.table()
    k, w = t["key"].to_numpy(), t["weight"].to_numpy()
    assert len(np.unique(k)) == len(k)
    assert t.num_rows < len(y) / 4
    # Every positive is kept at weight 1, and so is each day's exact top 50.
    assert set(keys[y]) <= set(k[w == 1])
    for d in range(10):
        m = day == d
        top = keys[m][np.argsort(-s[m])[:50]]
        assert set(top) <= set(k[w == 1])
    assert w.sum() == pytest.approx(len(y), rel=0.02)
    full = evaluate(y, s, day=day, n_boot=0)["metrics"]
    est = evaluate(t["label"].to_numpy(), t["score"].to_numpy(), w, t["day"].to_numpy(), n_boot=0)["metrics"]
    assert est["ap"]["value"] == pytest.approx(full["ap"]["value"], rel=0.05)
    assert est["recall@50/day"]["value"] == pytest.approx(full["recall@50/day"]["value"], abs=1e-12)


def test_hash_sample_is_deterministic_and_close_to_rate():
    keys = np.arange(100_000)
    a, b = in_sample(keys, 0.05), in_sample(keys, 0.05)
    assert np.array_equal(a, b)
    assert a.mean() == pytest.approx(0.05, rel=0.05)
