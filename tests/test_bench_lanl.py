"""End to end on the generated LANL-format fixture: ingest, label, split, run, report."""

import copy
import gzip

import numpy as np
import pytest

from vigil import models  # noqa: F401  (registers the experiments)
from vigil.bench import report, runner
from vigil.bench.experiment import Context, Experiment, register
from vigil.data import lanl


@pytest.fixture(scope="module")
def root(lanl_fixture):
    return lanl_fixture[0]


@pytest.fixture(scope="module")
def cfg(lanl_fixture):
    return lanl_fixture[1]


def _con(cfg):
    _, pqd, derived = lanl.data_paths(cfg)
    return lanl.connect(pqd, derived=derived)


def test_ingest_keeps_every_row_with_unique_keys(cfg):
    con = _con(cfg)
    raw, pqd, _ = lanl.data_paths(cfg)
    for t in lanl.TABLES:
        with gzip.open(raw / f"{t}.txt.gz", "rt") as f:
            lines = sum(1 for _ in f)
        n, lo, hi, distinct = con.execute(
            f"SELECT count(*), min(key), max(key), count(DISTINCT key) FROM {t}").fetchone()
        assert (n, lo, hi, distinct) == (lines, 0, lines - 1, lines)
    assert con.execute("SELECT count(*) FROM auth WHERE day <> time // 86400").fetchone()[0] == 0


def test_profile_reports_label_matching(cfg):
    con = _con(cfg)
    _, pqd, _ = lanl.data_paths(cfg)
    prof = lanl.profile(con, pqd, log=lambda m: None)
    assert prof.redteam["match_histogram"] == {"0": 1, "1": 31, "2+": 1}
    assert prof.redteam["matched_auth_events"] == 33
    card = lanl.render_card(prof, cfg["data"]["splits"])
    assert "| test | 4–5 |" in card


def test_labels_attach_to_matching_auth_events(cfg):
    con = _con(cfg)
    n = con.execute(f"SELECT count(*) FROM ({lanl.auth_events_sql('human')}) WHERE label").fetchone()[0]
    assert n == 33


def test_train_events_exclude_red_team(cfg, root):
    c = copy.deepcopy(cfg)
    c["data"]["splits"]["train"] = [0, 6]
    ctx = Context(c, _con(c), root, 0)
    sql = ctx.train_events_sql()
    cols = [d[0] for d in ctx.con.execute(f"SELECT * FROM ({sql}) LIMIT 0").description]
    assert "label" not in cols
    labelled = ctx.con.execute(f"SELECT key FROM ({ctx.events_sql()}) WHERE label").fetchall()
    kept = ctx.con.execute(
        f"SELECT count(*) FROM ({sql}) WHERE key IN (SELECT key FROM ({ctx.events_sql()}) WHERE label)"
    ).fetchone()[0]
    assert labelled and kept == 0


seen_batches = []


@register("_test_batch_probe")
class BatchProbe(Experiment):
    def score_batch(self, ctx, batch):
        seen_batches.append((batch.column_names, batch["day"].to_pylist(), batch["time"].to_pylist()))
        return np.zeros(batch.num_rows)


@register("_test_label_peek")
class LabelPeek(Experiment):
    def score_sql(self, ctx):
        return "", "e.label::INT"


def test_models_never_see_the_label(cfg, tmp_path):
    seen_batches.clear()
    runner.run("_test_batch_probe", cfg, runs_dir=tmp_path, force_power=True)
    assert seen_batches
    times = []
    for cols, days, ts in seen_batches:
        assert "label" not in cols
        times += ts
        assert all(2 <= d < 6 for d in days)
    assert times == sorted(times)
    with pytest.raises(ValueError, match="label"):
        runner.run("_test_label_peek", cfg, runs_dir=tmp_path, force_power=True)


def test_benchmark_end_to_end(cfg, tmp_path):
    dirs = {e: runner.run(e, cfg, runs_dir=tmp_path, force_power=True) for e in ("random", "first_seen_edge")}
    assert runner.run("random", cfg, runs_dir=tmp_path, force_power=True) == dirs["random"]  # completed: skipped
    bench = report.write(cfg["name"], runs_dir=tmp_path)
    by = {e["experiment"]: e["splits"]["test"]["metrics"] for e in bench["experiments"]}
    assert by["first_seen_edge"]["ap"]["mean"] > 0.5 > by["random"]["ap"]["mean"]
    assert by["random"]["roc_auc"]["mean"] == pytest.approx(0.5, abs=0.15)
    assert (tmp_path / "BENCHMARKS-fixture.md").read_text(encoding="utf-8").count("| first_seen_edge |") == 2
    for d in dirs.values():
        assert {"config.yaml", "meta.json", "metrics.json", "scores_val.parquet", "scores_test.parquet"} <= {
            p.name for p in d.iterdir()}


def test_readme_table_is_generated_from_runs(cfg, tmp_path):
    """README numbers come from the run files, never from hand editing."""
    from vigil.bench import report

    for e in ("random", "first_seen_edge"):
        runner.run(e, cfg, runs_dir=tmp_path, force_power=True)
    bench = report.collect(cfg["name"], runs_dir=tmp_path)
    table = report.render_readme(bench)
    assert "| first_seen_edge |" in table and "| random |" in table
    assert "red-team logons among" in table

    readme = tmp_path / "README.md"
    readme.write_text(f"before\n{report.README_START}\nplaceholder\n{report.README_END}\nafter\n", encoding="utf-8")
    assert report.update_readme(bench, readme)
    written = readme.read_text(encoding="utf-8")
    assert "placeholder" not in written
    assert written.startswith("before") and written.rstrip().endswith("after")

    # A README without the markers is left alone rather than mangled.
    plain = tmp_path / "plain.md"
    plain.write_text("no markers here\n", encoding="utf-8")
    assert not report.update_readme(bench, plain)
    assert plain.read_text(encoding="utf-8") == "no markers here\n"


def test_ntlm_control_is_reported_with_its_measured_auc(cfg, tmp_path):
    """Every labelled LANL event is NTLM, so the protocol alone is a strong ranker by AUC.

    Both generated reports have to say so, and with the number from the run:
    without it a reader takes a high AUC as evidence of detection.
    """
    for e in ("random", "ntlm_only"):
        runner.run(e, cfg, runs_dir=tmp_path, force_power=True)
    bench = report.collect(cfg["name"], runs_dir=tmp_path)
    control = next(e for e in bench["experiments"] if e["experiment"] == "ntlm_only")
    auc = control["splits"]["test"]["metrics"]["roc_auc"]["mean"]
    for text in (report.render(bench), report.render_readme(bench)):
        assert "confound control" in text
        assert f"{auc:.3f}" in text

    # No control run, no claim about one.
    only_random = report.collect(cfg["name"], runs_dir=tmp_path)
    only_random["experiments"] = [e for e in only_random["experiments"] if e["experiment"] != "ntlm_only"]
    assert "confound control" not in report.render(only_random)
