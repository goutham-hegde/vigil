# Handoff: LANL benchmark work

Where the ML upgrade stands, and the exact commands to carry it on. Update this at the end of every working day.

## State (2026-09-17, day 1)

**Done: M0, the benchmark foundations**
- `vigil/bench/metrics.py`: AP, ROC-AUC, TPR at a fixed FPR, precision@k, recall at a daily alert budget, and cluster-bootstrap CIs. Every metric is weighted. The calibration helpers moved here from `vigil/train.py`.
- `vigil/bench/scores.py`: `ScoreSink` keeps each day's exact top scores, all positives, and a hash sample of benign events, weighted by 1/rate. A test window of hundreds of millions of events fits in a few MB, and every alert-budget metric stays exact.
- `vigil/bench/runner.py` and `experiment.py`: `python -m vigil.bench run <exp>`.
  - Run folders are keyed by a config hash, and completed runs are skipped.
  - Runs record the git SHA and versions.
  - The runner refuses to start on low battery.
  - Models never receive the label: SQL that mentions it is rejected, and the column is dropped from batches.
- `vigil/bench/report.py`: builds `docs/BENCHMARKS.md` and `models/benchmarks.json` from `runs/`, grouping seeds.
- `vigil/data/lanl.py`: gz → day-partitioned Parquet with a unique row `key`, the data-card profile, and hourly edge tables.
- `vigil/data/fixture.py`: a tiny dataset in LANL format, used by the tests.
- `vigil/models/baselines.py`: the `random` sanity check and the `first_seen_edge` heuristic.
- Tests: `tests/test_bench_metrics.py` and `tests/test_bench_lanl.py`. They check agreement with sklearn, sink exactness, label matching, the leakage guard, and the end-to-end run on the fixture.

**Started: M2, the tabular models**
- `vigil/models/auth_features.py`: 40 causal features in 7 groups (event, novelty, history, user_hour, host_proc, host_flow, host_dns).
  - They are built as DuckDB lookup tables by `lanl build`.
  - The protocol is hourly batch scoring: a feature may use everything up to the end of the event's hour.
  - `tests/test_bench_features.py` proves causality: deleting future days changes no earlier feature.
- `vigil/models/gbm.py`:
  - `iforest`: unsupervised.
  - `gbm_supervised`: trained on training-window red-team labels, and marked † in the report as an upper bound.
  - Both take `groups=[...]` for ablations.
- Not done yet: the unsupervised GBM variant, and tuning.

**Data**
- Raw files are in `C:\data\lanl\`: redteam, dns, flows, proc. All pass `gzip -t`.
- `auth.txt.gz` (7.2 GB) is still downloading.
- Ingested so far:
  - redteam: 749 rows.
  - dns: 40,821,591 rows in 43 s.
  - flows: 129,977,412 rows in 256 s. Flows covers only 30 of the days, so host-flow features are missing on the other days.
  - proc: 426,045,096 rows in 674 s (58 days). At about 0.6–0.9 M rows/s, auth (about 1.05 B rows) should take roughly 20–30 min.

## Commands

```bash
# Ingestion, once per table; skips tables that are already done. Needs about 1 M rows/s.
.venv/Scripts/python -m vigil.data.lanl ingest --tables auth      # after the download finishes
.venv/Scripts/python -m vigil.data.lanl profile                   # -> docs/data/LANL_DATA_CARD.md
.venv/Scripts/python -m vigil.data.lanl build                     # hourly auth edge tables -> data/lanl/lanl/

# Benchmarks (needs data.splits set in configs/lanl.yaml)
.venv/Scripts/python -m vigil.bench run random
.venv/Scripts/python -m vigil.bench run first_seen_edge
.venv/Scripts/python -m vigil.bench run iforest
.venv/Scripts/python -m vigil.bench run gbm_supervised                       # needs red-team days inside train
.venv/Scripts/python -m vigil.bench run iforest --set "groups=[event,novelty,history]"   # ablation
.venv/Scripts/python -m vigil.bench report --data lanl            # -> docs/BENCHMARKS.md, models/benchmarks.json

# The same pipeline on the fixture (seconds)
.venv/Scripts/python -m vigil.data.fixture --out data/lanl_fixture/raw
.venv/Scripts/python -m vigil.data.lanl ingest --config configs/fixture.yaml
.venv/Scripts/python -m vigil.data.lanl build --config configs/fixture.yaml
.venv/Scripts/python -m vigil.bench run first_seen_edge --config configs/fixture.yaml
```

Raw data goes in `C:\data\lanl` and Parquet in `C:\data\lanl\parquet`. The env vars `VIGIL_LANL_RAW` and `VIGIL_LANL_PARQUET` override both locations. G: has little free space, so only small derived tables go there, under `data/`, which is gitignored.

## Next steps

1. When `auth.txt.gz` finishes, run `gzip -t` on it, then run `ingest --tables auth`. That's about 1.05 B rows, so expect 20–60 min, on AC power.
2. Run `profile`, then read the data card and **fix `data.splits` in `configs/lanl.yaml`**:
   - the splits are temporal;
   - training red-team events are removed automatically;
   - the test window must hold red-team activity.

   Record the split in the card by rerunning `profile`.
3. Run `build`, then `bench run random` and `bench run first_seen_edge`. That gives the first real numbers.
4. Run `iforest` and `gbm_supervised` on LANL, and check how long the feature joins take per day.
   - If they are too slow, lower `train_sample`, or materialise the features for each day.
5. M2 continued: an unsupervised GBM, for example real-vs-shuffled density-ratio training or novelty pseudo-labels; a small tuning grid on val; then the first `docs/BENCHMARKS.md`.
6. The `.gitignore` rule `data/` was changed to `/data/`, because it was hiding `vigil/data/`.
