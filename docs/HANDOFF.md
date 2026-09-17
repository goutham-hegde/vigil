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
- `vigil/models/gbm.py` also has `gbm_density_ratio`: an unsupervised GBM. Benign training events are class 1, and class 0 is made by shuffling each feature column independently, so the model learns which *combinations* normal activity never produces (ESL 14.2.4). Same features as the supervised model, no labels anywhere.

**Started: M3 and M4-lite**
- `vigil/models/graph.py` (`graph_embed`): the user-host logon graph, weighted by PPMI, factorised with a truncated SVD. A logon scores high when the user's vector and the host's vector do not match. Fitted on the training window only; minutes of CPU, not hours.
- `vigil/models/sequence.py` (`sequence_gru`): a per-user event language model (Tuor et al. 2017). A 2-layer GRU reads each user's logon stream and predicts the next event; the score is the negative log-likelihood of what actually happened. One hidden state per user is carried forward in time, and a test proves an event's score cannot be changed by later events.
  - Needs PyTorch CPU: `.venv/Scripts/pip install --index-url https://download.pytorch.org/whl/cpu torch` (2.14.0+cpu is installed).
  - torch is not a runtime dependency of the engine, so its tests skip when it is missing and CI stays fast.
  - Not tuned or run on real data yet; sizes and epochs are parameters.
- Still to do: stacking/fusion (M5), ablations, the error analysis, and the benchmark tab (M6).

**Data (all ingested, 2026-09-18)**

| table | rows | days present | load time |
|---|---:|---|---:|
| auth | 1,051,430,459 | 0-57 | 38 min |
| proc | 426,045,096 | 0-57 | 11 min |
| flows | 129,977,412 | 0-23, 26-29, 36 | 4 min |
| dns | 40,821,591 | 0-57 (56 days) | 43 s |
| redteam | 749 | 18 days between 1 and 29 | - |

The five totals sum to 1,648,275,307, exactly the figure LANL publishes for the collection, so nothing was dropped or duplicated. Parquet is 11.6 GB in `C:\data\lanl\parquet` and C: has about 22 GB free.

**What the data card says (`docs/data/LANL_DATA_CARD.md`)**
- 749 red-team rows, 715 distinct, 104 accounts, 301 destination hosts, only 4 source hosts (C17693, C18025, C19932, C22409).
- 700 rows match exactly one auth event, 1 matches duplicates, 14 match none: **702 labelled events out of 1.05 B**, about 1 in 1.5 million.
- **Every labelled event is NTLM / Network.** Report NTLM's benign base rate alongside any result, so no model gets credit for learning "NTLM".
- Human (`U...`) logons are 3.8-7.2 M per day; 5-13 k distinct human accounts per day.
- Flows covers every red-team day, so the multi-layer ablation is possible throughout.

**Splits, fixed in `configs/lanl.yaml`**
- train days 0-7 (50 red-team rows removed), val days 8-11 (288 red-team events), test days 12-29 (411 red-team events).
- Days 30-57 are unused: no red-team activity, and no flow sensor for most of them.
- Day numbering is 0-based; some papers number the same days 1-58.

**Derived tables built** (`data/lanl/lanl/`, gitignored)
- `auth_edges_hourly`: 58 days of hourly per-edge counts.
- Features: 459,676 distinct user->host edges, 7.4 M user-hour rows, plus the host context tables.

## Commands

```bash
# Ingestion, once per table; skips tables that are already done. Needs about 1 M rows/s.
.venv/Scripts/python -m vigil.data.lanl ingest --tables auth      # after the download finishes
.venv/Scripts/python -m vigil.data.lanl profile                   # -> docs/data/LANL_DATA_CARD.md
.venv/Scripts/python -m vigil.data.lanl build --tables host       # proc/flows/dns context (done, 3 min)
.venv/Scripts/python -m vigil.data.lanl build                     # + hourly auth edges and auth features

# Benchmarks (needs data.splits set in configs/lanl.yaml)
.venv/Scripts/python -m vigil.bench run random
.venv/Scripts/python -m vigil.bench run first_seen_edge
.venv/Scripts/python -m vigil.bench run iforest
.venv/Scripts/python -m vigil.bench run gbm_density_ratio                    # unsupervised
.venv/Scripts/python -m vigil.bench run graph_embed
.venv/Scripts/python -m vigil.bench run sequence_gru --seed 0                # long; checkpointed and resumable
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

## Next steps (day 3, 2026-09-18)

Everything below runs unattended. **Plug the laptop in first** — it was on battery all night and the CPU throttles hard.

1. **Finish the model runs.** The overnight chain was stopped after `graph_embed` on purpose; these two are left:

   ```bash
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio     # est. 30-50 min
   .venv/Scripts/python -m vigil.bench run iforest               # est. 45-90 min
   .venv/Scripts/python -m vigil.bench report --data lanl        # rewrites docs/BENCHMARKS.md + the README table
   ```

   Estimates come from the measured runs: scoring 127 M events (val + test) is 1-2 min for a SQL model; the feature
   join and the model's own predict dominate for the rest. `gbm_density_ratio` will confirm the per-day join cost, so
   revise `iforest` from whatever it shows.

2. **The supervised upper bound**, once the unsupervised numbers are in:

   ```bash
   .venv/Scripts/python -m vigil.bench run gbm_supervised        # marked as having seen labels
   ```

3. **Ablations** (M5). Each is a separate run, and the report groups them:

   ```bash
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio --set "groups=[event,novelty]"
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio --set "groups=[event,novelty,history,user_hour]"   # auth only
   ```

   The auth-only run against the full-feature run is the "does multi-layer help?" answer. Report it either way.

4. **Fusion** (needs the members above): `ensemble_mean`, then `ensemble_stack`.

5. **`sequence_gru` is the risk.** Training is 1-3 h and scoring 127 M events through a per-user GRU may be 2-6 h,
   and it is unmeasured. Start it only with the laptop on AC, and time a single day first:
   if scoring cannot cover the whole test window, say so in the report and drop the model rather than scoring a subset.

6. **NTLM base rate.** Every labelled red-team event is `NTLM / Network`, so report how common NTLM is among benign
   logons; otherwise a model gets credit for learning one protocol. One query over `auth_edges_hourly`.

7. Then R1: README hero (the table is already generated), architecture SVG, demo GIF, and the resume bullets.

## Gotchas found the hard way

- `recall@budget` averages over tied scores; coarse heuristics tie thousands of events per day, and row order must not
  decide the result. If a metric definition changes, `vigil.bench recompute` re-evaluates finished runs from their
  score files instead of rescoring (scoring is the expensive part).
- The bootstrap is the slow half of a run if anything in it re-sorts per draw. Keep it to cumulative sums.
- The data card must never contain raw records: the LANL data is not redistributable. Counts only.
- Both paper references in the original plan were wrong: Tuor's LANL paper is arXiv:1712.00557 (AUC 0.98), and Euler
  is NDSS 2022. Verified figures and protocol differences are in `configs/published_baselines.yaml`.
