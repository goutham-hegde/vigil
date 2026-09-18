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
.venv/Scripts/python -m vigil.bench run ntlm_only                            # confound control, always report it
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

1. **Finish the model runs.** The overnight chain was stopped after `graph_embed` on purpose; these are left:

   ```bash
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio     # est. 30-50 min
   .venv/Scripts/python -m vigil.bench run iforest               # est. 45-90 min
   .venv/Scripts/python -m vigil.bench run ntlm_only             # ~2 min, SQL; the confound control, see below
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
   # The one that matters most: is the model finding lateral movement, or finding NTLM?
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio \
       --set "drop=[auth_type_code,logon_type_code,user_hour_ntlm]"

   .venv/Scripts/python -m vigil.bench run gbm_density_ratio --set "groups=[event,novelty]"
   .venv/Scripts/python -m vigil.bench run gbm_density_ratio --set "groups=[event,novelty,history,user_hour]"   # auth only
   ```

   The auth-only run against the full-feature run is the "does multi-layer help?" answer. Report it either way.

   The `drop` run is the answer to finding 3 below. Three features carry the NTLM confound
   (`auth_features.PROTOCOL_FEATURES`) and they span two groups, so `groups` cannot isolate them — hence `drop`.
   **Run it for `gbm_supervised` too, where the confound is worst**: a supervised model will learn "NTLM" straight
   from the labels, so its unablated number is close to meaningless as an upper bound.

4. **Fusion** (needs the members above): `ensemble_mean`, then `ensemble_stack`.

5. **`sequence_gru` is the risk.** Training is 1-3 h and scoring 127 M events through a per-user GRU may be 2-6 h,
   and it is unmeasured. Start it only with the laptop on AC, and time a single day first:
   if scoring cannot cover the whole test window, say so in the report and drop the model rather than scoring a subset.

6. ~~**NTLM base rate.**~~ Done — and it is worse than expected. See "Three questions answered" below: a bare
   `auth_type = 'NTLM'` test scores ROC-AUC ≈ 0.98 on its own. Run `ntlm_only` and print it in every table.

7. Then R1: README hero (the table is already generated), architecture SVG, demo GIF, and the resume bullets.

## First real results (2026-09-18, days 12-29, 386 red-team events in 106.7 M)

| model | AP | recall @100/day | ROC-AUC |
|---|---:|---:|---:|
| first_seen_edge | 2.3e-04 | 3.3e-04 | 0.889 |
| graph_embed | 1.2e-05 | 1.1e-04 | 0.734 |
| random | 3.8e-06 | 0 | 0.513 |

Random's AP equals the positive rate (3.6e-06), so the evaluation itself is sound. `first_seen_edge` is ~60x random
on AP with a respectable AUC, and still catches almost nothing inside a realistic alert budget.

## Three questions answered (2026-09-18, day 3)

All three were open at the end of day 2. The first two hypotheses in this file were **wrong**; the answers are below
and the reasoning they replace has been deleted so nobody re-runs it.

### 1. Red-team logons *are* novel edges. The novel-edge population is just enormous.

The worry was that `first_seen_edge` scores 3.3e-04 at 100 alerts/day because red-team logons are not first-contact
edges at all. They are:

| test events | first-ever user→dst | first-ever user←src | both |
|---|---:|---:|---:|
| benign (106,704,127) | 0.313% | 0.489% | 0.237% |
| red team (386) | **37.6%** | 21.8% | 8.8% |

A 120x lift, so novelty is a genuine signal. The budget metric is low for a different reason — the size of the tie
groups it has to average over:

| score | what it means | benign/day | red team (18 days) |
|---:|---|---:|---:|
| 3.5 | dst *and* src edge both new | 14,154 | 34 |
| 2.5 | dst edge new | 4,190 | 111 |
| | **cumulative** | **18,343** | **145** |

145 of 386 red-team events sit in the top two tie groups, alongside 18,343 benign events *per day*. A 100-alert budget
buys ~0.5% of one tie group, which reproduces the measured 3.3e-04 almost exactly. So the metric is right and the
heuristic is real but hopelessly unselective: in a network of 5.9 M human logons a day, 18 k first-contact logons a day
are simply routine. **This is the finding to report** — it is the argument for the whole modelling effort, since
ranking *within* that block is exactly what a learned model has to do.

### 2. `graph_embed`'s `UNSEEN` constant is not what holds it back — the embedding is.

The `UNSEEN = 1.0` block is large (68,728 benign events/day, 1.15% of benign; 9.8% of labelled), but deleting it makes
the model *worse*, not better:

| graph_embed, test | ROC-AUC | AP | recall@100/day |
|---|---:|---:|---:|
| as reported | 0.734 | 1.2e-05 | 1.1e-04 |
| known (user, host) pairs only | 0.714 | 8.0e-06 | 0 |

So the constant is carrying the model and the learned PPMI+SVD cosine is the weak half. Widening the fitting window or
softening `UNSEEN` would not rescue it. **The honest conclusion is that the graph embedding adds nothing over the
trivial novelty heuristic on this data**, and the reason is the embedding itself. Do not spend more time on it; if the
graph is worth another attempt it needs a different formulation (temporal, or community-deviation), not a tweak.

### 3. The NTLM confound is severe, and it invalidates ROC-AUC as a headline.

Every one of the labelled events is NTLM/Network, against a 3.30% benign base rate. So this rule —

```sql
score = (auth_type = 'NTLM')
```

— ranks nearly every red-team event above nearly every benign one, for **ROC-AUC ≈ 0.98**. That beats every model
measured so far (`first_seen_edge` 0.889) and matches the 0.98 that Tuor et al. publish on this dataset. It is also
useless: it flags ~195,700 events a day.

Consequences, and they are not optional:
- `ntlm_only` is now a registered baseline (`vigil/models/baselines.py`) so the number comes from a run, not from
  arithmetic in a doc. Every report must carry it.
- **AP and recall at an alert budget are the headline metrics; ROC-AUC is reported but never led with.** An AUC below
  0.98 on this data means a model is doing *worse than a protocol check*.
- Any model that is allowed `auth_type` as a feature must be checked against this, or it gets credit for learning one
  protocol. This is the same class of shortcut as the three the README already documents.

## Gotchas found the hard way

- `recall@budget` averages over tied scores; coarse heuristics tie thousands of events per day, and row order must not
  decide the result. If a metric definition changes, `vigil.bench recompute` re-evaluates finished runs from their
  score files instead of rescoring (scoring is the expensive part).
- The bootstrap is the slow half of a run if anything in it re-sorts per draw. Keep it to cumulative sums.
- The data card must never contain raw records: the LANL data is not redistributable. Counts only.
- Both paper references in the original plan were wrong: Tuor's LANL paper is arXiv:1712.00557 (AUC 0.98), and Euler
  is NDSS 2022. Verified figures and protocol differences are in `configs/published_baselines.yaml`.
