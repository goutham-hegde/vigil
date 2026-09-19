# Design decisions

Why this project is built the way it is, and what was deliberately not done.
Results live in `docs/BENCHMARKS.md` and `models/metrics.json`; this file is
about the reasoning, including the parts that are uncomfortable.

Vigil has two halves:

* a **synthetic engine**: a simulated organisation, a live attack simulator, a
  detector, alert and incident correlation, and a SOC dashboard;
* a **benchmark on real data**: the LANL *Comprehensive, Multi-Source
  Cyber-Security Events* collection, 58 days of enterprise logs with red-team
  labels.

The first shows the pipeline works end to end. Only the second says anything
about the detection itself, because a model evaluated on data produced by its
own simulator is mostly measuring the simulator.

## Evaluation

**Time-based splits, never a random row split.** Neighbouring events of one
attack are near-duplicates. Splitting rows at random puts a copy of nearly
every attack event in the training set, and every metric goes up for no real
reason. Training uses earlier days; validation and test are later days, and
the test window holds red-team activity never seen during training. The
synthetic engine does the same thing differently: train, validation and test
come from independent simulation runs with different seeds, attacker
addresses, victims and times of day.

**Average precision and recall at an alert budget, not ROC-AUC.** Red-team
events are a vanishing fraction of authentication traffic. With positives that
rare, ROC-AUC is dominated by the enormous benign majority and looks excellent
while the alert queue is useless. It is still reported, because it is what
most published work reports, but it is never the headline. The headline is
**recall at 50, 100 and 500 alerts a day**: a SOC has a fixed number of
analyst-hours, and the only question is how many real compromises fit inside
that budget.

**Confidence intervals by bootstrapping users, not events.** One compromised
account produces many correlated events, so resampling events would pretend
there is far more independent evidence than there is. Whole users are
resampled instead. The interval is computed by reweighting a single sorted
score array rather than rebuilding datasets, which keeps a thousand bootstrap
draws cheap even on a very large test window.

**Keeping a small, honest slice of the scores.** A test window holds hundreds
of millions of events, and storing every score is wasteful — but plain
subsampling destroys exactly the region that matters, the top 100 alerts of a
day. So each score file keeps three strata: every day's exact top scores,
every positive, and a hash sample of the remaining benign events weighted by
1/rate. Weighted metrics on that file estimate metrics on the full stream, and
the alert-budget numbers are exact rather than estimated. The sample depends
only on a hash of the row id, so every model is judged on the same negatives.

**Supervised results are labelled as such.** `gbm_supervised` trains on
red-team labels from the training window, and `ensemble_stack` fits its
weights on labelled validation data. Both are marked † in the report. They
measure recognising an attacker already seen labelled, not detecting a new one:
on LANL every test catch comes from the host that dominates the training labels.
A real deployment meeting a new intrusion has no labels for it.
The unsupervised models are the honest number, and the gap between them is
itself a result worth reporting.

**Rejected:** tuning anything on the test window; reporting a single best seed
for neural models (they are reported as mean and spread over seeds); and
quoting a figure from a paper as a head-to-head comparison when the protocol
differs. Published results go in a table that states each protocol difference,
and only after the figure has been checked against the paper.

## Leakage, and how it is prevented

Evaluation shortcuts are the easiest way to produce impressive nonsense. Three
were found and removed from the synthetic engine earlier: large uploads
appearing only in attacks, a malicious launcher process always present, and
external sources appearing only in attacks. Each let the model identify
attacks from an artefact of the simulator rather than from behaviour. They are
described in the README so the earlier numbers are not quietly forgotten.

On the LANL side the guards are structural:

* **Models never receive the label.** The runner attaches labels to scores
  itself, strips the column from every batch handed to a model, and refuses
  scoring SQL that mentions it. A test asserts this.
* **Features may not see the future.** A test rebuilds the whole pipeline with
  every later day deleted and asserts that no feature of an earlier day
  changes.
* **Scoring is hourly.** A feature may use everything up to the end of the
  event's own hour and nothing after it, which is what an hourly SOC job would
  have. This is stated rather than hidden, because "has this user ever reached
  this host before?" is computed from a first-seen table: the first hour of an
  edge is fixed by the past, so comparing it with the event's own hour is
  causal, while the same table would leak if it were compared against a
  finer-grained timestamp.
* **Training excludes known red-team events**, which is the standard
  unsupervised protocol on this data.

**Known limitation:** the red-team file lists *known* compromise. Other
malicious activity in those 58 days is unlabelled, so anything a model flags
that is not in that file counts as a false positive even if it was genuinely
suspicious. Precision is therefore a lower bound. This is a property of the
dataset, not something to fix.

## Models

Four detectors, chosen so that they fail differently:

| model | question it asks | why it is here |
|---|---|---|
| `first_seen_edge` | has this account ever reached this host before? | the strong, simple baseline on LANL; anything learned must beat it |
| `gbm_density_ratio` | is this *combination* of properties one that normal activity produces? | a learned model that needs no labels |
| `graph_embed` | does this host fit the community the account belongs to? | lateral movement is a graph violation |
| `sequence_gru` | is this what this user does next? | per-user habit, not global rarity |

**The unsupervised GBM is a density-ratio trick** (Hastie et al., ESL 14.2.4):
real events are one class, and the other class is manufactured by shuffling
each feature column independently, which keeps every marginal but destroys the
joint structure. A classifier separating the two learns the ratio of the real
density to the product of its marginals, so a low value is a combination that
normal activity never produces. This gives a learned model with the same
features as the supervised one and no labels anywhere, which makes the
comparison between them meaningful.

**The graph model is a factorisation, not a graph neural network.** Logons
form a bipartite user-host graph. It is weighted by PPMI, so sharing a rare
host counts for more than sharing a popular one, then truncated to ~32
dimensions by SVD. A logon scores high when the user's vector and the host's
do not match. A temporal GCN with a GRU over snapshots is the stronger method
in the literature, and it is the honest thing to try with a GPU; on a CPU-only
laptop it costs hours per run, while the factorisation costs minutes and asks
the same question. This is a compute decision, and it is recorded as one.

**The sequence model keeps one hidden state per user**, carried forward from
the training window through the evaluation days, so an event is always scored
from that user's own past. Two bugs in the first version are worth
remembering: padded positions in a batch corrupted the state carried to the
next batch (fixed by batching only runs of equal length), and the training
query sorted the entire training window instead of the sampled users (fixed by
sampling users first).

**Fusion normalises by rank before combining.** A negative log-likelihood, a
cosine distance and a tree score share no scale, so each is mapped to its
position in a reference distribution, and the ensemble averages those. The
stacked variant learns weights on validation labels and is marked supervised.
Fusion has to earn its place: if the ensemble does not beat every member, or a
member adds nothing in the ablation, the report says so and the simpler model
wins.

## Engineering

**Stream, never decompress.** The raw collection is ~11 GB compressed and far
larger expanded. Each file is streamed once from gzip into day-partitioned
Parquet, with a unique row id assigned during the pass, and everything after
that is SQL over Parquet. Nothing is ever fully decompressed to disk, and the
laptop's small second drive holds only small derived tables.

**One row id, used for everything.** Sampling, the score strata and the joins
all key off it, so two models sample the same events without coordinating.

**Runs are reproducible or they do not count.** Every run records the git
commit, library versions, seed, config and timings, and is skipped if an
identical run already completed. `docs/BENCHMARKS.md` is generated from those
runs; no number in it is typed by hand.

**The laptop is part of the design.** It is CPU-only and throttles about
10-30x on battery, so long jobs check the power state and refuse to start on
low battery, neural training is checkpointed and resumable, and model sizes
are chosen to fit CPU minutes or a single overnight run.

## Still open

* Which days form the train, validation and test windows: to be fixed from the
  data card before any model is run on the real data, and recorded there.
* Whether multi-layer context (process, flow and DNS) beats authentication
  alone. The ablation is built; the answer is reported either way.
* Whether the sequence and graph models add anything over the GBM. Same rule:
  if they do not, they are reported as not helping.
