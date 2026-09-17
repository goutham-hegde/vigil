"""A per-user event language model, in the spirit of Tuor et al. (2017).

Each user's authentications are a sentence: this host, then that one, at this
hour, with this protocol. A small GRU reads the sentence and predicts the next
event. Where the prediction is bad, the event is surprising for *that* user,
which is the definition of an insider or a stolen credential rather than a
globally rare event.

* Tokens per event: destination host, source host (both hashed into buckets,
  since there are 17k computers), auth type, logon type, orientation, outcome
  and hour of day.
* The model embeds all of them, runs a 2-layer GRU, and predicts the next
  event's destination, auth type, logon type and outcome with one softmax head
  each.
* The anomaly score is the negative log-likelihood of the event that actually
  happened, given everything the user did before it.

Causality: the hidden state only ever moves forward in time. Scoring keeps one
state per user, carried from the training window through the evaluation days,
so an event is scored from its own past and nothing else. Training uses the
training window only, with red-team events removed.

CPU notes: about 1-2 M parameters, checkpointed every few minutes, and
resumable. Training subsamples users; scoring always covers every test event.
"""

from __future__ import annotations

import json
import time
import zlib

import numpy as np
import pyarrow as pa

from ..bench.experiment import Context, Experiment, register

# (column, vocabulary size). Hashed columns use the bucket count; the small
# categorical columns get an exact vocabulary plus one slot for anything else.
FIELDS = [("dst_comp", 4096), ("src_comp", 4096), ("auth_type", 32), ("logon_type", 32),
          ("orientation", 16), ("success", 4), ("hour_of_day", 24)]
TARGETS = ["dst_comp", "auth_type", "logon_type", "success"]
EMB = {"dst_comp": 64, "src_comp": 32, "auth_type": 8, "logon_type": 8, "orientation": 4, "success": 4,
       "hour_of_day": 8}


def _bucket(values: pa.Array, size: int) -> np.ndarray:
    """Stable hashing of string columns; identical strings always land in the same bucket."""
    uniq = values.unique().to_pylist()
    table = {v: (zlib.crc32(str(v).encode()) % (size - 1)) + 1 for v in uniq}
    return np.fromiter((table[v] for v in values.to_pylist()), dtype=np.int64, count=len(values))


def encode(batch: pa.Table) -> np.ndarray:
    """Events -> an (n, len(FIELDS)) integer token matrix."""
    cols = []
    for name, size in FIELDS:
        if name == "hour_of_day":
            cols.append(batch["hour"].to_numpy() % 24)
        else:
            cols.append(_bucket(batch[name], size))
    return np.stack(cols, axis=1)


def _make_model(hidden: int, layers: int, dropout: float, seed: int):
    import torch
    from torch import nn

    torch.manual_seed(seed)

    class EventLM(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.ModuleList([nn.Embedding(size, EMB[name]) for name, size in FIELDS])
            self.gru = nn.GRU(sum(EMB.values()), hidden, num_layers=layers, batch_first=True,
                              dropout=dropout if layers > 1 else 0.0)
            self.heads = nn.ModuleDict({t: nn.Linear(hidden, dict(FIELDS)[t]) for t in TARGETS})

        def forward(self, tokens, state=None):
            x = torch.cat([e(tokens[:, :, i]) for i, e in enumerate(self.emb)], dim=-1)
            out, state = self.gru(x, state)
            return {t: head(out) for t, head in self.heads.items()}, state

    return EventLM()


@register("sequence_gru")
class SequenceGRU(Experiment):
    def __init__(self, params=None):
        super().__init__(params)
        self.hidden = int(self.params.get("hidden", 128))
        self.layers = int(self.params.get("layers", 2))
        self.window = int(self.params.get("window", 64))
        self.batch = int(self.params.get("batch", 128))
        self.cell_budget = int(self.params.get("cell_budget", 200_000))

    # ---------------------------------------------------------------- training

    def fit(self, ctx: Context) -> None:
        import torch

        self.torch = torch
        torch.set_num_threads(int(self.params.get("threads", 0)) or torch.get_num_threads())
        self.model = _make_model(self.hidden, self.layers, float(self.params.get("dropout", 0.1)), ctx.seed)
        streams = self._training_streams(ctx)
        windows = self._windows(streams)
        ctx.log.info("sequence_gru: %d users, %d training windows of %d events",
                     len(streams), len(windows), self.window)
        opt = torch.optim.Adam(self.model.parameters(), lr=float(self.params.get("lr", 2e-3)))
        start_epoch = self._restore(ctx, opt)
        epochs = int(self.params.get("epochs", 3))
        rng = np.random.default_rng(ctx.seed)
        for epoch in range(start_epoch, epochs):
            order = rng.permutation(len(windows))
            total, seen, last_save = 0.0, 0, time.monotonic()
            for i in range(0, len(order), self.batch):
                chunk = np.stack([windows[j] for j in order[i:i + self.batch]])
                loss = self._loss(torch.from_numpy(chunk))
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                opt.step()
                total += float(loss.detach()) * len(chunk)
                seen += len(chunk)
                if time.monotonic() - last_save > 300:
                    self._save(ctx, opt, epoch)
                    ctx.log.info("  epoch %d: %d/%d windows, loss %.4f", epoch, seen, len(order), total / seen)
                    last_save = time.monotonic()
            ctx.log.info("sequence_gru: epoch %d done, loss %.4f", epoch, total / max(seen, 1))
            self._save(ctx, opt, epoch + 1)
        self.model.eval()
        self._warm_up(ctx)

    def _loss(self, chunk):
        """Next-event cross-entropy, summed over the prediction heads."""
        torch = self.torch
        logits, _ = self.model(chunk[:, :-1])
        loss = 0.0
        for t in TARGETS:
            target = chunk[:, 1:, FIELD_IX[t]]
            loss = loss + torch.nn.functional.cross_entropy(
                logits[t].reshape(-1, logits[t].shape[-1]), target.reshape(-1))
        return loss

    def _training_streams(self, ctx: Context) -> dict[str, np.ndarray]:
        max_users = int(self.params.get("max_users", 3000))
        per_user = int(self.params.get("max_events_per_user", 4000))
        cut = max(1, int(1_000_000 * max_users / max(1, self._n_users(ctx))))
        # Sample the users first, so the window functions run over those users only
        # and never over the whole training window.
        tbl = ctx.con.execute(f"""
            WITH sampled AS (
                SELECT src_user, time, time // 3600 AS hour, dst_comp, src_comp, auth_type, logon_type,
                       orientation, success
                FROM ({ctx.train_events_sql()})
                WHERE hash(src_user) % 1000000 < {cut}
            )
            SELECT * FROM sampled
            QUALIFY row_number() OVER (PARTITION BY src_user ORDER BY time DESC) <= {per_user}
                AND count(*) OVER (PARTITION BY src_user) >= {self.window + 1}
            ORDER BY src_user, time
        """).to_arrow_table()
        if tbl.num_rows == 0:
            raise ValueError("sequence_gru: no training events (is the training window long enough?)")
        return self._split_by_user(tbl)

    def _n_users(self, ctx: Context) -> int:
        return ctx.con.execute(
            f"SELECT count(DISTINCT src_user) FROM ({ctx.train_events_sql()})").fetchone()[0] or 1

    def _split_by_user(self, tbl: pa.Table) -> dict[str, np.ndarray]:
        tokens = encode(tbl)
        users = np.asarray(tbl["src_user"].to_pylist())
        out = {}
        starts = np.flatnonzero(np.r_[True, users[1:] != users[:-1]])
        for a, b in zip(starts, np.r_[starts[1:], len(users)]):
            out[users[a]] = tokens[a:b]
        return out

    def _windows(self, streams: dict[str, np.ndarray]) -> list[np.ndarray]:
        """Consecutive, non-overlapping slices of each user's stream."""
        w = self.window + 1  # one extra event: the last one is only a prediction target
        return [s[i:i + w] for s in streams.values() for i in range(0, len(s) - w + 1, self.window)]

    # ---------------------------------------------------------------- checkpoints

    def _save(self, ctx: Context, opt, epoch: int) -> None:
        self.torch.save({"model": self.model.state_dict(), "opt": opt.state_dict()},
                        ctx.checkpoint_dir / "state.pt")
        (ctx.checkpoint_dir / "progress.json").write_text(json.dumps({"epoch": epoch}))

    def _restore(self, ctx: Context, opt) -> int:
        path = ctx.checkpoint_dir / "state.pt"
        if not path.exists():
            return 0
        state = self.torch.load(path, weights_only=True)
        self.model.load_state_dict(state["model"])
        opt.load_state_dict(state["opt"])
        epoch = json.loads((ctx.checkpoint_dir / "progress.json").read_text())["epoch"]
        ctx.log.info("sequence_gru: resuming from epoch %d", epoch)
        return epoch

    # ---------------------------------------------------------------- scoring

    def _warm_up(self, ctx: Context) -> None:
        """Run the tail of the training window so every user starts scoring with real state."""
        self.state: dict[str, np.ndarray] = {}
        self.last: dict[str, np.ndarray] = {}
        a, b = ctx.splits["train"]
        days = int(self.params.get("warmup_days", 2))
        tbl = ctx.con.execute(f"""
            SELECT src_user, time, time // 3600 AS hour, dst_comp, src_comp, auth_type, logon_type,
                   orientation, success
            FROM ({ctx.train_events_sql()}) WHERE day >= {max(a, b - days)} ORDER BY src_user, time
        """).to_arrow_table()
        if tbl.num_rows:
            for user, tokens in self._split_by_user(tbl).items():
                self._advance(user, tokens)
        ctx.log.info("sequence_gru: warmed up %d users on the last %d training days", len(self.state), days)

    def _advance(self, user: str, tokens: np.ndarray) -> None:
        """Move a user's hidden state forward over `tokens` without scoring them."""
        torch = self.torch
        with torch.no_grad():
            x = torch.from_numpy(tokens[None, :, :])
            state = self._state_for([user])
            _, state = self.model(x, state)
        self.state[user] = state[:, 0, :].numpy()
        self.last[user] = tokens[-1]

    def _state_for(self, users: list[str]):
        torch = self.torch
        zero = np.zeros((self.layers, self.hidden), dtype=np.float32)
        return torch.from_numpy(np.stack([self.state.get(u, zero) for u in users], axis=1))

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        tokens = encode(batch)
        users = np.asarray(batch["src_user"].to_pylist())
        order = np.argsort(users, kind="stable")  # group each user's events, keeping time order
        scores = np.zeros(len(users))
        by_length: dict[int, list] = {}
        s = users[order]
        starts = np.flatnonzero(np.r_[True, s[1:] != s[:-1]])
        for a, b in zip(starts, np.r_[starts[1:], len(s)]):
            by_length.setdefault(b - a, []).append((s[a], order[a:b]))
        # Batch users whose runs have the same length: no padding, so the state
        # carried forward is the state after the user's last real event.
        for length, groups in by_length.items():
            per_batch = max(1, self.cell_budget // length)
            for i in range(0, len(groups), per_batch):
                self._score_group(groups[i:i + per_batch], tokens, scores)
        return scores

    def _score_group(self, part, tokens: np.ndarray, scores: np.ndarray) -> None:
        """Score a batch of equal-length user runs and carry each user's state forward."""
        torch = self.torch
        users = [u for u, _ in part]
        # Input t is the user's previous event; target t is the event being scored.
        y = np.stack([tokens[ix] for _, ix in part])
        x = np.stack([np.vstack([self.last.get(u, np.zeros(len(FIELDS), dtype=np.int64)), tokens[ix][:-1]])
                      for u, ix in part])
        with torch.no_grad():
            logits, state = self.model(torch.from_numpy(x), self._state_for(users))
            nll = torch.zeros(y.shape[:2])
            for t in TARGETS:
                lp = torch.log_softmax(logits[t], dim=-1)
                nll -= lp.gather(-1, torch.from_numpy(y[:, :, FIELD_IX[t]])[..., None])[..., 0]
        nll = nll.numpy()
        for r, (user, ix) in enumerate(part):
            scores[ix] = nll[r]
            self.state[user] = state[:, r, :].numpy()
            self.last[user] = tokens[ix[-1]]


FIELD_IX = {name: i for i, (name, _) in enumerate(FIELDS)}
