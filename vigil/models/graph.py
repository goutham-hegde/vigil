"""Lateral movement as a link-prediction problem on the user-host graph.

Who logs on where is a bipartite graph: users on one side, computers on the
other. Accounts doing the same job share the same handful of hosts, so the
graph has strong community structure. Lateral movement violates it: a stolen
account reaches a host that nobody like its owner ever touches.

`graph_embed` factorises that graph and scores each logon by how badly it fits:

1. count logons per (user, host) over the training window;
2. weight them by PPMI, so a shared rare host says more than a shared popular
   one, and popular hosts stop dominating;
3. take a truncated SVD, giving every user and host a vector of ~32 numbers;
4. score an event by the cosine between its user's vector and its host's,
   turned round so that a poor fit scores high.

This is the cheap stand-in for a temporal GCN: minutes of CPU rather than
hours, and the same question. A pair where either side never appeared in
training gets the maximum score, which is the "first seen" signal.

The embedding is fitted once on the training window and then held fixed, so
nothing from the evaluation period leaks into it.
"""

from __future__ import annotations

import numpy as np
import pyarrow as pa
from scipy.sparse import coo_matrix
from scipy.sparse.linalg import svds

from ..bench.experiment import Context, Experiment, register

UNSEEN = 1.0  # cosine distance given to a user or host never seen in training


@register("graph_embed")
class GraphEmbed(Experiment):
    def fit(self, ctx: Context) -> None:
        a, b = ctx.splits["train"]
        rows = ctx.con.execute(f"""
            SELECT src_user, dst_comp, sum(n)::DOUBLE AS n
            FROM auth_edges_hourly
            WHERE {ctx.user_filter_sql} AND hour >= {a * 24} AND hour < {b * 24}
            GROUP BY ALL
        """).to_arrow_table()
        users = rows["src_user"].to_pylist()
        comps = rows["dst_comp"].to_pylist()
        counts = rows["n"].to_numpy()
        self.user_ix = {u: i for i, u in enumerate(dict.fromkeys(users))}
        self.comp_ix = {c: i for i, c in enumerate(dict.fromkeys(comps))}
        ui = np.fromiter((self.user_ix[u] for u in users), dtype=np.int64, count=len(users))
        ci = np.fromiter((self.comp_ix[c] for c in comps), dtype=np.int64, count=len(comps))
        m = coo_matrix((counts, (ui, ci)), shape=(len(self.user_ix), len(self.comp_ix))).tocsr()
        ctx.log.info("graph_embed: %d users x %d computers, %d edges", m.shape[0], m.shape[1], m.nnz)

        ppmi = _ppmi(m)
        k = min(int(self.params.get("dim", 32)), min(ppmi.shape) - 1)
        u, s, vt = svds(ppmi, k=k, random_state=ctx.seed)
        self.U = _unit_rows(u * s)  # scaling by the singular values weights the strong factors
        self.V = _unit_rows(vt.T)

    def score_batch(self, ctx: Context, batch: pa.Table) -> np.ndarray:
        ui = np.fromiter((self.user_ix.get(u, -1) for u in batch["src_user"].to_pylist()), dtype=np.int64,
                         count=batch.num_rows)
        ci = np.fromiter((self.comp_ix.get(c, -1) for c in batch["dst_comp"].to_pylist()), dtype=np.int64,
                         count=batch.num_rows)
        known = (ui >= 0) & (ci >= 0)
        out = np.full(batch.num_rows, UNSEEN)
        if known.any():
            cos = np.einsum("ij,ij->i", self.U[ui[known]], self.V[ci[known]])
            out[known] = (1 - cos) / 2  # cosine in [-1, 1] -> score in [0, 1]
        return out


def _ppmi(m):
    """Positive pointwise mutual information, kept sparse.

    PMI is negative infinity wherever the count is zero, so PPMI is zero
    there: only the non-zero entries need computing, and the matrix stays as
    sparse as the graph.
    """
    m = m.tocoo()
    total = m.data.sum()
    if total == 0:
        return m.tocsr()
    row = np.asarray(m.sum(axis=1)).ravel()
    col = np.asarray(m.sum(axis=0)).ravel()
    with np.errstate(divide="ignore", invalid="ignore"):
        pmi = np.log((m.data * total) / (row[m.row] * col[m.col]))
    data = np.maximum(np.nan_to_num(pmi, nan=0.0, posinf=0.0, neginf=0.0), 0.0)
    return coo_matrix((data, (m.row, m.col)), shape=m.shape).tocsr()


def _unit_rows(a: np.ndarray) -> np.ndarray:
    return a / np.maximum(np.linalg.norm(a, axis=1, keepdims=True), 1e-12)
