"""python -m vigil.bench run <experiment> --config configs/lanl.yaml | report --data lanl"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import yaml

from ..data.lanl import REPO
from . import report, runner
from .experiment import EXPERIMENTS
from .. import models  # noqa: F401  (registers the experiments)


def _value(v: str):
    return yaml.safe_load(v)


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    ap = argparse.ArgumentParser(prog="python -m vigil.bench")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("experiment", choices=sorted(EXPERIMENTS))
    r.add_argument("--config", type=Path, default=REPO / "configs" / "lanl.yaml")
    r.add_argument("--seed", type=int, default=None)
    r.add_argument("--set", nargs="*", default=[], metavar="KEY=VALUE", help="experiment parameters")
    r.add_argument("--force", action="store_true", help="rerun a completed run")
    r.add_argument("--force-power", action="store_true", help="start even on low battery")
    p = sub.add_parser("report")
    p.add_argument("--data", default="lanl")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        cfg = yaml.safe_load(args.config.read_text())
        params = dict(kv.split("=", 1) for kv in args.set)
        params = {k: _value(v) for k, v in params.items()}
        out = runner.run(args.experiment, cfg, params, args.seed, force=args.force, force_power=args.force_power)
        print(out)
    else:
        bench = report.write(args.data)
        print(f"{len(bench['experiments'])} experiments reported")


if __name__ == "__main__":
    main()
