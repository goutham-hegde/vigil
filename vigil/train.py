"""Build datasets from the simulator, train the detectors, evaluate, save.

    python -m vigil.train            # full run (about a minute on a laptop)
    python -m vigil.train --quick    # smaller data, for CI and smoke tests

Train, validation and test come from independent simulation runs: different
seeds, different attacker IPs, victims, rates and times of day. Splitting rows
of one run at random would leak near-identical neighbours of each attack into
the test set and inflate every number.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_recall_fscore_support

from .detection import DetectionEngine
from .environment import Environment
from .features import FEATURE_NAMES, FEATURES, FeatureExtractor
from .model import DEFAULT_MODEL_DIR, Detector, softmax
from .schema import THREAT_CLASSES, Event
from .simulator import SCENARIOS, Background, Campaign

DAY = 86400.0
EPOCH = datetime(2026, 9, 14, tzinfo=timezone.utc).timestamp()
WARMUP = 1800.0
CHUNK = 600.0


@dataclass
class Split:
    name: str
    X: np.ndarray
    y: np.ndarray
    events: list[Event]
    campaigns: list[Campaign]
    start: float
    end: float

    @property
    def hours(self) -> float:
        return (self.end - self.start) / 3600


def simulate(name: str, seed: int, start: float, hours: float, counts: dict[str, int], env: Environment,
             ) -> tuple[list[Event], list[Event], list[Campaign], float, float]:
    rng = random.Random(seed)
    bg = Background(env, seed)
    end = start + hours * 3600
    warm = []
    t = start - WARMUP
    while t < start:
        warm += bg.generate(t, min(t + CHUNK, start))
        t += CHUNK
    events: list[Event] = []
    while t < end:
        events += bg.generate(t, min(t + CHUNK, end))
        t += CHUNK
    campaigns = []
    for scenario, n in counts.items():
        for _ in range(n):
            c_start = rng.uniform(start + 600, end - 2400)
            c = SCENARIOS[scenario](env, rng, c_start, intensity=rng.uniform(0.6, 1.4))
            campaigns.append(c)
            events += [e for e in c.events if e.ts < end]
    events.sort(key=lambda e: e.ts)
    print(f"  {name:<5} {hours:>4.0f} h  {len(events):>8,} events  {len(campaigns):>3} campaigns")
    return warm, events, campaigns, start, end


def featurize(env: Environment, warm: list[Event], events: list[Event]) -> np.ndarray:
    fx = FeatureExtractor(env.role_of, frozenset({env.dc.ip, env.servers[5].ip}))
    for e in warm:
        fx.update(e)
    return np.asarray([fx.update(e) for e in events], dtype=np.float32)


def build_split(name: str, seed: int, start: float, hours: float, counts: dict[str, int], env: Environment) -> Split:
    warm, events, campaigns, s, e = simulate(name, seed, start, hours, counts, env)
    X = featurize(env, warm, events)
    y = np.array([THREAT_CLASSES.index(ev.label) for ev in events], dtype=np.int32)
    return Split(name, X, y, events, campaigns, s, e)


def sample_weights(split: Split) -> np.ndarray:
    counts = np.bincount(split.y, minlength=len(THREAT_CLASSES)).astype(float)
    per_class = np.sqrt(counts.sum() / (len(THREAT_CLASSES) * np.maximum(counts, 1)))
    w = per_class[split.y]
    lookalike = np.array([e.lookalike for e in split.events])
    w[lookalike] *= 3.0  # hard negatives matter most for alert fatigue
    return w


def fit_temperature(raw: np.ndarray, y: np.ndarray) -> float:
    best_t, best_nll = 1.0, np.inf
    for t in np.linspace(0.4, 4.0, 37):
        p = softmax(raw / t)
        nll = -np.mean(np.log(p[np.arange(len(y)), y] + 1e-12))
        if nll < best_nll:
            best_t, best_nll = float(t), nll
    return best_t


def expected_calibration_error(probs: np.ndarray, y: np.ndarray, bins: int = 15) -> float:
    conf = probs.max(axis=1)
    correct = probs.argmax(axis=1) == y
    ece = 0.0
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi)
        if m.any():
            ece += m.mean() * abs(conf[m].mean() - correct[m].mean())
    return float(ece)


def pick_threshold(p_mal: np.ndarray, is_mal: np.ndarray, beta: float = 0.5) -> float:
    """Threshold on P(malicious) maximising F-beta; beta < 1 favours precision."""
    best, best_score = 0.5, -1.0
    for t in np.linspace(0.2, 0.97, 78):
        pred = p_mal >= t
        tp = np.sum(pred & is_mal)
        if tp == 0:
            continue
        prec = tp / pred.sum()
        rec = tp / is_mal.sum()
        score = (1 + beta**2) * prec * rec / (beta**2 * prec + rec)
        if score > best_score:
            best, best_score = float(t), score
    return best


def replay(detector: Detector, env: Environment, split: Split, batch: int = 512) -> DetectionEngine:
    """Run the full alerting pipeline over a split, as the live system would."""
    engine = DetectionEngine(detector, env)
    bg = Background(env, 999)
    t = split.start - WARMUP
    while t < split.start:
        engine.warmup(bg.generate(t, min(t + CHUNK, split.start)))
        t += CHUNK
    for i in range(0, len(split.events), batch):
        engine.process(split.events[i:i + batch])
    return engine


def pipeline_metrics(engine: DetectionEngine, split: Split) -> dict:
    alerts = list(engine.alerts.alerts.values())
    false_alerts = [a for a in alerts if a.truth["malicious"] < a.truth["benign"]]
    by_scenario: dict[str, dict] = defaultdict(lambda: {"runs": 0, "detected": 0, "ttd": [], "alerts": 0,
                                                        "stages_total": 0, "stages_detected": 0, "incident": 0})
    alerts_by_campaign: dict[str, list] = defaultdict(list)
    for a in alerts:
        for c in a.campaigns:
            alerts_by_campaign[c].append(a)
    for c in split.campaigns:
        s = by_scenario[c.scenario]
        s["runs"] += 1
        own = alerts_by_campaign.get(c.id, [])
        s["alerts"] += len(own)
        stages = {k: v for k, v in c.stages.items() if v < split.end}
        detected = engine.alerts.detections.get(c.id, {})
        s["stages_total"] += len(stages)
        s["stages_detected"] += sum(1 for k in stages if k in detected)
        if stages and detected:
            s["detected"] += 1
            s["ttd"].append(min(detected.values()) - min(stages.values()))
        if any(a.incident_id for a in own):
            s["incident"] += 1
    scenarios = {}
    for name, s in by_scenario.items():
        malicious = name != "benign_noise"
        scenarios[name] = {
            "runs": s["runs"],
            "alerts": s["alerts"],
            "detected_runs": s["detected"] if malicious else None,
            "stage_recall": round(s["stages_detected"] / s["stages_total"], 3) if s["stages_total"] else None,
            "median_time_to_detect_s": round(statistics.median(s["ttd"]), 1) if s["ttd"] else None,
            "runs_with_incident": s["incident"],
            "detectors": dict(Counter(a.detector for c in split.campaigns if c.scenario == name
                                      for a in alerts_by_campaign.get(c.id, []))),
        }
    # An incident is "pure" when all of its campaign-linked alerts come from one campaign.
    mixed = 0
    for inc in engine.correlator.incidents.values():
        owners = {c for aid in inc.alert_ids for c in engine.alerts.alerts[aid].campaigns}
        mixed += len(owners) > 1
    return {
        "hours": round(split.hours, 1),
        "events": len(split.events),
        "alerts": len(alerts),
        "false_alerts": len(false_alerts),
        "false_alerts_per_hour": round(len(false_alerts) / split.hours, 2),
        "alert_precision": round(1 - len(false_alerts) / max(1, len(alerts)), 3),
        "events_per_alert": round(len(split.events) / max(1, len(alerts))),
        "incidents": len(engine.correlator.incidents),
        "mixed_incidents": mixed,
        "false_alert_examples": [
            {"threat": a.threat, "entity": a.hostname or a.entity, "detector": a.detector,
             "confidence": round(a.confidence, 2), "events": a.event_count}
            for a in sorted(false_alerts, key=lambda a: -a.event_count)[:8]
        ],
        "scenarios": scenarios,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_MODEL_DIR)
    ap.add_argument("--quick", action="store_true", help="small datasets, for CI")
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args()
    t0 = time.time()
    scale = 0.25 if args.quick else 1.0

    def plan(hours: float, n: dict[str, int]) -> tuple[float, dict[str, int]]:
        return max(2.0, hours * scale), {k: max(1, round(v * scale)) for k, v in n.items()}

    env = Environment()
    print("Simulating telemetry")
    h, n = plan(16, {"intrusion_chain": 10, "credential_stuffing": 8, "c2_exfil": 10, "low_and_slow": 6, "benign_noise": 20})
    train = build_split("train", args.seed, EPOCH, h, n, env)
    h, n = plan(6, {"intrusion_chain": 4, "credential_stuffing": 3, "c2_exfil": 4, "low_and_slow": 2, "benign_noise": 8})
    val = build_split("val", args.seed + 1, EPOCH + DAY + 15 * 3600, h, n, env)
    h, n = plan(8, {"intrusion_chain": 5, "credential_stuffing": 4, "c2_exfil": 5, "low_and_slow": 3,
                    "benign_noise": 10, "dns_tunnel": 4})
    test = build_split("test", args.seed + 2, EPOCH + 2 * DAY + 4 * 3600, h, n, env)
    print(f"  class counts (train): {dict(zip(THREAT_CLASSES, np.bincount(train.y, minlength=6).tolist()))}")

    print("Training gradient-boosted classifier")
    params = {
        "objective": "multiclass", "num_class": len(THREAT_CLASSES), "learning_rate": 0.05,
        "num_leaves": 31, "min_data_in_leaf": 40, "feature_fraction": 0.8, "bagging_fraction": 0.8,
        "bagging_freq": 1, "lambda_l2": 1.0, "verbose": -1, "seed": args.seed,
    }
    dtrain = lgb.Dataset(train.X, train.y, weight=sample_weights(train), feature_name=list(FEATURE_NAMES))
    dval = lgb.Dataset(val.X, val.y, weight=sample_weights(val), reference=dtrain)
    booster = lgb.train(params, dtrain, num_boost_round=800, valid_sets=[dval],
                        callbacks=[lgb.early_stopping(40, verbose=False)])
    print(f"  best iteration {booster.best_iteration}")
    booster = lgb.Booster(model_str=booster.model_to_string(num_iteration=booster.best_iteration))

    raw_val = booster.predict(val.X, raw_score=True)
    temperature = fit_temperature(raw_val, val.y)
    p_val = softmax(raw_val / temperature)
    threshold = pick_threshold(1 - p_val[:, 0], val.y > 0)
    print(f"  temperature {temperature:.2f}, alert threshold P(malicious) >= {threshold:.2f}")

    print("Training anomaly detector on benign traffic only")
    rng = np.random.default_rng(args.seed)
    benign = train.X[train.y == 0]
    fit_rows = benign[rng.choice(len(benign), size=min(60_000, len(benign)), replace=False)]
    iforest = IsolationForest(n_estimators=200, max_samples=1024, random_state=args.seed, n_jobs=-1).fit(fit_rows)
    val_benign_scores = -iforest.score_samples(val.X[val.y == 0])
    anomaly_threshold = float(np.quantile(val_benign_scores, 0.99995))
    anomaly_scale = float(np.std(val_benign_scores) + 1e-6)

    meta = {
        "version": datetime.now(timezone.utc).strftime("%Y.%m.%d-%H%M"),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "classes": list(THREAT_CLASSES),
        "features": list(FEATURE_NAMES),
        "temperature": temperature,
        "threshold": threshold,
        "anomaly_threshold": anomaly_threshold,
        "anomaly_scale": anomaly_scale,
        "benign_mean": benign.mean(axis=0).astype(float).tolist(),
        "benign_std": (benign.std(axis=0) + 1e-3).astype(float).tolist(),
        "best_iteration": booster.current_iteration(),
        "quick": args.quick,
    }
    detector = Detector(booster, iforest, meta)

    print("Evaluating on held-out test run")
    held_out = {c.id for c in test.campaigns if c.scenario == "dns_tunnel"}
    known = np.array([e.campaign not in held_out for e in test.events])
    Xk, yk = test.X[known], test.y[known]
    p_test = detector.probabilities(Xk)
    p_mal = 1 - p_test[:, 0]
    flagged = p_mal >= threshold
    pred = np.where(flagged, p_test[:, 1:].argmax(axis=1) + 1, 0)
    labels = list(range(len(THREAT_CLASSES)))
    report = classification_report(yk, pred, labels=labels, target_names=THREAT_CLASSES, output_dict=True, zero_division=0)
    prec, rec, f1, _ = precision_recall_fscore_support(yk > 0, flagged, average="binary", zero_division=0)
    lookalike = np.array([e.lookalike for e, k in zip(test.events, known) if k])
    benign_mask = yk == 0
    relevant = (yk > 0) | (p_mal >= 0.5)

    engine = replay(detector, env, test)
    pipeline = pipeline_metrics(engine, test)

    gain = booster.feature_importance(importance_type="gain")
    importance = sorted(
        ({"feature": f.name, "label": f.label, "gain": round(float(g / gain.sum()), 4)} for f, g in zip(FEATURES, gain)),
        key=lambda d: -d["gain"],
    )
    metrics = {
        "model": {k: meta[k] for k in ("version", "trained_at", "temperature", "threshold", "best_iteration", "quick")},
        "data": {
            s.name: {"hours": round(s.hours, 1), "events": len(s.events), "campaigns": dict(Counter(c.scenario for c in s.campaigns)),
                     "class_counts": dict(zip(THREAT_CLASSES, np.bincount(s.y, minlength=6).tolist()))}
            for s in (train, val, test)
        },
        "event_level": {
            "macro_f1": round(f1_score(yk, pred, labels=labels, average="macro", zero_division=0), 4),
            "per_class": {c: {k: round(v, 4) for k, v in report[c].items()} for c in THREAT_CLASSES},
            "confusion_matrix": {"labels": list(THREAT_CLASSES), "matrix": confusion_matrix(yk, pred, labels=labels).tolist()},
            "malicious_precision": round(float(prec), 4),
            "malicious_recall": round(float(rec), 4),
            "malicious_f1": round(float(f1), 4),
            "benign_false_positive_rate": round(float(flagged[benign_mask].mean()), 5),
            "lookalike_false_positive_rate": round(float(flagged[benign_mask & lookalike].mean()), 5),
            # Benign events are >95% of rows and trivially confident, so calibration is
            # measured only where it matters: true attacks and anything the model flagged.
            "ece_uncalibrated": round(expected_calibration_error(softmax(booster.predict(Xk[relevant], raw_score=True)), yk[relevant]), 4),
            "ece_calibrated": round(expected_calibration_error(p_test[relevant], yk[relevant]), 4),
        },
        "pipeline": pipeline,
        "feature_importance": importance,
    }

    args.out.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(args.out / "classifier.txt"))
    joblib.dump(iforest, args.out / "anomaly.joblib")
    (args.out / "meta.json").write_text(json.dumps(meta, indent=2))
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2))

    ev = metrics["event_level"]
    print(f"\n  event macro-F1          {ev['macro_f1']:.3f}")
    print(f"  malicious P / R         {ev['malicious_precision']:.3f} / {ev['malicious_recall']:.3f}")
    print(f"  benign FPR (look-alike) {ev['benign_false_positive_rate']:.4%} ({ev['lookalike_false_positive_rate']:.4%})")
    print(f"  ECE before / after      {ev['ece_uncalibrated']:.3f} / {ev['ece_calibrated']:.3f}")
    print(f"  alerts {pipeline['alerts']}, false {pipeline['false_alerts']} "
          f"({pipeline['false_alerts_per_hour']}/h), incidents {pipeline['incidents']} ({pipeline['mixed_incidents']} mixed)")
    for name, s in pipeline["scenarios"].items():
        print(f"    {name:<20} runs {s['runs']}  detected {s['detected_runs']}  stage recall {s['stage_recall']}  "
              f"TTD {s['median_time_to_detect_s']}s  alerts {s['alerts']}  incidents {s['runs_with_incident']}  {s['detectors']}")
    print(f"\nSaved to {args.out} in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
