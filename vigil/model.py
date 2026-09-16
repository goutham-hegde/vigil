"""Loads trained artifacts and turns feature rows into scored, explained verdicts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np

from .features import FEATURE_NAMES, FEATURES, display_value
from .schema import ANOMALY, THREAT_CLASSES

DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


class ModelNotTrained(RuntimeError):
    pass


def softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


@dataclass(slots=True)
class Verdict:
    threat: str  # a THREAT_CLASSES entry or ANOMALY
    confidence: float
    detector: str  # supervised | anomaly


class Detector:
    def __init__(self, booster: lgb.Booster, iforest, meta: dict):
        if tuple(meta["features"]) != FEATURE_NAMES:
            raise ModelNotTrained("Model was trained on a different feature set; retrain with `python -m vigil.train`.")
        self.booster = booster
        self.iforest = iforest
        self.meta = meta
        self.temperature = float(meta["temperature"])
        self.threshold = float(meta["threshold"])
        self.anomaly_threshold = float(meta["anomaly_threshold"])
        self.anomaly_scale = float(meta["anomaly_scale"])
        self.benign_mean = np.asarray(meta["benign_mean"])
        self.benign_std = np.asarray(meta["benign_std"])

    @classmethod
    def load(cls, model_dir: Path = DEFAULT_MODEL_DIR) -> "Detector":
        model_dir = Path(model_dir)
        try:
            meta = json.loads((model_dir / "meta.json").read_text())
            booster = lgb.Booster(model_file=str(model_dir / "classifier.txt"))
            iforest = joblib.load(model_dir / "anomaly.joblib")
        except FileNotFoundError as exc:
            raise ModelNotTrained(f"No trained model in {model_dir}. Run `python -m vigil.train` first.") from exc
        return cls(booster, iforest, meta)

    # ---------------------------------------------------------------- scoring
    def probabilities(self, X: np.ndarray) -> np.ndarray:
        raw = self.booster.predict(X, raw_score=True)
        return softmax(raw / self.temperature)

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        return -self.iforest.score_samples(X)

    def score(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, list[Verdict | None]]:
        probs = self.probabilities(X)
        anomaly = self.anomaly_scores(X)
        verdicts: list[Verdict | None] = []
        p_mal = 1.0 - probs[:, 0]
        best = probs[:, 1:].argmax(axis=1) + 1
        for i in range(len(X)):
            if p_mal[i] >= self.threshold:
                verdicts.append(Verdict(THREAT_CLASSES[best[i]], float(p_mal[i]), "supervised"))
            elif anomaly[i] >= self.anomaly_threshold:
                excess = (anomaly[i] - self.anomaly_threshold) / self.anomaly_scale
                verdicts.append(Verdict(ANOMALY, float(min(0.95, 0.55 + 0.4 * np.tanh(excess))), "anomaly"))
            else:
                verdicts.append(None)
        return probs, anomaly, verdicts

    # --------------------------------------------------------- explanations
    def explain(self, x: np.ndarray, threat: str, top: int = 6) -> list[dict]:
        """Top features behind a verdict.

        Supervised verdicts use exact TreeSHAP contributions (log-odds) toward
        the predicted class. Anomaly verdicts use deviation from the benign
        baseline in standard deviations, since isolation forests have no
        native attribution.
        """
        x = np.asarray(x, dtype=np.float64).reshape(1, -1)
        n = len(FEATURES)
        if threat == ANOMALY:
            z = (x[0] - self.benign_mean) / self.benign_std
            order = np.argsort(-np.abs(z))[:top]
            return [self._item(i, x[0, i], float(z[i]), "z") for i in order]
        k = THREAT_CLASSES.index(threat)
        contrib = self.booster.predict(x, pred_contrib=True).reshape(len(THREAT_CLASSES), n + 1)[k, :n]
        order = np.argsort(-np.abs(contrib))[:top]
        return [self._item(i, x[0, i], float(contrib[i]), "shap") for i in order]

    @staticmethod
    def _item(i: int, value: float, weight: float, method: str) -> dict:
        spec = FEATURES[i]
        return {
            "feature": spec.name,
            "label": spec.label,
            "value": display_value(spec, float(value)),
            "weight": round(weight, 3),
            "method": method,
        }

    def info(self) -> dict:
        return {k: v for k, v in self.meta.items() if k not in ("benign_mean", "benign_std")}
