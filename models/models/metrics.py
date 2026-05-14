"""FPR/FNR/Accuracy metric helper for binary classification."""

from __future__ import annotations

import numpy as np


def compute_metrics(probs: np.ndarray, targets: np.ndarray) -> dict[str, float]:
    """Compute FPR / FNR / accuracy from sigmoid probabilities and binary targets.

    Decision rule: probs >= 0.5 -> predicted adult.
    """
    probs = np.asarray(probs).reshape(-1)
    targets = np.asarray(targets).reshape(-1)
    n = int(targets.shape[0])

    if n == 0:
        return {"n": 0, "fpr": 0.0, "fnr": 0.0, "accuracy": 0.0}

    pred_adult = probs >= 0.5
    true_adult = targets >= 0.5
    minors_mask = ~true_adult

    fpr = float(pred_adult[minors_mask].mean()) if minors_mask.sum() > 0 else 0.0
    fnr = float((~pred_adult[true_adult]).mean()) if true_adult.sum() > 0 else 0.0
    accuracy = float((pred_adult == true_adult).mean())

    return {"n": n, "fpr": fpr, "fnr": fnr, "accuracy": accuracy}
