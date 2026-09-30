"""Reproducible domain-disjoint training. Dataset label mapping must be explicit."""

import argparse, json, hashlib, sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    fbeta_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    brier_score_loss,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.features import normalize, extract, NAMES, VERSION


def metrics(y, p, t):
    pred = p >= t
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred)),
        "f1": float(f1_score(y, pred)),
        "f2": float(fbeta_score(y, pred, beta=2)),
        "roc_auc": float(roc_auc_score(y, p)),
        "pr_auc": float(average_precision_score(y, p)),
        "fpr": float(fp / max(1, fp + tn)),
        "fnr": float(fn / max(1, fn + tp)),
        "brier": float(brier_score_loss(y, p)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def run(path, out, phishing_label):
    out = Path(out)
    out.mkdir(exist_ok=True, parents=True)
    df = pd.read_csv(path, usecols=["URL", "label"])
    before = len(df)
    conflicts = df.groupby("URL").label.nunique()
    bad = set(conflicts[conflicts > 1].index)
    df = df[~df.URL.isin(bad)].drop_duplicates("URL")
    features = []
    labels = []
    groups = []
    invalid = 0
    for row in df.itertuples(index=False):
        try:
            n = normalize(row.URL)
            features.append(list(extract(n).values()))
            groups.append(n["domain"])
            labels.append(int(row.label == phishing_label))
        except (ValueError, UnicodeError):
            invalid += 1
    X = np.array(features)
    y = np.array(labels)
    g = np.array(groups)
    train, rest = next(
        GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(X, y, g)
    )
    ci, ti = next(
        GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(
            X[rest], y[rest], g[rest]
        )
    )
    cal, test = rest[ci], rest[ti]
    ci, vi = next(
        GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=44).split(
            X[cal], y[cal], g[cal]
        )
    )
    calibration, validation = cal[ci], cal[vi]
    parts = [train, calibration, validation, test]
    assert all(
        not (set(g[a]) & set(g[b])) for i, a in enumerate(parts) for b in parts[i + 1 :]
    )
    assert all(len(np.unique(y[a])) == 2 for a in parts)
    scaler = StandardScaler().fit(X[train])
    Z = scaler.transform(X)
    lr = LogisticRegression(
        max_iter=1000, class_weight="balanced", random_state=42
    ).fit(Z[train], y[train])
    calibrator = LogisticRegression(C=1e6).fit(
        lr.decision_function(Z[calibration]).reshape(-1, 1), y[calibration]
    )

    def prob(idx):
        return calibrator.predict_proba(lr.decision_function(Z[idx]).reshape(-1, 1))[
            :, 1
        ]

    vp = prob(validation)
    eligible = [
        t
        for t in np.arange(0.05, 0.96, 0.01)
        if metrics(y[validation], vp, t)["fpr"] <= 0.03
    ]
    threshold = (
        max(eligible, key=lambda t: metrics(y[validation], vp, t)["f2"])
        if eligible
        else 0.5
    )
    et = ExtraTreesClassifier(
        n_estimators=100,
        max_depth=18,
        min_samples_leaf=3,
        n_jobs=2,
        random_state=42,
        class_weight="balanced",
    ).fit(X[train], y[train])
    et_v = et.predict_proba(X[validation])[:, 1]
    report = {
        "dataset": "UCI PhiUSIIL",
        "source": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "input_rows": before,
        "usable_unique_urls": len(y),
        "invalid_urls": invalid,
        "conflicting_urls_removed": len(bad),
        "feature_version": VERSION,
        "feature_names": NAMES,
        "label_mapping": {"source_phishing": phishing_label, "internal_phishing": 1},
        "split": {
            name: {
                "rows": len(idx),
                "domains": len(set(g[idx])),
                "phishing": int(y[idx].sum()),
            }
            for name, idx in zip(["train", "calibration", "validation", "test"], parts)
        },
        "group_overlap": 0,
        "selection": "Logistic regression selected for portable auditable inference. ExtraTrees is a comparison.",
        "threshold": float(threshold),
        "logistic_validation": metrics(y[validation], vp, threshold),
        "extra_trees_validation": metrics(y[validation], et_v, 0.5),
        "logistic_test": metrics(y[test], prob(test), threshold),
        "extra_trees_test": metrics(y[test], et.predict_proba(X[test])[:, 1], 0.5),
        "limitations": [
            "Single-source historical benchmark",
            "No temporal holdout: collection timestamps unavailable",
            "Calibration measured only on this source",
            "Source shortcuts including HTTPS may dominate",
            "Risk fusion is not a calibrated probability",
        ],
    }
    model = {
        "version": "phiusiil-lr-v1",
        "feature_version": VERSION,
        "names": NAMES,
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "coef": lr.coef_[0].tolist(),
        "intercept": float(lr.intercept_[0]),
        "calibration_coef": float(calibrator.coef_[0][0]),
        "calibration_intercept": float(calibrator.intercept_[0]),
        "threshold": float(threshold),
        "metrics": report["logistic_test"],
        "training_rows": len(train),
        "test_rows": len(test),
    }
    (out / "model.json").write_text(json.dumps(model, indent=2))
    (out / "evaluation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--out", default="artifacts")
    p.add_argument("--phishing-label", type=int, required=True)
    a = p.parse_args()
    run(a.csv, a.out, a.phishing_label)
