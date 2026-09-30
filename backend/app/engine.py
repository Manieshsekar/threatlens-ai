import json, math, os
from pathlib import Path
from .features import extract, signals, redact, VERSION, NAMES

MODEL_PATH = Path(
    os.getenv(
        "MODEL_PATH", str(Path(__file__).resolve().parents[2] / "artifacts/model.json")
    )
)


def load_model():
    m = json.loads(MODEL_PATH.read_text())
    assert m["feature_version"] == VERSION and m["names"] == NAMES
    return m


def assess(n, observations=None, verification=None):
    f = extract(n)
    m = load_model()
    contributions = [
        (f[k] - m["mean"][i]) / m["scale"][i] * m["coef"][i]
        for i, k in enumerate(NAMES)
    ]
    logit = m["intercept"] + sum(contributions)
    cal = logit * m["calibration_coef"] + m["calibration_intercept"]
    p = 1 / (1 + math.exp(-max(-700, min(700, cal))))
    rules = signals(n, f)
    rule_score = min(100, sum(s["weight"] for s in rules))
    risk = round(max(p * 100, rule_score), 1)
    obs = observations or []
    hits = [o for o in obs if o.get("malicious") is True and o.get("status") == "ok"]
    risk = max(risk, 95) if hits else risk
    classification = (
        "high risk" if risk >= 75 else "suspicious" if risk >= 35 else "low risk"
    )
    if verification and verification.get("verdict") == "malicious":
        classification = "verified malicious"
        risk = 100
    # A clean verification never suppresses later conflicting threat evidence.
    conflict = bool(
        verification and verification.get("verdict") == "clean" and (hits or risk >= 75)
    )
    return {
        "url": redact(n),
        "hostname": n["hostname"],
        "domain": n["domain"],
        "classification": classification,
        "risk_score": risk,
        "confidence": "limited" if not hits else "corroborated",
        "model": {
            "version": m["version"],
            "probability": round(p, 6),
            "threshold": m["threshold"],
            "classification": "phishing" if p >= m["threshold"] else "legitimate",
            "calibration_scope": "historical PhiUSIIL benchmark",
        },
        "signals": rules,
        "features": f,
        "explanation": sorted(
            [
                {
                    "feature": k,
                    "contribution": round(v, 4),
                    "direction": "raises" if v > 0 else "lowers",
                }
                for k, v in zip(NAMES, contributions)
            ],
            key=lambda x: abs(x["contribution"]),
            reverse=True,
        )[:8],
        "observations": obs,
        "verification": verification,
        "verification_conflict": conflict,
        "recommendation": "Avoid entering credentials or downloading files; verify through a known official channel."
        if risk >= 35
        else "No strong lexical warning was found. Verify the destination before sharing sensitive information.",
        "score_method": "max(calibrated benchmark model score, capped lexical rule points); confirmed provider hits floor risk at 95. Analyst malicious verification sets 100. This fused score is not a probability.",
    }
