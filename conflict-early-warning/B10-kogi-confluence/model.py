"""ConfluenceEWS risk model: logistic regression written from scratch (no numpy, no scikit-learn).

Unit of analysis: one LGA on one day (sampled weekly). Target: at least one violent incident
(severity >= 3) in that LGA in the next 14 days.
Features (standardised): violent incidents in the last 7 and 30 days, severity-weighted count in
the last 90 days, days since the last violent incident (log), season factor, LGA baseline,
closeness to the stock route.
Training: batch gradient descent on log-loss with L2 penalty, temporal split (train on older
weeks, test on the most recent 90 days), so the test imitates real forecasting.
Evaluation: AUC (Mann-Whitney), Brier score, and comparison with a naive "last 30 days" baseline.
"""
import datetime as dt
import json
import math
import os

import geo

FEATURES = ["violent_7d", "violent_30d", "severity_90d", "log_days_since", "season", "baseline", "route_close"]


def features(incidents, lga_name, t):
    g = geo.lga(lga_name)
    past = [i for i in incidents if i["lga"] == lga_name and i["ts"] < t]
    v = [i for i in past if i["severity"] >= 3]
    v7 = sum(1 for i in v if t - i["ts"] <= 7 * 86400)
    v30 = sum(1 for i in v if t - i["ts"] <= 30 * 86400)
    s90 = sum(i["severity"] for i in past if t - i["ts"] <= 90 * 86400)
    since = (t - max((i["ts"] for i in v), default=t - 365 * 86400)) / 86400
    route = min(geo.dist_to_polyline(g["lat"], g["lon"], r) for r in geo.cfg()["routes"].values())
    return [v7, v30, s90, math.log1p(since), geo.season_factor(dt.datetime.fromtimestamp(t).month), g["baseline"],
            math.exp(-route / 20)]


def label(incidents, lga_name, t, horizon):
    return int(any(i["lga"] == lga_name and i["severity"] >= 3 and t <= i["ts"] < t + horizon * 86400 for i in incidents))


def dataset(incidents, start, end, step_days=7, horizon=14):
    rows = []
    t = start
    while t + horizon * 86400 <= end:
        for g in geo.lgas():
            rows.append((features(incidents, g["name"], t), label(incidents, g["name"], t, horizon), t, g["name"]))
        t += step_days * 86400
    return rows


def sigmoid(z):
    return 1 / (1 + math.exp(-z)) if z > -30 else 0.0


class Logistic:
    def fit(self, X, y, lr=0.5, epochs=600, l2=0.01):
        n, k = len(X), len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(k)]
        self.sd = [max(1e-6, math.sqrt(sum((r[j] - self.mu[j]) ** 2 for r in X) / n)) for j in range(k)]
        Z = [self.scale(r) for r in X]
        self.w, self.b = [0.0] * k, math.log((sum(y) + 1) / (n - sum(y) + 1))
        for _ in range(epochs):
            gw, gb = [0.0] * k, 0.0
            for z, t in zip(Z, y):
                err = sigmoid(self.b + sum(a * b for a, b in zip(self.w, z))) - t
                gb += err
                for j in range(k):
                    gw[j] += err * z[j]
            self.b -= lr * gb / n
            self.w = [w - lr * (g / n + l2 * w) for w, g in zip(self.w, gw)]
        return self

    def scale(self, r):
        return [(v - m) / s for v, m, s in zip(r, self.mu, self.sd)]

    def predict(self, r):
        return sigmoid(self.b + sum(a * b for a, b in zip(self.w, self.scale(r))))

    def to_dict(self):
        return {"w": self.w, "b": self.b, "mu": self.mu, "sd": self.sd, "features": FEATURES}

    @classmethod
    def from_dict(cls, d):
        m = cls()
        m.w, m.b, m.mu, m.sd = d["w"], d["b"], d["mu"], d["sd"]
        return m


def auc(scores, labels):
    """Probability that a random positive is ranked above a random negative (Mann-Whitney U)."""
    pairs = sorted(zip(scores, labels))
    rank, i, rsum = 1, 0, 0.0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (rank + rank + (j - i)) / 2
        rsum += avg * sum(1 for k in range(i, j + 1) if pairs[k][1] == 1)
        rank += j - i + 1
        i = j + 1
    npos = sum(labels)
    nneg = len(labels) - npos
    return (rsum - npos * (npos + 1) / 2) / (npos * nneg) if npos and nneg else None


def train_and_evaluate(incidents, now, path):
    c = geo.cfg()
    split = now - c["train_until_days_ago"] * 86400
    first = min(i["ts"] for i in incidents) + 90 * 86400
    train = dataset(incidents, first, split, horizon=c["horizon_days"])
    test = dataset(incidents, split, now, horizon=c["horizon_days"])
    m = Logistic().fit([r[0] for r in train], [r[1] for r in train], c["learning_rate"], c["epochs"], c["l2"])
    p = [m.predict(r[0]) for r in test]
    y = [r[1] for r in test]
    base = [r[0][1] for r in test]  # naive: violent events in the last 30 days
    ev = {"train_rows": len(train), "test_rows": len(test), "positive_rate_test": round(sum(y) / len(y), 3),
          "auc_model": round(auc(p, y), 3), "auc_naive_last30": round(auc(base, y), 3),
          "brier_model": round(sum((a - b) ** 2 for a, b in zip(p, y)) / len(y), 4),
          "brier_climatology": round(sum((sum(y) / len(y) - b) ** 2 for b in y) / len(y), 4),
          "weights": dict(zip(FEATURES, [round(w, 3) for w in m.w]))}
    json.dump({"model": m.to_dict(), "evaluation": ev}, open(path, "w"), indent=1)
    return m, ev
