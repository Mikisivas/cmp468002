"""KadunaCorridor: self-exciting (Hawkes) model of conflict escalation.

For each LGA g, the conditional intensity (expected events per day) is
    lambda_g(t) = mu_g + sum over past events i in g of  alpha * beta * exp(-beta * (t - t_i))
mu_g is the background rate. alpha (0..1) is the branching ratio: the expected number of
follow-up events each event triggers (retaliation). 1/beta is the memory in days.
alpha and beta are shared by all LGAs and fitted by maximum likelihood (grid search);
mu_g has a closed-form estimate for each candidate (alpha, beta).
Evaluation compares held-out log-likelihood with a plain Poisson model (alpha = 0).
"""
import math
import os
import sqlite3
import time

import geo

DATA = os.path.join(geo.BASE, "data")
DAY = 86400.0


def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "corridor.db"), timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, ts REAL, lga TEXT, lat REAL, lon REAL, type TEXT, severity INT,
        fatalities INT, source TEXT);
    CREATE TABLE IF NOT EXISTS fits(id INTEGER PRIMARY KEY, at REAL, alpha REAL, beta REAL, loglik REAL, mu TEXT,
        test_ll_hawkes REAL, test_ll_poisson REAL, n_train INT, n_test INT);
    CREATE TABLE IF NOT EXISTS forecasts(at REAL, lga TEXT, intensity REAL, background REAL, ratio REAL, expected_7d REAL,
        p_any_7d REAL, status TEXT);
    CREATE TABLE IF NOT EXISTS warnings(id INTEGER PRIMARY KEY, at REAL, lga TEXT, text TEXT);
    CREATE TABLE IF NOT EXISTS staff(name TEXT PRIMARY KEY, hash TEXT, role TEXT);
    """)
    return con


def events(t0, t1):
    """Events per LGA, as day offsets from t0. Only severity >= 3 counts as 'violent event'."""
    out = {g["name"]: [] for g in geo.lgas()}
    with db() as con:
        for r in con.execute("SELECT ts, lga FROM incidents WHERE ts>=? AND ts<? AND severity>=3 ORDER BY ts", (t0, t1)):
            out.setdefault(r["lga"], []).append((r["ts"] - t0) / DAY)
    return out


def _excitation_sums(times, beta):
    """A_i = sum_{j<i} exp(-beta (t_i - t_j)), computed recursively in O(n)."""
    a, out = 0.0, []
    for i, t in enumerate(times):
        if i:
            a = math.exp(-beta * (t - times[i - 1])) * (1 + a)
        out.append(a)
    return out


def loglik(ev, T, alpha, beta, mu=None):
    """Log-likelihood over [0, T] days. If mu is None, use the closed-form background estimate."""
    total, mus = 0.0, {}
    for g, times in ev.items():
        comp = sum(1 - math.exp(-beta * (T - t)) for t in times)
        m = mu[g] if mu else max((len(times) - alpha * comp) / T, 1e-4)
        mus[g] = m
        A = _excitation_sums(times, beta)
        total += sum(math.log(m + alpha * beta * a) for a in A) - m * T - alpha * comp
    return total, mus


def fit(now=None):
    c = geo.cfg()
    now = now or time.time()
    t_split = now - c["test_days"] * DAY
    t0 = t_split - c["fit_days"] * DAY
    train = events(t0, t_split)
    T = c["fit_days"]
    ll, alpha, beta, mus = fit_grid(train, T)
    # held-out test: does the fitted model explain the next 60 days better than Poisson?
    test = events(t0, now)
    ll_h = _window_ll(test, alpha, beta, mus, T, T + c["test_days"])
    pois_mu = {g: max(len(v) / T, 1e-4) for g, v in train.items()}
    ll_p = _window_ll(test, 0.0, beta, pois_mu, T, T + c["test_days"])
    n_train = sum(map(len, train.values()))
    n_test = sum(1 for v in test.values() for t in v if t >= T)
    with db() as con:
        import json
        con.execute("INSERT INTO fits(at,alpha,beta,loglik,mu,test_ll_hawkes,test_ll_poisson,n_train,n_test) "
                    "VALUES(?,?,?,?,?,?,?,?,?)", (now, alpha, beta, ll, json.dumps(mus), ll_h, ll_p, n_train, n_test))
    return {"alpha": alpha, "memory_days": round(1 / beta, 2), "loglik": round(ll, 2), "n_train": n_train, "n_test": n_test,
            "test_loglik_hawkes": round(ll_h, 2), "test_loglik_poisson": round(ll_p, 2),
            "hawkes_better": ll_h > ll_p, "mu_per_day": {g: round(m, 4) for g, m in mus.items()}}


def fit_grid(ev, T):
    """Maximum likelihood by grid search over alpha (0 to 0.85) and memory 1/beta (0.5 to 21 days)."""
    best = None
    for alpha in [i / 20 for i in range(0, 18)]:
        for memory_days in (0.5, 1, 2, 3, 5, 7, 10, 14, 21):
            ll, mus = loglik(ev, T, alpha, 1 / memory_days)
            if not best or ll > best[0]:
                best = (ll, alpha, 1 / memory_days, mus)
    return best


def simulate(mu, alpha, beta, T, seed=1):
    """Ogata's thinning algorithm: draw a Hawkes process with known parameters (used to test the fitter)."""
    import random
    rnd = random.Random(seed)
    t, times = 0.0, []
    while True:
        lam_bar = mu + alpha * beta * sum(math.exp(-beta * (t - s)) for s in times[-200:]) + alpha * beta
        t += rnd.expovariate(lam_bar)
        if t >= T:
            return times
        lam_t = mu + alpha * beta * sum(math.exp(-beta * (t - s)) for s in times[-200:])
        if rnd.random() <= lam_t / lam_bar:
            times.append(t)


def _window_ll(ev, alpha, beta, mus, a, b):
    """Log-likelihood of events in [a, b) given all earlier history (prediction without refitting)."""
    total = 0.0
    for g, times in ev.items():
        m = mus.get(g, 1e-4)
        for i, t in enumerate(times):
            if a <= t < b:
                lam = m + alpha * beta * sum(math.exp(-beta * (t - s)) for s in times[:i])
                total += math.log(lam)
        integral = m * (b - a) + alpha * sum(math.exp(-beta * max(0, a - s)) - math.exp(-beta * (b - s))
                                             for s in times if s < b)
        total -= integral
    return total


def latest_fit():
    import json
    with db() as con:
        f = con.execute("SELECT * FROM fits ORDER BY id DESC LIMIT 1").fetchone()
    return (f["alpha"], f["beta"], json.loads(f["mu"])) if f else None


def intensity(times_days, now_day, alpha, beta, mu):
    return mu + alpha * beta * sum(math.exp(-beta * (now_day - s)) for s in times_days if s <= now_day)


def forecast(now=None, horizon=7):
    """Expected violent events in the next `horizon` days per LGA, and escalation status."""
    c = geo.cfg()
    now = now or time.time()
    alpha, beta, mus = latest_fit()
    t0 = now - 120 * DAY
    ev = events(t0, now + 1)
    T = (now - t0) / DAY
    out = []
    for g, times in ev.items():
        mu = mus.get(g, 1e-4)
        lam = intensity(times, T, alpha, beta, mu)
        expected = mu * horizon + alpha * sum(math.exp(-beta * (T - s)) - math.exp(-beta * (T + horizon - s)) for s in times)
        ratio = lam / mu
        status = "ESCALATING" if ratio >= c["escalation_ratio"] else ("elevated" if ratio >= 1.5 else "background")
        out.append({"lga": g, "intensity": round(lam, 4), "background": round(mu, 4), "ratio": round(ratio, 2),
                    "expected_7d": round(expected, 3), "p_any_7d": round(1 - math.exp(-expected), 3), "status": status})
    with db() as con:
        con.execute("DELETE FROM forecasts")
        con.executemany("INSERT INTO forecasts VALUES(?,?,?,?,?,?,?,?)", [(now, o["lga"], o["intensity"], o["background"],
                                                                        o["ratio"], o["expected_7d"], o["p_any_7d"],
                                                                        o["status"]) for o in out])
        for o in out:
            if o["status"] == "ESCALATING" and not con.execute("SELECT 1 FROM warnings WHERE lga=? AND at>?",
                                                               (o["lga"], now - DAY)).fetchone():
                con.execute("INSERT INTO warnings(at,lga,text) VALUES(?,?,?)", (now, o["lga"],
                            f"ESCALATION WARNING {o['lga']}: violence intensity is {o['ratio']}x its background level. "
                            f"Chance of at least one more violent event in 7 days: {o['p_any_7d'] * 100:.0f}%. "
                            f"Act now to break the retaliation cycle: joint patrol, traditional rulers, youth leaders."))
    return sorted(out, key=lambda o: -o["ratio"])


def series(lga_name, days=120, now=None):
    now = now or time.time()
    alpha, beta, mus = latest_fit()
    t0 = now - days * DAY
    times = events(t0 - 30 * DAY, now + 1)[lga_name]
    shift = 30
    pts = []
    for d in range(days + 1):
        pts.append(round(intensity([s - shift for s in times], d, alpha, beta, mus.get(lga_name, 1e-4)), 4))
    marks = [round(s - shift, 2) for s in times if s - shift >= 0]
    return pts, marks


def chains(days=120, now=None):
    """Retaliation chains: an event joins the chain of an earlier violent event within 72 h and 25 km."""
    c = geo.cfg()
    now = now or time.time()
    with db() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM incidents WHERE ts>? AND severity>=3 ORDER BY ts",
                                             (now - days * DAY,))]
    parent = {}
    for i, r in enumerate(rows):
        for j in range(i - 1, -1, -1):
            p = rows[j]
            if r["ts"] - p["ts"] > c["chain_hours"] * 3600:
                break
            if geo.km(r["lat"], r["lon"], p["lat"], p["lon"]) <= c["chain_km"]:
                parent[r["id"]] = p["id"]
                break
    roots = {}
    for r in rows:
        root = r["id"]
        while root in parent:
            root = parent[root]
        roots.setdefault(root, []).append(r)
    out = [v for v in roots.values() if len(v) >= 3]
    return sorted(out, key=len, reverse=True)
