"""KadunaCorridor end-to-end test. Resets demo data first. Results in results/selftest.json."""
import json
import os
import time

import geo
import hawkes as hk
import main as cli

cases = []


def case(name, ok, detail=""):
    cases.append({"test": name, "passed": bool(ok), "detail": str(detail)})
    print("PASS" if ok else "FAIL", name, detail)


def run():
    res = {}
    t0 = time.time()
    s = cli.setup()
    res["setup"] = s
    res["setup_seconds"] = round(time.time() - t0, 2)

    sims = {f"S{i}": hk.simulate(0.05, 0.5, 1 / 3, 2000, seed=i) for i in range(4)}
    ll, alpha, beta, mus = hk.fit_grid(sims, 2000)
    res["parameter_recovery"] = {"true_alpha": 0.5, "fitted_alpha": alpha, "true_memory_days": 3,
                                 "fitted_memory_days": round(1 / beta, 2), "events": sum(map(len, sims.values()))}
    case("Fitter recovers known parameters from simulated data (alpha 0.5, memory 3 days)",
         abs(alpha - 0.5) <= 0.15 and 1.5 <= 1 / beta <= 5, res["parameter_recovery"])
    pois = hk.fit_grid({k: [i * 2000.0 / (len(v) + 1) for i in range(len(v))] for k, v in sims.items()}, 2000)
    case("Evenly spaced (non-clustered) events give a low branching ratio", pois[1] <= 0.15, pois[1])

    f = s["fit"]
    case("Fitted on the history: retaliation present (alpha > 0)", f["alpha"] > 0, f)
    case("Hawkes beats Poisson on held-out data (log-likelihood)", f["hawkes_better"],
         f"{f['test_loglik_hawkes']} vs {f['test_loglik_poisson']}")

    quiet = [r for r in hk.forecast() if r["lga"] == "Sanga"][0]
    after = cli.flare("Sanga")
    res["sanga"] = {"before": quiet, "after": after}
    case("Three linked attacks in Sanga raise its status to ESCALATING", after["status"] == "ESCALATING" and
         after["ratio"] > quiet["ratio"], f"ratio {quiet['ratio']} -> {after['ratio']}")
    case("7-day risk rises after the flare", after["p_any_7d"] > quiet["p_any_7d"], f"{quiet['p_any_7d']} -> {after['p_any_7d']}")
    with hk.db() as con:
        w = con.execute("SELECT * FROM warnings WHERE lga='Sanga'").fetchall()
    case("One escalation warning issued for Sanga", len(w) == 1, w[0]["text"] if w else "")
    hk.forecast()
    with hk.db() as con:
        case("No repeated warning within 24 h", con.execute("SELECT COUNT(*) FROM warnings WHERE lga='Sanga'").fetchone()[0] == 1)
    ch = hk.chains()
    res["longest_chain"] = len(ch[0]) if ch else 0
    case("Retaliation chain detected around the Sanga flare", any(len(c) >= 3 and c[-1]["lga"] == "Sanga" for c in ch),
         f"{len(ch)} chains, longest {res['longest_chain']}")

    import app
    app.app.secret_key = "t"
    cl = app.app.test_client()
    cl.post("/login", data={"u": "commander", "p": "ChangeMe@468"})
    case("Forecast page renders with intensity charts", cl.get("/").status_code == 200 and b"<svg" in cl.get("/").data)
    case("Commander cannot refit the model", cl.post("/model", data={"csrf": "x"}).status_code == 403)

    res.update(tests=cases, passed=sum(c["passed"] for c in cases), total=len(cases))
    os.makedirs(os.path.join(geo.BASE, "results"), exist_ok=True)
    json.dump(res, open(os.path.join(geo.BASE, "results", "selftest.json"), "w"), indent=1)
    print(f"\n{res['passed']}/{res['total']} passed")
    cli.setup()


if __name__ == "__main__":
    run()
