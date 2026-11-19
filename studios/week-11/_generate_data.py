"""Week 11 studio — regenerate the synthetic data files (GIVEN; run only to rebuild).

The audit flagged the "provided simulated model" as living *only* in the notebook.
This script extracts every synthetic artifact the Session-A notebook builds — the
released medical table, the public voter roll, and the simulated model's per-record
losses — into concrete JSON files (`medical.json`, `voter_roll.json`, `model.json`).
The generation code and seed are copied VERBATIM from the notebook, so the files are
bit-for-bit the same values as the demo. All data is synthetic: there is no real
personal data here, which is itself the week's ethics rule.

Run:  python3 _generate_data.py   (only if you intentionally rotate the seed)
"""
import json
import os
import random

SEED = 20250807

HERE = os.path.dirname(os.path.abspath(__file__))

# --- Section 1 datasets: population -> released + voter roll (verbatim) -------
ZIPS = ["02101", "02102", "02139"]
SEX = ["M", "F"]
DIAGNOSES = ["flu", "diabetes", "hiv", "cancer", "none"]


def build_population():
    rng = random.Random(SEED)
    population = []
    for i in range(120):
        population.append({
            "name": f"person{i:03d}",
            "zip": rng.choice(ZIPS),
            "yob": rng.randint(1950, 2000),
            "sex": rng.choice(SEX),
            "diagnosis": rng.choice(DIAGNOSES),
        })
    return population


# --- Section 5 simulated model: per-record losses (verbatim) ------------------
def build_probe():
    r = random.Random(SEED)

    def cohort(n, is_member):
        # Members were memorized -> lower loss; non-members -> higher; overlap.
        mu = 0.3 if is_member else 0.9
        return [{"member": is_member, "loss": r.gauss(mu, 0.35)} for _ in range(n)]

    return cohort(100, True) + cohort(100, False)   # 50/50 -> guessing = 50%


def main():
    population = build_population()
    # RELEASED medical data: name dropped, everything else kept.
    released = [{k: v for k, v in p.items() if k != "name"} for p in population]
    # AUXILIARY public data (a voter roll): name + the quasi-identifiers.
    voter_roll = [{"name": p["name"], "zip": p["zip"], "yob": p["yob"], "sex": p["sex"]}
                  for p in population]
    probe = build_probe()

    for fname, obj in (("medical.json", released),
                       ("voter_roll.json", voter_roll),
                       ("model.json", probe)):
        with open(os.path.join(HERE, fname), "w") as f:
            json.dump(obj, f, indent=1)
        print(f"wrote {fname}: {len(obj)} records")


if __name__ == "__main__":
    main()
