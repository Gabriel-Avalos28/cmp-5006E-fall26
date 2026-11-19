"""Week 11 studio — the synthetic data + expected values (GIVEN; do not modify).

Loads the three synthetic artifacts extracted from the Session-A notebook (same
seed, same values) so your results line up with the demo:

  * ``RELEASED``   — the 'anonymized' medical table (name dropped, qid kept)
  * ``VOTER_ROLL`` — the public auxiliary data (name + quasi-identifiers)
  * ``PROBE``      — the SIMULATED MODEL's per-record losses (members vs non-members)

The simulated model used to live only inside the notebook; it is now a real file
(``model.json``) so the membership-inference task has a concrete, reproducible
target. Rebuild any of these with ``python3 _generate_data.py``.

``HOMOGENEOUS_GROUP`` is the deliberately-constructed teaching case for the
homogeneity attack: a k-anonymous group (k = 5, nobody unique) that is *uniform* on
the sensitive attribute, so the attribute leaks even though identity is hidden. The
notebook constructs it rather than hoping the random data produces one — the effect
is real; we just make it legible.

Every value here is synthetic. There is no real personal data in this studio.
"""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(_HERE, name)) as f:
        return json.load(f)


RELEASED = _load("medical.json")        # 120 'anonymized' medical records
VOTER_ROLL = _load("voter_roll.json")   # 120 name + {zip, yob, sex} rows
PROBE = _load("model.json")             # 200 simulated per-record losses (50/50)

# --- Task 1: what the notebook's linkage reports ------------------------------
UNIQUE_FRACTION_EXPECTED = 0.75         # 90 / 120 unique on (zip, yob, sex)
VICTIM_NAME_EXPECTED = "person001"      # the first uniquely-identified record
VICTIM_DIAGNOSIS_EXPECTED = "diabetes"  # the secret linkage exposes

# --- Task 2: the constructed homogeneity teaching case ------------------------
# k = 5, all rows share the generalized qid AND the same diagnosis.
HOMOGENEOUS_GROUP = [
    {"zip": "021xx", "yob": "1960s", "diagnosis": "hiv"} for _ in range(5)
]
HOMOGENEITY_LEAK_EXPECTED = "hiv"       # learned without singling anyone out

# --- Task 3: the aggregate query DP protects ----------------------------------
DP_EPSILONS = (0.1, 0.5, 1.0, 5.0)
TRUE_HIV_COUNT = sum(1 for r in RELEASED if r["diagnosis"] == "hiv")  # 24

# --- Task 4: membership inference ---------------------------------------------
MI_THRESHOLDS = (0.4, 0.6, 0.8)
MI_BASELINE = 0.50                      # random guessing on a 50/50 probe
