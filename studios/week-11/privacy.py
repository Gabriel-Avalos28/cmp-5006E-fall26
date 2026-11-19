"""Week 11 studio — the privacy engine (GIVEN to you; do not modify).

These are the primitives from the Session-A notebook, unchanged. Week 11 is about
*which kind of guarantee a privacy defense gives* — k-anonymity and its kin **raise
the attacker's cost with no guarantee**, while **differential privacy gives a bound
you can state as a number (e^ε)**. You do not re-implement the primitives; you use
them to mount the attacks and measure the two kinds of defense, in ``starter.py``.

All data is synthetic (see ``data.py`` / ``_generate_data.py``). Nothing here is real
personal data — that is the week's ethics rule, not an accident.
"""
import math


# --- Re-identification by linkage --------------------------------------------

def quasi_id(r):
    """The fields kept 'because they aren't identifying' — {zip, yob, sex}.
    Sweeney: this triple uniquely identifies ~87% of Americans. It is the
    fingerprint that makes 'anonymized' data linkable to a name."""
    return (r["zip"], r["yob"], r["sex"])


# --- k-anonymity by generalization -------------------------------------------

def generalize(r):
    """Coarsen the quasi-identifiers: 3-digit ZIP prefix, 20-year birth band.
    Generalizing until every combination is shared by >= k people is exactly the
    k-anonymity recipe — it hides *identity in a crowd*, and nothing else."""
    return (r["zip"][:3], (r["yob"] // 20) * 20)


# --- Differential privacy: the Laplace mechanism -----------------------------

def laplace_noise(scale, r):
    """Sample from a Laplace distribution — the DP mechanism for counts. For a
    query of sensitivity 1, the calibrated scale is 1/ε. The mean absolute noise
    equals ``scale`` (= 1/ε), which is why the error is a *statable* bound."""
    u = r.uniform(-0.5, 0.5)
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def epsilon_guarantee(eps):
    """The DP guarantee made literal: for budget ε, no adversary — with ANY side
    information — can tell whether a given individual is in the dataset with
    advantage beyond a factor of **e^ε**. That number is the whole point: it is a
    guarantee you can write down. k-anonymity has no such number."""
    return math.exp(eps)


# --- Membership inference: the loss threshold --------------------------------

def membership_guess(record, threshold):
    """The tell of an overfit model: it is more confident (lower loss) on data it
    memorized. Guess 'member' when the record's loss is below ``threshold``."""
    return record["loss"] < threshold
