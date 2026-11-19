"""Week 11 studio — starter (four privacy attacks + one measurement).

Fill in the functions below, then run ``python3 test_privacy.py``. All provided
tests must pass, INCLUDING the two that pin the week's spine against each other:

  * differential privacy gives a **statable ε guarantee** — the noise error is a
    bound you can write down (mean |error| = 1/ε: ±10 at ε=0.1, ±0.2 at ε=5), and
    the adversary's advantage is capped at a factor of e^ε; and
  * k-anonymity **only raises cost** — it protects identity but has NO guarantee
    about the secret, and the homogeneity attack watches it leak the diagnosis.

Nothing here touches real personal data — every dataset is synthetic (``data.py``).
"""
from privacy import quasi_id, generalize, laplace_noise, membership_guess


# ---- Task 1: re-identify by linkage ----------------------------------------

def reidentify(released, voter_roll):
    """Link the 'anonymized' ``released`` medical table to the public ``voter_roll``
    on the quasi-identifier {zip, yob, sex}, and re-identify a victim.

    Return a dict with:
      * ``"fraction_unique"`` — share of released records that are UNIQUE on the
        quasi-id (uniqueness is what makes a row linkable). ~0.75 here.
      * ``"victim"``          — the first uniquely-identified released record.
      * ``"victim_name"``     — the name that record links to in the voter roll.
        This is the ORACLE: a re-identification is confirmed by a successful NAME
        link, not by "this row looks unique".

    Hints: ``Counter(quasi_id(r) for r in released)`` to find uniques; a dict
    ``{quasi_id(v): v["name"] for v in voter_roll}`` to link a qid back to a name.
    """
    # TODO: count quasi-ids, collect the unique released rows, take the first as
    #       the victim, and link its quasi-id to a name via the voter roll.
    raise NotImplementedError


# ---- Task 2: k-anonymize, then break it with the homogeneity attack --------

def homogeneity_attack(group):
    """A k-anonymous ``group`` (list of records sharing a generalized quasi-id, so
    no member is unique) is handed to you. Mount the homogeneity attack: if every
    member shares the SAME sensitive value, you learn it WITHOUT singling anyone
    out — k-anonymity protected identity, not the attribute.

    Return the single leaked ``diagnosis`` if the group is uniform on it, else
    ``None`` (a diverse group does not leak — that is what l-diversity buys).

    State in your write-up exactly what k-anonymity did (hid identity: k = len(group),
    no unique row) and did NOT do (bound what the attacker learns).
    """
    # TODO: collect the distinct diagnoses; if there is exactly one, return it.
    raise NotImplementedError


# ---- Task 3: differential privacy — a statable guarantee -------------------

def noisy_count(true_count, eps, rng):
    """Answer a COUNT query under ε-differential privacy. A count has sensitivity
    1, so the calibrated Laplace scale is 1/ε. Return the noised answer as a float.

    Smaller ε -> more noise -> stronger privacy, less accuracy. The mean absolute
    error equals 1/ε — a bound you can STATE, unlike anything k-anonymity offers.

    Hint: ``true_count + laplace_noise(1.0 / eps, rng)``.
    """
    # TODO: add Laplace noise at scale 1/eps to the true count.
    raise NotImplementedError


# ---- Task 4: membership inference on the simulated model -------------------

def membership_inference(probe, thresholds):
    """Mount the loss-threshold membership-inference attack on the simulated
    model's ``probe`` (each record has a ``loss`` and a ground-truth ``member``
    flag). For each candidate threshold, guess 'member' when loss < threshold
    (``membership_guess``); pick the threshold with the best accuracy.

    Return a dict: ``{"best_threshold": t, "accuracy": a}``. Beating the 50%
    baseline means the MODEL leaked training membership — a breach with no table
    involved. For a 'diabetes model', being in the training set IS the secret.
    """
    # TODO: for each threshold, compute accuracy over the probe; return the best.
    raise NotImplementedError


if __name__ == "__main__":
    import random
    from data import (RELEASED, VOTER_ROLL, PROBE, HOMOGENEOUS_GROUP,
                      DP_EPSILONS, TRUE_HIV_COUNT, MI_THRESHOLDS)

    try:
        res = reidentify(RELEASED, VOTER_ROLL)
        print(f"re-identified {res['fraction_unique']:.0%} uniquely; "
              f"victim -> {res['victim_name']} (diagnosis {res['victim']['diagnosis']!r})")
    except NotImplementedError:
        print("reidentify: not implemented yet")

    try:
        print("homogeneity attack leaks:", homogeneity_attack(HOMOGENEOUS_GROUP))
    except NotImplementedError:
        print("homogeneity_attack: not implemented yet")

    try:
        print(f"DP count of HIV (true = {TRUE_HIV_COUNT}):")
        for eps in DP_EPSILONS:
            r = random.Random(1)
            errs = [abs(noisy_count(TRUE_HIV_COUNT, eps, r) - TRUE_HIV_COUNT)
                    for _ in range(5000)]
            print(f"  eps={eps:>4}  mean|error|={sum(errs)/len(errs):>6.2f}  (bound 1/eps = {1/eps})")
    except NotImplementedError:
        print("noisy_count: not implemented yet")

    try:
        mi = membership_inference(PROBE, MI_THRESHOLDS)
        print(f"membership inference: {mi['accuracy']:.0%} accuracy "
              f"(baseline 50%) at threshold {mi['best_threshold']}")
    except NotImplementedError:
        print("membership_inference: not implemented yet")
