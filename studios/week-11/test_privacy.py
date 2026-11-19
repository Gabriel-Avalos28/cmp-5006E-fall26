"""Provided tests for the week-11 studio.

Run: ``python3 test_privacy.py``. Passes => your four attacks/measurements are
correct and you are ready to write the Control Scorecard (Task 5).

The two GUARANTEE tests are the point of the week, and they are pinned AGAINST each
other because the contrast is the lesson:

  * ``test_dp_gives_a_statable_epsilon_guarantee`` — DP's error is a bound you can
    WRITE DOWN (mean |error| = 1/ε: ±10 at ε=0.1, ±0.2 at ε=5), and the adversary's
    advantage is capped at e^ε. That is a guarantee.
  * ``test_kanonymity_only_raises_cost_and_leaks`` — k-anonymity hides identity
    (k = 5, no unique row) yet the homogeneity attack LEARNS the diagnosis. There is
    no number it can promise about the secret. That is a cost-raiser, not a guarantee.

Everything is synthetic and reproducible — no real personal data, the ethics rule.
"""
import math
import random
import sys

from privacy import quasi_id, generalize, epsilon_guarantee
from data import (RELEASED, VOTER_ROLL, PROBE, HOMOGENEOUS_GROUP,
                  UNIQUE_FRACTION_EXPECTED, VICTIM_NAME_EXPECTED,
                  VICTIM_DIAGNOSIS_EXPECTED, HOMOGENEITY_LEAK_EXPECTED,
                  DP_EPSILONS, TRUE_HIV_COUNT, MI_THRESHOLDS, MI_BASELINE)
import starter as s


def test_linkage_reidentifies_majority_and_names_victim():
    # 'Anonymized' medical data ⋈ voter roll on {zip, yob, sex}: most rows are
    # unique on the quasi-id, and a unique row links straight to a name.
    res = s.reidentify(RELEASED, VOTER_ROLL)
    assert abs(res["fraction_unique"] - UNIQUE_FRACTION_EXPECTED) < 1e-9, (
        f"expected {UNIQUE_FRACTION_EXPECTED:.0%} uniquely identified, "
        f"got {res['fraction_unique']:.0%}"
    )
    assert res["victim_name"] == VICTIM_NAME_EXPECTED, (
        f"the oracle is a NAME link; expected {VICTIM_NAME_EXPECTED}, "
        f"got {res['victim_name']}"
    )
    assert res["victim"]["diagnosis"] == VICTIM_DIAGNOSIS_EXPECTED
    print(f"  ok  linkage re-identified {res['fraction_unique']:.0%} — "
          f"{res['victim_name']} outed as {res['victim']['diagnosis']!r}; "
          "'we removed the name' protected nothing")


def test_dp_gives_a_statable_epsilon_guarantee():
    """GUARANTEE TEST (positive) — DP's error is a bound you can STATE.

    For a count query (sensitivity 1) the Laplace scale is 1/ε and the mean
    absolute error equals 1/ε. So the accuracy cost is a number: ±10 at ε=0.1
    down to ±0.2 at ε=5. And the adversary's advantage is capped at e^ε. This is
    the first control in the course whose guarantee is literally a number.
    """
    mean_err = {}
    for eps in DP_EPSILONS:
        r = random.Random(1)
        errs = [abs(s.noisy_count(TRUE_HIV_COUNT, eps, r) - TRUE_HIV_COUNT)
                for _ in range(5000)]
        mean_err[eps] = sum(errs) / len(errs)
        # The STATABLE bound: mean |error| tracks 1/ε (within sampling noise).
        assert abs(mean_err[eps] - 1.0 / eps) < 0.2 * (1.0 / eps), (
            f"ε={eps}: mean error {mean_err[eps]:.2f} should track the "
            f"statable bound 1/ε = {1.0/eps}"
        )
    # The knob works both ways: strong privacy (ε=0.1) is ~±10, weak (ε=5) ~±0.2.
    assert mean_err[0.1] > 5.0 and mean_err[5.0] < 0.5
    assert mean_err[0.1] > mean_err[5.0]
    # The guarantee is a finite, statable factor e^ε.
    assert math.isclose(epsilon_guarantee(0.1), math.exp(0.1))
    assert epsilon_guarantee(0.1) < epsilon_guarantee(5.0)
    print(f"  ok  DP is a STATABLE guarantee: mean|error| ±{mean_err[0.1]:.0f} at "
          f"ε=0.1 -> ±{mean_err[5.0]:.1f} at ε=5, advantage capped at e^ε")


def test_kanonymity_only_raises_cost_and_leaks():
    """GUARANTEE TEST (negative) — k-anonymity has NO number for the secret.

    Generalization hides IDENTITY: the group is k-anonymous (k = 5, nobody
    unique). But it says nothing about the sensitive attribute, so a group uniform
    on the diagnosis leaks it — the homogeneity attack. k-anonymity raises cost;
    it does not guarantee. Watching the leak succeed is how you know.
    """
    group = HOMOGENEOUS_GROUP
    # Identity IS protected: every row shares the generalized qid; k = 5, no unique.
    assert len(group) >= 5
    assert len({(m["zip"], m["yob"]) for m in group}) == 1, (
        "k-anonymity requires the group to share one generalized quasi-id"
    )
    # ...yet the SECRET leaks — the guarantee k-anonymity never made.
    leaked = s.homogeneity_attack(group)
    assert leaked == HOMOGENEITY_LEAK_EXPECTED, (
        f"homogeneity attack should learn {HOMOGENEITY_LEAK_EXPECTED!r} without "
        f"singling anyone out; got {leaked!r}"
    )
    # A diverse group does NOT leak — that is exactly what l-diversity buys.
    diverse = [{"zip": "021xx", "yob": "1960s", "diagnosis": d}
               for d in ("hiv", "flu", "none", "cancer", "diabetes")]
    assert s.homogeneity_attack(diverse) is None
    print(f"  ok  k-anonymity RAISES COST but LEAKS: identity hidden (k={len(group)}) "
          f"yet diagnosis {leaked!r} learned — no guarantee about the attribute")


def test_membership_inference_beats_50pct_baseline():
    # The overfit model is more confident (lower loss) on its training data;
    # thresholding that confidence infers membership above the 50% baseline.
    mi = s.membership_inference(PROBE, MI_THRESHOLDS)
    assert mi["accuracy"] > MI_BASELINE, (
        f"membership inference should beat the {MI_BASELINE:.0%} baseline; "
        f"got {mi['accuracy']:.0%}"
    )
    assert mi["accuracy"] >= 0.75, (
        f"expected ~80% accuracy on this probe, got {mi['accuracy']:.0%}"
    )
    print(f"  ok  membership inference {mi['accuracy']:.0%} > {MI_BASELINE:.0%} "
          "baseline — the MODEL leaked training membership, no table needed")


TESTS = [
    test_linkage_reidentifies_majority_and_names_victim,
    test_dp_gives_a_statable_epsilon_guarantee,
    test_kanonymity_only_raises_cost_and_leaks,
    test_membership_inference_beats_50pct_baseline,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: attack not implemented yet")
            failed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed}/{len(TESTS)} failed")
        sys.exit(1)
    print(f"\nall {len(TESTS)} tests pass")


if __name__ == "__main__":
    main()
