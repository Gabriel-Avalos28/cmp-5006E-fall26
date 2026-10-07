#!/usr/bin/env python3
"""Break #5 -- keygen_fleet : RSA keys from a low-entropy device fleet (shared prime).

Assumption broken: "a 2^64-ish random prime is never repeated" -- true only if the random
source has enough entropy at key-generation time. Devices booting with the same weak PRNG
state produced the same prime p, so  gcd(n_i, n_j) = p  and factoring is trivial, even
though factoring a 128-bit n from scratch is the thing RSA relies on being hard.

Method: batch-GCD over the public moduli. For each n_i compute
        g_i = gcd( n_i , (P mod n_i^2) / n_i )     where P = product of all moduli.
g_i > 1 and g_i != n_i  <=> n_i shares a prime with another modulus (this is the simple
version of Bernstein's product-tree algorithm, fine for 4 keys; a product/remainder tree
makes it quasi-linear for millions of keys, as in the 2012 "Mining your Ps and Qs" scan).
Then rebuild the private exponent d and PROVE it works.

Run:  python3 break5_batch_gcd.py
"""
import os, sys, math
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import keygen_fleet

fleet = keygen_fleet()                       # PUBLIC data only: n, e per device
names = list(fleet)
ns = [fleet[k]["n"] for k in names]
e = fleet[names[0]]["e"]
print(f"{len(ns)} public keys, e = {e}, modulus sizes (bits): {[n.bit_length() for n in ns]}")

# --- batch GCD ---------------------------------------------------------------
P = math.prod(ns)
vulnerable = {}
for name, n in zip(names, ns):
    g = math.gcd(n, (P % (n * n)) // n)      # = product of primes of n shared with others
    if 1 < g < n:
        vulnerable[name] = g
    print(f"  {name}: batch-gcd = {g if g > 1 else 1}  ->  {'SHARES A PRIME' if 1 < g < n else 'no shared prime'}")

# Cross-check with plain pairwise gcd to see WHICH devices share the prime
print("\nPairwise gcd cross-check:")
for i in range(len(ns)):
    for j in range(i + 1, len(ns)):
        g = math.gcd(ns[i], ns[j])
        if g > 1:
            print(f"  gcd(n_{i}, n_{j}) = {g}   (shared prime, {g.bit_length()} bits)")

# --- recover private keys & prove they work ----------------------------------
print("\nRecovered private keys:")
for name, p in vulnerable.items():
    n = fleet[name]["n"]
    q = n // p
    assert p * q == n
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)                      # modular inverse (Python 3.8+)
    # confirmation 1: decrypt a ciphertext we created with the PUBLIC key
    m = 0xC0FFEE1234567
    c = pow(m, e, n)
    assert pow(c, d, n) == m
    # confirmation 2: forge a signature with d that verifies under the public key
    h = 0xDEADBEEFCAFE
    sig = pow(h, d, n)
    assert pow(sig, e, n) == h
    print(f"  {name}:  p = {p}\n           q = {q}\n           d = {d}")
    print(f"           decrypt(encrypt(m)) == m: True   |  forged signature verifies: True")

safe = [k for k in names if k not in vulnerable]
print(f"\nCompromised devices: {list(vulnerable)}   Not compromised by this attack: {safe}")
print("(Those two have unique primes: batch-gcd gives 1. The 128-bit toy moduli could still be")
print(" factored directly, but that is a separate, unrelated weakness of the toy key size.)")
