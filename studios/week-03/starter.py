"""Week 3 studio — starter (three misuse exploits).

Fill in the three functions below. Then run ``python3 test_modes.py``.
All provided tests must pass, INCLUDING the guarantee test that watches the
``H(secret‖msg)`` MAC *fail* under length extension while HMAC holds — because a
guarantee you cannot watch collapse is not a guarantee you understood.

Nothing you write breaks AES or SHA-256. Every exploit is a misuse of the MODE
or the CONSTRUCTION around a primitive that stayed intact.
"""
from modes import ecb_encrypt, cbc_encrypt, distinct_blocks, ctr_keystream, xor
from mdhash import md_hash, bad_mac


# ---- Task 1: ECB leaks structure, CBC hides it ------------------------------

def ecb_leak_count(image: bytes, key: bytes) -> int:
    """Encrypt ``image`` under ECB and return the number of DISTINCT ciphertext
    blocks. Because ECB maps identical plaintext blocks to identical ciphertext
    blocks, this equals the number of distinct plaintext blocks — the structure
    leaks 1:1. For the provided IMAGE this should be 2 (the two flat regions).

    Hint: ``ecb_encrypt(image, key)`` then ``distinct_blocks(...)``.
    """
    ciphertext = ecb_encrypt(image, key)
    return distinct_blocks(ciphertext)


# ---- Task 2: CTR nonce reuse == week-2 two-time pad -------------------------

def recover_second_plaintext(c1: bytes, c2: bytes, known_m1: bytes) -> bytes:
    """Two messages were CTR-encrypted under the SAME key AND the SAME nonce, so
    they share a keystream. Given both ciphertexts and knowledge of the first
    plaintext ``known_m1``, recover the second plaintext.

    This is the EXACT week-2 two-time-pad break on a modern mode: the keystream
    cancels, so  c1 ⊕ c2 == m1 ⊕ m2,  therefore  m2 == c1 ⊕ c2 ⊕ m1.

    Use ``xor(...)`` from ``modes``. Return bytes of length ``len(known_m1)``.
    """
    return xor(xor(c1, c2), known_m1)


# ---- Task 3: forge a H(secret‖msg) MAC by length extension ------------------

def forge_extension(observed_msg: bytes, observed_tag: int, secret_len: int,
                    extension: bytes):
    """Forge a valid ``bad_mac`` (= H(secret‖msg)) tag for attacker-chosen
    ``extension``, WITHOUT knowing the secret. You know only ``observed_msg``,
    its tag ``observed_tag``, and the secret's LENGTH.

    Return ``(forged_msg, forged_tag)`` such that
    ``bad_mac(secret, forged_msg) == forged_tag``.

    Recipe (replicate the hash's internal padding, then RESUME hashing from the
    observed tag):

      1. total = secret_len + len(observed_msg)
      2. pad   = bytes((-total) % 4)          # the toy hash pads to 4-byte blocks
      3. forged_msg = observed_msg + pad + extension
      4. forged_tag = md_hash(extension, iv=observed_tag)   # resume from the tag
    """
    total = secret_len + len(observed_msg)
    pad = bytes((-total) % 4)
    forged_msg = observed_msg + pad + extension
    forged_tag = md_hash(extension, iv=observed_tag)
    return forged_msg, forged_tag


if __name__ == "__main__":
    import os
    from data import IMAGE, M1, M2, CRIB, MAC_SECRET, MAC_MSG, MAC_EXTENSION

    key = os.urandom(16)
    try:
        print("ECB distinct ciphertext blocks:", ecb_leak_count(IMAGE, key),
              "(expected 2 — structure leaks)")
    except NotImplementedError:
        print("ecb_leak_count: not implemented yet")

    nonce = os.urandom(8)  # the BUG: reused across both messages below
    ks = ctr_keystream(key, nonce, max(len(M1), len(M2)))
    c1, c2 = xor(M1, ks), xor(M2, ks)
    try:
        print("recovered m2:", recover_second_plaintext(c1, c2, M1))
    except NotImplementedError:
        print("recover_second_plaintext: not implemented yet")

    tag = bad_mac(MAC_SECRET, MAC_MSG)
    try:
        fm, ft = forge_extension(MAC_MSG, tag, len(MAC_SECRET), MAC_EXTENSION)
        print(f"forged msg {fm!r} tag valid? {bad_mac(MAC_SECRET, fm) == ft}")
    except NotImplementedError:
        print("forge_extension: not implemented yet")
