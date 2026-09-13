"""HashSmash experiment: seeded trajectory prefix-collision probe for md5-s63.

Reads one JSON request from stdin (schema_version 1, experiment id, event, and
organizer trials with per-trial seeds). For each trial, iterate the claim's
iteration function f (md5-s63 of the 16-byte little-endian encoding of the
current 128-bit word) for at most 512 steps, tracking the leading 16 digest
bits (digest bytes 0 and 1, i.e. the low 16 bits of the A word). On the first
prefix match, return the two 16-byte messages whose digests share the prefix;
otherwise return two nulls. Deterministic given the organizer seeds: standard
library only, no OS randomness, no wall time, no ambient state.
"""

import hashlib
import json
import sys

MASK32 = 0xFFFFFFFF

K63 = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB,
)

ROTATIONS = ((7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21))

MAX_STEPS = 512
PREFIX_BITS = 16
PREFIX_MASK = (1 << PREFIX_BITS) - 1


def rol(value, count):
    return ((value << count) | (value >> (32 - count))) & MASK32


def f63(word):
    """md5-s63 (steps 0..62, standard IV/padding/feed-forward) of the 16-byte
    little-endian encoding of word, returned as the claim's numeric digest
    A + (B << 32) + (C << 64) + (D << 96)."""
    m = (word & MASK32, (word >> 32) & MASK32, (word >> 64) & MASK32, (word >> 96) & MASK32,
         0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for i in range(63):
        if i < 16:
            f, g = (b & c) | (~b & d), i
        elif i < 32:
            f, g = (d & b) | (~d & c), (5 * i + 1) % 16
        elif i < 48:
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, g = c ^ (b | ~d), (7 * i) % 16
        a, b, c, d = d, (b + rol((a + f + K63[i] + m[g]) & MASK32, ROTATIONS[i // 16][i % 4])) & MASK32, b, c
    return ((a + 0x67452301) & MASK32 | ((b + 0xEFCDAB89) & MASK32) << 32
            | ((c + 0x98BADCFE) & MASK32) << 64 | ((d + 0x10325476) & MASK32) << 96)


def run_trial(seed_hex):
    start = int.from_bytes(hashlib.shake_256(bytes.fromhex(seed_hex)).digest(16), "little")
    seen = {}
    w = start
    for step in range(1, MAX_STEPS + 1):
        digest = f63(w)
        prefix = digest & PREFIX_MASK
        other = seen.get(prefix)
        if other is not None and other != w:
            return w, other, step
        seen[prefix] = w
        w = digest
    return None, None, MAX_STEPS


def main():
    request = json.loads(sys.stdin.read())
    trials = []
    for entry in request["trials"]:
        hit_w, hit_other, steps = run_trial(entry["seed"])
        if hit_w is None:
            trials.append({"trial": entry["trial"], "message_a_hex": None, "message_b_hex": None,
                           "observations": {"evaluations_used": steps}})
        else:
            trials.append({
                "trial": entry["trial"],
                "message_a_hex": hit_w.to_bytes(16, "little").hex(),
                "message_b_hex": hit_other.to_bytes(16, "little").hex(),
                "observations": {"evaluations_used": steps},
            })
    sys.stdout.write(json.dumps({"schema_version": 1, "trials": trials}))


if __name__ == "__main__":
    main()
