"""Step-3 completion from the published matched chaining value (sha256-r31).

Each trial derives a deterministic byte stream from its organizer seed. It then
completes the second block of the published 31-step pair with new values of E13
and E15 (hence new W13 and W15) that satisfy the Table 6 conditions of rows
13-16. The first block M0 and second-block words W0..W12 and W14 are the
published values. A trial returns two 128-byte messages M0||M1 and M0||M1'.
"""
import hashlib
import json
import sys

MASK = 0xFFFFFFFF
K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351]
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
M0 = bytes.fromhex(
    "8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082"
    "dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249")
M1 = bytes.fromhex(
    "9abdeb1b1f195f415a7210c155614f13a2269dd1be888a61359257d4adf3737b"
    "9f0484a6eb830a5866add94a9669232d45271fa5b8f69585428bbce30703b904")
# XOR masks of the signed message difference of Table 6 (rows W5..W9).
DW_XOR = {5: 0x0000F006, 6: 0x00208811, 7: 0x50105A0E, 8: 0x58011100, 9: 0x00008004}
# Table 6 E rows as (xor difference, bits equal to 1, bits equal to 0 in M1's path).
E13 = (0x0, 0x00408000, 0x10800000)
E14 = (0x8004, 0x0, 0x800C)
E15 = (0x0, 0x4, 0x8000)
E16 = (0x0, 0x8004, 0x0)


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def s0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def s1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def big_s0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_s1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def words(block):
    return [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]


def expand(w):
    w = list(w)
    for t in range(16, 31):
        w.append((w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2])) & MASK)
    return w


def step(st, t, wt):
    a, b, c, d, e, f, g, h = st
    t1 = (h + big_s1(e) + ((e & f) ^ (~e & g)) + K[t] + wt) & MASK
    t2 = (big_s0(a) + ((a & b) ^ (a & c) ^ (b & c))) & MASK
    return ((t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g)


def compress(cv, w16):
    w = expand(w16)
    st = tuple(cv)
    for t in range(31):
        st = step(st, t, w[t])
    return tuple((x + y) & MASK for x, y in zip(cv, st))


def cond(value, value2, row):
    diff, one, zero = row
    return (value ^ value2) == diff and (value & one) == one and (value & zero) == 0


class Stream:
    """Deterministic 32-bit words from SHAKE-256 of the trial seed."""

    def __init__(self, seed_hex):
        self.seed = bytes.fromhex(seed_hex)
        self.counter = 0
        self.buf = b""

    def word(self):
        if len(self.buf) < 4:
            self.buf = hashlib.shake_256(self.seed + self.counter.to_bytes(8, "big")).digest(4096)
            self.counter += 1
        v = int.from_bytes(self.buf[:4], "big")
        self.buf = self.buf[4:]
        return v


CV1 = compress(IV, words(M0))
BASE = words(M1)
BASE2 = [w ^ DW_XOR.get(i, 0) for i, w in enumerate(BASE)]


def prefix(w):
    st = tuple(CV1)
    for t in range(13):
        st = step(st, t, w[t])
    return st


ST12 = prefix(BASE)
ST12B = prefix(BASE2)


def trial(seed_hex, max_e13=20000, max_e15=256):
    rng = Stream(seed_hex)
    w = list(BASE)
    wb = list(BASE2)
    # E13 = base13 + W13 on both paths (W13 carries no difference).
    base13 = step(ST12, 13, 0)[4]
    for _ in range(max_e13):
        e13 = (rng.word() | E13[1]) & ~E13[2] & MASK
        w13 = (e13 - base13) & MASK
        s13 = step(ST12, 13, w13)
        s13b = step(ST12B, 13, w13)
        if not cond(s13[4], s13b[4], E13) or s13[0] != s13b[0]:
            continue
        s14 = step(s13, 14, w[14])
        s14b = step(s13b, 14, wb[14])
        if not cond(s14[4], s14b[4], E14) or s14[0] != s14b[0]:
            continue
        # The modular difference of E15 and A15 does not depend on W15.
        probe = step(s14, 15, 0)
        probeb = step(s14b, 15, 0)
        if probe[4] != probeb[4] or probe[0] != probeb[0]:
            continue
        base15 = probe[4]
        for _ in range(max_e15):
            e15 = (rng.word() | E15[1]) & ~E15[2] & MASK
            w15 = (e15 - base15) & MASK
            m1 = w[:13] + [w13, w[14], w15]
            m1b = wb[:13] + [w13, wb[14], w15]
            if compress(CV1, m1) == compress(CV1, m1b):
                blk = b"".join(x.to_bytes(4, "big") for x in m1)
                blkb = b"".join(x.to_bytes(4, "big") for x in m1b)
                return (M0 + blk).hex(), (M0 + blkb).hex(), 1
        return None, None, 0
    return None, None, 0


def main():
    request = json.loads(sys.stdin.read())
    out = []
    for item in request["trials"]:
        a, b, _ = trial(item["seed"])
        out.append({"trial": item["trial"], "message_a_hex": a, "message_b_hex": b})
    sys.stdout.write(json.dumps({"schema_version": 1, "trials": out}))


if __name__ == "__main__":
    main()
