"""Step-3 completions from the published matched chaining value (sha256-r31).

The published first block M0 and path-1 second-block words W0..W12 are fixed.
Each trial runs the complete Step 3 of proof.md section 5.4 with randomness
derived from its organizer seed: it scans V16 from a seed-chosen offset for an
admissible W16 (which sets W14 and W18), then draws E13 and E15. It returns
M0||M1 and M0||M1' when the two second-block compressions agree.
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
# Published pair (Li-Liu-Wang-Dong-Sun, ASIACRYPT 2024): first block and path-1 second block.
M0 = bytes.fromhex(
    "8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082"
    "dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249")
M1 = bytes.fromhex(
    "9abdeb1b1f195f415a7210c155614f13a2269dd1be888a61359257d4adf3737b"
    "9f0484a6eb830a5866add94a9669232d45271fa5b8f69585428bbce30703b904")
# Table 6 rows as (xor difference, path-1 bits equal to 1, path-1 bits equal to 0).
ROW_A = {5: (0x000017FA, 0x000013FA, 0x00000400), 6: (0x00800001, 0x00800000, 0x00000001), 7: (0x11201005, 0x01201004, 0x10000001), 8: (0x00000004, 0x00000004, 0x00000000), 10: (0x00008004, 0x00000000, 0x00008004)}
ROW_E = {3: (0x00000000, 0x00000020, 0x00000010), 4: (0x00000000, 0x00000010, 0x00088021), 5: (0x0000303E, 0x1D1FA7DD, 0xE2E05022), 6: (0x00088001, 0xAD8878E7, 0x50148418), 7: (0xD0880489, 0x4C97CAE5, 0xB328341A), 8: (0x4D008804, 0x942B8048, 0x6B802DB6), 9: (0x00000008, 0x61C101D1, 0x9E2A8C2C), 10: (0x2F8187F8, 0x702293FA, 0x0FD94C05), 11: (0x10C00008, 0x2A270418, 0x55C0C3E2), 12: (0x00008008, 0x316181E8, 0x0E000612), 13: (0x00000000, 0x00408000, 0x10800000), 14: (0x00008004, 0x00000000, 0x0000800C), 15: (0x00000000, 0x00000004, 0x00008000), 16: (0x00000000, 0x00008004, 0x00000000)}
ROW_W = {5: (0x0000F006, 0x00008000, 0x00007016), 6: (0x00208811, 0x00000010, 0x00208801), 7: (0x50105A0E, 0x0010520A, 0x50000804), 8: (0x58011100, 0x18000020, 0x40011100), 9: (0x00008004, 0x00000010, 0x00008004), 16: (0x0007FFFC, 0x0003BFFC, 0x00044000), 18: (0x00008004, 0x00028004, 0x00002000)}
# Starting point: A1..A12, E5..E12, W9..W12 (path 1 of the published second block).
SP_A = [None, 0xf36e6fcf, 0xb741c202, 0x90c67413, 0xfc7566c3, 0xfa9053fb, 0x11af5d4e,
        0x87f5120c, 0x9180b607, 0x4f5af3a8, 0x4b9e4fb8, 0x83e817e6, 0x2be31c3f]
SP_E = {5: 0x1d1fa7dd, 6: 0xafe878e7, 7: 0x4c97cbe5, 8: 0x946f8048,
        9: 0x61c171d3, 10: 0xf02293fa, 11: 0xaa270418, 12: 0xb1f7f9e8}
SP_W = {9: 0xeb830a58, 10: 0x66add94a, 11: 0x9669232d, 12: 0x45271fa5}
CLASSES = (0xd0017fe0, 0xcffe8020, 0xd0018020, 0xcffe7fe0)
NONE = (0, 0, 0)


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def s0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def s1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def bs0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def bs1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def t2(a, b, c):
    return (bs0(a) + maj(a, b, c)) & MASK


def cond(x, xp, row):
    return (x ^ xp) == row[0] and (x & row[1]) == row[1] and (x & row[2]) == 0


def admissible(w, row):
    return (w & row[1]) == row[1] and (w & row[2]) == 0


def moddiff(row):
    d = 0
    for k in range(32):
        if row[0] >> k & 1:
            d += -(1 << k) if row[1] >> k & 1 else (1 << k)
    return d & MASK


DW = {i: moddiff(ROW_W[i]) for i in ROW_W}
FLIP = {i: ROW_W[i][0] for i in (5, 6, 7, 8, 9)}


def in_v5(w, t):
    return admissible(w, ROW_W[5]) and (s0(w ^ FLIP[5]) - s0(w)) & MASK == t


def in_v6(w):
    return admissible(w, ROW_W[6]) and (s0(w ^ FLIP[6]) - s0(w)) & MASK == (-DW[5]) & MASK


def in_v7(w):
    return admissible(w, ROW_W[7]) and (s0(w ^ FLIP[7]) - s0(w)) & MASK == (-DW[6]) & MASK


def in_v8(w):
    return admissible(w, ROW_W[8]) and (s0(w ^ FLIP[8]) - s0(w)) & MASK == (-(DW[16] + DW[7])) & MASK


def v16_list():
    row = ROW_W[16]
    free = ~(row[0] | row[1] | row[2]) & MASK
    out = []
    sub = 0
    while True:
        w = row[1] | sub
        if ((w ^ row[0]) - w) & MASK == DW[16]:
            out.append(w)
        sub = (sub - free) & free
        if sub == 0:
            break
    return out


def s1_inverse_rows():
    m = []
    ident = []
    for r in range(32):
        row = 0
        for j in range(32):
            if (s1(1 << j) >> r) & 1:
                row |= 1 << j
        m.append(row)
        ident.append(1 << r)
    for c in range(32):
        p = next(r for r in range(c, 32) if (m[r] >> c) & 1)
        m[c], m[p] = m[p], m[c]
        ident[c], ident[p] = ident[p], ident[c]
        for r in range(32):
            if r != c and (m[r] >> c) & 1:
                m[r] ^= m[c]
                ident[r] ^= ident[c]
    return ident


S1INV = s1_inverse_rows()


def s1inv(y):
    x = 0
    for r in range(32):
        x |= (bin(S1INV[r] & y).count("1") & 1) << r
    return x


def step(st, t, wt):
    a, b, c, d, e, f, g, h = st
    x1 = (h + bs1(e) + ch(e, f, g) + K[t] + wt) & MASK
    return ((x1 + t2(a, b, c)) & MASK, a, b, c, (d + x1) & MASK, e, f, g)


def expand(w):
    w = list(w)
    for t in range(16, 31):
        w.append((w[t - 16] + s0(w[t - 15]) + w[t - 7] + s1(w[t - 2])) & MASK)
    return w


def compress(cv, w16):
    w = expand(w16)
    st = tuple(cv)
    for t in range(31):
        st = step(st, t, w[t])
    return tuple((x + y) & MASK for x, y in zip(cv, st))


def words(block):
    return [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]


def to_bytes(ws):
    return b"".join(x.to_bytes(4, "big") for x in ws)


def second(w):
    return [x ^ FLIP.get(i, 0) for i, x in enumerate(w)]


class Stream:
    """Deterministic 32-bit words from SHAKE-256 of a trial seed."""

    def __init__(self, seed_hex, label):
        self.seed = bytes.fromhex(seed_hex) + label.encode()
        self.counter = 0
        self.buf = b""

    def word(self):
        if len(self.buf) < 4:
            self.buf = hashlib.shake_256(self.seed + self.counter.to_bytes(8, "big")).digest(4096)
            self.counter += 1
        v = int.from_bytes(self.buf[:4], "big")
        self.buf = self.buf[4:]
        return v


def forced(rng, row):
    return (rng.word() | row[1]) & ~row[2] & MASK


def pair_entry(w7, w8, w5=0xbe888a61, w6=0x359257d4):
    """Section 5.2: derive E4, A0, E3, A-1 and check rows 3..12 on both paths."""
    a, e = SP_A, SP_E
    e4 = (e[8] - a[4] - bs1(e[7]) - ch(e[7], e[6], e[5]) - K[8] - w8) & MASK
    e3 = (e[7] - a[3] - bs1(e[6]) - ch(e[6], e[5], e4) - K[7] - w7) & MASK
    if not (cond(e3, e3, ROW_E[3]) and cond(e4, e4, ROW_E[4])):
        return None
    a0 = (e4 + t2(a[3], a[2], a[1]) - a[4]) & MASK
    am1 = (e3 + t2(a[2], a[1], a0) - a[3]) & MASK
    e2 = (e[6] - a[2] - bs1(e[5]) - ch(e[5], e4, e3) - K[6] - w6) & MASK
    e1 = (e[5] - a[1] - bs1(e4) - ch(e4, e3, e2) - K[5] - w5) & MASK
    ws = {5: w5, 6: w6, 7: w7, 8: w8, 9: SP_W[9], 10: SP_W[10], 11: SP_W[11], 12: SP_W[12]}
    s = (a[4], a[3], a[2], a[1], e4, e3, e2, e1)
    sp = s
    for t in range(5, 13):
        s = step(s, t, ws[t])
        sp = step(sp, t, ws[t] ^ FLIP.get(t, 0))
        if not (cond(s[0], sp[0], ROW_A.get(t, NONE)) and cond(s[4], sp[4], ROW_E.get(t, NONE))):
            return None
    return (w7, w8, e3, e4, a0, am1)


def derive_block(entry, w6, w5, am4, em):
    """Sections 5.2-5.3: chaining words A-1..A-3 and W0..W12 for an entry and (W6, W5).

    em = (E-1, E-2, E-3, E-4). Returns (cv, W0..W12)."""
    w7, w8, e3, e4, a0, am1 = entry
    a, e = SP_A, SP_E
    e2 = (e[6] - a[2] - bs1(e[5]) - ch(e[5], e4, e3) - K[6] - w6) & MASK
    am2 = (e2 + t2(a[1], a0, am1) - a[2]) & MASK
    e1 = (e[5] - a[1] - bs1(e4) - ch(e4, e3, e2) - K[5] - w5) & MASK
    am3 = (e1 + t2(a0, am1, am2) - a[1]) & MASK
    e0 = (a0 + am4 - t2(am1, am2, am3)) & MASK
    av = {-4: am4, -3: am3, -2: am2, -1: am1, 0: a0}
    ev = {-1: em[0], -2: em[1], -3: em[2], -4: em[3], 0: e0, 1: e1, 2: e2, 3: e3, 4: e4}
    w = []
    for i in range(5):
        w.append((ev[i] - av[i - 4] - ev[i - 4] - bs1(ev[i - 1]) - ch(ev[i - 1], ev[i - 2], ev[i - 3]) - K[i]) & MASK)
    w += [w5, w6, w7, w8, SP_W[9], SP_W[10], SP_W[11], SP_W[12]]
    cv = (am1, am2, am3, am4, em[0], em[1], em[2], em[3])
    return cv, w


V16 = v16_list()
S1V16 = [(s1(x), s1(x ^ ROW_W[16][0]), x) for x in V16]


def step3(cv, w13, t, rng, max_e13=65536, max_e15=256):
    """Section 5.4. w13 = W0..W12. Returns path-1 second block words or None."""
    c = (w13[11] + s0(w13[3]) + w13[2]) & MASK
    n1, n0, fl = ROW_W[18][1], ROW_W[18][2], ROW_W[18][0]
    start = rng.word() % len(S1V16)
    chosen = None
    for j in range(len(S1V16)):
        sa, sb, w16 = S1V16[(start + j) % len(S1V16)]
        w18 = (sa + c) & MASK
        if (w18 & n1) != n1 or (w18 & n0):
            continue
        w18p = (sb + c) & MASK
        if (w18 ^ w18p) != fl or (s1(w18p) - s1(w18) + t) & MASK:
            continue
        chosen = w16
        break
    if chosen is None:
        return None
    w14 = s1inv((chosen - w13[9] - s0(w13[1]) - w13[0]) & MASK)
    base = list(w13) + [0, w14, 0]
    basep = second(base)
    s, sp = tuple(cv), tuple(cv)
    for t_ in range(13):
        s = step(s, t_, base[t_])
        sp = step(sp, t_, basep[t_])
    b13 = step(s, 13, 0)[4]
    for _ in range(max_e13):
        e13 = forced(rng, ROW_E[13])
        x13 = (e13 - b13) & MASK
        s13, s13p = step(s, 13, x13), step(sp, 13, x13)
        if not cond(s13[4], s13p[4], ROW_E[13]) or s13[0] != s13p[0]:
            continue
        s14, s14p = step(s13, 14, w14), step(s13p, 14, w14)
        if not cond(s14[4], s14p[4], ROW_E[14]) or s14[0] != s14p[0]:
            continue
        probe, probep = step(s14, 15, 0), step(s14p, 15, 0)
        if probe[4] != probep[4] or probe[0] != probep[0]:
            continue
        for _ in range(max_e15):
            e15 = forced(rng, ROW_E[15])
            x15 = (e15 - probe[4]) & MASK
            m1 = list(w13) + [x13, w14, x15]
            if compress(cv, m1) == compress(cv, second(m1)):
                return m1
        return None
    return None


CV_PUBLISHED = compress(IV, words(M0))
W_PUBLISHED = words(M1)[:13]


def fresh_collision(seed_hex, label):
    """Step 3 from the published matched chaining value; returns a verified pair or (None, None)."""
    rng = Stream(seed_hex, label)
    m1 = step3(CV_PUBLISHED, W_PUBLISHED, CLASSES[2], rng)
    if m1 is None:
        return None, None
    return (M0 + to_bytes(m1)).hex(), (M0 + to_bytes(second(m1))).hex()


def respond(results):
    out = [{"trial": t, "message_a_hex": a, "message_b_hex": b} for t, a, b in results]
    sys.stdout.write(json.dumps({"schema_version": 1, "trials": out}))


def main():
    request = json.loads(sys.stdin.read())
    results = []
    for item in request["trials"]:
        a, b = fresh_collision(item["seed"], "fresh")
        results.append((item["trial"], a, b))
    respond(results)


if __name__ == "__main__":
    main()
