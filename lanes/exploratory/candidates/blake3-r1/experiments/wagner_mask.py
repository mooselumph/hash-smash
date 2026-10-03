"""Seeded Wagner four-sum mask-collision witness generator for blake3-r1.

For each organizer trial seed this program fixes the eight column message
words of a 64-byte blake3-r1-prefix-v1 message, splits the 256-bit digest
into two independent 128-bit halves that each decompose as an XOR of a
function of one diagonal message pair, and runs the same two-level
four-sum (Wagner) search used by the full-scale claim, constrained to the
32 masked digest bits of the declared event. It returns the found message
pair; the organizer independently recomputes both complete digests and
checks the mask event. All randomness derives from the organizer seed via
SHAKE-256; no OS randomness, wall time, or ambient state is used.
"""

import hashlib
import json
import struct
import sys

MASK32 = 0xFFFFFFFF
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

# Per-trial search parameters: sublist size S and level-1 filter bits C.
# Predicted per-trial success under the ideal model: 1 - exp(-lambda) with
# lambda = S^4 / 2^(32 + C) = 2 for S = 2048, C = 11, i.e. about 0.865.
S = 2048
C = 11


def ror(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK32


def g4(a, b, c, d, x, y):
    """One BLAKE3 G call on four 32-bit words; returns updated (a, b, c, d)."""
    a = (a + b + x) & MASK32
    d = ror(d ^ a, 16)
    c = (c + d) & MASK32
    b = ror(b ^ c, 12)
    a = (a + b + y) & MASK32
    d = ror(d ^ a, 8)
    c = (c + d) & MASK32
    b = ror(b ^ c, 7)
    return a, b, c, d


def column_state(cols):
    """Intermediate compression state after the four column G calls."""
    v = list(IV) + list(IV[:4]) + [0, 0, 64, 11]
    v[0], v[4], v[8], v[12] = g4(v[0], v[4], v[8], v[12], cols[0], cols[1])
    v[1], v[5], v[9], v[13] = g4(v[1], v[5], v[9], v[13], cols[2], cols[3])
    v[2], v[6], v[10], v[14] = g4(v[2], v[6], v[10], v[14], cols[4], cols[5])
    v[3], v[7], v[11], v[15] = g4(v[3], v[7], v[11], v[15], cols[6], cols[7])
    return v


def alpha(cs, e0, e1):
    """Diagonal G(0,5,10,15,e0,e1): words (v0, v10, v5, v15) packed for R."""
    a, b, c, d = g4(cs[0], cs[5], cs[10], cs[15], e0, e1)
    return a | (c << 32) | (b << 64) | (d << 96)


def beta(cs, g0, g1):
    """Diagonal G(2,7,8,13,g0,g1): words (v8, v2, v13, v7) packed for R."""
    a, b, c, d = g4(cs[2], cs[7], cs[8], cs[13], g0, g1)
    return c | (a << 32) | (d << 64) | (b << 96)


def gamma(cs, f0, f1):
    """Diagonal G(1,6,11,12,f0,f1): words (v1, v11, v12, v6) packed for L."""
    a, b, c, d = g4(cs[1], cs[6], cs[11], cs[12], f0, f1)
    return a | (c << 32) | (d << 64) | (b << 96)


def delta(cs, h0, h1):
    """Diagonal G(3,4,9,14,h0,h1): words (v9, v3, v4, v14) packed for L."""
    a, b, c, d = g4(cs[3], cs[4], cs[9], cs[14], h0, h1)
    return c | (a << 32) | (b << 64) | (d << 96)


def project(x):
    """Gather the 32 masked bits: low byte of each 32-bit lane of a half."""
    return ((x & 0xFF) | ((x >> 24) & 0xFF00)
            | ((x >> 48) & 0xFF0000) | ((x >> 72) & 0xFF000000))


class Stream:
    """Deterministic SHAKE-256 byte stream from the organizer trial seed."""

    def __init__(self, seed, tag):
        self.shake = hashlib.shake_256(tag + seed)
        self.buf = b""
        self.pos = 0

    def u32(self):
        if self.pos + 4 > len(self.buf):
            self.buf = self.shake.digest(1 << 16)
            self.pos = 0
        value = struct.unpack_from("<I", self.buf, self.pos)[0]
        self.pos += 4
        return value


def build_list(cs, stream, bit, fn):
    """S entries: (projected half value, message-pair words) for one sublist.

    The top bit of the first word is forced to ``bit`` so the two sublists
    of each function are disjoint by construction.
    """
    out = []
    for index in range(S):
        w0 = (stream.u32() & 0x7FFFFFFF) | (bit << 31)
        w1 = stream.u32()
        out.append((project(fn(cs, w0, w1)), w0, w1))
    return out


def wagner(list_a1, list_a2, list_b1, list_b2):
    """Two-level four-sum on 32-bit projected values; returns a solution
    (e1, e2, g1, g2) of message-word pairs or None."""
    cmask = (1 << C) - 1

    def join(xlist, ylist):
        xs = sorted(xlist, key=lambda t: t[0] & cmask)
        ys = sorted(ylist, key=lambda t: t[0] & cmask)
        out = []
        i = j = 0
        nx, ny = len(xs), len(ys)
        while i < nx and j < ny:
            xi = xs[i][0] & cmask
            yi = ys[j][0] & cmask
            if xi < yi:
                i += 1
            elif xi > yi:
                j += 1
            else:
                ii = i
                while ii < nx and (xs[ii][0] & cmask) == xi:
                    ii += 1
                jj = j
                while jj < ny and (ys[jj][0] & cmask) == yi:
                    jj += 1
                for a in range(i, ii):
                    for b in range(j, jj):
                        out.append((xs[a][0] ^ ys[b][0], xs[a], ys[b]))
                i, j = ii, jj
        return out

    sums_a = join(list_a1, list_a2)
    sums_b = join(list_b1, list_b2)
    sums_a.sort(key=lambda t: t[0])
    sums_b.sort(key=lambda t: t[0])
    i = j = 0
    na, nb = len(sums_a), len(sums_b)
    while i < na and j < nb:
        if sums_a[i][0] < sums_b[j][0]:
            i += 1
        elif sums_a[i][0] > sums_b[j][0]:
            j += 1
        else:
            return sums_a[i][1], sums_a[i][2], sums_b[j][1], sums_b[j][2]
    return None


def run_trial(seed, half):
    stream = Stream(seed, b"wagner-mask-v1:" + half.encode())
    cols = [stream.u32() for _ in range(8)]
    fixed_x = (stream.u32(), stream.u32())
    fixed_y = (stream.u32(), stream.u32())
    cs = column_state(cols)
    if half == "R":
        fn_a, fn_b = alpha, beta
    else:
        fn_a, fn_b = gamma, delta
    list_a1 = build_list(cs, stream, 0, fn_a)
    list_a2 = build_list(cs, stream, 1, fn_a)
    list_b1 = build_list(cs, stream, 0, fn_b)
    list_b2 = build_list(cs, stream, 1, fn_b)
    solution = wagner(list_a1, list_a2, list_b1, list_b2)
    if solution is None:
        return None, {"list_size": S, "filter_bits": C, "solutions": 0}
    (_, e1w0, e1w1), (_, e2w0, e2w1), (_, g1w0, g1w1), (_, g2w0, g2w1) = solution
    if half == "R":
        words_a = cols + [e1w0, e1w1, fixed_x[0], fixed_x[1],
                          g1w0, g1w1, fixed_y[0], fixed_y[1]]
        words_b = cols + [e2w0, e2w1, fixed_x[0], fixed_x[1],
                          g2w0, g2w1, fixed_y[0], fixed_y[1]]
    else:
        words_a = cols + [fixed_x[0], fixed_x[1], e1w0, e1w1,
                          fixed_y[0], fixed_y[1], g1w0, g1w1]
        words_b = cols + [fixed_x[0], fixed_x[1], e2w0, e2w1,
                          fixed_y[0], fixed_y[1], g2w0, g2w1]
    message_a = struct.pack("<16I", *words_a)
    message_b = struct.pack("<16I", *words_b)
    if message_a == message_b:
        return None, {"list_size": S, "filter_bits": C, "solutions": 0}
    return (message_a, message_b), {"list_size": S, "filter_bits": C,
                                    "solutions": 1}


def main():
    request = json.load(sys.stdin)
    half = "R" if "rhalf" in request["experiment_id"] else "L"
    trials = []
    for trial in request["trials"]:
        pair, observations = run_trial(bytes.fromhex(trial["seed"]), half)
        if pair is None:
            row = {"trial": trial["trial"], "message_a_hex": None,
                   "message_b_hex": None}
        else:
            row = {"trial": trial["trial"],
                   "message_a_hex": pair[0].hex(),
                   "message_b_hex": pair[1].hex()}
        row["observations"] = observations
        trials.append(row)
    json.dump({"schema_version": 1, "trials": trials}, sys.stdout)


if __name__ == "__main__":
    main()
