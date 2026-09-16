# SHA-256, first 32 rounds: single-block birthday table with radix grouping

This package is bound to track `sha256-r32-exploratory`, target profile
`sha256-r32-prefix-v1`, cost model `collision-frontier-v5` and review policy
`paired-lanes-v1`. It gives a classical probabilistic algorithm whose charged
time is at most `2^128.22` target compressions on **every** choice of coins,
with peak memory at most `2^136.01` bytes and algorithmic success probability
at least `0.393` for the fixed sha256-r32 hash. It is a complete analytic
candidate; no full-scale execution or concrete collision is claimed.

The required identifier `sha256-r32-nominal-v2` names the organizer display
reference only. This package does **not** claim a cryptanalytic advance or an
improvement over the nominal exponent 128; its scalar `128.22` is above 128.
It is a generic, distribution-free attack whose only purpose is to account for
the generic birthday construction more tightly than the organizer baseline
(which used two-block messages, `2^129` samples and a 129-pass merge sort).
No heuristic premise is used, so `heuristics` is empty.

Three changes relative to that baseline carry the whole improvement, and each is
proved below rather than assumed:

1. Messages are 55 bytes, so the padded message is **one** block: one
   compression per hash instead of two (Section 1).
2. `q = 2^128` samples suffice for success probability `>= 0.393 >= 0.39`,
   using a distribution-free bound; the 440-bit message space makes repeated
   inputs negligible (Section 4).
3. Equal digests are grouped by a two-pass stable counting sort (LSD radix sort
   with two 128-bit digits), whose worst-case cost is linear in q and does not
   depend on the output distribution of H (Sections 2, 3 and 5).

## 1. Exact complete-message target

`BE_k(x)` is the k-byte big-endian encoding of an integer `0 <= x < 2^(8k)`.
Each sampled message is

```
m(u, v) = BE_32(u) || BE_23(v),     0 <= u < 2^256,  0 <= v < 2^184.
```

This is exactly 55 bytes (440 bits, far below `2^64`) and the map
`(u, v) -> m(u, v)` is injective, so it identifies `D = 2^440` distinct
messages. FIPS 180-4 padding appends `0x80`, then `(55 - 55) mod 64 = 0` zero
bytes, then `BE_8(440)`. The padded message is therefore exactly one 64-byte
block. Viewed as two 256-bit big-endian halves:

```
M0 = u
M1 = v * 2^72  +  0x80 * 2^64  +  440       (440 = 0x1b8)
```

Bytes 32..54 of the block are v (bits 255..72 of M1), byte 55 is `0x80`
(bits 71..64) and bytes 56..63 are the 64-bit length 440 (bits 63..0).
This layout was checked locally against the trusted
`verifier/hash_functions.py` padding for random `(u, v)`; that check is a
consistency test of this description, not an evidentiary claim.

The complete hash is `H(u, v) = Ser(C32(IV, M0, M1))`, where IV is the standard
fixed SHA-256 initial value

```
6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
```

used once at the start of the complete message. `C32` is the selected-round
compression: parse the block into big-endian 32-bit words `W[0..15]`; for
`t = 16..31`

```
W[t] = W[t-16] + sigma0(W[t-15]) + W[t-7] + sigma1(W[t-2])      (mod 2^32)
sigma0(x) = R_7(x) xor R_18(x) xor (x >> 3)
sigma1(x) = R_17(x) xor R_19(x) xor (x >> 10)
```

(`R_n` is 32-bit right rotation). With `(a,b,c,d,e,f,g,h)` = incoming state and
for `t = 0..31` using old values on the right:

```
T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
T2 = Sigma0(a) + Maj(a,b,c)
(a,b,c,d,e,f,g,h) = (T1+T2, a, b, c, d+T1, e, f, g)
Sigma0(x) = R_2(x) xor R_13(x) xor R_22(x)
Sigma1(x) = R_6(x) xor R_11(x) xor R_25(x)
Ch(x,y,z) = (x and y) xor ((not x) and z)
Maj(x,y,z) = (x and y) xor (x and z) xor (y and z)
```

with the standard constants at their original indices 0..31:

```
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
```

Finally the feed-forward adds each working word to the incoming state word
modulo `2^32`. `Ser` concatenates the eight resulting words big-endian in
standard order: the full 256-bit digest, with no truncation. Because there is
exactly one block, this is precisely the fixed-IV, first-32-round, padded,
feed-forward complete hash of the profile. There is no chosen IV, free-start
state, compression-only relation, changed padding or round renumbering.

Throughout, the digest `d = H(u, v)` is handled as one 256-bit RAM word
(the big-endian integer value of the 32 digest bytes).

## 2. Algorithm and storage layout

Parameters: `q = 2^128` samples, `N = 2^256` digest values, `K = 2^128`
buckets per radix digit. For a digest word d write `lo(d) = d and (2^128 - 1)`
and `hi(d) = d >> 128`.

RAM regions (disjoint contiguous address intervals; all addresses `< 2^256`):

| Region | Words | Contents |
| --- | --- | --- |
| A | `3q` | records `(d, u, v)`, record i at `A + 3i` |
| B | `3q` | records `(d, u, v)`, same layout |
| CL | `K` | counters/positions for `lo` digit |
| CH | `K` | counters/positions for `hi` digit |
| fixed | `< 2^15` | code, constants (IV word, round constants, masks, padding word `P = 0x80*2^64 + 440`), registers' spill, output buffer |

`UniformWord()` is the model's independent uniform 256-bit random-word
primitive, invoked afresh; it is not a seeded PRNG.

```
# Phase S: sampling
for i = 0 .. q-1:
    u  = UniformWord()
    v  = UniformWord() and (2^184 - 1)
    d  = Ser(C32(IV, u, (v << 72) or P))
    A[i] = (d, u, v)

# Phase Z: zero both counter arrays
for j = 0 .. K-1:  CL[j] = 0;  CH[j] = 0

# Phase Hst: both histograms in one scan of A
for i = 0 .. q-1:
    d = A[i].d
    CL[lo(d)] += 1
    CH[hi(d)] += 1

# Phase Pfx: convert counts to starting record indices
sL = 0; sH = 0
for j = 0 .. K-1:
    c = CL[j]; CL[j] = sL; sL = sL + c
    c = CH[j]; CH[j] = sH; sH = sH + c

# Phase P1: stable distribution by lo digit, A -> B
for i = 0 .. q-1:
    (d, u, v) = A[i]
    k = CL[lo(d)];  CL[lo(d)] = k + 1
    B[k] = (d, u, v)

# Phase P2: stable distribution by hi digit, B -> A
for i = 0 .. q-1:
    (d, u, v) = B[i]
    k = CH[hi(d)];  CH[hi(d)] = k + 1
    A[k] = (d, u, v)

# Phase Scan
for i = 1 .. q-1:
    if A[i-1].d == A[i].d and (A[i-1].u, A[i-1].v) != (A[i].u, A[i].v):
        m0 = m(A[i-1].u, A[i-1].v);  m1 = m(A[i].u, A[i].v)
        recompute H of both, compare all 256 bits and check m0 != m1
        if both checks hold: return (m0, m1)
        return FAIL
return FAIL
```

Every loop has a fixed trip count (q, K, or at most `q - 1`), there is no
recursion, no data-dependent loop length, no restart and no amplification.
Counts and positions never exceed q, so they fit a single word, and record
addresses `A + 3k` are formed as `A + (k << 1) + k` without multiplication.

## 3. Correctness of grouping and of any returned pair

*Counting-sort pass.* After Phase Pfx, `CL[j]` equals the number of records
whose `lo` digit is smaller than j, so the buckets partition indices
`0..q-1` into consecutive intervals of the right sizes. P1 visits A in
increasing i and writes each record to the next free slot of its bucket, so
every slot of B is written exactly once, the multiset of records is preserved,
B is ordered by `lo(d)`, and records with equal `lo` keep their A order
(stability). The histogram of `hi` digits is computed from A but the multiset of
records in B is identical, so `CH` gives valid bucket starts for P2. P2 is the
same argument keyed by `hi(d)`: A ends ordered by `hi(d)`, and within equal
`hi(d)` the B order (ordered by `lo(d)`) is kept. Hence the final A is sorted by
`(hi(d), lo(d))`, i.e. by the full 256-bit digest d.

*Scan.* In a list sorted by d, records with equal d are contiguous. Suppose a
digest group contains two records whose messages differ. If every adjacent pair
in that group had equal `(u, v)`, then by transitivity all members would have
equal `(u, v)`, a contradiction. So some adjacent pair with equal d and unequal
`(u, v)` exists, and the scan returns at the first such pair in the array.
Because `m` is injective, unequal `(u, v)` means unequal message bytes. The
final recomputation of both complete hashes from the fixed IV cannot fail for a
correctly stored record, and the explicit comparisons ensure that every
returned pair satisfies the profile relation: two distinct in-domain messages
with byte-identical complete sha256-r32 digests. Conversely, whenever the
sample contains distinct messages with equal digests, the algorithm succeeds.

## 4. Success probability for this fixed hash

The only randomness is the `2q` fresh random words. Each message
`X_i = m(u_i, v_i)` is uniform on the `D = 2^440` messages (u uses a full word,
v keeps 184 independent uniform bits), and `X_1, ..., X_q` are independent.
The hash is fixed and deterministic. Let `p_y = Pr[H(X) = y]` over the uniform
message, for each of the N digest values (zero entries allowed). Then the
outputs `Y_i = H(X_i)` are iid with distribution p. **No uniformity or
pseudorandomness of H is assumed.**

*Distribution-free birthday bound.* For `2 <= q <= N`,
`Pr[Y_1..Y_q all distinct] = q! e_q(p)`, where `e_q` is the elementary
symmetric polynomial of degree q (sum over q-subsets of distinct outputs, times
the `q!` orderings). On the compact simplex, `e_q` has a maximizer; take a
maximizer with minimum `sum p_y^2`. If two coordinates `a != b`, write
`e_q(p) = A0 + (a+b) B0 + ab C0` with `A0, B0, C0 >= 0` depending only on the
other coordinates (`C0 = e_(q-2)` of the rest). Replacing both by `(a+b)/2`
keeps the sum, strictly increases `ab`, so it does not decrease `e_q`, and
strictly decreases `sum p_y^2`, contradicting the choice. Hence the uniform
vector maximizes `e_q`, and for every p:

```
Pr[all Y_i distinct] <= prod_{j=0}^{q-1} (1 - j/N) <= exp(-q(q-1)/(2N)),
```

using `1 - z <= exp(-z)` termwise (no independence of pairwise events is
used). With `q = 2^128`, `N = 2^256`: `q(q-1)/(2N) = 1/2 - 2^-129`.

*Repeated inputs.* Any fixed pair `i < j` has `X_i = X_j` with probability
exactly `1/D`, so by the union bound
`Pr[R] <= binom(q,2)/D < 2^256 / 2^441 = 2^-185`.

*Combination.* Let E be the event that two outputs agree. On `E and not R`
there are distinct messages with equal digests, so by Section 3 the algorithm
succeeds. Hence

```
Pr[success] >= 1 - exp(-1/2 + 2^-129) - 2^-185.
```

*Rational certificate.* `exp(1/2) > 1 + 1/2 + 1/8 + 1/48 + 1/384 = 633/384`,
so `exp(-1/2) < 384/633`. For `0 <= z <= 1`, `exp(z) <= 1 + 2z`, so
`exp(2^-129) <= 1 + 2^-128`. The failure probability is therefore below
`384/633 + 2^-128 + 2^-185 < 384/633 + 2^-127`, and

```
Pr[success] > 249/633 - 2^-127 > 0.393,
```

because `249/633 - 393/1000 = 231/633000 > 2^-127`. Since `0.393 >= 0.39`,
the required algorithmic success probability is met by the single run. The
declared value is a proved lower bound over the algorithm's coins for this
fixed target, not confidence in any review.

## 5. Charged time under collision-frontier-v5

Pricing: one selected C32 compression costs 1; every other primitive 256-bit
RAM operation (load, store, add/sub, AND/OR/XOR/NOT, shift/rotation,
comparison, conditional branch, random word) costs `1/C` with
`C = 2224` for sha256-r32. The compression's internals are not charged again.

*Interface wrapper, charged separately.* To be conservative the unit-cost
compression is assumed to take eight 32-bit state words and sixteen 32-bit
block words, and to return eight 32-bit words. Per hash the wrapper therefore
pays: 16 block words extracted from `M0, M1` by one shift and one mask each
(32 operations), 8 IV words extracted the same way (16; they could also be
fixed constants) and 8 output words packed into d by one shift and one OR each
(16). That is **64 operations per hash** outside the unit compression.

*Itemized loop bodies.* Counts below include every memory load/store, every
arithmetic, logical or shift operation on data or addresses, and the per-trip
loop control (increment, compare, branch). Registers hold working values; each
region base, mask and the padding word P is held in a register loaded once in
the fixed initialization. The right-hand column is the budget actually charged,
at least roughly double the itemized count to absorb any reasonable alternative
encoding (for example, charging register-to-register moves as a load plus a
store).

| Loop (trips) | Itemized primitive operations per trip | Count | Budget |
| --- | --- | ---: | ---: |
| S sampling (q) | 2 random words; AND mask for v; shift v by 72; OR with P; wrapper 64; store d; add + store for u; add + store for v; pointer add 3; counter add, compare, branch | 78 | 160 |
| Z zeroing (K) | two stores; two address increments; compare; branch | 6 | 16 |
| Hst histogram (q) | load d; AND for lo; shift for hi; per digit: add base, load, add 1, store (x2 = 8); pointer add; compare; branch | 14 | 32 |
| Pfx prefix (K) | per array: load count, store position, add running sum (x2 = 6); address increment(s) 2; compare; branch | 10 | 24 |
| P1 lo pass (q) | load d; AND; add CL base; load k; add 1; store k+1; `k<<1`, add k, add B base; store d; add + load u; add + store u; add + load v; add + store v; pointer add; compare; branch | 21 | 48 |
| P2 hi pass (q) | same with shift instead of AND and bases swapped | 21 | 48 |
| Scan (q-1) | load d; compare with previous d; branch; add + load u, add + load v; compare u, branch; compare v, branch; 3 register moves to "previous"; pointer add; compare; branch | 17 | 32 |
| Fixed initialization and final verification (once) | load IV/constants/bases/masks; 2 wrappers, message rebuild, 256-bit compare, inequality check, serialize at most 110 output bytes byte-by-byte | below 2^16 | 2^17 |

The scan's equality branch is taken at most once before returning; charging the
`u, v` loads and comparisons on every trip is an overestimate. No sort, table
lookup or allocator is uncharged: Z charges the counter initialization even
though fresh RAM might already be zero, and both P passes charge every record
move (three loads and three stores).

*Total.* With `K = q`, the budgeted non-compression operations are at most

```
(160 + 32 + 48 + 48 + 32) q + (16 + 24) K + 2^17 = 360 q + 2^17.
```

Compressions: exactly q in Phase S and at most 2 in verification. Hence, on
every coin sequence,

```
T <= q + 2 + (360 q + 2^17) / 2224
  <  q * (1 + 360/2224 + 2^-100)
  =  q * 1.16187...
  <  q * 2^0.22           (2^0.22 = 1.16473...)
  =  2^128.22.
```

The declared `time_log2 = 128.22` is therefore a worst-case bound in
target-compression units that includes preprocessing (fixed initialization),
randomness, every sample (including those in unsuccessful runs), sorting,
lookup, collision checking and final verification. There are no restarts or
omitted failed trials; the success bound of Section 4 is for this single run.

*Sensitivity.* Using only the itemized counts (171 per record-equivalent)
gives `log2 T ~ 128.11`; doubling every budget again (720 per
record-equivalent) would give `log2 T ~ 128.40`. The time is dominated by the
q compressions; any encoding within a factor of ~2 of the stated budgets stays
below `2^128.4`, and the declared bound uses the ~2x budget column.

## 6. Memory, data, preprocessing and advice

Peak storage (all regions coexist):

```
A: 3q words, B: 3q words, CL: K words, CH: K words  =>  8q words = 256 q bytes = 2^136 bytes
fixed region (code <= 1024 instructions x 4 words, constants, scratch, output): < 2^20 bytes
M <= 2^136 + 2^20 < 2^136.01 bytes.
```

This covers every stored digest, message word and random value retained in
memory; there is no separate message list, seed tape or index array.
Code is uniform (a constant number of instructions; loops are not unrolled) and
is charged in M; its initialization is inside the `2^17`-operation constant
in T.

`data_log2 = 134.01`: data is measured as bytes of padded hash input processed,
`64 (q + 2) = 2^134 + 128 < 2^134.01` bytes (original message bytes are fewer,
`55 (q + 2)`). No external, chosen-prefix or challenge data is required.

`preprocessing_log2 = 17`: fixed initialization is at most `2^17` primitive
operations, hence below `2^17` compression units; it is already included in T.
There is no offline search or table build before the run.

`nonuniform_advice_log2_bytes = 0`: no advice is used (actual size zero bytes;
the schema requires a finite non-negative value, so 0 denotes a bound of one
byte). No stored collision or precomputed target-specific data is used.

## 7. Premises, evidence and limitations

`heuristics` is empty. The argument depends only on the exact target definition,
the cost model's independent random-word primitive, the distribution-free
inequality proved in Section 4, and deterministic bookkeeping. It does not
assume ideal-hash behaviour, output balance, differential-trail independence,
round independence, seed expansion or empirical extrapolation. Independence of
the outputs `Y_i` follows from independence of the charged random words even if
H were constant or heavily biased; a biased H can only make a collision more
likely under the bound used.

The certificate manifest is valid and empty, and no experiment manifest is
declared, because no empirical premise is used. A reduced-size execution would
not strengthen a distribution-free proof and is not substituted for it.

Limitations: this is a generic attack. It does not use any structure of
32-round SHA-256, does not produce a concrete collision, and does not claim
feasibility, wall-clock time, or improvement over the nominal 128 exponent.
The improvement over the organizer's prior package comes entirely from
(i) single-block messages, (ii) the smallest sample size that meets the 0.39
requirement and (iii) linear-time radix grouping with explicit operation
accounting. The scalar remains above 128 because the q compressions alone
cost `2^128` and the required success probability forces `q >= ~2^127.99`.
Structural cryptanalysis of 32-step SHA-256 (for example extending published
31-step collision techniques) would be needed to go meaningfully below this.
