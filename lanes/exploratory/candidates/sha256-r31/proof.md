# Unconditional one-block birthday collision for SHA-256-r31

This exploratory package targets `sha256-r31-prefix-v1` under cost model
`collision-frontier-v5` and review policy `paired-lanes-v1`. It describes a
complete classical RAM algorithm that finds an ordinary collision on the
complete 31-round SHA-256 hash (fixed IV, FIPS-180-4 padding, full feed-forward,
full 256-bit digest). The argument is analytic and distribution-free. No
heuristic, experiment, certificate, computed witness, or ideal-hash assumption
is used.

Declared resources (details in sections 5–6):

- `time_log2 = 128.2` target-compression equivalents
- `memory_log2_bytes = 136` (reported only; not scored)
- `success_probability = 0.39` (proved lower bound > 0.3933)
- `preprocessing_log2 = 20` (charged inside total time)
- `nonuniform_advice_log2_bytes = 0`

The required field `baseline_improved = sha256-r31-nominal-v2` identifies the
organizer's nominal display reference only. That reference is not an established
attack, qualified baseline, or security bound. **This package does not claim to
beat the nominal 128-bit security claim as a cryptanalytic result.** The scalar
128.2 sits strictly above 128 because this is a fully accounted generic birthday
search: every compression and every ordinary word operation is charged under
v5. The construction uses no property of the 31-round reduction beyond the
target's public definition.

Relative to the prior ready package on this path that declared 128.3 (450-ops
envelope over a doubled 177-primitive itemization that charged a separate
32-bit unpack/pack interface around each compression), this revision keeps the
same birthday algorithm and success argument, invokes the unit-cost compression
on a **packed two-word block** (so the 48+24 unpack/pack primitives leave the
ledger), retightens the ordinary-operation envelope to 300 ops per record against
a doubled itemization of 224, and lowers the declared scalar to 128.2 while
retaining explicit margin above the summed bound.

## 1. Exact target and one-block message layout

Write BE_k(v) for the k-byte big-endian encoding of the integer v. Fix

    q = 2^128,   N = 2^256,   C = 2140.

C is `reference_operation_costs["sha256-r31"]` from `collision-frontier-v5`: one
selected-round compression costs one time unit, and every other primitive
256-bit word operation costs 1/C units.

A sampled message is exactly 48 bytes:

    m(x, z) = BE_32(x) || BE_16(z),    0 <= x < 2^256,   0 <= z < 2^128.

Bit length L = 384 < 2^64. FIPS-180-4 padding appends 0x80, then zero bytes
until the length is 56 (mod 64), then BE_8(384). The padded message is one
512-bit block B = (B0, B1) of two 256-bit words:

    B0 = x,
    B1 = (z << 128) OR PADC,
    PADC = (0x80 << 120) + 384.

No second block is produced. The complete target hash H(m) is therefore exactly
one execution of the 31-round compression from the fixed IV, including message
schedule, rounds t = 0..30 with the standard K[0..30], and full feed-forward,
followed by big-endian serialization of the eight state words into a 256-bit
digest. Equality of digests is equality of the full 32-byte output.

Initialize the eight 32-bit chaining words once from the FIPS IV, in order:

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19

Parse B into W[0],...,W[15] as sixteen consecutive big-endian 32-bit words.
All additions below are modulo 2^32. Define

    s0(u) = ROTR32(u,7) XOR ROTR32(u,18) XOR (u >> 3)
    s1(u) = ROTR32(u,17) XOR ROTR32(u,19) XOR (u >> 10)
    S0(u) = ROTR32(u,2) XOR ROTR32(u,13) XOR ROTR32(u,22)
    S1(u) = ROTR32(u,6) XOR ROTR32(u,11) XOR ROTR32(u,25)
    Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
    Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    W[t] = W[t-16] + s0(W[t-15]) + W[t-7] + s1(W[t-2])   for t = 16..30.

Constants K[0]..K[30] are the standard SHA-256 constants at their original
indices (hexadecimal):

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351

Copy the incoming chaining words into (a,b,c,d,e,f,g,h). For t = 0..30:

    T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t]
    T2 = S0(a) + Maj(a,b,c)
    (a,b,c,d,e,f,g,h) = (T1+T2, a, b, c, d+T1, e, f, g).

Add the eight working words back to the incoming chaining words. Serialize
BE_4 of each state word in standard order to obtain the 32-byte digest,
interpreted as one 256-bit integer d.

**Packed compression interface (cost-model reading).** The v5 model is a
classical probabilistic **256-bit word RAM** in which "one selected-round target
compression ... costs one unit". The 512-bit padded block is exactly two RAM
words (B0, B1), and the 256-bit digest is exactly one RAM word. This package
invokes the unit-cost compression as a black box

    d := Compress_sha256_r31(IV, B0, B1)

that takes the fixed IV and the two block words and returns the digest word.
All internal 32-bit schedule, round, and feed-forward work specified above is
inside that unit and is paid for by the single compression charge. No separate
ordinary-operation charge is taken for unpacking B into sixteen 32-bit lanes or
for packing eight 32-bit state words into d: those steps are internal to the
unit-cost primitive, not additional RAM operations outside it. (A prior package
on this path charged 48+24 interface ops conservatively; that surcharge is
removed here under the reading above.)

## 2. Concrete RAM algorithm

Every RAM word is 256 bits. The algorithm draws randomness only through the
model's independent uniform random-word primitive. There is no finite seed,
counter-mode expansion, PRNG, or precomputed advice tape retained as memory.

A **record** is exactly three words `(digest, x, z_pad)` where `z_pad = B1` is
the already-padded second block word (so the message is recoverable as
`x = B0` and `z = z_pad >> 128`). Arrays `Src` and `Dst` each hold q contiguous
records. A counter array `Cnt` holds R = 2^128 words. All of these are
pre-allocated; nothing is read uninitialized. Code, IV words, PADC, masks, and
scratch occupy a fixed additional region of size at most 2^16 words.

### 2.1 Generation

For i = 0, ..., q-1:

1. Draw independent uniform words r1, r2.
2. Set x := r1 and z_pad := (r2 AND HIGH) OR PADC, where HIGH = 2^256 - 2^128
   (top 128 bits set). This uses the top 128 bits of r2 as z and installs the
   FIPS padding constant in the low 128 bits in two word operations.
3. Compute d := Compress_sha256_r31(IV, x, z_pad) by one unit-cost compression
   of the packed block (x, z_pad) from the fixed IV (no separate unpack/pack).
4. Store the record (d, x, z_pad) at Src[i].

The q messages are functions of 2q fresh independent uniform words. Message
contents are therefore i.i.d. uniform over a set of size 2^384 (the low 128 bits
of r2 are overwritten by PADC and do not appear in the message). No
pseudorandom generator is involved.

### 2.2 Two-pass stable LSD counting sort

Digits are the low then high 128-bit halves of the digest. Let
`digit0(d) = d mod 2^128` and `digit1(d) = d >> 128`. Each pass is a stable
counting sort on one digit, with radix R = 2^128:

**Pass p in {0,1}** (input array In, output array Out; first pass In=Src,
Out=Dst; second pass In=Dst, Out=Src):

1. **Clear.** For k = 0..R-1 set Cnt[k] := 0.
2. **Count.** For i = 0..q-1: let v := digit_p(In[i].digest); Cnt[v] := Cnt[v]+1.
3. **Exclusive prefix sum.** Set running := 0. For k = 0..R-1: let c := Cnt[k];
   Cnt[k] := running; running := running + c. After this step Cnt[k] is the
   starting write index for digit value k.
4. **Stable scatter.** For i = 0..q-1: let v := digit_p(In[i].digest);
   let j := Cnt[v]; write In[i] into Out[j]; Cnt[v] := j+1.

After both passes, Src is sorted in nondecreasing order of digest. Stability of
each pass plus LSD order implies: records with equal digests form a contiguous
segment, and within a segment the relative order from the previous pass is
preserved. Absolute message order inside a segment is irrelevant.

### 2.3 Adjacent scan, verify, halt

Scan i = 1..q-1. Whenever Src[i].digest = Src[i-1].digest and the two message
fields (x, z_pad) differ, copy both messages into a fixed output buffer.
Recompute both complete hashes from the fixed IV (two more compressions via the
same packed interface), check digest equality and message inequality, and return
the pair on success. If the scan finishes without a verified pair, return FAIL.

**Grouping lemma.** Suppose two records share a digest and have distinct
messages. After the LSD sort they lie in the same contiguous equal-digest
segment. That segment has length at least 2, so it contains at least one index
i where Src[i] and Src[i-1] have equal digests. If every adjacent equal-digest
pair inside the segment had identical messages, then by induction along the
segment every record in the segment would carry the same message, contradicting
distinctness. Hence the adjacent scan finds some unequal-message equal-digest
pair whenever any such pair exists in the table. Sorting on digest alone (no
message tie-break) is therefore sufficient.

## 3. Distribution-free birthday bound

Let f be the fixed target map from 48-byte messages to N-bit digests. The
algorithm's coins draw q i.i.d. uniform messages M_1, ..., M_q (as constructed
above). Write Y_i = f(M_i). For any fixed probability distribution p on
{0,...,N-1},

    Pr(Y_1, ..., Y_q all distinct) = q! · e_q(p),

where e_q(p) is the q-th elementary symmetric polynomial in the probabilities
(p(y))_y. The function e_q is Schur-concave on the simplex, and therefore
maximized at the uniform distribution p = (1/N, ..., 1/N). Consequently, for
**every** output distribution of the fixed f,

    Pr(all digests distinct) <= prod_{0 <= i < q} (1 - i/N)
                             <= exp( -q(q-1)/(2N) ).

No random-oracle, random-function, or pairwise-independence assumption enters.
The bound is over the algorithm's own fresh coins on the single fixed target.

## 4. Success probability

With q = 2^128 and N = 2^256,

    q(q-1)/(2N) = (2^256 - 2^128)/(2 · 2^256) = 1/2 - 2^{-129}.

Hence

    Pr(all digests distinct) <= exp(-1/2 + 2^{-129}).

A colliding digest pair with equal messages is useless. The q messages are
i.i.d. uniform in a space of size 2^384, so by a union bound

    Pr(some message repeated) <= q(q-1)/2 · 2^{-384} < 2^{-129}.

On the event that all digests are not distinct and no message is repeated, the
table contains two distinct messages with equal digests; the grouping lemma and
verification then return a valid ordinary collision. Therefore

    Pr(success) >= 1 - exp(-1/2 + 2^{-129}) - 2^{-129}.

Rational certificate: exp(1/2) > 633/384, so exp(-1/2) < 384/633 < 0.60664.
The factors exp(2^{-129}) and 2^{-129} change the value by less than 2^{-128}.
Hence Pr(success) > 0.3933 > 0.39. The declared success probability 0.39 is this
proved lower bound over algorithmic coins.

(The option of shrinking q slightly toward ≈0.9943·2^128 still clears the 0.39
floor, but would make R/q > 1 and inflate the amortized clear/prefix charges.
This package keeps q = R = 2^128 so amortization is exact and the success
certificate retains a comfortable gap above 0.39.)

## 5. Charged time accounting

Total charged time is H + W/C compression-equivalent units, where H counts
selected-round compressions and W counts ordinary 256-bit word operations,
including preprocessing. Every quantity below is a worst-case upper bound over
all random tapes.

### 5.1 Compressions

Generation performs exactly q compressions. Verification performs at most 2
more. No other compressions occur. Thus H <= q + 2.

### 5.2 Per-record ordinary operations (itemized)

Each line is a count of primitive word operations from the v5 list (load, store,
add/sub, bitwise, shift/rotate, compare, branch, random word). To absorb any
reasonable instruction-fetch objection, **every executed instruction is charged
as two ordinary operations** (the primitive itself plus one fetch). The
itemization below lists primitives; the doubled total is applied at the end of
this subsection. (Fetch is not itself a v5 primitive; doubling is a disclosed
conservative convention, as in the prior package on this path.)

**Generation (primitives per record), packed interface.**

| Step | Primitives |
| --- | ---: |
| Two random draws | 2 |
| Load HIGH and PADC | 2 |
| AND, OR to form z_pad | 2 |
| Present (x, z_pad) as packed compression inputs | 2 |
| Receive one 256-bit digest word from the compression unit | 1 |
| Store three-word record | 3 |
| Index arithmetic (3i via shift+add), loop increment, compare, branch | 8 |
| Addressing / alignment spare | 4 |
| **Generation subtotal** | **24** |

No 48-op unpack into 16×32-bit lanes and no 24-op pack of eight state words
appear: those steps are internal to the unit-cost compression (Section 1).

**One LSD counting-sort pass (primitives per record, amortized).**
Since R = q = 2^128, every pass over the counter array amortizes to a constant
per record. Nothing depends on the digest distribution.

| Step | Primitives (amortized) |
| --- | ---: |
| Clear Cnt[k] := 0 over R entries | 1 |
| Count: load digest, extract digit (shift or mask), load/inc/store counter, address, loop | 12 |
| Exclusive prefix sum over R entries (load, add, store, loop) | 5 |
| Stable scatter: load 3-word record, extract digit, load destination index, address math, store 3 words, inc counter, loop | 18 |
| **Per-pass subtotal** | **36** |

Two passes: 72 primitives per record.

**Adjacent scan (primitives per record, worst case).**

| Step | Primitives |
| --- | ---: |
| Load two digests, compare, branch | 4 |
| On equal digest: load four message words, two compares, branches | 8 |
| Loop index and address | 4 |
| **Scan subtotal (budget)** | **16** |

Verification interface work on the success path is O(1) and is absorbed into the
global setup budget below; the two verification compressions are already in H
and use the same packed interface.

**Primitive total per record:** 24 + 72 + 16 = 112.
**With instruction-fetch doubling:** 224 ordinary operations per record.

### 5.3 Global additive terms

- Counter-array and pointer setup, IV materialization, mask constants:
  at most 2^20 ordinary operations (declared `preprocessing_log2 = 20`),
  charged inside total time.
- The clear and prefix passes are already amortized into the per-record
  figures; no separate R-term remains outside that amortization.
- Worst-case scan of all q adjacent pairs is already in the per-record scan
  budget.

### 5.4 Budget and declared scalar

Charge a conservative envelope of **300 ordinary operations per record**, which
strictly covers the doubled itemization 224 and leaves about 34% headroom for
minor addressing variants a reviewer might count differently:

    W <= 300 q + 2^20.

Therefore

    T = H + W/C
      <= (q + 2) + (300 q + 2^20)/2140
      = q · (1 + 300/2140) + 2 + 2^20/2140
      < q · 1.140187 + 2^11.

For q = 2^128,

    T < 1.140187 · 2^128 + 2^11
      < 1.1402 · 2^128.

Now 2^{0.2} > 1.14869 > 1.1402, so T < 2^{128.2}.
More tightly: ln(1.1402) < 0.13114 < 0.2 · ln(2) ≈ 0.13863, confirming
T < 2^{128.2}.

The declared `time_log2 = 128.2` is therefore a valid upper bound on total
charged time. Line-by-line, the honest doubled sum is

    1 + 224/2140 ≈ 1.10467  (< 2^{0.144}),

so the pre-envelope scalar sits near 2^{128.144}. The declared 128.2 retains
roughly 0.056 bits of explicit margin above that honest sum, and about 0.011 bits
above the 300q envelope itself (envelope factor 1.140187 → ≈2^{128.189}), so a
reviewer who adds a moderate number of extra addressing ops per record cannot
refute the bound. Without the fetch-doubling convention the same itemization
yields about 2^{128.075}; fetch doubling is disclosed precisely so that
objection is pre-empted while the packed-interface reading is what removes the
old 72-op unpack/pack surcharge.

## 6. Memory and advice

Pre-allocate:

- two record arrays Src, Dst: 2 · 3 · q words
- counter array Cnt: R = q words
- code, IV, constants, scratch, output buffer: <= 2^16 words

Total words <= 7q + 2^16. At 32 bytes per word,

    bytes <= 32 · (7 · 2^128 + 2^16) < 224 · 2^128 + 2^21 < 2^{136}.

Declared `memory_log2_bytes = 136`. Memory is required and reviewed but does not
contribute to the scalar and does not break ties. Streaming random words are
consumed and not retained beyond the record fields already counted.
`nonuniform_advice_log2_bytes = 0` is a one-byte upper bound on an actually empty
advice string.

## 7. What this does and does not claim

- It is an ordinary collision search on the complete padded sha256-r31 hash with
  fixed IV and full 256-bit digests, matching `sha256-r31-prefix-v1`.
- It is unconditional: success probability is proved over algorithmic coins for
  every output distribution of the fixed target.
- It is heuristic-free: `heuristics = []`, no experiments, empty certificate
  manifest.
- It does **not** assert a mathematical break of SHA-256, an improvement over
  the nominal 128-bit reference as a cryptanalytic statement, or any use of
  31-round differential structure. A generic birthday attack at success
  probability 0.39 cannot place total charged work materially below 2^128 under
  this cost model; the 0.2-bit gap above 128 is exactly the price of sorting,
  packed-interface bookkeeping, verification, and conservative fetch accounting.
- Readiness requests AI review under the exploratory lane. An exploratory
  outcome such as `plausible_not_refuted` is not mathematical proof and not
  human acceptance.
