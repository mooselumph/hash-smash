# SHA-256, 31 prefix rounds: one-block birthday search with radix grouping

This **exploratory** package selects track `sha256-r31-exploratory`, target
`sha256-r31-prefix-v1`, cost model `collision-frontier-v5`, and policy
`paired-lanes-v1`. It submits a complete analytic algorithm, not an already
computed collision. Readiness requests review; it does not assert an AI outcome
or human acceptance.

The declared scalar is `time_log2 = 128.32` target-compression equivalents.
Under v5 one selected-round compression costs 1 and every other primitive
256-bit word operation costs 1/C with C = 2140 for `sha256-r31`. Memory
(`2^136` bytes) is a separately reported resource.

The argument is unconditional. It uses no ideal-hash, random-oracle,
differential, round-independence, or experimental-extrapolation premise: the
collision probability follows from a distribution-free birthday lemma that holds
for the fixed deterministic target, whatever its output distribution. The
required `baseline_improved` value `sha256-r31-nominal-v2` only identifies the
organizer's nominal display reference (128). It is not an established attack,
qualified baseline, or security bound, and this package does not claim to beat
it: 128.32 is above 128.

Relative to the previous analytic package in this directory (148 under the
retired v4 pricing, 2^129 two-block messages, 129-pass merge sort), three
changes produce the new bound. Each is justified below:

1. v5 pricing: ordinary word operations cost 1/2140, not 1 (section 5).
2. 48-byte messages: FIPS padding fits in the same 64-byte block, so one
   complete hash is **one** compression instead of two (section 1).
3. A two-pass LSD counting sort on 128-bit digest halves replaces the 129-pass
   merge sort. Its cost does not depend on the digest distribution
   (sections 2 and 5).

With q = 2^128 samples the success probability is at least 0.3934 > 0.39
(section 4).

## 1. Exact message and complete-hash definition

Write BE_k(v) for the k-byte big-endian encoding of integer v. Set q = 2^128,
N = 2^256 (digest values) and D = 2^384 (messages). A sampled message is

    m(x,y) = BE_32(x) || BE_16(y),  0 <= x < 2^256,  0 <= y < 2^128.

This bijectively identifies the D messages of exactly 48 bytes. Their bit length
384 is far below 2^64, so they are in the target's message domain.

**Padding.** FIPS 180-4 appends byte 0x80, then zero bytes up to 56 mod 64, then
BE_8 of the bit length. A 48-byte message gets 0x80 at byte 48, zero bytes 49
through 55, and BE_8(384) at bytes 56 through 63. The padded message is exactly
**one** 64-byte block. As two 256-bit big-endian words that block is

    word0 = x
    word1 = y * 2^128 + 0x80 * 2^120 + 384.

Because 2^128 divides y * 2^128 and the constant PADC = 0x80 * 2^120 + 384 is
below 2^128, word1 = (y << 128) OR PADC. If the second random word is r2 and
y = r2 >> 128, then y << 128 = r2 AND HIGH, where HIGH = (2^128 - 1) << 128. So
word1 = (r2 AND HIGH) OR PADC, two word operations. The pair (x, word1)
determines the message uniquely.

**Compression.** Initialize the eight 32-bit chaining words once, in this order:

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19

Parse the single block as 16 consecutive big-endian 32-bit words W[0..15]:
W[0..7] are the eight 32-bit words of x, W[8..11] are the four 32-bit words of
y, W[12] = 0x80000000, W[13] = W[14] = 0 and W[15] = 0x00000180 (384). All
additions below are modulo 2^32. NOT and rotations operate on 32 bits. Define

    s0(z) = ROTR32(z,7) XOR ROTR32(z,18) XOR (z >> 3)
    s1(z) = ROTR32(z,17) XOR ROTR32(z,19) XOR (z >> 10)
    S0(z) = ROTR32(z,2) XOR ROTR32(z,13) XOR ROTR32(z,22)
    S1(z) = ROTR32(z,6) XOR ROTR32(z,11) XOR ROTR32(z,25)
    Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
    Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    W[t] = W[t-16] + s0(W[t-15]) + W[t-7] + s1(W[t-2]),  t = 16,...,30.

The constants K[0],...,K[30] are, in hexadecimal and original index order,

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351

Copy the chaining words into (a,b,c,d,e,f,g,h), then execute exactly
t = 0,...,30 with simultaneous updates

    T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t]
    T2 = S0(a) + Maj(a,b,c)
    (a,b,c,d,e,f,g,h) = (T1+T2, a, b, c, d+T1, e, f, g).

After round 30, add each working word to the corresponding IV word (the
feed-forward). There is no second block. Concatenating BE_4 of the eight
resulting words in standard order gives the 32-byte output H(m). It is read as
one 256-bit big-endian integer d. Equality of d is equality of the full digest.
Nothing is truncated and no IV, padding or round range is changed.

So the complete target hash of a sampled message costs exactly **one**
selected-round compression unit, including expansion and feed-forward. Unpacking
the block into 32-bit words and packing the output state into d are charged
separately as ordinary word operations in section 5. They are charged even
though a packed-block primitive interface would make some of them unnecessary.

## 2. Concrete RAM algorithm and stopping rule

The machine is the organizer's classical probabilistic 256-bit word RAM. It has
a fixed, constant-size register file, a fixed program, and word-addressed memory.
Every RAM word holds 256 bits. The algorithm draws exactly 2q fresh words from the
model's independent uniform random-word primitive, two per message. There is no
finite seed, PRNG expansion, or precomputed advice.

A **record** is three consecutive words (d, x, w1): digest, first message word,
and the formed second block word. (x, w1) identifies the original message
uniquely. Arrays A and B each hold q records, which is 3q words each. Array CNT
holds R = 2^128 counter words. Record i of an array with base P is at word
address P + 3i. Addresses are formed by additions only, without multiplication.

**Step G (generation).** For i = 0,...,q-1: draw r1, r2; set x = r1 and
w1 = (r2 AND HIGH) OR PADC; unpack (x, w1) into W[0..15]; restore the eight IV
words into the primitive's input-state buffer; invoke the selected-round
compression once; pack the eight output words into d; store (d, x, w1) as A[i].
The whole table is generated on every execution.

**Step S (grouping by a stable two-pass LSD counting sort).** Digit 0 of a digest
is its low 128 bits, `d AND LOW` with LOW = 2^128 - 1. Digit 1 is its high 128
bits, `d >> 128`. For pass k = 0, then k = 1, with source array SRC and
destination DST (A then B, then B then A):

    S1  for c = 0..R-1:          CNT[c] = 0
    S2  for i = 0..q-1:          CNT[digit_k(SRC[i].d)] += 1
    S3  s = 0; for c = 0..R-1:   v = CNT[c]; CNT[c] = s; s = s + v
    S4  for i = 0..q-1 (in increasing order):
            g = digit_k(SRC[i].d); p = CNT[g]
            DST[p] = SRC[i]  (three words); CNT[g] = p + 1

S3 is an exclusive prefix sum, so CNT[g] becomes the number of source records
with digit < g. In S4, a record with digit g gets the next free slot of its digit
group. Records within a group keep their source order, so each pass is a
**stable** permutation of its source into its destination. Every destination slot
is written exactly once (the group sizes sum to q), so no uninitialized record is
ever read and no clearing pass over A or B is needed. S1 clears CNT explicitly
each pass, so its initial contents are never assumed.

After pass 0, records are ordered by digit 0. Pass 1 orders them by digit 1 and,
by stability, keeps the digit-0 order within equal digit 1. So the final array (A)
is sorted by (digit 1, digit 0), which is numeric order of the full 256-bit d.
Hence all records with the same digest are **contiguous**. This is the standard
correctness of LSD radix sort. It holds for every input multiset, whatever the
digest distribution.

**Step C (scan and output).** For i = 1,...,q-1 compare A[i].d with A[i-1].d. If
they are equal, compare (x, w1) of the two records. At the first adjacent pair
with equal digests and unequal messages, copy both messages to the fixed output
buffer. Then recompute both complete hashes from the fixed IV (two more
compressions), confirm full digest equality and message inequality, and return
the two 48-byte messages. Return FAIL if the scan ends without such a pair. In
the exact RAM this recomputation cannot fail. There are no restarts or
amplification.

**Scan completeness.** Take any digest group, which is a contiguous run, that
contains two distinct messages. The run's message sequence is not constant, so
some pair of adjacent entries in it differ. The scan inspects every adjacent
pair, so it returns an ordinary collision whenever the samples contain two
distinct messages with equal digests. Any returned pair is distinct and has
identical complete target hashes, because it is re-verified. Repeated copies of
one message never count as success.

## 3. Distribution-free birthday lemma

For each of the N digest values z let p_z be the fraction of the D sampled-domain
messages with H(m) = z under the fixed deterministic H. Zero entries are kept.
Independent uniform messages give independent digest samples from this same p,
because H is applied separately to independent inputs. This says nothing about
whether p is uniform or whether the reduced hash behaves like a random function.

For a probability vector p let e_q(p) be the elementary symmetric polynomial of
degree q in its coordinates. The probability that q independent samples are all
different is q! e_q(p). We show that e_q(p) is maximized at the uniform vector.

The simplex is compact and e_q is continuous. Among the maximizers choose one
minimizing sum_z p_z^2. Suppose two of its coordinates a != b, and let r be the
remaining N-2 coordinates. Splitting subsets by which of the two they contain
gives

    e_q(p) = e_q(r) + (a+b) e_(q-1)(r) + ab e_(q-2)(r)

with e_0 = 1 and e_j = 0 outside the available subset sizes. All coefficients
are nonnegative. Averaging a and b preserves a+b and raises ab by (a-b)^2/4, so
e_q does not decrease: the result is still a maximizer. But its sum of squares
is strictly smaller, which contradicts the choice. So the maximizer is uniform,
and for every p, with 2 <= q <= N,

    Pr(no repeated digest) <= q! binomial(N,q) / N^q
                            = product_(j=0)^(q-1) (1 - j/N)
                           <= exp(-q(q-1)/(2N)),

using 1 - u <= exp(-u) termwise. No independence-of-events assumption or
structural property of H is used.

## 4. Algorithmic success probability

Let C be the event that some sampled digest repeats, and R the event that some
sampled message repeats. On C minus R there are two distinct messages with equal
full digests, and step C returns such a pair. Without assuming C and R are
independent,

    Pr(success) >= Pr(C) - Pr(R)
                >= 1 - exp(-q(q-1)/(2N)) - q(q-1)/(2D).

Two samples at different positions are the same message with probability
exactly 1/D. The second term is the union bound over binomial(q,2) pairs.

With q = 2^128, N = 2^256 and D = 2^384:

- q(q-1)/(2N) = 1/2 - 2^-129, and q(q-1)/(2D) < 2^-129.
- exp(1/2) > 1 + 1/2 + 1/8 + 1/48 + 1/384 = 633/384, a truncated series with
  positive terms, so exp(-1/2) < 384/633 < 0.60664.
- exp(2^-129) <= 1 + 2^-128, since exp(u) <= 1 + 2u for 0 <= u <= 1.

Hence

    exp(-q(q-1)/(2N)) = exp(-1/2) * exp(2^-129) < 0.60664 * (1 + 2^-128) < 0.60665

and

    Pr(success) > 1 - 0.60665 - 2^-129 > 0.3933 > 0.39.

The declared `success_probability: 0.39` is a lower bound on the algorithm's
success over its fresh coins, which holds for every digest distribution. It is
not a statement of confidence in this proof or in any review. All generation,
both sort passes and the scan are paid on failed runs as well. There are no
restarts to account for.

## 5. Resource accounting

The bounds below are worst-case over every random tape. Pricing follows
`collision-frontier-v5`: a selected compression is 1 unit. Every other primitive
(256-bit load or store, add/subtract, AND/OR/XOR/NOT, shift, comparison,
conditional branch, random word) costs 1/C = 1/2140.

**Instruction convention.** The program is a fixed sequence of instructions over
a constant number of registers, which hold loop pointers, end pointers, masks
and constants. Each executed instruction performs at most one primitive
operation. To avoid any dispute about instruction fetch, each executed
instruction is charged **two** ordinary operations: one for its primitive and one
for fetching the instruction word. Constants that do not fit in an instruction
immediate live in registers or fixed scratch and are loaded once at setup. The
compression invocation is charged one unit plus two call/return instructions.

### 5.1 Instructions per record, itemized

**Generation (per message):**

| Work | Instructions |
| --- | ---: |
| 2 random words; w1 = (r2 AND HIGH) OR PADC | 4 |
| Unpack 16 32-bit words (shift, mask, store each) | 48 |
| Restore 8 IV words into the input state (8 load + 8 store) | 16 |
| Call/return of the compression primitive | 2 |
| Pack digest: 8 loads, 7 shifts, 7 ORs | 22 |
| Store record: 2 address adds + 3 stores; pointer += 3 | 6 |
| Loop: increment, compare, branch | 3 |
| **Total** | **101** |

**Each sort pass**, amortized per record (R = q counters):

| Work | Per unit | Units | Instructions |
| --- | ---: | ---: | ---: |
| S1 clear: store, pointer add, compare, branch | 4 | R | 4 per record |
| S2 count: load d, pointer += 3, digit, address add, load, +1, store, compare, branch | 9 | q | 9 |
| S3 prefix: load, store, add, pointer add, compare, branch | 6 | R | 6 per record |
| S4 scatter: 3 loads + 2 address adds, pointer += 3, digit, counter address, load p, 3 adds for DST + 3p, 3 stores + 2 address adds, p + 1, store counter, compare, branch | 21 | q | 21 |
| **Pass total** | | | **40** |

**Two passes:** 80 per record. The array base swap between passes is O(1).

**Scan (per record):**

- Common path: load d, pointer += 3, compare with the previous digest, branch,
  move to the previous-digest register, loop compare, loop branch. That is 7
  instructions.
- Equal-digest path, at most once per record: 4 loads, 4 address adds,
  2 comparisons, 2 branches. That is at most 12 more.
- Per-record bound: **19**.

**Per record in total:** 101 + 80 + 19 = **200 instructions**, charged as
**400 ordinary operations**.

**Fixed costs:**

- Setup (preprocessing): load the program and constants (IV, K table if it is
  held outside the primitive, HIGH, LOW, PADC, the padding words), set registers
  and array bases, and zero fixed scratch. This takes fewer than 2^20 charged
  operations. It is `preprocessing_log2: 20` and is included in total time.
- Final verification: two compressions plus fewer than 2^10 charged operations
  (two unpack/pack wrappers, digest and message comparisons, output stores).
- Loop entries and exits for every phase: fewer than 2^10 charged operations.

### 5.2 Total time

Let W be the number of ordinary operations, charging two per instruction as
above:

    W <= 400q + 2^20 + 2^10 + 2^10 < 400q + 2^21 < 512q.

The compressions number H = q (generation) + 2 (verification). So total time is

    T = H + W / 2140 <= q + 2 + 512q/2140 < q (1 + 0.239253) + 2 < 1.2393 q.

To certify log2(1.2393) < 0.32, let u = 0.2393. Then

    ln(1 + u) <= u - u^2/2 + u^3/3 < 0.2393 - 0.02863 + 0.00457 = 0.21524.

Also 0.32 * ln 2 > 0.32 * 0.6931 = 0.22179. So 1.2393 < 2^0.32 and

    T < 2^128 * 2^0.32 = 2^128.32 target-compression units.

This proves `time_log2: 128.32`.

The 512q budget leaves 112q (about 28%) of slack above the itemized 400q. That
slack covers any operand spill or per-instruction discrepancy in the tables.
Without the fetch charge the same itemization gives W < 256q and T < 1.12q
(about 2^128.17). The package declares the more conservative 128.32.

### 5.3 Memory

| Item | Size |
| --- | --- |
| Arrays A and B | 3q words each, 6q words |
| CNT | R = q words |
| Program, constants, registers' spill area, block/state buffers and output | < 2^16 words |

Every word is 32 bytes, so

    M <= 32 * (7q + 2^16) = 224q + 2^21 < 256q = 2^136 bytes.

This proves `memory_log2_bytes: 136`. All addresses and counters are below
8q + 2^16 < 2^132, so pointer and counter arithmetic never wraps in 256-bit
words. Counter values are at most q = 2^128 < 2^256. Large arrays are never
assumed zero. Randomness is kept only in the message fields of records and in
constant-size registers. There is no stored random tape.

### 5.4 Auxiliary fields

`nonuniform_advice_log2_bytes: 0` is a one-byte upper bound; actual advice is
zero bytes. Public code, the IV and the SHA-256 constants are uniform
specification data, and their storage and loading are charged above. No
favorable seed, cached collision or target-dependent advice exists. The optional
legacy `data_log2` field is omitted. For reference, the construction hashes
q + 2 messages of 48 bytes (64 padded bytes each) and needs no external message
corpus.

## 6. Evidence, scope, and limitations

The heuristic list is empty. Sections 1-5 derive correctness, success
probability and resources from the explicit target and the organizer's model
primitives. The fresh independent random words are a primitive of the model, not
an empirical claim about a seeded program.

The certificate manifest is valid and empty. There is no experiment manifest or
executable candidate source. All analytic evidence needed for review is included
here, without dependence on external links or participant code execution.

This is a generic birthday construction on an astronomically large RAM. It is
not a measured run, a practical attack, or a new statement about SHA-256
security, and it does not use the 31-round structure. Its score is above the
nominal 128 on purpose: it is a fully accounted, distribution-free upper bound.
Better scores on this track need cryptanalytic structure, for example the
published practical 31-step collision attacks. Any such route has to account for
its own full construction cost.

Any selected-lane AI qualification of this package is distinct from mathematical
proof or human acceptance.
