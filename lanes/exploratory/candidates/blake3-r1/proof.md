# A fixed-function collision construction for 1-round BLAKE3 with radix-sort accounting

The scalar below is `time_log2` under `collision-frontier-v5`. Memory remains
a separately reported resource bound.

This independent exploratory package targets blake3-r1-prefix-v1. It proposes
a classical randomized algorithm with success at least 1/2, total charged time
at most 2^129.5 units, and peak memory at most 2^136 bytes under
collision-frontier-v5. These are conservative analytical upper bounds, not
measured execution costs. The claimed scalar is 129.5.

The proof uses no distributional property of the selected hash: every fixed function from
the chosen message domain to 256-bit strings satisfies its probability bound.
Fresh independent uniform coins are the explicit RAM model's random-word
primitive. No PRNG, random-oracle, round-independence, or differential heuristic
is assumed. The sorting and lookup accounting is distribution-free: the charged
work of every phase is a deterministic worst-case bound for any input multiset.
Accordingly the heuristic list is empty.

This package adapts the organizer's merge-sort baseline package for the same
target. It keeps that package's exact target description, message domain,
probability space, and universal success argument, and changes only the
collision-detection data structure (four-pass LSD radix sort in place of a
129-pass merge sort), the sample count (5*2^126 in place of 2^129), and the
resulting resource ledger. The improvement is accounting and data-structure
discipline, not a new cryptanalytic idea.

## 1. Exact complete hash

Each message is exactly 64 bytes, of bit length 512 < 2^64. Two 256-bit words
u,v encode m=LE32(u)||LE32(v), where LE32 includes all 32 little-endian bytes,
including zeros. These encodings bijectively cover a domain D of size 2^512.
There is no unknown IV, free-start state, or supplied prefix/advice.

H is unkeyed BLAKE3-256 with 1 prefix rounds in every compression.
On these exactly 64-byte messages there is one chunk, one full block, no parent,
and exactly one compression with CHUNK_START | CHUNK_END | ROOT = 11.
There is no extra padding block, key, or derivation flag. The true block length
is 64 and both the chunk index and root-output counter are zero.

Decode m into sixteen little-endian 32-bit words w[0..15]. The eight-word IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

Initialize v[0..7]=IV, v[8..11]=IV[0..3], and
v[12..15]=(0,0,64,11). All arithmetic additions below are modulo 2^32;
ROR rotates right within a 32-bit lane. Define G(a,b,c,d,x,y) on v by

    v[a] = v[a]+v[b]+x; v[d] = ROR(v[d] XOR v[a],16)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],12)
    v[a] = v[a]+v[b]+y; v[d] = ROR(v[d] XOR v[a],8)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],7).

For each round, use the current message schedule s, initially w, and call

    G(0,4,8,12,s[0],s[1]);    G(1,5,9,13,s[2],s[3])
    G(2,6,10,14,s[4],s[5]);   G(3,7,11,15,s[6],s[7])
    G(0,5,10,15,s[8],s[9]);   G(1,6,11,12,s[10],s[11])
    G(2,7,8,13,s[12],s[13]);  G(3,4,9,14,s[14],s[15]).

Between rounds replace s by s[P[i]], where
P=(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8).
Execute exactly the first 1 rounds, with no later rounds. The full
compression output is o[i]=v[i] XOR v[i+8], and
o[i+8]=v[i+8] XOR IV[i], for i=0..7. The digest H(m) is
LE4(o[0]) || ... || LE4(o[7]), the first 32 root-output bytes.
This retains the ordinary hash's flags and feed-forward, rather than searching
for a collision of a free-start or non-root compression function.

The target profile permits other message lengths and preserves the complete
standard 1024-byte chunk tree, parent nodes, counters and root output, with the
same prefix reduction in every compression. This algorithm only generates
64-byte messages, so the one-root-compression description covers every hash
it evaluates, including final verification. No uncharged parent, chunk or
second root-output compression is needed on this domain.

## 2. Algorithm and representation

Set n=5*2^126. A record is three 256-bit words (h,u,v), with h the little-endian
integer encoding of H(LE32(u)||LE32(v)). Unsigned comparison of h is a total
order whose equality is full digest equality. Use two flat arrays A and B,
each of n records, and one shared bucket table T of 2^64 words reused by all
passes. The arrays are not pre-initialized: every read of an array cell is
dominated by a write to that same cell, as justified below. The bucket table
is initialized at the start of every pass, because its counters are read and
incremented before any record is scattered in that pass.

1. For i=0,...,n-1, draw fresh independent uniform 256-bit words u and v,
   construct their 64-byte message, compute its complete H, and store
   (h,u,v) in A[i]. Retain repeated inputs; there is no resampling.
   Generation writes all three words of every cell of A before any later
   phase reads them.
2. Sort the records by full h with a least-significant-digit radix sort
   made of four stable counting-sort passes. Pass k=0,1,2,3 sorts by digit
   d_k(h) = floor(h / 2^(64k)) mod 2^64, computed from the single 256-bit
   word h by one shift and one mask. The passes alternate source and
   destination arrays A,B,A,B,A, so the sorted records finish in A.
   Each pass has three stages:
   a. Initialize all 2^64 bucket counters in T to zero.
   b. Counting: read the source records in index order; for each record
      compute d_k(h) and increment T[d_k(h)] by one.
   c. Prefix: sweep T in index order with a running sum, replacing each
      counter by the start offset of its bucket in the destination array.
   d. Scatter: read the source records in index order a second time; for
      each record recompute d_k(h), copy all three words of the record to
      the destination cell at offset T[d_k(h)], and increment that offset.
      Because the source is read in order and each bucket's offsets are
      consumed in order, equal-digit records keep their relative order:
      the pass is stable.
3. Scan all adjacent positions j-1,j in the final sorted array, from j=1
   through n-1. Test h equality and inequality of the pair (u,v), testing
   both message words. On the first qualifying pair, reconstruct both
   messages and recompute both complete hashes from the all-zero state.
   Check message distinctness and equality of all 256 recomputed output
   bits. Return the two messages if verified; otherwise halt with failure.
4. If the scan finishes without such a pair, halt with failure.

There is one batch, no restart, and at most one final verification of two
messages. Verification failure cannot occur in the exact RAM model because
the original digests came from the same deterministic H. This explicit
defensive check is still charged. Every outcome halts within the same budget.

Record i starts at byte address base+96i, calculated as
base+(i<<6)+(i<<5), without multiplication. Word offsets are 0,32,64.
Bucket table entries are single words at byte address tbase+32j, calculated
as tbase+(j<<5). Indices, counters, running sums, bucket offsets and byte
addresses are less than 2^137, far below 2^256. The value n is made by
5<<126. Message contents occupy two words; no 512-bit single-word arithmetic
is assumed. The proof's symbolic domain/codomain cardinalities need not be
represented in the machine.

## 3. Correctness of any returned collision

Each counting pass is a textbook stable counting sort for a fixed 64-bit
digit: stage (b) counts each digit value, stage (c) converts counts to
bucket start offsets, and stage (d) places each record at the next free
offset of its bucket while reading the source in order, which is exactly
stability. The standard least-significant-digit radix invariant follows by
induction: after pass k the array is sorted by the low 64(k+1) bits of h,
because the pass sorts by digit k and stability preserves the existing
order of the low 64k bits within each new bucket. After pass 3 the records
are sorted by all 256 bits of h. Copying entire records preserves each
digest's associated message, and no record is created or deleted: every
pass writes each destination cell exactly once, so every read in every
later stage is dominated by a write, which also validates the decision to
skip array pre-initialization.

Every fixed digest occupies a contiguous interval in the sorted array. If
that interval contains distinct messages, some adjacent messages differ:
otherwise equality of every adjacent pair would make the entire interval
one repeated message by transitivity. Thus the scan finds a distinct-message
collision whenever the sample contains one, including samples with repeated
inputs. Repeated inputs alone are never accepted as collisions.

Every returned message is in the profile's allowed domain. The explicit final
checks establish inequality of the messages and equality of the entire
complete-message hash from Section 1. This is an ordinary collision, not a
compression-only, free-start, raw-permutation, truncated-output, or
different-round result.

## 4. Success for every fixed function

The sole probability space consists of 2n independent uniform 256-bit words
drawn in Step 1. Hence the messages M_1,...,M_n are independent uniform samples
from D. For fixed deterministic H, the Y_i=H(M_i) are iid with probabilities

    p_y = |{m in D : H(m)=y}| / 2^512.

There are Q=2^256 possible output strings, including any with probability zero.
These probabilities may be arbitrarily nonuniform. Independence here follows
from applying a fixed function separately to independent inputs, not from
assuming independent internal rounds or assuming a randomly chosen hash.

For any probability vector p of length Q, let e_n(p) denote the sum of products
of n distinct coordinates. Independence gives

    Pr[all Y_i distinct] = n! e_n(p).

Uniform p maximizes e_n: a maximum exists by continuity on the compact
simplex, and among maximizers choose one minimizing the sum of squared
coordinates; if coordinates a,b differ, averaging them leaves e_n maximal
(because with the other coordinates r fixed,
e_n(p) = ab e_(n-2)(r) + (a+b) e_(n-1)(r) + e_n(r) has nonnegative
coefficients) while strictly decreasing the sum of squares, a contradiction.
Therefore

    Pr[all Y_i distinct]
      <= Q(Q-1)...(Q-n+1)/Q^n
       = product_(j=0,...,n-1) (1-j/Q)
      <= exp(-n(n-1)/(2Q))
       < exp(-25/32)
       < 23/50.

Here n<Q and 1-t<=exp(-t) on 0<=t<1, obtained by integrating the derivative
-1/(1-t)<=-1 of log(1-t). The exponent is exact:
n(n-1)/(2Q) = (25*2^252 - 5*2^126)/2^257 = 25/32 - 5*2^-131. Since
exp(x) < 1+2x for 0<x<1, the correction factor satisfies
exp(5*2^-131) < 1 + 5*2^-130 < 1 + 2^-127, so
exp(-n(n-1)/(2Q)) < exp(-25/32) * (1 + 2^-127).
For the rational cap, exp(25/32) > 1 + 25/32 + (25/32)^2/2 + (25/32)^3/6
+ (25/32)^4/24 = 1 + 0.78125 + 0.305175... + 0.079472... + 0.015521...
> 2.1814 > 50/23, since 50/23 = 2.173913...; hence exp(-25/32) < 23/50 and
Pr[all Y_i distinct] < (23/50)(1 + 2^-127) < 23/50 + 2^-128.
This also covers distributions with small support.

Let E be the event that some input messages repeat. The union bound gives

    Pr[E] <= n(n-1)/(2|D|) < 25*2^252/(2*2^512) = 25*2^-261 < 2^-256.

No independence of the pair-events is required. If outputs collide and E
does not occur, the algorithm succeeds. Thus

    Pr[success] >= 1 - Pr[all Y_i distinct] - Pr[E]
                > 1 - 23/50 - 2^-128 - 2^-256
                > 1/2.

The declared success_probability is 0.5, below this proved universal lower
bound 0.54 - o(1) and above the required 0.39. Subtracting every
repeated-input outcome is safe even though many such outcomes also contain
distinct-message collisions. The number concerns algorithmic success, not
confidence in a proof or review.

## 5. Fully charged RAM implementation

One 256-bit word is 32 bytes. Each selected compression costs one unit; every
other listed RAM primitive costs 1/C units, where C=222. All bounds include
message construction, failed samples, randomness, bucket-table
initialization, sorting, scanning, verification, and fixed code/constants.
There is no external disk, unaccounted preprocessing service, whole-hash
oracle, or free sorting step.

Code and fixed storage are bounded explicitly. The algorithm above can use
fewer than 120 loop-body statements outside the selected permutation, each
expandable into fewer than 64 primitive instruction templates. A direct
implementation of the displayed compression formulas needs fewer than 2,000
additional templates, retaining a fixed loop over the selected rounds;
operations on constant 32-bit lane positions use shifts, masks and fixed
addresses. The loops over records, buckets and passes remain loops; the pass
count is the constant 4. A ceiling of 2^16 instruction templates therefore
exceeds the required code. Encode each template in at most four 256-bit words
(opcode and up to three operands), using separate primitive instructions for
loads, stores and branches. Its size is at most 2^23 bytes.

Reserve another 2^23 bytes for public target constants, working state,
register spills, loop counters, address variables, the current message/record,
the radix running sum, verification scratch and final output. In particular
the compression may keep 16 state words, 16 message words, 16 permuted
message words and 8 IV words in individual RAM words. Thus all fixed
storage is at most 2^24 bytes, or 2^19 words. This bound includes the program;
no precomputed collision, target advice, large lookup table or hidden runtime
is present. The bound refers to the specified RAM program, not Python or a
host library. All fixed storage is initialized and its cost is charged below.

The following large caps allow redundant copying, instruction decoding,
explicit operand loading/storing and address arithmetic. They do not depend
on treating high-level sort/serialization as unit-cost operations, and they
are worst-case for every input multiset: counting-sort work per record does
not depend on the data distribution, unlike hash-table probing.

| Activity | Charged word-operation upper bound |
| --- | ---: |
| Initialize code, constants and all fixed workspace | 2^24 |
| Generate, hash and retain n messages | 64n word ops + n compressions |
| Bucket table over all four passes | 2^68 |
| Four counting-sort passes | 96n |
| Scan adjacent records | 16n |
| Final reconstruction, verification and output | 2^12 word ops + 2 compressions |

For fixed initialization, 2^19 words with at most 16 units per word costs
at most 2^23, within the stated 2^24 cap. This loads the finite explicit code
and public constants; it does not assume a target-dependent advice oracle.

Here is an explicit wrapper construction justifying 64 word operations per
generated record. Draw the two fresh uniform 256-bit words u and v (2
random-word primitives). Store both words into the message buffer with two
stores and two address computations (4). The one selected root compression
per message is charged separately as one unit, including its internal loads,
the eight G calls, and writing the sixteen output words. Pack the digest:
load the eight 32-bit output lanes o[0..7], shift each into its final
position and OR it into the accumulator (8 loads, 8 shifts, 7 ORs), and
store the resulting 256-bit record key h (24 total). Store the record
(h,u,v): three stores plus the address calculation base+(i<<6)+(i<<5)
(2 shifts, 2 adds), 7 total. Sample-loop control (increment, compare,
branch) is 3. The sum is 2+4+24+7+3 = 40 < 64. No array pre-initialization
is charged or needed, because generation writes every cell of A before any
phase reads it, and each sort pass writes every destination cell before that
array becomes the next source.

For the bucket table, each of the four passes initializes all 2^64 counters
with one store each (2^64) and sweeps the prefix stage with one load, one
add and one store per bucket (3*2^64); the scatter stage reuses the same
table cells as offsets without re-initialization. Across four passes this is
4*(2^64+3*2^64) = 2^68 word operations. The table is 2^64 words = 2^69
bytes, allocated once and shared by all passes.

For each counting-sort pass, per source record: the counting stage loads h,
computes the digit with one shift and one mask, and increments the bucket
counter with a load, an address add, an increment and a store (7); the
scatter stage reloads h, recomputes the digit (2), loads the bucket offset
with its address add (2), computes the destination address from the offset
with two shifts and two adds (4), stores the three record words (3),
increments and stores the bucket offset (2), for 14; loop control is 3.
The per-record pass total is 24, so four passes cost 96n. Every boundary is
exact; there is no recursion and no per-record pointer.

The scan uses, per adjacent pair, two key loads, a comparison and branch,
and on equality two message-word loads and comparisons with a branch:
fewer than 16 word operations per pair, so the scan fits 16n. Address
calculation by stride 96 is expanded into shifts/adds as above.

Final verification uses at most two complete hash wrappers, message
distinctness, full digest comparisons and output serialization: less than
2*64+2^10 < 2^12 word operations plus the two charged compressions. There
is no restart cost because no restart occurs.

Summing all phases, including batches that fail to find a collision, the
non-compression word operations are at most

    W <= (64 + 96 + 16)n + 2^24 + 2^68 + 2^12
       = 176n + 2^24 + 2^68 + 2^12
       < 176n + 2^69,

and the selected-compression count is n+2. Charging word operations at their
v5 weight 1/C = 1/222,

    T <= (n+2) + W/222
       <= (n+2) + (176n + 2^69)/222
       <  n + 2 + 0.7928n + 2^61.21
       <  2n
       =  5 * 2^127
       <  2^129.33
       <  2^129.5.

The step 0.7928n + 2^61.21 + 2 < n uses n = 5*2^126 > 2^128, so that
0.2072n > 2^126 >> 2^62 > 2^61.21 + 2. Here 176/222 = 0.79279... < 0.7928
and 2^69/222 < 2^61.21 because 222 > 2^7.79. This is a deterministic worst-case charged-time
cap on the randomized algorithm, not merely a birthday exponent or a
conditional cost given favorable trials, and it already includes every
failed batch: the algorithm runs its fixed n samples and four full passes
even when an early collision exists. For reusable v5 accounting, the
target-compression count is n+2 < 2^129 and all non-compression primitive
operations together are < 176n + 2^69 < 2^136 by the same expanded loops and
table. Repricing these disjoint raw counts at the v5 weights gives exactly
the tight bound above, T <= (n+2) + (176n + 2^69)/222 < 2^129.33, which is
consistent with the claimed 2^129.5; the rounded category exponents 2^129
and 2^136 are ledger conveniences, not the claimed sum. The raw-count
ledger can support subsequent repricing without inventing an operation mix.

Each array uses n*3*32 = 96n bytes. With the shared bucket table and all
fixed storage included,

    peak bytes <= 192n + 2^69 + 2^24
               = 960 * 2^126 + 2^69 + 2^24
               <  2^135.91 + 2^70
               <  2^136.

The arrays contain every retained message, digest and sampled random word.
There is no extra index array, recursion, message database or per-record
pointer. The reserve includes all temporary randomness, state,
code/advice/constants, verification state and final output. All arrays and
the reserve fit below byte address 2^137. This validates the one-word
pointer/counter assumption. The memory figure is an abstract RAM allowance,
not a claim of physical feasibility.

The claim fields have these precise meanings:

- time_log2=129.5 bounds total charged time by 2^129.5 units.
- memory_log2_bytes=136 bounds simultaneous storage by 2^136 bytes.
- data_log2=129 bounds complete-hash evaluations by n+2 < 2^129, including
  the two final re-evaluations. It counts evaluated message instances, not
  bytes or distinct messages. Every repeated sample is counted; external
  supplied data is zero and all retained data bytes are in peak memory.
- preprocessing_log2=67 bounds fixed setup plus all bucket-table counter
  initialization: 2^24 + 4*2^64 < 2^67 units. It is already included in T,
  not an omitted phase. The record arrays need no initialization phase, as
  justified in Sections 2 and 3.
- nonuniform_advice_log2_bytes=0 means at most 2^0=1 byte of advice; actual
  nonuniform advice is zero. The schema cannot express log2(0). Public
  constants and code are fully charged in the fixed storage and
  initialization.
- success_probability=0.5 is the lower bound proved in Section 4.

## 6. Evidence and interpretation

This is a conservative generic construction with tightened data-structure
accounting, not a new cryptanalytic advance. The complete algorithm, target
definition, probability proof and RAM ledger are the supporting evidence. No
full-scale execution, observed collision pair, measured success rate,
experimental independence or measured resource usage is asserted. No sampled
experiment is needed for the universal finite probability argument, and the
sorting cost is worst-case rather than amortized or distributional. The
certificate manifest is valid and empty; no experiment manifest or
participant executable is supplied.

The required baseline_improved identifier blake3-r1-nominal-v2 names the
organizer's nominal display reference 128. It is not an established attack,
qualified baseline or security bound; the identifier's field name is not a
claim of improvement. This candidate's scalar bound 129.5 exceeds 128. No
Pareto dominance claim follows from scalar scoring. Relative to the
organizer's imported baseline package for this same track (scalar 149 from a
129-pass merge sort over 2^129 records), this package reduces the claimed
bound to 129.5 by cutting the sample count to 5*2^126 within the same
universal success proof and by replacing the merge sort with a four-pass
radix sort whose per-record work is constant and distribution-free.

submission_state=ready means this independent exploratory package is complete
for review. It does not assert an actual qualifying review, an emitted score,
human acceptance, or Yukon promotion. Its substantive obligations and evidence
are intended to meet rigorous standards, while each lane still requires its own
correctly bound package and selected-lane review outcome.
