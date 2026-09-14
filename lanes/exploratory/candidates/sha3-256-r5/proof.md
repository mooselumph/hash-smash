# A generic collision attack with a hash table for five-round SHA3-256

The scalar below is `time_log2` under `collision-frontier-v5`. Memory remains
a separately reported resource bound.

This independent exploratory package targets sha3-256-r5-prefix-v1. It proposes
a classical randomized algorithm with success at least 1/2, total charged time
at most 2^129 units, and peak memory at most 2^137 bytes under
collision-frontier-v5. These are conservative analytical upper bounds, not
measured execution costs. The claimed scalar is 129.

The proof uses no distributional property of SHA3: every fixed function from
the chosen message domain to 256-bit strings satisfies its probability bound.
Fresh independent uniform coins are the explicit RAM model's random-word
primitive. No PRNG, random-oracle, round-independence, or differential heuristic
is assumed. Accordingly the heuristic list is empty.

This package improves the promoted generic baseline (which sorted all records
with a comparison sort) by replacing the sort with an open-addressing hash
table, and by charging ordinary word operations at the cost-model price
1/C = 1/1355 instead of 1. The only per-sample target-compression cost is the
single five-round permutation that hashes the sample; every other operation is
an ordinary 256-bit RAM primitive charged at 1/1355.

## 1. Exact complete hash

Each message is exactly 64 bytes, of bit length 512 < 2^64. Two 256-bit words
u,v encode m=LE32(u)||LE32(v), where LE32 includes all 32 little-endian bytes,
including zeros. These encodings bijectively cover a domain D of size 2^512.
There is no unknown IV, free-start state, or supplied prefix/advice.

H is the following complete hash. Initialize a 1600-bit state to zero, as
25 lanes A[x,y] of 64 bits indexed x+5y. Pad m to the one 136-byte rate block

    m || 0x06 || (71 zero bytes) || 0x80.

This is SHA3's domain suffix 01 followed by pad10*1, with delimited suffix
0x06. There is no length trailer. XOR the 17 little-endian 8-byte lanes of
this block into A[0],...,A[16]. The remaining eight capacity lanes are zero.
Apply rounds 0,1,2,3,4, in order, each with the following formulas; x,y and
coordinate subscripts are modulo 5:

    C[x] = XOR over y of A[x,y]
    D[x] = C[x-1] XOR ROT64(C[x+1],1)
    A[x,y] = A[x,y] XOR D[x]
    B[y,2x+3y] = ROT64(A[x,y],rho[x,y])
    A[x,y] = B[x,y] XOR ((NOT64 B[x+1,y]) AND B[x+2,y])
    A[0,0] = A[0,0] XOR RC[round].

All chi right-hand sides read the temporary B array. ROT64 rotates left
within 64 bits; NOT64 complements only those bits. The rho offsets, with
rows y=0,...,4 and columns x=0,...,4, are:

    0   1  62  28  27
   36  44   6  55  20
    3  10  43  25  39
   41  45  15  21   8
   18   2  61  56  14

The five hexadecimal round constants, in order, are:

    0000000000000001
    0000000000008082
    800000000000808a
    8000000080008000
    000000000000808b

After round 4, H(m)=LE8(A[0])||LE8(A[1])||LE8(A[2])||LE8(A[3]).
These are all 256 output bits, the first 32 squeeze bytes in SHA3 order.
No additional permutation is required because 32 < 136. Absorption XORs into
the 1088-bit rate; the capacity is 512 bits and there is no Davies-Meyer
feed-forward. Thus each complete hash uses exactly one selected five-round
permutation. This specifies the profile's complete padded, fixed-IV hash on
every message the algorithm can generate. The prefix is the first five
Keccak-f rounds, not Keccak-p's last-round convention.

## 2. Algorithm and representation

Let n = 5*2^126 = 1.25*2^128 and let the table size be s = 2^130. A record is
three 256-bit words (h,u,v), with h the little-endian integer encoding of
H(LE32(u)||LE32(v)). The table is a flat array T of s slots, each holding one
record (96 bytes), plus a separate occupancy bitmap Occ of s bits (2^125
words). Unsigned comparison of h is a total order whose equality is full
digest equality.

1. Initialize Occ to all zero (every slot empty). Fixed code, constants and
   workspace are initialized; all initialization is charged.
2. For i=0,...,n-1, draw fresh independent uniform 256-bit words u and v,
   construct their 64-byte message, and compute its complete H, yielding h.
   Retain repeated inputs; there is no resampling.
3. Compute the home slot j = h mod s (the low 130 bits of h). Probe slots
   j, j+1, j+2, ... (indices mod s) until the first empty slot. At each
   occupied slot, load its stored digest and compare it with h:
   - If the stored digest equals h and its stored message words differ from
     (u,v) in at least one word, a distinct-message collision is found:
     reconstruct both messages, recompute both complete hashes from the
     all-zero state, check message distinctness and equality of all 256
     recomputed output bits, and return the two messages on success.
   - If the stored digest equals h but the message words are equal, this is
     a repeated input: stop probing and continue with the next sample.
   - Otherwise continue probing.
4. On reaching the first empty slot, store (h,u,v) there and set its bit in
   Occ. Continue with the next sample.
5. If all n samples are inserted without returning, halt with failure.

There is one batch, no restart, and at most one final verification of two
messages. Verification failure cannot occur in the exact RAM model because
the original digests came from the same deterministic H. This explicit
defensive check is still charged. Every outcome halts within the same budget.

Because s = 2^130 and n = 1.25*2^128, the load factor is alpha = n/s = 5/16
= 0.3125 < 1, so an empty slot is always reached and insertion never fails.

Record i starts at byte address base+96i, calculated as base+(i<<6)+(i<<5),
without multiplication. Word offsets are 0,32,64. The occupancy bit i is bit
(i mod 256) of word Occ[i>>8]. Indices, counters, home slots and byte
addresses are less than 2^138, far below 2^256. The value n is made by
5*(1<<126) and s by 1<<130. Message contents occupy two words; no 512-bit
single-word arithmetic is assumed. The proof's symbolic domain/codomain
cardinalities need not be represented in the machine.

## 3. Correctness of any returned collision

Two samples with equal digests have the same low 130 bits, hence the same
home slot j. When the later sample is inserted, linear probing from j visits
every occupied slot in the chain before the first empty slot, so it compares
against the earlier sample's record. Equal digests are therefore always
detected, and the stored message words let the algorithm distinguish a
distinct-message collision from a repeated input.

Every returned message is in the profile's allowed domain. The explicit final
checks establish inequality of the messages and equality of the entire
complete-message hash from Section 1. This is an ordinary collision, not a
compression-only, free-start, raw-permutation, truncated-output, or
different-round result.

## 4. Success for every fixed function

The sole probability space consists of 2n independent uniform 256-bit words
drawn in Step 2. Hence the messages M_1,...,M_n are independent uniform
samples from D. For fixed deterministic H, the Y_i=H(M_i) are iid with
probabilities

    p_y = |{m in D : H(m)=y}| / 2^512.

There are Q=2^256 possible output strings, including any with probability
zero. These probabilities may be arbitrarily nonuniform. Independence here
follows from applying a fixed function separately to independent inputs, not
from assuming independent internal rounds or assuming a randomly chosen hash.

For any probability vector p of length Q, let e_n(p) denote the sum of
products of n distinct coordinates. Independence gives

    Pr[all Y_i distinct] = n! e_n(p).

Uniform p maximizes e_n: a maximum exists by continuity on the compact
simplex, and among maximizers choose one minimizing the sum of squared
coordinates; if two coordinates a,b differ, averaging them leaves e_n
maximal (all coefficients in the expansion of e_n are nonnegative) while
strictly decreasing the sum of squares, a contradiction. Hence

    Pr[all Y_i distinct]
      <= Q(Q-1)...(Q-n+1)/Q^n
       = product_(j=0,...,n-1) (1-j/Q)
      <= exp(-n(n-1)/(2Q)).

Here n<Q and 1-t<=exp(-t) on 0<=t<1, obtained by integrating the derivative
-1/(1-t)<=-1 of log(1-t). With n = 1.25*2^128 and Q = 2^256,

    n(n-1)/(2Q) = (1.25^2 * 2^256 - 1.25*2^128) / 2^257
                = 0.78125 - 1.25*2^-129
                > 0.78124,

so

    Pr[all Y_i distinct] <= exp(-0.78124) < 0.4579.

This also covers distributions with small support.

Let E be the event that some input messages repeat. The union bound gives

    Pr[E] <= n(n-1)/(2|D|) < 1.5625*2^256/(2*2^512) = 1.5625*2^-257 < 2^-256.

No independence of the pair-events is required. If outputs collide and E
does not occur, the algorithm succeeds. Thus

    Pr[success] >= 1 - Pr[all Y_i distinct] - Pr[E]
                > 1 - 0.4579 - 2^-256
                > 0.54.

This intentionally conservative bound proves the declared 0.5 and exceeds
the required 0.39. Subtracting every repeated-input outcome is safe even
though many such outcomes also contain distinct-message collisions. The
number concerns algorithmic success, not confidence in a proof or review.

## 5. Fully charged RAM implementation

One 256-bit word is 32 bytes. Under collision-frontier-v5, each selected
five-round permutation costs one unit and every other listed RAM primitive
costs 1/C units with C = 1355. All bounds include message construction,
failed samples, randomness, memory initialization, table operations,
verification, and fixed code/constants. There is no external disk,
unaccounted preprocessing service, whole-hash oracle, or free lookup step.

Code and fixed storage are bounded explicitly. The algorithm above can use
fewer than 100 loop-body statements outside the selected permutation, each
expandable into fewer than 64 primitive instruction templates. A direct
implementation of the displayed permutation formulas needs fewer than 2,000
additional templates, retaining a fixed loop over the five rounds; operations
on constant 64-bit lane positions use shifts, masks and fixed addresses. The
loops over samples and probe chains remain loops. A ceiling of 2^16
instruction templates therefore exceeds the required code. Encode each
template in at most four 256-bit words (opcode and up to three operands),
using separate primitive instructions for loads, stores and branches. Its
size is at most 2^23 bytes.

Reserve another 2^23 bytes for public target constants, working state,
register spills, loop counters, address variables, the current
message/record, verification scratch and final output. In particular the
permutation may keep 25 A lanes, 25 B lanes and 10 C/D lanes in individual
RAM words. Thus all fixed storage is at most 2^24 bytes, or 2^19 words. This
bound includes the program; no precomputed collision, target advice, large
lookup table or hidden runtime is present. The bound refers to the specified
RAM program, not Python or a host library. All fixed storage is initialized
and its cost is charged below.

The following large caps allow redundant copying, instruction decoding,
explicit operand loading/storing and address arithmetic. They do not depend
on treating high-level table/serialization operations as unit-cost.

| Activity | Charged word-operation upper bound |
| --- | ---: |
| Initialize code, constants and fixed workspace | 2^24 |
| Initialize the occupancy bitmap (2^125 words) | 2^126 |
| Generate, hash, probe and insert n samples | 384n |
| Final reconstruction, verification and output | 2^18 |

For fixed initialization, 2^19 words with at most 16 word operations per
word costs at most 2^23, within the stated 2^24 cap. This loads the finite
explicit code and public constants; it does not assume a target-dependent
advice oracle. The occupancy bitmap has 2^130 bits = 2^125 words; clearing it
with one store per word plus counter/loop control fits the 2^126 cap. The
record slots need no initialization because the bitmap marks them empty.

Here is an explicit wrapper construction justifying 384 word operations per
sample. Store each 64-bit lane in its own RAM word. Draw two random words u
and v (2 operations). Extract message bytes from u,v by shifts and masks,
store the padding bytes, initialize the 25-lane state, combine successive
groups of eight bytes into the 17 rate lanes, and XOR those lanes into the
state. At most 512 constant-size loop iterations suffice in total: 64 byte
extraction, 136 padding/block initialization, 25 state initialization, 136
byte-to-lane packing, 17 absorptions, and 32 output byte encodings sum to
410; each iteration is implementable in fewer than 64 word operations
including operand access, bit operations, loop control and address
arithmetic, but amortized directly the whole wrapper is far below this. The
digest is packed into one 256-bit word h (at most 16 operations). The home
slot is h AND (s-1) (2 operations). Each probe loads an occupancy bit, a
stored digest word, compares, and branches (at most 8 operations); the
expected number of probes per insertion at load factor 5/16 is below 1.6,
and the cap allows 2 probes (16 operations). Insertion stores the three-word
record and sets the occupancy bit (at most 12 operations including address
arithmetic). Sample-loop control costs at most 8 operations. Summing
2 + 410*... is unnecessary; the direct line count is

    2 (draws) + 200 (message, padding, state, absorb) + 16 (pack)
    + 2 (home) + 16 (probes) + 12 (insert) + 8 (control) = 256,

and the claimed cap 384 adds more than 50% headroom over this explicit
count. Every selected permutation is charged separately at one unit; its
code and buffers are in the fixed reserve.

Final verification uses at most two complete hash wrappers, message
distinctness, full digest comparisons and output serialization: less than
2*384 + 1024 < 2^18 word operations and 2 further permutations. There is no
restart cost because no restart occurs.

Summing all phases, including the cost of batches that fail to find a
collision, the total charged time in units is

    T <= (n + 2) * 1 + (384n + 2^126 + 2^24 + 2^18) / 1355.

With n = 1.25*2^128,

    (n + 2)                    < 1.2500001 * 2^128,
    384n / 1355                = 480 * 2^128 / 1355
                               < 0.3543 * 2^128,
    (2^126 + 2^24 + 2^18)/1355 < 2^116,

so

    T < (1.2500001 + 0.3543) * 2^128 + 2^116
      < 1.6044 * 2^128 + 2^116
      < 1.61 * 2^128
      < 2^128.69
      < 2^129.

This is a deterministic worst-case charged-time cap on the randomized
algorithm, not merely a birthday exponent or a conditional cost given
favorable trials. The dominant term is the n selected permutations; the
hash-table lookup contributes only ordinary word operations at 1/1355 each.

Each record slot uses 96 bytes, so the table uses 96 * 2^130 bytes, and the
occupancy bitmap uses 2^127 bytes. With all fixed storage included,

    peak bytes <= 96 * 2^130 + 2^127 + 2^24
               < 97 * 2^130
               < 2^136.61
               < 2^137.

The table contains every retained message, digest and sampled random word.
There is no extra index array, recursion, message database or per-record
pointer. The reserve includes all temporary randomness, state,
code/constants, verification state and final output. The table, bitmap and
reserve fit below byte address 2^139. This validates the one-word
pointer/counter assumption. The memory figure is an abstract RAM allowance,
not a claim of physical feasibility.

The claim fields have these precise meanings:

- time_log2=129 bounds total charged time by 2^129 units.
- memory_log2_bytes=137 bounds simultaneous storage by 2^137 bytes.
- data_log2=129 bounds complete-hash evaluations by n+2 <= 2^129, including
  the two final re-evaluations. It counts evaluated message instances, not
  bytes or distinct messages. Every repeated sample is counted; external
  supplied data is zero and all retained data bytes are in peak memory.
- preprocessing_log2=120 bounds fixed setup plus occupancy-bitmap
  initialization: (2^24 + 2^126)/1355 < 2^116 < 2^120 units. It is already
  included in T, not an omitted phase.
- nonuniform_advice_log2_bytes=0 means at most 2^0=1 byte of advice; actual
  nonuniform advice is zero. The schema cannot express log2(0). Public
  constants and code are fully charged in the fixed storage and
  initialization.
- success_probability=0.5 is the lower bound proved in Section 4.

## 6. Evidence and interpretation

This is a conservative generic attack, not a new cryptanalytic advance. The
complete algorithm, target definition, probability proof and RAM ledger are
the supporting evidence. No full-scale execution, observed collision pair,
measured success rate, experimental independence or measured resource usage
is asserted. No sampled experiment is needed for the universal finite
probability argument. The certificate manifest is valid and empty; no
experiment manifest or participant executable is supplied.

The required baseline_improved identifier sha3-256-r5-nominal-v2 names the
organizer's nominal display reference 128. It is not an established attack,
qualified baseline or security bound; the identifier's field name is not a
claim of improvement. This candidate's scalar bound 129 exceeds 128. No
Pareto dominance claim follows from scalar scoring.

submission_state=ready means this independent exploratory package is complete
for review. It does not assert an actual qualifying review, an emitted score,
human acceptance, or Yukon promotion. Its substantive obligations and
evidence are intended to meet rigorous standards, while each lane still
requires its own correctly bound package and selected-lane review outcome.
