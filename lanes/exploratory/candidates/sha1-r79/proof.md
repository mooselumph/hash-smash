# A distribution-free radix-sort baseline for complete SHA-1 with 79 prefix rounds

The scalar below is `time_log2` under `collision-frontier-v5`. Memory remains
a separately reported resource bound and contributes nothing to the scalar.

This package selects `sha1-r79-prefix-v1`, ordinary collisions, 79 rounds,
and the exploratory lane under `paired-lanes-v1` and `collision-frontier-v5`.
Its claim is an upper bound for a finite randomized RAM algorithm, not a
measurement, an executed collision search, or a cryptanalytic improvement.
It improves the previously promoted package for this track (an analytic
merge-sort birthday construction scored 82.663) by replacing the 80-pass
merge sort with a two-pass radix sort and by re-pricing every word operation
at the collision-frontier-v5 rate of 1/1957 per 256-bit operation.

## 1. Parameters and claimed bounds

Let N = 2^80, D be all 32-byte strings, d = |D| = 2^256, and M = 2^160.
Let H be the exact complete-message hash specified in Section 2. Sample N
independent uniform 256-bit words and interpret each as a 32-byte message in
big-endian order, retaining leading zero bytes. This is a bijection with D.
The probability space is the product of N uniform word spaces, with H fixed.
Independent random-word access is the charged primitive supplied by the
organizer's probabilistic RAM model, not a seeded PRNG or a random oracle.

| Claim field | Upper bound and units |
| --- | --- |
| `time_log2: 80.5` | At most 2^80.1 charged operations, in the model's target-compressions unit; one selected-round target compression costs 1 and each ordinary 256-bit RAM primitive costs 1/1957. |
| `memory_log2_bytes: 88` | At most 2^88 bytes of peak memory, including both record arrays, the counter array, code, constants, messages, retained coins, and scratch. |
| `data_log2: 81` | At most N+2 <= 2^81 complete selected-target evaluations counting final verification; at most N distinct chosen messages. |
| `preprocessing_log2: 20` | At most 2^20 charged initialization operations, included in total time. |
| `success_probability: 0.39` | Probability of returning distinct complete messages with equal full digests is greater than 0.39. |
| `nonuniform_advice_log2_bytes: 0` | Actual nonuniform advice is zero bytes; the field encodes the admissible upper bound 2^0 = 1 byte, not log2(0). |

The data field counts chosen-message evaluations, not bytes or entropy bits.
There is no external dataset. Exactly N random-word draws consume 256N
random bits; the sampled input bytes counting multiplicity total 32N; the
bytes submitted to hash evaluations total at most 32(N+2). No random tape is
stored separately from the messages. The scalar is 80.5, a conservative
upper bound rather than an optimality claim. The schema-required field
`baseline_improved` contains the reference identifier `sha1-r79-nominal-v2`.
The nominal reference value is 80; this construction's scalar is 80.5 > 80,
which is worse under the lower-is-better numerical comparison. The identifier
is metadata, and the candidate makes no assertion of improvement over that
reference or of Pareto dominance. The nominal entry is not an established
attack, qualified baseline, or security bound.

## 2. Exact complete-message target

Every message has 32 bytes and bit length 256 < 2^64. Append byte 0x80,
then 23 zero bytes, then the 8-byte big-endian encoding of 256. The padded
message is exactly one 64-byte block. Initialize the chaining words once
per message to these hexadecimal values, in order:

    h0=67452301; h1=efcdab89; h2=98badcfe; h3=10325476; h4=c3d2e1f0.

All hash-state words below are 32 bits, and all hash additions are modulo
2^32. For masked x, define ROL32(x,s) =
((x << s) OR (x >> (32-s))) AND 0xffffffff. Parse consecutive big-endian
32-bit block words W[0..15]. W[0..7] are the message words, W[8]=0x80000000,
W[9..14]=0, W[15]=0x00000100. For t=16,...,78 set

    W[t] = ROL32(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16],1).

Initialize (a,b,c,d,e)=(h0,h1,h2,h3,h4). Execute indices t=0,...,78:

    t=0..19:  f=(b AND c) OR ((NOT b) AND d); K=5a827999
    t=20..39: f=b XOR c XOR d; K=6ed9eba1
    t=40..59: f=(b AND c) OR (b AND d) OR (c AND d); K=8f1bbcdc
    t=60..78: f=b XOR c XOR d; K=ca62c1d6
    z=(ROL32(a,5)+f+e+K+W[t]) mod 2^32
    (a,b,c,d,e)=(z,a,ROL32(b,30),c,d)  [simultaneous update]

NOT is restricted to 32 bits, equivalently masked before use. Feed-forward
produces (g0,g1,g2,g3,g4)=(h0+a,h1+b,h2+c,h3+d,h4+e), wordwise modulo 2^32.
H is the concatenation of the five 4-byte big-endian encodings, all 160 bits.
Represent it in a record by g0*2^128+g1*2^96+g2*2^64+g3*2^32+g4, extended
with zero high bits to one 256-bit word. This representation is injective
on full 20-byte digests, including those with leading zero bytes.

For sampled word R, the padded block in two 256-bit words is precisely
(R, (0x80 << 248) OR 256). One selected-round target compression on this
block and the fixed IV costs one model unit, including expansion, rounds,
and feed-forward. Preparing the block, calling the primitive, and packing
the result are separately charged below. The displayed internal formula
specifies that primitive exactly. All returned messages use ordinary fixed-IV,
complete-message, 79-prefix-round hashing with full output.

## 3. Bounded algorithm and storage

Reserve two disjoint arrays A and B of N records. Each aligned record is
two 256-bit words (64 bytes): the packed digest integer followed by the
entire message integer. Reserve one counter array C of 2^80 words (each
counter holds values below 2^80 < 2^256, so one 256-bit word suffices).
Record i of an array has byte address base+(i << 6); its second word is at
address+32. Counter j has byte address cbase+(j << 5). All byte addresses
and counters are below 2^88 and fit in one 256-bit word. Reservation is a
choice of disjoint RAM addresses, not a library allocation; each record word
is written before being read, and each counter word is written by the
clearing loop before being read, so no uninitialized read occurs. Both
arrays and the counter array are nevertheless fully included in peak memory.

The sort key is the 160-bit packed digest, split into a low digit
lo(X) = X mod 2^80 (bits 0..79) and a high digit hi(X) = floor(X/2^80)
(bits 80..159). The algorithm is a least-significant-digit-first radix sort
with two stable counting-sort passes, followed by a linear scan:

    N := 1 << 80
    for i := 0,...,N-1:
        R := independent_uniform_random_256_bit_word()
        X := H(the 32-byte big-endian encoding of R)
        A[i] := (X,R)

    source := A; destination := B
    for pass in (lo, hi):                       # two passes
        for j := 0,...,2^80-1: C[j] := 0
        for i := 0,...,N-1:
            k := pass(source[i].digest)         # extract 80-bit digit
            C[k] := C[k] + 1
        s := 0
        for j := 0,...,2^80-1:                  # prefix sums, in place
            t := C[j]; C[j] := s; s := s + t
        for i := 0,...,N-1:                     # stable scatter
            k := pass(source[i].digest)
            destination[C[k]] := source[i]
            C[k] := C[k] + 1
        swap(source,destination)

    for k := 1,...,N-1:
        (x,r) := source[k-1]; (y,s) := source[k]
        if x == y and r != s:
            U := 32-byte big-endian encoding of r
            V := 32-byte big-endian encoding of s
            HU := H(U); HV := H(V)
            if U != V and HU == HV: return (U,V)
            else: return failure
    return failure

N is a power of two and each digit is exactly 80 bits, so every pass uses
the full counter array. Exponential loops are not unrolled. Swapping
source/destination exchanges pointers. All N inputs are sampled before
sorting. The algorithm stops at the first nontrivial match, or returns
failure after all N-1 adjacent pairs. There is one attempt, no restart, and
no success amplification. Verification failure is a specified halt but
Section 4 proves it is unreachable under the algorithm's semantics.

## 4. Deterministic correctness

Every generated record is (H(R),R). Each counting pass first computes, for
every digit value k, the number of records with that digit, then replaces
counts by running offsets (the prefix-sum loop leaves in C[k] the number of
records with digit strictly below k), then walks the source in index order
and places each record at the next free position for its digit. That is the
standard stable counting sort: induction on i shows the i-th source record
is placed after exactly the earlier source records with equal digit, so each
pass preserves the relative order of records with equal digits (stability)
and produces an array sorted by the pass digit.

After the low pass the array is sorted by lo; after the subsequent stable
high pass it is sorted by hi, and within equal hi it remains sorted by lo.
Hence the final array is sorted by the full 160-bit digest: standard
least-significant-digit-first radix-sort correctness. Each digest's records
are contiguous. Within such a group, if two message values differ, some two
consecutive records lie at a boundary between unequal message values. The
scan reaches such a boundary and finds equal digests but unequal messages.
Repeated copies of one message cannot conceal that boundary. Conversely,
every candidate output has unequal 32-byte encodings and equal full digest
integers. H is deterministic, so recomputation accepts. Thus success occurs
exactly when two distinct sampled messages have equal complete hashes. The
algorithm returns no false collision.

## 5. Distribution-free probability proof

For each possible full digest y define p_y=|{R in D:H(R)=y}|/d. The M
nonnegative p_y sum to one; zero-probability digests are allowed. The outputs
are iid with this distribution because H is fixed and inputs are iid.
Uniform outputs are not assumed.

Let e_N(p) be the degree-N elementary symmetric polynomial on these M
coordinates. For N<=M, the probability of no repeated output is N!e_N(p):
every N-element set of outputs occurs in N! possible orders, each having
the product of its coordinate probabilities. Its maximum is attained at
p_y=1/M, as the following finite proof shows. Fixing all coordinates except
a,b writes e_N as A+(a+b)B+abC with C>=0. Averaging a,b preserves a+b and
does not decrease ab. On the compact probability simplex choose a maximizer
minimizing the sum of squared coordinates. Such extrema exist by continuity.
If two coordinates differ, averaging either increases e_N, contradicting
maximality, or preserves it while decreasing the squared sum, contradicting
the tie-break. Thus that maximizer has all coordinates equal. Consequently

    Pr[no repeated output] <= N! choose(M,N)/M^N
                           = product_{i=0}^{N-1}(1-i/M)
                           <= exp(-N(N-1)/(2M)).

The last inequality applies 1-u<=exp(-u) to each factor. That elementary
inequality follows from exp(v)>=1+v for real v. No independence of
pair-collision events is asserted.

Let E be a repeated-output event and F a repeated-input event. On E outside
F a pair of distinct inputs collides, so Section 4 gives
Pr[success]>=Pr[E]-Pr[F]. Each specified input pair is equal with probability
1/d; a union bound gives Pr[F]<=N(N-1)/(2d)<2^-97. Hence

    Pr[success] >= 1-exp(-N(N-1)/(2M))-N(N-1)/(2d).

For the exact parameters x=N(N-1)/(2M)=1/2-2^-81>499/1000. The positive
exponential series gives

    exp(x) > 1+499/1000+(499/1000)^2/2+(499/1000)^3/6
           = 9865254499/6000000000,
    exp(-x) < 6000000000/9865254499 < 609/1000.

The last strict comparison is the integer inequality
609*9865254499=6007939989891>6000000000000. Therefore
Pr[success]>391/1000-2^-97>390/1000=0.39, since 2^97>1000.
This includes repeated-input false matches, arbitrary fiber imbalance,
and every unsuccessful attempt. It is a finite statement for the exact
target, not an asymptotic or empirical extrapolation.

## 6. Time and memory ledger

All accounting is in the fixed 256-bit RAM under collision-frontier-v5: one
selected-round target compression costs 1; load/store, addition/subtraction,
bitwise operation, shift/rotation, comparison, conditional branch and fresh
uniform word each cost 1/1957. No unit-cost sort or arbitrary-precision
arithmetic is used. Moves, address arithmetic, loop control, argument
construction and scratch accesses are charged. Loops keep running pointers,
so record and counter addresses cost one addition per step after one shift
and one addition at loop entry.

Generation costs at most 16 word operations per message: one random draw,
at most 2 for the two block words and IV arguments, one compression (charged
as 1 unit, not a word operation), at most 8 for masking/packing the five
output words into one word, 2 for writing the record, and at most 3 for
counter control, call/return, and scratch moves. These allowances sum to 16.
All N trials, successful or not, count.

Each pass clears the counter array (at most 4 word operations per counter:
one store, one pointer addition, one comparison, one branch), counts records
(at most 11 per record: one load, two for digit extraction, two for counter
address, one load, one addition, one store, one pointer addition, two loop
control), prefix-sums the counters in place (at most 6 per counter: one
load, one addition, one store, three loop control), and scatters stably (at
most 16 per record: two loads, two for digit extraction, two for offset
address, one load, two for destination address, two stores, one offset
addition, one store, one pointer addition, two loop control). Per pass this
is at most 27N+10*2^80 word operations; two passes cost at most
54N+20*2^80 = 74N word operations.

A scan iteration costs at most 7 word operations: two adjacent digest loads
through a running pointer, one comparison, one branch, one pointer addition,
and two loop control. Charge 7N for the entire scan. At most one final
verification occurs; charge 2^10 word operations for its two block
preparations, two complete hashes (2 units), full comparisons, and two
32-byte output writes. Even early success was charged the whole scan.

Program storage is finite uniform code, not omitted advice. An explicit
encoding uses at most four 256-bit words per primitive instruction: opcode
plus up to three operands, including an immediate or branch destination.
Unary operations/load/store/branch fit in this format; binary operations
use result and two arguments. Lower Sections 2 and 3 with fixed registers,
scratch addresses, and counted loops. There are fewer than 256 elementary
assignment, test, loop-control, and action statements after splitting the
displayed tuple updates and compound expressions at their arithmetic
operators. Each stated record access or comparator macro takes fewer than
16 primitive instructions by the expansions above; the split hash statements
and loop scaffolding also fit that bound. Thus at most 4096 instruction
records suffice, including the looped hash specification even though its
evaluation is a selected primitive. They occupy at most
4096*4*32=2^19 bytes. There is no unrolling over N or table of answers.

Fewer than 256 data words suffice for constants, the 79 schedule words,
hash working state, record temporaries, pointers, counters, padding,
verification inputs/outputs, and flags. Reserving another 2^16 bytes for
them and instruction scratch is conservative. Code and all fixed state
therefore fit strictly within 2^20 bytes. Charge at most 2^20 operations
for writing/copying this finite code, constants and scratch and setting the
array base addresses. The program and fixed constants are specified above;
there is no target-dependent search, precomputed collision, external advice,
or hidden dataset. This initialization is the entire preprocessing phase.
The record and counter regions need no initial writes beyond the charged
clearing loop because every read follows a write, as specified in Section 3.

Total worst-case word operations, including initialization and verification,
are

    W <= 2^20 + 16N + 74N + 7N + 2^10
       = 97N + 2^20 + 2^10
       < 128N = 2^87.

Total charged time in target-compression units is therefore

    T <= (N + 2) * 1 + W/1957
       < 2^80 + 2 + 2^87/1957
       = 2^80 + 2^87/1957 + 2
       < 2^80 * (1 + 2^7/1957) + 2
       < 2^80 * 1.066
       < 2^80.1.

Both N-record arrays together occupy 128N=2^87 bytes, and the counter array
occupies 32*2^80=2^85 bytes. No recursion stack, fourth array, separate
message list, or extra random tape is used. The message fields are the
retained random choices. Including code, constants, all scratch, and the two
output messages, peak allocated memory is

    S < 2^87 + 2^85 + 2^20 < 2^88 bytes.

## 7. Evidence scope

All material claims are the specified algorithm, exact target, finite
counting argument and explicit conservative ledger. The heuristics array
is empty: no cryptanalytic, uniform-output, statistical-independence or
extrapolation premise is used beyond the organizer's defined computation
model. Replacing ideal random words with a deterministic PRNG would require
a different probability argument. Each ideal word here is charged.

The empty certificate manifest is intentional. No full-scale collision
search has been executed and no stored collision is used as advice. No
experiment manifest is declared: this analytic argument does not rely on
empirical support, and toy or seeded experiments cannot establish a
full-scale randomness premise. The enormous memory bound is not a claim
of practical feasibility.
