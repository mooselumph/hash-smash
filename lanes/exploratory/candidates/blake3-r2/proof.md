# Distribution-free birthday search with fused radix histograms

This package claims time_log2=128.67, memory_log2_bytes=137,
preprocessing_log2=126 and success_probability=0.39 under
collision-frontier-v5 for blake3-r2-prefix-v1. These are analytical bounds
for a classical 256-bit word RAM, not full-scale measured costs. Memory is
a required reported metric and has no scalar contribution. There are no
heuristics, precomputed collisions, PRNG premise or nonuniform advice.

Attribution: submission 8fab4dd4-b700-4125-abd7-2c7f11d6d5ee supplies the
33-byte uniform domain, exact root target, finite distribution-free success
proof, two wide radix digits and record representation. Its precursor
1ae3c621-1c2d-4e57-a1f7-91252c92a967 was inspected directly for the generic
birthday proof and v5 split accounting. The first-write initialization
argument of submission 543f0ce8-3c2e-454b-8f5e-008bcbc9ea94 is retained.
The immediate wide-radix source credits submissions
6253bf01-dba8-49c2-863f-9e6bbe308992,
5e3c5e47-59b7-419f-9d99-d2f6953598ab,
4e878bdf-d639-4bf9-8829-08f78cc35bb8 and
399d50b1-d199-4132-903d-982c075e5413 for its smaller batch, radix invariant,
wide tables and primitive schedules. No independent origin is claimed for
inherited material. This variant fuses both histograms into generation,
uses two bucket tables with joint clear/prefix loops, and retains the
previous record in registers during the final scan. All actual work is charged.

## 1. Exact complete hash

Each message is exactly 33 bytes, of bit length 264 < 2^64. Draw independent
uniform 256-bit words u and r, and set v=r AND 255. Define
m=LE32(u)||LE1(v), with all 32 bytes of u and the one byte v retained.
This is uniform on a domain D of size 2^264. The 248 discarded random bits
are still drawn and their cost is charged. There is no IV freedom, advice,
fixed unknown prefix or PRNG hypothesis.

H is unkeyed BLAKE3-256 with exactly two prefix rounds in every compression.
These messages consist of one partial 33-byte block in one chunk, so each
complete hash uses exactly one root compression with flags11, true block
length33, and counter0. There is no extra padding block or parent compression.
For word loading, append exactly 31 zero bytes to m, making sixteen lanes.
The true length field remains 33; zero-fill is not a change of message length.
The first eight lanes encode u, lane8 equals v, and lanes9..15 are zero.

Decode the zero-filled block into sixteen little-endian 32-bit words w[0..15]. The eight-word IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

Initialize v[0..7]=IV, v[8..11]=IV[0..3], and
v[12..15]=(0,0,33,11). All arithmetic additions below are modulo 2^32;
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
Execute exactly the first 2 rounds, with no later rounds. The full
compression output is o[i]=v[i] XOR v[i+8], and
o[i+8]=v[i+8] XOR IV[i], for i=0..7. The digest H(m) is
LE4(o[0]) || ... || LE4(o[7]), the first 32 root-output bytes.
This retains the ordinary hash's flags and feed-forward, rather than searching
for a collision of a free-start or non-root compression function.

The target profile permits other message lengths and preserves the complete
standard 1024-byte chunk tree, parent nodes, counters and root output, with the
same prefix reduction in every compression. This algorithm only generates
33-byte messages, so the one-root-compression description covers every hash
it evaluates, including final verification. No uncharged parent, chunk or
second root-output compression is needed on this domain.

## 2. Concrete algorithm and representation

Let n=b=2^128 and mask=b-1. Use disjoint arrays A and B with n records each.
A record is three consecutive 256-bit words (h,u,v), where h is the full
digest integer, u is the message's first 32 bytes and 0<=v<256 is its last
byte. Use two disjoint b-word tables P0 and P1, and fixed scalar scratch.

1. Explicitly clear every word of both tables using one joint streaming
   loop. Set fixed registers and constants. Record arrays are reserved
   address intervals and are initialized by their first complete writes.
2. For each of n samples, draw u,r independently and uniformly, set v=r&255,
   compute the complete 33-byte target hash h, and write (h,u,v) to A.
   Set d0=h&mask and d1=h>>128. Increment P0[d0] and P1[d1]. These counters
   count every generated record, including repeated messages and digests.
3. Prefix both tables in one joint loop: maintain t0=t1=0. For d=0..b-1,
   load c0=P0[d],c1=P1[d], store t0,t1 into those slots, then set
   t0=t0+c0,t1=t1+c1. Each table now holds starting bucket offsets.
4. Stable-scatter A into B by d0=h&mask, reading A in index order. For each
   record load j=P0[d0], write j+1 back to that slot, and copy all three
   words into B[j]. P1 is not modified in this pass.
5. Stable-scatter B into A by d1=h>>128, reading B in index order. Use and
   increment P1[d1] as offsets. P0 is no longer needed. All three record
   words are written to A at each destination.
6. Load the first sorted A record into three previous-record registers.
   For each remaining A record, load its three words into current-record
   registers. Test full digest equality and distinctness of (u,v). If they
   hold, recompute the two complete hashes, verify all output bits and
   input inequality, return the messages and halt. Otherwise copy current
   to previous and continue. If no pair is found, halt with failure.

The two histogram tables are never reconstructed after sorting. A histogram
of any digit is invariant under record permutation. Therefore the generation
histogram for the high digit is exactly the histogram required by the second
pass, even though its source order has changed. Prefixing P1 early is safe:
P1 is untouched by the entire first scatter. There are exactly two scatters,
no standalone histogram scans, no restart and at most two final recompressions.
Repeated inputs are retained and charged; every failure also fits the budget.

Record i has byte address base+(i<<6)+(i<<5), with field offsets 0,32,64.
Bucket d has address base+(d<<5). Each array spans 96n bytes, each table 32n.
All pointers, counts, endpoints and prefix sums fit below 2^138, hence in
one 256-bit word. No multiplication, library sorting, free clearing or
unbounded primitive is required. Ordinary instructions act on scalar registers;
loads, stores and address calculations are explicit and charged below.

## 3. Correctness and first-write initialization

Each histogram counts every input exactly once for its digit. Prefix sums
partition [0,n) into disjoint intervals whose sizes are those counts. During
a scatter, exactly the bucket count of records is encountered for each digit;
its consecutive offsets cover precisely its assigned interval. Every record
is copied once, with associated message fields intact, and every destination
record is written exactly once. Source order is preserved inside each digit
bucket, so scattering is stable for every possible frequency distribution.

After the first scatter, B is sorted by low digit. Its high-digit multiset is
the generation multiset, so P1 still contains its correct untouched start
offsets. The second scatter sorts by high digit and preserves low-digit
order inside a high-digit bucket. Thus A is sorted by the entire 256-bit
unsigned digest. These facts do not assume uniform or independent digits.

Generation writes every word of A before sorting reads A. The first scatter
writes every word of B before the second scatter reads B. That second scatter
writes every word of A before the scan reads A. Each scatter reads only its
source and offsets, never its destination. Source and destination storage
are disjoint. Therefore no previous value of a record cell is ever consulted,
and no separate record-array zero-fill is required. No free initialized
allocation or stale-memory assumption is used. Every actual first write is
included in the generation/scatter budgets. Bucket tables, unlike record
arrays, are read-modify-written before assignment during generation, so both
are explicitly cleared. Scalar registers are assigned on their code paths.

Equal full digests are contiguous in the final array. If a digest interval
contains distinct messages, some adjacent records differ in message fields;
otherwise transitivity makes the entire interval one message. The register
scan compares exactly those adjacent pairs. It finds a distinct-message
collision whenever one is in the sample. Complete verification uses Section
1's ordinary hash with fixed IV, flags11, counter0 and true length33.
Any returned pair is an ordinary complete-message collision of the exact
selected two-round profile, not a truncated or free-start result.

## 4. Finite success probability for every fixed function

Write D=2^264 and Q=2^256 for domain and codomain sizes. The probability
space consists solely of 2n independent ideal uniform RAM random-word draws.
For fixed deterministic H the outputs are iid with probabilities
p_y=|H^{-1}(y)|/D. This independence follows from independent inputs; neither
a random hash nor independence of internal rounds is assumed.

For any probability vector p on Q points, the probability of no output
collision is n! e_n(p), where e_n is the elementary symmetric polynomial.
Uniform p maximizes e_n: a maximum exists on the compact simplex. Among
maximizers choose one minimizing the sum of squares. Averaging two unequal
coordinates a,b cannot decrease e_n, since with other coordinates r fixed,
e_n = ab e_(n-2)(r)+(a+b)e_(n-1)(r)+e_n(r), with nonnegative coefficients.
Averaging strictly reduces the sum of squares, a contradiction. Thus

    Pr[all outputs distinct] <= product_(j=0..n-1)(1-j/Q)
                            <= exp(-n(n-1)/(2Q))
                             = exp(-1/2 + 2^-129).

Let E denote any repeated input message. The union bound, without independence
of pair events, gives Pr[E] <= n(n-1)/(2D) < 2^-9 = 1/512.
Therefore the success probability is at least

    1 - exp(-1/2+2^-129) - 1/512 > 0.39.

Here is an exact rational margin check, rather than rounding 0.393 down.
We have 2^-129 < 1/1000, so 1/2-2^-129 > 499/1000.
The first five terms of exp(499/1000) are

    1 + 499/1000 + (499/1000)^2/2
      + (499/1000)^3/6 + (499/1000)^4/24
      = 39523019494001/24000000000000
      > 125/76.

(All omitted terms are positive.) Hence exp(-1/2+2^-129)<608/1000.
Hence success > 1-608/1000-1/512 = 24963/64000 > 39/100.
The exact margin is 3/64000, positive even after the full repeated-input
union bound. Every input has exactly 33 bytes and the randomness is uniform
on that byte domain. A 32-byte domain would not support this argument:
a fixed 256-bit function can be injective there. No such claim is made.
This deliberately weak margin proof is finite and strict. There is no
extrapolated empirical probability, confidence score, or heuristic assumption.

## 5. Charged RAM schedule and bounds

A selected two-round compression costs 1, and every other primitive 256-bit
RAM operation costs 1/430. The program uses scalar registers, explicitly
priced memory operations, additions, bit operations, comparisons, conditional
branches and independent uniform random words. Arithmetic instructions write
their destination directly. Extra register copies where needed are counted.
Instruction fetch is implicit in a primitive RAM instruction, not a runtime
interpreter; no high-level array/sort/serialization operation is unit cost.

Code, public constants, working state and scratch fit within 2^24 bytes.
Fewer than 2^16 instruction templates of at most four words occupy at most
2^23 bytes, and another 2^23 bytes exceeds all registers, target buffers and
verification/output scratch. Record and bucket loops remain loops, and fixed
16-lane conversions can be unrolled. Initialize this finite reserve using
at most 2^24 ordinary operations, including all base addresses, constants,
masks and public code. There is no stored collision or target-dependent advice.
Reserving array intervals assigns base addresses and touches no record cell;
its constant arithmetic is included in fixed setup. First writes and all
subsequent accesses are counted below. All code and retained data count in memory.

### Generation: 160n ordinary operations and n compressions

Keep the inherited 144-operation generation wrapper. Draw u,r (2) and mask
v (1). Extract eight 32-bit lanes of u with shifts/masks (16), store those
and lane8=v (9 stores), and rewrite zero lanes9..15 using at most 14 operations.
These input steps total 42. Initialize sixteen state/descriptor slots with
at most 48 operations, allowing constant loads, stores and copies. The
compression, including schedule and feed-forward, is one separate unit.
Read eight output lanes (8), shift each to its packed position (8), OR them
into h (8), totaling 24. Store the three record words with two field-address
additions (5); advance its streaming pointer, decrement remaining samples,
compare and branch (4); allow seven extra copies/boundaries. This is 16
for record storage/control. Total 42+48+24+16=130, below the retained 144
ceiling. The 14 spare operations accommodate any additional copies or exits.
Input zero fill is rewritten per sample; no in-place schedule assumption.

For fused histograms, h is already in a register. Compute d0 with one AND
and d1 with one shift (2 operations). For each digit, shift/add to form the
table address (2), load its count, add one in a register and store it (3).
The total extra cost is 2+2*(2+3)=12, capped at 16. No record key is reread,
and the generation loop supplies all counter/control instructions. Tables
are disjoint from all generation buffers and records. Including both extra
histograms gives the declared 144+16=160 operations per generated record.
No randomness, discarded bits or complete-hash work is omitted.

### Joint clear and prefix: 20b ordinary operations

The clear loop sets both current table words to zero (2 stores), advances
the two pointers (2 additions), decrements a shared remaining-bucket counter
(1), compares and branches (2). Total 7 per bucket, capped at 8. Set zero
and initial pointers once in fixed setup. No table is assumed pre-cleared.

For prefixing, load c0,c1 (2 loads), store current t0,t1 (2 stores), and
update t0=t0+c0,t1=t1+c1 (2 additions). Advance two pointers (2), decrement
one counter (1), compare and branch (2). Total 11 per bucket, capped at 12.
The old counts survive in c0,c1 registers through the stores. Each running
sum is initialized once, not copied per bucket. The two loops jointly cost
at most (8+12)b=20b, including both complete tables and spare instructions.

### Stable scatter: 26n per pass, two passes

Read h,u,v (3 loads) with two additional field-address additions (2).
Extract the selected digit using one AND or shift (1). Form its table
address (shift/add: 2), load j, compute j+1 in a different register and
store that new value to the slot (3). Retain j for destination addressing;
no copy is necessary. Form base+(j<<6)+(j<<5) (4), store the three fields
and form the two field offsets (5). Advance source pointer and decrement
remaining count (2), compare and branch (2). Total 24 per source record,
capped at 26, leaving two extra operations for copies/control. All table
and record addresses are computed; no pointer array is hidden. There is
no histogram loop in either pass. The original second digit counts are
preserved in their own table until the second scatter uses them.

### Register scan: 20n ordinary operations

Initial previous-record loading and loop setup are fixed overhead. Each
iteration loads the current three words (3), computing the two extra field
addresses (2). Compare h with previous h and branch (2). If equal, compare
both message words for inequality (2), combine the comparison bits with OR
(1), and branch (1). This is at most 6 for all collision tests and branches.
If not returning, copy current h,u,v to previous registers (3). Advance
the streaming pointer, decrement the remaining count, compare and branch
(4). Total 3+2+6+3+4=18 per iteration, capped at 20. There are n-1 iterations;
20n also covers the most conservative full scan. Qualifying pairs halt and
invoke final verification rather than continuing this loop. Verification
failure cannot occur in exact computation, but it would also halt.

### Fixed work, total computation and memory

A reserve of 2^16 ordinary operations for each scatter covers its base,
control and mask setup. This also covers the constant extra setup for both
table loops, histograms and scan. Reconstruction, two complete-hash wrappers,
full equality and distinctness checking and output serialization require at
most 2^18 ordinary operations plus two selected compressions. The unchanged
144-operation wrappers above are vastly smaller than that fixed allowance.
The finite code/workspace setup reserve is 2^24 ordinary operations. Therefore,
for every execution with n=b=2^128,

    H <= n+2,
    W <= (160+2*26+20)n + 20b + 2^24 + 2*2^16 + 2^18
       = 252n + 17170432,
    T = H + W/430
      <= (682/430)n + 2 + 17170432/430
       < 1.587n
       < 2^(128.67).

For exact slack, 1.587-682/430=41/43000>0, whose product with n exceeds
the fixed additive quantity 2+17170432/430. Also log2(1.587)<0.67.
Thus this is a worst-case total charged-time bound over successful and
unsuccessful executions, not an expectation or favorable-case estimate.
All failed samples, repeated inputs, both complete clears, all prefix and
scatter work, final checking and randomness are included. The leading
logarithm is 128+log2(682/430), approximately 128.6654.

Preprocessing includes fixed reserve initialization and both table clears:
(8n+2^24)/430 < 2^126. It is already part of W. Prefixing and histogram
work are computation on generated samples and are also included in T;
classifying prefixing as preprocessing as well would give
(20n+2^24)/430 < 2^126, still within the declared ceiling.

Two record arrays occupy 192n bytes. Two bucket tables occupy 64n bytes.
Adding the fixed 2^24-byte reserve gives 256n+2^24 < 512n=2^137 bytes.
This includes code, constants, all retained randomness as message fields,
registers, working state and output. No external storage, separately growing
index stack, hidden third array or advice is present. Address endpoints
are below 2^138 and fit in a single RAM word. Actual nonuniform advice is
zero; the schema field nonuniform_advice_log2_bytes=0 is a one-byte ceiling.
The memory bound is an abstract RAM allowance, not a physical allocation
requirement for the scoring or review VM.

## 6. Evidence scope and interpretation

The evidence is this finite algorithm, target definition, correctness and
first-write invariants, finite probability argument and primitive schedule.
The certificate manifest is empty and no experiment manifest is requested.
No collision pair, empirical success rate or full-scale execution is claimed.
The heuristic list is empty. Algorithmic success refers to fresh ideal
random-word coins of the specified fixed hash, not epistemic confidence.

The bound improves the 128.81 first-write variant and the 128.87 wide-radix
source through joint histogram/table loops and register scan. It is not
an estimate of BLAKE3's exact security or an assertion that no faster attack
exists. The baseline_improved identifier blake3-r2-nominal-v2 is required
reference metadata; the nominal exponent 128 is not an established attack
or qualified baseline, and 128.67 does not improve it. Memory has no scalar
contribution or tie-break. Ready means complete for review; qualification,
official score, owner review and promotion remain separate outcomes.
