# Distribution-free birthday search by linked low buckets and high predecessors

This package claims time_log2=128.394, memory_log2_bytes=136,
preprocessing_log2=126 and success_probability=0.39 under
collision-frontier-v5 for blake3-r2-prefix-v1. These are analytical bounds
for a classical 256-bit word RAM, not measured full-scale execution costs.
Memory is a separately reported metric, with no scalar contribution. There
are no heuristics, precomputed collisions, PRNG premise or nonuniform advice.

Attribution: 8fab4dd4-b700-4125-abd7-2c7f11d6d5ee supplies the uniform
33-byte domain, exact selected target, finite fixed-function success proof,
wide-digit partition viewpoint and digest/message representation.
1ae3c621-1c2d-4e57-a1f7-91252c92a967 was inspected directly for the generic
birthday proof and split v5 accounting. The first-write initialization
invariant of 543f0ce8-3c2e-454b-8f5e-008bcbc9ea94 is retained for the new
four-word records. Submission 44cb9947-be0b-4d6a-8525-6e1a918efa19 supplies
the fused generation/table-update viewpoint, joint table-clear schedule and
explicit register-level accounting discipline reused here. The wide-radix
source credits 6253bf01-dba8-49c2-863f-9e6bbe308992,
5e3c5e47-59b7-419f-9d99-d2f6953598ab,
4e878bdf-d639-4bf9-8829-08f78cc35bb8 and
399d50b1-d199-4132-903d-982c075e5413 for its inherited batch/radix/schedules.
No independent origin is claimed for inherited material.

The linked low-bucket/high-predecessor detector is inherited from
submission ecfb63db-f11e-46e3-9f39-13f8700faea3. Submission 64eeb0c8-3169-481a-b305-0b4af6804f82 introduces the
first-full-digest-match halt rule, compatible with the finite repeated-input
subtraction, and its digest-only traversal. That behavior is retained here.
The inherited implementation preloads a small read-only bank of public target
constants into scalar registers once, then writes mutable state constants from
that bank on each sample. Constant input zero slots are written once, as
proved below. This revision's explicit per-phase instruction envelopes are
93 wrapper operations, eight link-insertion operations and eighteen record-
traversal operations. No compression, clear, record access or failure is
removed from accounting. There is one four-word-record array and two
explicitly cleared pointer tables, with no sort, prefix sum or scatter.

## 1. Exact complete hash

Each message is exactly 33 bytes, of bit length 264 < 2^64. Draw independent
uniform 256-bit words u and rho, and set v=rho AND 255. Define
m=LE32(u)||LE1(v), with all 32 bytes of u and the one byte v retained.
This is uniform on a domain D of size 2^264. The 248 discarded random bits
are still drawn and their cost is charged. There is no IV freedom, advice,
fixed unknown prefix or PRNG hypothesis.

H is unkeyed BLAKE3-256 with exactly two prefix rounds in every compression.
These messages consist of one partial 33-byte block in one chunk, so each
complete hash uses exactly one root compression with flags 11, true block
length 33, and counter0. There is no extra padding block or parent compression.
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

## 2. Concrete algorithm and storage

Let n=b=2^128 and mask=b-1. Use one flat array A of n records. Record i
contains four consecutive 256-bit words (h,u,v,next), where h is the full
digest integer, u is the first 32 message bytes, v is its final byte and
next is a record byte address or zero. Use two disjoint b-word tables P,L.
P[d] is the head of the low-digit bucket d. L[e] is the previously visited
record of high digit e. Both tables use zero as a null sentinel.

Reserve the first 2^24 bytes for code, public constants and fixed scratch.
Place A at byte address a=2^24, P at a+128n, and L at a+160n. Thus every
valid record pointer is nonzero. A record pointer r has field addresses
r,r+32,r+64,r+96. Table entry d is at table_base+(d<<5). All intervals are
disjoint, and all address endpoints are below 2^136. All counters and
sentinels fit easily in a 256-bit word. There is no pointer multiplication.

1. Explicitly zero all b entries of P and all b entries of L using a joint
   streaming loop. Initialize code/constants, counters and fixed scratch.
   A is initialized by complete first writes, without a separate zero-fill.
2. Generate n independent uniform 33-byte messages as in Section 1. For
   the current record pointer r, compute the full hash h, set d=h&mask,
   load old=P[d], and store (h,u,v,old) in A's current four-word record.
   Store r into P[d], then advance the record pointer by 128 bytes. This
   inserts the complete record at the front of its low-digit list. All
   repeats are retained, including repeated messages and digests. L is
   untouched by generation and remains entirely zero.
3. For d=0..b-1 in increasing order, load r=P[d]. While r!=0, load just
   the digest h and next fields at r. Set e=h>>128 and load q=L[e]. If q!=0, load
   its digest h field and compare full digests. If they agree, stop traversal
   and load the two records' message fields. If the messages are equal,
   halt with failure. Otherwise recompute both complete selected hashes,
   verify all output bits and input inequality, return the messages and
   halt. If no digest match occurred, store r into L[e], set r=next, and
   continue that list. When it ends, advance to the next low-digit bucket.
4. If traversal completes without a qualifying pair, halt with failure.

There is one batch, no restart, no sort, no prefix-sum phase and no scatter.
At most one pair receives terminal distinctness checking and final
verification, costing at most two recompressions.
Verification cannot fail in exact computation, but it would also halt. Every
failure fits the same budget. The lists need no distributional balancing:
all b buckets and all n records are visited at most once even if every
sample has the same low digit. The table L persists across bucket visits.

## 3. Correctness, traversal order and initialized reads

After generating i records, each record belongs to exactly one P bucket,
its low digest digit. Its next pointer is the previous head of that same
bucket at insertion time. It therefore points to a strictly earlier generated
record or to zero. Induction proves disjoint, acyclic lists containing all
i generated records once, with no omitted or shared node. Generation writes
all four fields before exposing r as a new bucket head. No array cell is
read before generation initializes it.

After generation, all lists and record fields are immutable. Step 3 reads
each head, follows its finite links to zero, then advances the bucket index.
Every record is visited exactly once unless a collision causes earlier halt.
The stream of visited records is nondecreasing in low digest digit because
buckets are processed in increasing order. Within one bucket the insertion
order is immaterial to this property. Neither sorted high digits nor stable
within-bucket order is required.

At each visit, L[e] is zero if no previously visited record has high digit e;
otherwise it is the byte address of the most recently visited such record.
This invariant holds initially because L is explicitly zeroed. Its update
changes just the visited record's high-digit slot. Therefore every nonzero
q is a valid, already initialized record from an earlier visit of that high
digit. It cannot point into code, a table, an uninitialized record or a
future visit, and no untrusted pointer arithmetic is involved.

Fix any high digit e. Its subsequence of the visit stream is nondecreasing
in low digit, being a subsequence of a nondecreasing stream. All records
having a particular complete digest (e,low) are therefore contiguous in
this subsequence, even if other high digits interleave in the overall stream.
If those records contain different messages, some adjacent messages in their
subsequence differ: otherwise transitivity makes the run one message. L[e]
causes Step 3 to compare exactly adjacent records of that high-digit
subsequence. If all sampled messages are distinct, any digest collision is a valid
distinct-message collision, so the first digest-match halt succeeds. When
repeated inputs occur, a repeated message can instead trigger earlier
failure, even if some other collision exists; no success is promised on
that event. Section 4 subtracts the entire repeated-input event and thus
still proves its declared bound. The detection/order reasoning makes no
random-function or digit-distribution premise.

All P and L words are explicitly assigned zero before their first reads.
Each A record's four words are written during generation and then only read.
All scalars are assigned on their code paths before use, and record/table
intervals are disjoint. The first-write invariant permits omitting only a
separate A zero-fill; all actual record writes and pointer-table clears are
charged. No free zeroed allocation, unstated initial memory value or stale
record is consulted. Code and fixed workspace initialization are also charged.

Final recomputation uses the exact fixed IV, length 33, flags 11, counter0,
root output and two prefix rounds from Section 1. Each returned pair is a
valid ordinary complete-message collision of the selected profile, rather
than a free-start, truncated-output or compression-only result.

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

## 5. Primitive implementation and charged costs

A selected two-round compression costs one unit, and every other primitive
256-bit RAM operation costs 1/430. Loads, stores, additions, shifts, logic,
comparisons, branches and independent uniform random words are charged.
The finite RAM program keeps scalar registers for streaming pointers,
current/previous records, counters and addresses. Arithmetic instructions
write their destination directly; required extra scalar copies are counted.
Instruction fetch is implicit in a RAM primitive, not a separate interpreter.
No list operation, array access, serialization or comparison subroutine is
silently assigned unit cost. Every table/record address is formed explicitly.

Code, public constants and working scratch occupy at most 2^24 bytes.
Fewer than 2^16 instruction templates of at most four words occupy 2^23
bytes, and another 2^23 bytes exceeds all registers, selected compression
buffers, verification buffers and output. Record/list/bucket loops remain
loops; fixed lane conversions may be unrolled. Fixed initialization costs
at most 2^24 ordinary operations, including constructing masks, constants,
base addresses and code. This is public setup, not target-dependent advice.
Reserving intervals assigns base addresses without reading record cells.
All actual first writes, pointer updates and later reads are counted below.

### Preloaded public constants and generation: 101n ordinary operations

Initialize a read-only scalar register bank once during fixed setup. It
contains the eight IV words, zero, true length 33, flags 11, mask32=2^32-1,
mask8=255, mask128=2^128-1 and the public IV-buffer address. Fixed input,
state, descriptor and output-slot addresses occur as immediate operands in
the finite unrolled code. Building/loading all of these constants is charged
to the 2^24 fixed initialization allowance, and the register bank is within
the fixed memory reserve. It is public code/constants, not nonuniform advice.
The direct selected compression code uses distinct mutable state/schedule
registers and never assigns to this constant bank. It is inlined, so there
is no runtime register-save convention or interpreter. Arithmetic literals
and fixed addresses are instruction operands, as in the prior RAM schedules.

Before the sample loop, initialize fixed input slots w[9..15] to zero.
These seven stores are charged to fixed initialization. The input block buffer
is read-only to compression: the selected compression uses its own mutable
state and separate schedule storage, leaving all sixteen input slots unchanged.
At each call the schedule starts from the current w and uses exactly the
permutation in Section 1. This is the same selected compression, charged one
full unit, not a discounted partial compression. Schedule copy/permutation
work remains inside that full compression unit. All sixteen state slots are
still reset on every sample. Neither state nor schedule aliases the input.

For each sample, draw u,rho (2) and mask v with mask8 (1). Extract eight
32-bit lanes of u with at most one shift and mask each (16), and store those
and lane8=v (9). This totals 28, capped at 29 with one spare copy instruction.
Only w[0..8] are rewritten per sample. At the first call, all sixteen slots
are initialized. Inductively the call cannot write w, so w[9..15] remain zero;
the next sample overwrites exactly the nine variable slots. Consequently every
call sees exactly the zero-filled encoding of the new 33-byte message. There
is no assumption of zeroed allocation or an uninitialized read. The seven
constant zero stores previously performed per sample are now done once.

Initialize each of the sixteen fixed state slots by storing its appropriate
read-only IV/zero/length/flag register: sixteen stores. Also allow four
stores to the counter/length/flags/IV-address call-description slots. All
twenty destination addresses are fixed instruction operands. The constants
are already live in read-only registers, so there is no per-sample load of
each public constant. Cap this part at 24 ordinary operations, leaving four
spare instructions for extra copies/descriptor handling. This explicit
constant-register bank replaces the previous redundant load/store allowance.
The selected compression itself is one separate unit, with its schedule and
feed-forward. Its mutable variables do not alias the read-only bank or the
saved u,v record fields. The bank remains initialized for the next sample.

Read eight output lanes (8), shift to fixed packed positions (8), OR into h
(8): 24 operations. Store h,u,v with two field-address additions (5), advance
the record pointer by 128, decrement remaining samples, compare and branch
(4), and allow seven spare copies/control instructions:16 operations. Thus
input 29 + state 24 + output 24 + record/control 16 =93, charged at 93 ordinary
wrapper operations. The seven record/control spare instructions cover h=0
and additional scalar assignments. Fixed loop setup and boundary exits are
charged separately below, without an extra twelve instructions per sample. Both fresh random draws,
discarded bits, zero-fill, state initialization and conversion are charged.

List insertion still computes d=h&mask128 (1), forms P_base+(d<<5) (2),
loads old head (1), forms r+96 and stores old there (2), then stores r into
P[d] (1). This is seven operations, capped at 8, leaving one spare copy.
The other three record writes and loop control are in the wrapper. The
fourth field is stored before exposing the new head. Generation therefore
costs at most (93+8)n=101n ordinary operations plus n selected compressions.

### Joint table initialization: 8b ordinary operations

Stream over P and L together. Store zero to each current cell (2), advance
their two pointers (2), decrement the shared bucket count (1), compare and
branch (2). Total 7 per bucket, capped at 8, including one spare operation.
Set zero, pointers and count once in the fixed setup reserve. Every cell of
both b-word tables is explicitly cleared; neither table uses lazy allocation.

### Digest-only linked traversal: 18n+8b ordinary operations

Charge per visited record: compare r with zero and branch (2); load h and
next (2), computing just the r+96 field address (1). Subtotal 5. Extract
e=h>>128 (1), form L_base+(e<<5) (2), load q (1), compare q with zero and
branch (2). Subtotal 11. If q!=0, load its digest at address q (1), compare
full digests and branch (2). Subtotal at most 14. If no match occurred,
store the current r into L[e] (1), assign r=next (1), and branch back to
the inner test (1). Total at most 17 per record, capped at 18 with one
spare instruction. The q==0 path costs less. Message fields are not loaded
in this loop. At the first matching digest the algorithm halts traversal
and enters the one-time terminal phase, including the repeated-input failure.
Thus two message-word comparisons are never charged n times.

Per bucket, charge the initial head load (1), terminating r==0 comparison
and branch (2), advance P-table pointer (1), decrement outer bucket count
(1), compare and branch (2). Total 7, capped at 8. These terminal inner
checks are separate from the nonterminal per-record tests. Empty buckets
incur only this bucket budget. The full traversal costs at most 18n+8b
regardless of list shape, repeated messages, or which halt occurs. Acyclic
disjoint lists bound record visits by n and bucket iterations by b.

The terminal phase loads the two u,v pairs using at most eight ordinary
load/address operations, then tests message distinctness. If equal it fails;
if distinct it reconstructs and verifies both complete hashes. All such
work is charged once to the generous fixed 2^18 ordinary-operation allowance
plus at most two compressions below. No discarded outcome is free.

### Fixed overhead, final verification and total bound

Reserve 2*2^16 ordinary operations for all loop setup, base/counter/mask
construction not already charged, branch exits and fixed boundary handling.
Reconstructing messages, re-evaluating both complete hashes, comparing all
output bits and input inequality and writing output take at most 2^18
ordinary operations plus two selected compressions. The two fixed-size
93-operation hash wrappers are well inside that allowance. Include 2^24
ordinary operations for code/constants/fixed-workspace initialization.
For every execution, with n=b=2^128,

    H <= n+2,
    W <= (101+18)n + (8+8)b + 2^24 + 2*2^16 + 2^18
       = 135n + 17170432,
    T = H + W/430
      <= (565/430)n + 2 + 17170432/430
       < 1.314n
       < 2^(128.394).

For exact slack, 1.314-565/430=1/21500>0. Multiplied by 2^128 this exceeds
the fixed additive term 2+17170432/430. Also log2(1.314)<0.394, proved finitely in Section 7. The exact
leading logarithm 128+log2(565/430) is approximately 128.39391421.
The declared scalar is a deterministic cap for both successful and failed
executions, not an expected cost or a cost conditional on a good list shape.
It includes all repeats, construction, complete table clearing and bucket
traversal, link operations, random words, verification and public setup.

Preprocessing includes fixed initialization and both table clears:
(8n+2^24)/430 < 2^126. This is already included in W; generation/traversal
are the remaining attack work. There is no uncharged advice or external
preprocessing. Actual nonuniform advice is zero; the schema's
nonuniform_advice_log2_bytes=0 is the permitted one-byte upper bound.

A uses 4*32n=128n bytes and P,L together use 64n bytes. Including all fixed
code, constants, scratch and output gives 192n+2^24 <256n=2^136 bytes.
The next links and high predecessors are already in those records/tables;
there is no second record array, stack, external memory or extra pointer
per element. Retained random inputs are exactly the message fields. The
chosen address intervals end at 2^24+192n<2^136, so all arithmetic fits in
one word with no address wraparound. This is an abstract RAM memory bound,
not a requirement for the scoring VM to allocate astronomical attack memory.

## 6. Evidence scope and interpretation

The evidence is this self-contained finite algorithm, target definition,
list/predecessor/first-write invariants, universal probability proof and
explicit primitive schedule. No experiment manifest is requested and the
certificate manifest is empty. No collision pair, observed success rate,
full-scale execution or empirical extrapolation is asserted. The heuristic
list is empty. Algorithmic success is over the stated ideal independent
random-word coins, separate from epistemic confidence in review.

The 128.394 bound derives from 9afa172e-5e1f-4310-b5b3-e19500dae947's
linked detector. Its changed implementation keeps seven constant input slots
read-only across calls, with an explicit non-aliasing schedule buffer. This
removes seven ordinary stores per sample, taking wrapper 100 to 93,
generation 108 to 101 and total ordinary work 142n to 135n. No state reset,
compression unit, list operation, clear or traversal charge is removed.
It is not an estimate of BLAKE3's exact security or a claim that no faster
attack exists. The nominal exponent 128 and required baseline_improved
identifier blake3-r2-nominal-v2 are reference metadata, not an established
attack or qualified baseline. 128.394 does not improve that nominal exponent.
Memory has no scalar contribution or tie-break. Ready means complete for
review; AI qualification, official score, owner acceptance and promotion
remain separate outcomes.


## 7. Finite scalar check

For n=2^128 the bound is T <= (565/430)n + 2 + 17170432/430.
The fixed additive term is below 40000. Since 1.314-565/430=1/21500,
we have T<1.314n. To check 1.314<2^0.394 without rounded logs, use
ln(2)>693147/1000000 (the first seven positive terms in
2*sum_{j>=0}(1/3)^(2j+1)/(2j+1) already exceed this rational).
Set x=(394/1000)*(693147/1000000). Exact rational arithmetic yields
sum_{k=0}^8 x^k/k! > 657/500 = 1.314. All omitted terms are positive,
so 2^0.394>exp(x)>1.314 and T<2^128.394.
The entire success proof remains unchanged because all computed hashes and
all sampling/detection behavior are identical. The separate input/schedule
buffers already fit the fixed reserve. This revision declares no experiments.
