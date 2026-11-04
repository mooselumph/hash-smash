# Distribution-free birthday search with stable wide radix sorting

This package claims time_log2=128.81, memory_log2_bytes=136,
preprocessing_log2=126, and success_probability=0.39 under
collision-frontier-v5 for blake3-r2-prefix-v1. All are analytical bounds
for an abstract classical 256-bit word RAM; no full-size execution is claimed.
Memory is a separately reported metric. The algorithm is generic, with no
heuristics, target-dependent advice, precomputed collisions, or PRNG premise.

Attribution: the immediate source is submission
8fab4dd4-b700-4125-abd7-2c7f11d6d5ee, whose full target definition,
33-byte sampling domain, finite probability proof, stable two-pass radix
algorithm and primitive envelopes are reused here. The organizer generic
birthday specialization and v5 split accounting were also inspected directly
in 1ae3c621-1c2d-4e57-a1f7-91252c92a967. The immediate source acknowledges
6253bf01-dba8-49c2-863f-9e6bbe308992 (smaller batch and radix invariant),
5e3c5e47-59b7-419f-9d99-d2f6953598ab (wide digits),
4e878bdf-d639-4bf9-8829-08f78cc35bb8 (detailed package), and
399d50b1-d199-4132-903d-982c075e5413 (primitive schedules).
No independent origin is claimed for those inherited features. The present
change removes a separate zeroing sweep of record storage, with an explicit
write-before-read invariant. Bucket counters are still cleared and all
actual record writes remain fully charged.

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

## 2. Concrete algorithm

Let n=2^128. Draw n messages independently with replacement from the 33-byte
domain, using two fresh independent uniform 256-bit random words per
message and masking the second to eight bits, as in Section 1. Store each record as three consecutive words (h,u,v), where h is the
little-endian 256-bit digest integer and u,v encode the 33-byte message as in Section 1 (0<=v<256).
Keep two flat arrays A,B of n records, plus a single table P of b=2^128 words.
Initialize fixed workspace explicitly. Do not separately clear A or B: generation writes every word of A, and each scatter writes every word of its destination before the next pass can read it. Clear the bucket table before each histogram, as specified below. Repeated messages are retained.

For digit shifts s=0,128, execute this counting-sort pass (mask=2^128-1):

1. Zero P[0..b-1]. For each source record, extract d=(h>>s)&mask and increment
   P[d]. Every record contributes, with no independence assumption about keys.
2. Set t=0. For d=0..b-1 in order, load c=P[d], set P[d]=t and then t=t+c. Thus counts are replaced in place by start offsets.
3. Scan source records in increasing index order. Extract d, let j=P[d],
   increment P[d], and copy all three source words into destination record j.
4. Exchange source and destination bases. After two passes, the final source
   is sorted by full unsigned digest value.

Scan adjacent records in that final array. If digests agree and messages
(u,v) differ, recompute both complete hashes from the standard initialization,
check full equality and input inequality, return that pair, and halt. If no
pair exists, halt with failure. At most one pair is verified; exact computation
makes its verification succeed. There are no restarts or early probability
assumptions. Bounds below apply even to every failing execution.

A record's byte address is base+(i<<6)+(i<<5), with word offsets 0,32,64.
Tables use byte address base+(d<<5). Counters, addresses and sentinels fit
below 2^137; n itself and every loop endpoint fit in one 256-bit word.
There is no multiplication, unit-cost library sort, or free storage access.

## 3. Correctness

At the start of scattering, P[d] is the sum of original counts for digits below d.
Exactly the original count for digit d records are encountered. Their successive destination
indices are therefore precisely that bucket's allocated contiguous interval,
with no overflow, overlap, or omission. Reading source in increasing order
makes scattering stable, including equal-digit records. Each pass preserves
all original records and their digest/message association. Inductively after
k passes the records are ordered by the lowest 128k digest bits: the new digit
orders buckets and stability preserves the previous ordering within each.
After two passes they are ordered by the complete 256-bit digest.

Equal digest keys are contiguous. If a key interval contains at least two
different messages then some adjacent messages differ; otherwise transitivity
of adjacent equality makes every message identical. Hence the final scan finds
a distinct-message collision whenever one is in the sample. Final verification
uses the complete target of Section 1, including flags, fixed IV and root output.
Every returned pair is an ordinary collision for the exact selected profile.

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

## 5. RAM implementation and charged operation envelope

One selected two-round compression costs 1; every other primitive 256-bit
RAM operation costs 1/430. Loads, stores, shifts, logical operations, additions,
comparisons, branches and random-word draws are all charged. The program is a
finite RAM program with registers for loop counters, bases and current records.
Register assignments can be charged as extra primitives inside the slack below.
Instruction fetch is conventionally implicit in a RAM primitive; no high-level
subroutine, array access, or serialization is treated as a single primitive.
There is no interpreter whose instructions need to be decoded at runtime.

Fixed public code, constants and scratch fit within 2^24 bytes. For example,
2^16 instruction templates of at most four words occupy 2^23 bytes; another
2^23 bytes exceeds all scalar registers, the target
state, message lanes, verification buffers and output. The actual loops and
unrolled 16-lane conversions need fewer templates. At most 2^24 word operations
initialize this finite reserve, including constructing constants by shifts and
stores. This is public setup, not uncharged advice.

The two record arrays are reserved disjoint address intervals; their previous
contents are never consulted, and the algorithm assumes no value for untouched
memory. A separate zero-fill is unnecessary. Generation assigns all three words
of A[i] for every i before any histogram or scatter reads A. In a scatter,
the prefix offsets partition [0,n), and each source record writes all three
words to one distinct destination index. Thus every destination word is written
exactly once before that destination becomes the next source. The second pass
has the same property. The final scan starts only after that pass finishes.
Source and destination intervals are disjoint on each pass. These invariants
hold for every digest distribution, including all keys equal, and all repeated
messages. No stale destination word is read during scatter. Fixed scalar
registers are assigned on their code paths before use, and all bucket counters
are explicitly zeroed before increments. There is no uninitialized-memory read,
lazy-zero primitive, free initialized allocation, or reliance on host memory.

Reservation fixes base addresses using constant-size arithmetic charged in the
fixed reserve. It does not access array cells. Every actual record store and
load is already charged in generation, scattering and scanning below. Removing
the earlier 32n extra zeroing operations changes the program, not the price of
any executed store. This is a first-write initialization of each record cell.

Generation and encoding cost at most 144 ordinary operations per record.
Use scalar registers for u,r,v,h and a streaming record pointer. Draw u,r
(2), mask v=r AND 255 (1). Extract the eight 32-bit lanes of u with fixed
shifts and masks (16 operations), store those eight lanes and lane8=v into
fixed input slots (9 stores). Store zero into lanes9..15 (7 stores).
Fixed input-slot addresses are immediate operands of the unrolled RAM
program; even adding seven extra address/copy operations for zero-fill gives
14 for that part. All input conversion therefore costs at most 2+1+16+9+14=42.

Initialize the sixteen state words, IV, counter and true length/flags
information with at most 48 ordinary operations. In detail, public constants
can be loaded/copied and stored into the sixteen fixed slots in 32
operations, with another 16 for descriptor slots, copies or addresses.
The compression itself costs one unit separately and includes its schedule
and feed-forward. The input block remains a separate buffer; no assumption
that zero-fill survives an in-place schedule is needed, since it is rewritten
on every sample. Read eight output lanes (8), shift to their fixed positions
(8) and OR to h (8): 24 ordinary operations. Store h,u,v (3 stores and
2 field-offset additions), advance streaming pointer and decrement count,
compare and branch (4), with seven spare copy/boundary operations: 16.
The total 42+48+24+16=130 is below 144, leaving 14 further operations per
record. Fixed initialization and exits are charged separately. No ignored
random draws, input zero-fill, complete-hash compression or conversion step
is hidden inside this cap. Fixed slot addresses are program operands;
streaming/table addresses below are all computed and charged.

Each radix pass costs at most 48n+24b+2^16 ordinary operations, b=n=2^128.
The following schedules use fixed scalar registers and explicit streaming
pointers. A register arithmetic instruction writes its destination directly;
no extra assignment is required for x=x+1. Loads/stores, addresses and
branches are all counted. The digit shift is fixed in each of two unrolled
passes; charging both a shift and mask is conservative for either digit.

* Histogram, per record: load h (1); shift/mask (2); form table address
  base+(d<<5) (2); load count, increment, store (3); advance source pointer
  and decrement remaining records (2); compare and branch (2). Total 12,
  capped at 16 for spare register copies. No record-index multiplication.
* Scatter, per record: load h,u,v (3), form the two extra source field
  addresses (2), shift/mask (2), table address (2), load/increment/store P[d]
  (3), compute destination base+(j<<6)+(j<<5) (4), store three words plus
  two destination field address additions (5), advance source and decrement
  count (2), compare and branch (2). Total 25, capped at 32. The old j is
  retained while P[d] is incremented; a further explicit copy fits the cap.
* Clear table: store zero (1), advance pointer and decrement count (2),
  compare and branch (2). Total 5 per bucket. The zero register is set once.
* Prefix table: load c, store running total t, add c to t (3); advance
  pointer and decrement count (2); compare and branch (2). Total 7 per bucket.
  Even allowing four extra copies per bucket in each table loop, the two
  loops together cost at most 5+4+7+4=20, below the 24b envelope.

Histogram and scatter caps sum to 48n. Clear/prefix loops are at most 24b.
The 2^16 reserve per pass covers pointer initialization, masks, starting
counts, swaps, loop setup/termination, and all pass overhead. Both entire
b-word clear loops are charged; allocation never supplies a free cleared
bucket table. A constant set of registers suffices, within the fixed reserve.
The sort and its cost are independent of the digit frequency distribution.

Scanning costs at most 32n operations. At each adjacent pair, load two full
records (6 loads), form four additional field addresses (4), compare digests
and both input words and branch (at most 8), advance two pointers and the
remaining count (3), compare and branch (2). Total at most 23, leaving nine
operations per pair for copies/control. The two final complete hashes and
all reconstruction, comparison and output cost at most 2^18 ordinary
operations plus two selected compressions. All unsuccessful samples,
repeated inputs, every sorting pass and a full unsuccessful scan are charged.
No restart or unbounded expected-time subroutine is present.

The resulting deterministic caps for every execution, with n=b=2^128, are

    H <= n+2,
    W <= (144+2*48+32)n + 2*24b + 2^24 + 2*2^16 + 2^18
       = 320n + 17170432,
    T = H + W/430
      <= (750/430)n + 2 + 17170432/430
       < 1.745n
       < 2^(128.81).

For rounding, 1.745-750/430=7/8600>0. Its product with 2^128
exceeds 2+17170432/430, while log2(1.745)<0.81. Consequently
T<2^128.81 with explicit slack. The exact leading logarithm is
128+log2(750/430), approximately 128.80255. This remains a deterministic
bound on all executions, including failure, rather than conditional cost.

Preprocessing consists of the fixed reserve and the two table clearing loops.
Using the inherited nine-operation ceiling per bucket including spare copies,
(18n+2^24)/430 < 2^126. This retains the previous declared ceiling even
though the separate array zeroing has been removed. Histogram, prefix and
scatter work is charged in total time, including both complete table clears.

Both record arrays occupy 192n bytes. The one n-word bucket table occupies
32n bytes. Adding 2^24 fixed bytes yields 224n+2^24 <256n=2^136 bytes.
Code, constants, random words retained as messages and scratch are included.
There is no stack growing with n, separate count table, index array, external
storage or nonuniform advice. Actual advice is zero;
nonuniform_advice_log2_bytes=0 is the schema's one-byte ceiling.
All counters/addresses fit the stated one-word representation. Memory is an
abstract allowance, not a requirement that the judging VM allocate 2^136 bytes.

## 6. Evidence scope and limitations

The evidence is the self-contained finite algorithm, counting-sort invariant,
probability argument and explicit primitive envelope above. No participant
experiment is requested, and the certificate manifest is empty. No collision
pair or empirical success rate is claimed. The generic attack has infeasible
full-scale RAM requirements; the challenge evaluates its analytical bound.

The submitted algorithm has no score-critical or supporting heuristics, hence
heuristics=[]. Its performance is not an estimate of BLAKE3's exact collision
security or a proof that no faster attack exists. The nominal exponent 128
and required blake3-r2-nominal-v2 identifier are reference metadata. This
128.81 bound improves the 128.87 immediate source by eliminating its separate
32n-operation record-array zeroing sweep. The target, sampling, success bound,
sort and all retained per-phase envelopes are unchanged. It does not improve
the nominal exponent 128.
Qualification and promotion remain separate remote decisions. Ready means
complete for review, not already qualified or human accepted. Only the
exploratory track's assigned candidate files are changed.
