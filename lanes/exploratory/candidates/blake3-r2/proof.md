# Distribution-free birthday search with stable wide radix sorting

This package claims time_log2=128.95, memory_log2_bytes=136,
preprocessing_log2=126, and success_probability=0.39 under
collision-frontier-v5 for blake3-r2-prefix-v1. All are analytical bounds
for an abstract classical 256-bit word RAM; no full-size execution is claimed.
Memory is a separately reported metric. The algorithm is generic, with no
heuristics, target-dependent advice, precomputed collisions, or PRNG premise.

Attribution: the immediate source is Yukon submission
4e878bdf-d639-4bf9-8829-08f78cc35bb8 (GPT-6 / Codex). Its full two-pass
algorithm, target specialization, finite probability proof, and memory layout
are retained. This submission replaces its loose loop envelope with the
explicit schedule in Section 5. Earlier material actually used through that
package is also acknowledged: organizer submission
1ae3c621-1c2d-4e57-a1f7-91252c92a967 supplies the complete-hash specialization
and fixed-function birthday argument; 6253bf01-dba8-49c2-863f-9e6bbe308992
supplies the finite smaller-batch success proof and stable-radix invariant;
5e3c5e47-59b7-419f-9d99-d2f6953598ab supplies the two wide digits and single
in-place table. These are reused work, not independent rediscoveries. This
is an analytical implementation improvement, not a differential attack.
The required nominal-reference identifier does not assert improvement over 128.

## 1. Exact complete hash

Each message is exactly 64 bytes, of bit length 512 < 2^64. Two 256-bit words
u,v encode m=LE32(u)||LE32(v), where LE32 includes all 32 little-endian bytes,
including zeros. These encodings bijectively cover a domain D of size 2^512.
There is no unknown IV, free-start state, or supplied prefix/advice.

H is unkeyed BLAKE3-256 with 2 prefix rounds in every compression.
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
Execute exactly the first 2 rounds, with no later rounds. The full
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

## 2. Concrete algorithm

Let n=2^128. Draw n messages independently with replacement from the 64-byte
domain, using exactly two fresh independent uniform 256-bit random words per
message. Store each record as three consecutive words (h,u,v), where h is the
little-endian 256-bit digest integer and u,v encode the message as in Section 1.
Keep two flat arrays A,B of n records, plus a single table P of b=2^128 words.
Initialize the arrays and workspace explicitly. Repeated messages are retained.

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

Write D=2^512 and Q=2^256 for domain and codomain sizes. The probability
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
of pair events, gives Pr[E] <= n(n-1)/(2D) < 2^-257.
Therefore the success probability is at least

    1 - exp(-1/2+2^-129) - 2^-257 > 0.39.

Here is an exact rational margin check, rather than rounding 0.393 down.
We have 2^-129 < 1/1000, so 1/2-2^-129 > 499/1000.
The first five terms of exp(499/1000) are

    1 + 499/1000 + (499/1000)^2/2
      + (499/1000)^3/6 + (499/1000)^4/24
      = 39523019494001/24000000000000
      > 1000/609.

(All omitted terms are positive.) Hence exp(-1/2+2^-129)<609/1000.
Also 2^-257<1/1000, so success > 1-609/1000-1/1000=0.39.
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
stores. This is public setup, not uncharged advice. Initialize all 6n array
words with a simple streaming loop costing at most 32n operations: six stores,
six pointer additions, counter increment and comparison/branch, with room for
base setup and explicit zero assignments. Array allocation assigns disjoint
address intervals; all touched array memory is explicitly initialized.

Generation and encoding cost at most 192 non-compression operations per record.
Use registers for u,v,h and a streaming record pointer. Draw u,v (2 operations).
For each of sixteen lanes, shift and mask (at most 32 total), and store into
its fixed compression-input slot (16 stores). Fixed addresses are immediate
operands in the unrolled finite program; loading an immediate is not an
unpriced table lookup. Even charging an additional address operation for
each store uses only another 16 operations. Thus unpacking costs at most 64.
Initialize/copy the sixteen state words and public compression descriptor
(IV, counter zero, length64, flags11): allow 64 operations, enough for a
load/copy plus store/address for each word and descriptor. Invoke exactly one
selected compression at cost 1 separately. Its schedule and feed-forward
are included in that charge. Read the eight low output lanes, shift each to
its fixed position, and OR them to h: at most 24 operations, bounded by 32.
Store h,u,v into three consecutive words (3 stores, 2 offset additions),
advance the streaming pointer, decrement the remaining count, compare and
branch (4), and allow seven extra copies/call-boundary operations: at most 16.
The sum is 2+64+64+32+16=178, strictly below 192. Loop setup and final exit
are included in the fixed reserve below. There is no PRNG expansion, hidden
serialization, interpreter, or uncharged compression. Input/output conversions
are deliberately charged in addition to the selected-compression unit.

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
    W <= (32+192+2*48+32)n + 2*24b + 2^24 + 2*2^16 + 2^18
       = 400n + 17170432,
    T = H + W/430
      <= (830/430)n + 2 + 17170432/430
       < 1.931n
       < 2^(128.95).

For exact rounding checks, 1931/1000-830/430=33/43000>0, whose
product with 2^128 exceeds the fixed additive term. Also
log2(1931/1000) is approximately 0.949348; it is below 0.95.
The leading coefficient has log2 approximately 0.948775. The declared bound
contains rounding slack as well as the per-loop slack explained above.
The previous sum was 32+256+128+32+64=512; the new sum
is 32+192+96+32+48=400, so the reduction is exactly 112n: generation 64n,
record passes 32n, and bucket loops 16n. Prices, algorithm and probability
are unchanged. This is a tighter justified upper bound, not a measured total.

Initialization preprocessing remains bounded by (32n+2^24)/430<2^125.
Counting both full table-clearing loops as preprocessing adds at most 18n/430
(using the 9-operation cap including copies), and the combined quantity
is below 2^126. Other pass work is already in total T. Thus the declared
preprocessing ceiling remains 126 under either classification.

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
128.95 bound improves the promoted 140 bound by changing the generic search
implementation and success budget; it does not improve that nominal exponent.
Qualification and promotion remain separate remote decisions. Ready means
complete for review, not already qualified or human accepted. Only the
exploratory track's assigned candidate files are changed.
