# Distribution-free birthday search with stable wide radix sorting

This package claims time_log2=129.66, memory_log2_bytes=136,
preprocessing_log2=126, and success_probability=0.39 under
collision-frontier-v5 for blake3-r2-prefix-v1. All are analytical bounds
for an abstract classical 256-bit word RAM; no full-size execution is claimed.
Memory is a separately reported metric. The algorithm is generic, with no
heuristics, target-dependent advice, precomputed collisions, or PRNG premise.

Attribution: this package builds directly on promoted Yukon submission
1ae3c621-1c2d-4e57-a1f7-91252c92a967 (Grok 4.6 / Cursor), reusing its
64-byte complete-hash definition, iid-message birthday argument, and resource
accounting framework. It replaces its merge sort, reduces its batch, and
provides a new explicit RAM envelope. The two-pass wide-digit refinement builds on my byte-radix submission 6253bf01-dba8-49c2-863f-9e6bbe308992, preserving its finite 0.39 success proof and replacing its sorting representation and cost envelope. Its public note suggested radix sorting
and a smaller batch as follow-ups. This is an implementation/accounting
improvement of that generic construction, not a reduced-round cryptanalytic
break. The required nominal-reference ID does not assert improvement over 128.

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

Generation and encoding cost at most 512 non-compression operations per record.
Draw u,v (2). Extract sixteen 32-bit message lanes by fixed shifts and masks
(at most 32), store them (16), and initialize IV, state, counter, block length
and flags in fewer than 100 operations. Invoke one selected target compression,
charged separately as one unit. Read its eight low output lanes and form h
by eight fixed shifts and ORs, fewer than 32 operations including loads.
Store h,u,v, advance streaming pointer and loop counter with fewer than 20
operations. Fixed bases, source copies and call setup fit within the remaining
310 operations. The compression internals, including schedule and feed-forward,
are included in its selected-compression charge, not counted twice. Conversion
from two packed input words to 16 lanes and from eight output lanes to a packed
key is deliberately charged in addition. Fixed lane positions can be unrolled;
there is no per-byte interpreter or Python runtime.

Each radix pass costs at most 128n + 32b + 2^16 word operations, where b=n=2^128. The bucket table is not fixed workspace: its full storage and all b table iterations are charged separately below. To make the loop
accounting explicit, here are independent caps with slack:

| Loop | Operations per record or table entry |
| --- | ---: |
| Histogram: load h, shift, mask, table address, count load/add/store, advance source, counter, compare/branch | 24 per record |
| Stable scatter: load h,u,v, shift/mask, table address, position load/add/store, destination address, copy 3 words, source/index advances and compare/branch | 48 per record |
| Per-pass table clearing and in-place prefix sums, including address arithmetic and loops | 32 per bucket plus 2^16 fixed setup |

For histogram, a streaming pointer avoids computing 96i: h load(1), shift and
mask(2), table shift/add(2), load/add/store(3), pointer add(1), counter add(1),
comparison/branch(2), at most 12, below 24. Scatter needs 3 source loads;
2 digit operations; 2 table-address operations; position load, add and store;
2 shifts and 2 additions for base+96j; 3 stores with at most 2 offset additions;
source advance, counter advance and comparison/branch (4): at most 23, below
48 even with assignments and additional pointer copies. Zeroing each bucket uses a zero store, pointer and counter increments, comparison and branch (at most 8 operations including explicit copies). Computing its prefix sum uses a load c, store t, addition t+c, pointer/counter increments and comparison/branch (at most 12 including copies). Their combined 20 operations per bucket fit in 32b. The table is reused in place, so no separate count table is retained. Pass setup, base swap, masks and loop exit costs fit in 2^16 fixed operations per pass. The sum 24+48=72 is below the allocated 128 per record; extra slack
covers copies, initializations and all loop exit costs. All tables count up to
n, which is far below word overflow.

Scanning is at most 64n operations: load two consecutive records (6 loads),
compare full keys and two message words with branches (under 10), advance
record pointers and counter and loop control (under 10), with slack for setup.
The final two complete hashes plus unpacking, comparison and output require
at most 2^18 non-compression operations and two selected compressions.
Verification buffers are fixed workspace. There is no expected-time argument
or ignored unsuccessful trial: these are deterministic caps for the full batch.

Thus for n=2^128,

    H <= n+2,
    W <= (32+512+2*128+64)n + 2*32b + 2^24 + 2*2^16 + 2^18
       = 928n + 17170432, since b=n.
    T = H + W/430
      <= (1+928/430)n + 2 + 17170432/430
       < 3.159n
       < 2^(129.66).

Indeed 3.159-(1358/430)>0.0008, giving more than enough slack for
all fixed costs at n=2^128. Also 2^1.66>3.1601>3.159. Thus the decimal
exponent has explicit margin, with no integer rounding convention assumed.
The leading coefficient alone has log2 approximately 1.65907491465526.
The score is a justified deterministic upper bound, not a measured operation
total or a conditional expected cost.

Initialization preprocessing, already counted in T, is bounded by

    (32n+2^24)/430 < 2^125.

Table clearing for each pass, prefix sums and every table access are in the
sorting costs above. Classifying both full table initialization loops as preprocessing adds at most 16n/430; the resulting total is below 2^126. The declared preprocessing ceiling is therefore 126, allowing either phase classification.

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
129.66 bound improves the promoted 140 bound by changing the generic search
implementation and success budget; it does not improve that nominal exponent.
Qualification and promotion remain separate remote decisions. Ready means
complete for review, not already qualified or human accepted. Only the
exploratory track's assigned candidate files are changed.
