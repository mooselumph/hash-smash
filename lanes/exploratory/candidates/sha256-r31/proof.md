# SHA-256, 31 prefix rounds: unconditional single-block collision construction

The scalar below is `time_log2` under `collision-frontier-v5`. Memory is a
separately reported resource bound with no scalar contribution.

This independent **exploratory** package selects `sha256-r31-exploratory`, target
`sha256-r31-prefix-v1`, cost model `collision-frontier-v5`, and policy
`paired-lanes-v1`. It submits a complete analytic algorithm, not an already
computed collision. Readiness requests review; it does not assert an AI outcome
or human acceptance.

The construction is the same distribution-free birthday search used by the
organizer's nominal reference, tightened in two independent ways that both
lower the charged total under `collision-frontier-v5`:

1. **Single-block messages.** Each sampled message is exactly 55 bytes, so its
   padded length is one 512-bit block and each hash costs exactly one target
   compression rather than two. This halves the dominant compression term.
2. **Radix-sorted collision detection.** Duplicate digests are found by a
   least-significant-digit radix sort with a fixed number of linear passes,
   not a comparison sort. The detection work is `O(q)` charged word operations
   with no `log q` factor, so under this cost model it is dominated by the
   generation compressions instead of dominating the score.

No ideal-hash, random-oracle, differential, round-independence, or experimental
premise is used. The proof is worst-case over every random tape and every
possible output distribution of the fixed hash. The required `baseline_improved`
value `sha256-r31-nominal-v2` only identifies the organizer's nominal display
reference; it is not an established attack, qualified baseline, or security
bound. The declared scalar is `time_log2 = 130`; the true charged total is
below `2^129.5`, and 130 is the submitted upper bound. Memory is `2^138` bytes.

## 1. Exact message and complete-hash definition

Write BE_k(v) for the k-byte big-endian encoding of integer v. Set
q = 2^129, N = 2^256, and let the sampled-message content field hold 440 bits,
so the message domain has D = 2^440 distinct 55-byte messages.

A sampled message is exactly 55 bytes:

    m(w) = BE_55(w),  0 <= w < 2^440.

Its bit length is 440 < 2^64, so it is a valid target-domain message. Under
FIPS 180-4 padding, appending 0x80, then zero bytes to 56 modulo 64, then the
64-bit big-endian bit length 440, yields exactly one 512-bit block. Therefore
H(m(w)) is one selected-round compression from the fixed IV followed by
feed-forward, and no second block is processed. This is the single structural
change from a two-block sampler; the compression primitive is identical.

Parse the padded 512-bit block as sixteen big-endian 32-bit words
W[0],...,W[15]. Initialize the eight 32-bit chaining words once, in this order:

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19

All additions below are modulo 2^32; NOT and rotations operate on 32 bits.

    s0(z) = ROTR32(z,7) XOR ROTR32(z,18) XOR (z >> 3)
    s1(z) = ROTR32(z,17) XOR ROTR32(z,19) XOR (z >> 10)
    S0(z) = ROTR32(z,2) XOR ROTR32(z,13) XOR ROTR32(z,22)
    S1(z) = ROTR32(z,6) XOR ROTR32(z,11) XOR ROTR32(z,25)
    Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
    Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    W[t] = W[t-16] + s0(W[t-15]) + W[t-7] + s1(W[t-2]),  for t = 16,...,30.

The constants K[0],...,K[30] are, in hexadecimal and original index order,

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351

Copy the incoming chaining words into (a,b,c,d,e,f,g,h), then execute exactly
t = 0,...,30 with simultaneous updates:

    T1 = h + S1(e) + Ch(e,f,g) + K[t] + W[t]
    T2 = S0(a) + Maj(a,b,c)
    (a,b,c,d,e,f,g,h) = (T1+T2, a, b, c, d+T1, e, f, g).

After round 30 add all eight working words to the incoming chaining words
modulo 2^32 (feed-forward). Concatenate BE_4 of all eight resulting state words
in standard order. This 32-byte output is H(m); interpret it as one 256-bit
integer in the same big-endian order. Equality of that integer is equality of
the complete digest. The model supplies one execution of this selected-round
compression, including expansion and feed-forward, at one unit.

## 2. Concrete RAM algorithm and stopping rule

Every RAM word is 256 bits (32 bytes). A record is three words (digest, w_hi,
w_lo), where (w_hi, w_lo) hold the 440-bit content w of the original message
padded into two 256-bit words. There are no headers or hidden pointers. Two
arrays A and B each hold q contiguous records; record i occupies word address
base + (i + i + i), formed by additions because multiplication is not assumed.

1. **Generate.** For i = 0,...,q-1 draw an independent uniform 440-bit content
   w (drawing two independent uniform 256-bit words and discarding the unused
   high bits of one, all charged), form the 55-byte message, compute
   H(m(w)) with the fixed IV and the single padded block, and store
   (H(m(w)), w_hi, w_lo) in A[i]. The full table is generated on every run.

2. **Radix sort by digest.** Sort the q records into nondecreasing digest order
   with a least-significant-digit radix sort using 32-bit digits, that is
   eight passes over the 256-bit digest key. Each pass is a stable counting
   sort on the current 32-bit digit:

       for pass p = 0,...,7 with shift = 32*p:
         clear a count array C of 2^32 word counters
         for i = 0,...,q-1:  d = (digest(SRC[i]) >> shift) AND 0xffffffff
                             C[d] = C[d] + 1
         turn C into start offsets by a single prefix sum over its 2^32 slots
         for i = 0,...,q-1:  d = (digest(SRC[i]) >> shift) AND 0xffffffff
                             copy the three-word SRC[i] to DST[C[d]]
                             C[d] = C[d] + 1
         swap the roles of SRC and DST by exchanging their base-address words

   SRC starts as A and DST as B. Counting sort is stable, so after processing
   digit p the records are sorted by the low 32*(p+1) digest bits; after eight
   passes they are sorted by the full 256-bit digest. The runtime is fixed at
   eight linear passes regardless of the data, so this step is worst-case and
   input-distribution-independent. The 2^32-slot count array and its prefix sum
   are charged in section 5.

3. **Scan and verify.** Scan the sorted array from index 1 to q-1, comparing
   each record's digest with its predecessor's. At the first equal digest whose
   two content words differ, recompute both complete hashes H from the fixed IV,
   confirm full 256-bit digest equality and message inequality, and return the
   two 55-byte messages. Return FAIL if no adjacent equal-digest, distinct-
   content pair exists or the final recomputation disagrees (impossible in the
   exact RAM). There are no restarts or amplification.

Because the sort places all records sharing a digest contiguously, any two
sampled distinct messages with equal digests appear as an adjacent equal-digest
pair with differing content, so the scan finds an ordinary collision whenever
one exists among the samples. A returned pair is always two distinct valid
55-byte messages with identical complete sha256-r31 digests, confirmed by
recomputation. Repeated identical messages never count as success.

## 3. Distribution-free birthday lemma

For each digest value z in [0, N) let p_z be the fraction of the D messages
mapping to z under the fixed deterministic H; retain zero entries. Independent
uniform messages induce independent digest samples from this same vector p,
because H is applied separately to independent inputs. This assumes nothing
about whether p is uniform or whether SHA-256 behaves like a random function.

For a probability vector p let e_q(p) be the sum over all q-element coordinate
subsets of the product of those coordinates. The probability that q independent
samples are all distinct is q! e_q(p), since each unordered q-set contributes
its q! orderings. We show e_q(p) is maximized by the uniform vector.

The N-coordinate simplex is compact and e_q is continuous, so a maximizer
exists; among maximizers choose one minimizing sum_z p_z^2. Suppose two
coordinates a,b differ; group the remaining N-2 coordinates as r. Splitting the
q-subsets by how many of {a,b} they contain,

    e_q(p) = e_q(r) + (a+b) e_{q-1}(r) + a b e_{q-2}(r),

with e_0 = 1 and e_j = 0 for j outside its valid range; all coefficients are
nonnegative. Replacing a,b by their average preserves a+b and increases ab by
(a-b)^2/4, so e_q does not decrease, keeping the point a maximizer, yet strictly
decreases sum_z p_z^2, contradicting the choice. Hence every coordinate equals
1/N. This holds for every p, regardless of the true bias of H.

Therefore, since 2 <= q <= N, the probability of no repeated digest is at most

    q! binomial(N,q) / N^q = product_{j=0}^{q-1} (1 - j/N) <= exp(-q(q-1)/(2N)),

using 1 - u <= exp(-u) termwise. No independence-of-collision-events assumption
and no structural property of H is used.

## 4. Algorithmic success and repeated inputs

Let C be the event that some sampled digest repeats and R the event that some
sampled 440-bit content repeats. Then C minus R guarantees two distinct
messages with equal complete digests, which the algorithm returns. Without
assuming independence of C and R,

    Pr(success) >= Pr(C) - Pr(R)
                >= 1 - exp(-q(q-1)/(2N)) - q(q-1)/(2D).

The repeated-content term is the union bound over binomial(q,2) position pairs,
each equal with probability exactly 1/D for independent uniform 440-bit draws.
There is no rejection or sampling without replacement.

For q = 2^129 and N = 2^256, q(q-1)/(2N) = (2^129(2^129-1))/2^257 = 2 - 2^-127 > 2.
For D = 2^440, q(q-1)/(2D) < 2^258/2^441 = 2^-183. Using exp(-2) < 1/7,

    Pr(success) > 1 - 1/7 - 2^-183 > 0.85 > 0.8 > 0.39.

`success_probability: 0.8` is a lower bound on algorithmic success under the
fresh coins, not equality with the true value, confidence in this proof, or
confidence in a review. Every generation draw and every sorting pass is charged
on failed runs too; there is a single fully charged execution with no restart.

## 5. Auditable resource implementation

These are worst-case bounds for every random tape on the classical 256-bit word
RAM of `collision-frontier-v5`. Each selected compression costs one unit. Every
other primitive word operation -- 256-bit load or store, add/subtract, bitwise
op, shift or rotation, comparison, conditional branch, and independent uniform
random word -- costs 1/C units, with C = reference_operation_cost(sha256-r31) =
2140. Thus 2140 charged word operations cost one compression unit.

### 5.1 Compression term

Generation performs exactly one compression per message, so q = 2^129
compressions, costing 2^129 units. The scan recomputes at most one candidate
pair, at most 2 further compressions. Total compression term:

    T_comp <= 2^129 + 2 units < 2^129 * (1 + 2^-127) units.

Single-block hashing is what makes this term 2^129 rather than 2^130.

### 5.2 Word-operation term

A core scalar operation (two-operand arithmetic/comparison, assignment, branch,
or addressed load/store) is charged at most eight word operations, covering up
to four instruction-word fetches, two operand loads, the operation, and a store.
Address arithmetic base + 3*i uses additions and is charged as core work.

Generation wrapper, per message: unpack the drawn content into the message
buffer, run the padding block layout (a fixed constant except the content
bytes), address and store the three-word record, advance loop state, and fetch
and dispatch the two random-word draws and the one compression call. This is at
most 200 core operations, i.e. at most 8 * 200 = 1600 word operations per
message. Over q messages:

    1600 q / C = 1600 * 2^129 / 2140 < 2^129 * 2^-0.42 = 2^128.58 units.

Radix sort, per pass: two linear traversals of q records. The count traversal
charges digit extraction (load digest word, shift, mask) and a counter update
(load, add, store) at most 64 word operations per record. The scatter traversal
charges digit extraction, the offset load/increment/store, and the three-word
record copy (three addressed loads and three addressed stores) at most 64 word
operations per record. Clearing the 2^32 counters and forming the prefix sum
cost at most 4 * 2^32 word operations per pass. So one pass costs at most
128 q + 2^34 word operations, and the eight passes cost at most

    8 (128 q + 2^34) = 1024 q + 2^37 word operations
                     = 1024 * 2^129 + 2^37
    -> (1024 * 2^129 + 2^37) / C < 2^139 / 2140 < 2^127.94 units.

The scan charges at most 64 word operations per position for the two digest
loads, comparison, content comparison, branches, and index update, plus a
one-time candidate copy: at most 64 q + 8192 word operations,

    (64 * 2^129 + 8192) / C < 2^135 / 2140 < 2^123.94 units.

Summing the word-operation term:

    T_word < 2^128.58 + 2^127.94 + 2^123.94 < 2^129.2 units.

### 5.3 Total time and declared scalar

    T = T_comp + T_word < 2^129 (1 + 2^-127) + 2^129.2 < 2^129.5 units.

Hence `time_log2 = 130` is a valid upper bound on the charged total, with true
cost below `2^129.5`; the submitted bound is the declared scalar. The
compression term `2^129` alone is one unit above the pure birthday count
`2^128.3`; reducing q toward `2^128` approaches `time_log2 = 129` at the minimal
`0.39` success probability, but this package declares the robust `q = 2^129`
bound. Detection contributes under `2^128` units because radix sort removes the
`log q` comparison factor that would otherwise dominate; a comparison sort of
`q` records costs about `q log2 q ~ 2^136` charged word operations and is why an
unoptimized birthday search scores near 136 under this model.

### 5.4 Memory, preprocessing, and advice

Peak memory is the two record arrays plus fixed scratch and the count array.
Two arrays of q three-word records occupy 2 * 3 * q * 32 = 192 q bytes = 192 *
2^129 < 2^137.59 bytes. The 2^32-slot count array holds 2^32 word counters at 32
bytes each, 2^37 bytes. Fixed code, IV, the 31 constants, the padding template,
indices, and the output pair occupy under 2^20 bytes. Peak memory is therefore

    M < 192 * 2^129 + 2^37 + 2^20 < 2^138 bytes,

establishing `memory_log2_bytes: 138`. All addresses, indices, and counters are
below 2^138 << 2^256, so address and counter arithmetic never wraps.

A loader may write all code and constant words, initialize fixed scratch, and
establish the array and count-array base addresses in fewer than 2^20 charged
instructions; this is `preprocessing_log2: 20`, and it is included in the total
time bound above (it is dominated by the 2^129 term). There is no
message-dependent setup, precomputed search, cached collision, or favorable
seed. `nonuniform_advice_log2_bytes: 0`: actual nonuniform advice is zero bytes;
the public fixed code, IV, and SHA-256 constants are uniform specification data,
and their storage and initialization are still charged.

## 6. Evidence, scope, and limitations

The heuristic list is empty because sections 1-5 derive correctness, success
probability, and resources from the explicit target and the model's charged
primitives alone. Fresh independent random words are part of the organizer's
computation model, not an empirical claim about a seeded generator. No ideal
SHA-256 behavior, differential characteristic, or round property is invoked, and
the argument is worst-case over all output distributions.

The certificate manifest is valid and empty; there is no experiment manifest or
executable source. A finite toy run would add no premise to the all-
distributions lemma and cannot certify this full-scale cost. This is an
astronomically expensive theoretical RAM construction, not a measured run,
practical attack, or new SHA-256 security result; it does not improve on the
nominal 128-bit reference and makes no such claim. It improves only the charged
total of the distribution-free birthday search relative to the organizer's
recorded generic construction, by single-block hashing and linear-pass
detection.

Two same-time constructions trade rigor for memory and are noted for context
only, not claimed here: van Oorschot--Wiener parallel collision search with
distinguished points, and Pollard-style cycle finding, each reach comparable
charged time using far less memory (roughly `2^47` and `2^13` bytes), but they
rest on a random-mapping heuristic for the fixed iteration and so are weaker
than this unconditional bound. This package deliberately submits the
unconditional construction. Any eventual AI qualification remains distinct from
mathematical proof or human acceptance.
