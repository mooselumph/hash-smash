# SHA3-256 prefix rounds 0 through 5: unconditional generic collision package

The scalar below is `time_log2` under `collision-frontier-v5` with selected-target
reference operation cost C = 1626. Memory remains a separately reported resource
bound.

Selected lane: exploratory. Target: `sha3-256-r6-prefix-v1`.
This finite classical algorithm has total charged time below 2^128.08,
peak memory below 2^254 bytes, and success probability above 0.39.
The proposed scalar is 128.08. It is a generic analytic construction
with infeasible resource use, not a claimed cryptanalytic advance.
The required `baseline_improved` identifier `sha3-256-r6-nominal-v2`
identifies the organizer's nominal reference only. That nominal 128 is not
an established attack, qualified baseline, or security bound; this package
does not claim to improve it. Relative to the prior Yukon awaiting-review
package at time_log2 128.1 (n = 2^128 with a 112-operation envelope), this
revision only reduces the sample count to the birthday minimum for
probability 0.39 and tightens the per-sample word-operation envelope.

## 1. Exact complete hash and legal messages

Let n = ceil(0.9943 * 2^128) and N = 2^256. Explicitly,
n = ceil(9943 * 2^128 / 10000), so
0.9943 * 2^128 <= n < 0.9943 * 2^128 + 1 and n < 2^128.
The input family D is all 64-byte strings, so |D| = 2^512. Every message has
legal bit length 512 < 2^64. Represent a message by two 256-bit words u,v and
serialize it as LE32(u) || LE32(v), where LE32 writes exactly 32 little-endian
bytes, including zero bytes. This is a bijection from pairs of words onto D.
N and |D| are mathematical cardinalities used only in the proof; the
algorithm never stores either of those out-of-word-range integers. The
integer n itself fits in one 256-bit word.

The selected complete hash has a 1600-bit state, rate 1088 bits (136 bytes),
capacity 512, the all-zero initial state, and full 256-bit output.
Each such message's entire padded input is exactly one 136-byte block:

    LE32(u) || LE32(v) || 06 || (00 repeated 70 times) || 80

This is the SHA3 domain suffix 01 and pad10*1, using delimited suffix 0x06.
There is exactly one absorption permutation, no extra squeezing permutation,
and no Davies-Meyer feed-forward.

The complete subroutine H(u,v) is as follows. Store the state as 25 lanes,
each in the low 64 bits of a separate RAM word; upper bits are zero.
The lane index is x+5y for 0 <= x,y < 5, in little-endian lane order.
For j = 0,1,2,3 set

    A[j]   = (u >> (64*j)) AND (2^64-1)
    A[j+4] = (v >> (64*j)) AND (2^64-1),

set A[8] = 0x06 and A[16] = 0x8000000000000000, and set the remaining lanes
A[9..15] and A[17..24] to zero (fifteen lanes). Every lane is written exactly
once, and the result is precisely the padded rate block XORed into the
all-zero state.

Apply exactly the first six Keccak-f[1600] rounds, indices 0 through 5.
For each round use the following stages; within a stage assignments are
simultaneous, and each stage reads the preceding one. Subscripts x,y are
modulo 5. All lane arithmetic is on 64 bits, with NOT64 and rot64 restricted
to those bits, not the entire 256-bit RAM word.

    C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]
    D[x] = C[x-1] XOR rot64(C[x+1],1)
    T[x,y] = A[x,y] XOR D[x]
    B[y,2*x+3*y] = rot64(T[x,y],rho[x,y])
    Anew[x,y] = B[x,y] XOR ((NOT64 B[x+1,y]) AND B[x+2,y])
    A = Anew
    A[0,0] = A[0,0] XOR RC[round]

The rho offsets, listed in x+5y order, are

    0, 1,62,28,27, 36,44, 6,55,20, 3,10,43,25,39,
    41,45,15,21, 8, 18, 2,61,56,14.

Use these six RC constants in this order:

    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001.

Return

    d = A[0] OR (A[1] << 64) OR (A[2] << 128) OR (A[3] << 192).

LE32(d) is exactly the first 32 squeeze bytes, hence the full target digest.
This is the fixed prefix-round complete hash, not Keccak-p's last-round
convention, raw permutation hashing, a free initial state, different padding,
or truncated output. Equality of digests means all 256 output bits agree.
The six-round transformation costs one selected-target sponge permutation
under collision-frontier-v5; surrounding construction and serialization
operations are charged separately at 1/C units per primitive word operation.

## 2. Algorithm: direct-addressed collision search with sparse validation

The search stores the first occurrence of each observed digest in a
direct-addressed table indexed by the full 256-bit digest, so that a second
occurrence of any digest is detected exactly. Because a 2^256-entry table
cannot be initialized within any useful time bound, the table is never
initialized; instead each access is validated by the standard back-pointer
sparse-set argument (Briggs and Torczon), which is correct for arbitrary
initial memory contents. Two levels are used so that every address stays
below 2^256 while side arrays remain disjoint from the table region.

Split each digest word d as d = 256*h + l with h = d >> 8 (below 2^248)
and l = d AND 255. The structures are:

* T1: a level-1 table of 2^248 words, one per prefix h.
* Blocks: an arena of 256-word blocks, one block per allocated prefix;
  block b covers the 256 digests with prefix h(b).
* back1: array of at most n words; back1[b] is the prefix of block b.
* back: array of at most n words; back[r] is the full digest of record r.
* fwd: array of at most 2n words; fwd[2r], fwd[2r+1] are the message
  words u,v of record r.
* count1 (number of allocated blocks) and count (number of records),
  both starting at 0.

None of T1, the block arena, back1, back or fwd is initialized. Loads of
never-stored words may return arbitrary values; the invariants below hold
for every such outcome.

For each sample i = 0,...,n-1:

1. Draw fresh independent uniform 256-bit words u_i, v_i and compute
   d = H(u_i, v_i). Charge both draws and the hash, successful or not.
2. h = d >> 8; l = d AND 255. Load x = T1[h].
   If x < count1 and back1[x] = h, set b = x (the prefix is known).
   Otherwise allocate: b = count1; count1 = count1 + 1; back1[b] = h;
   T1[h] = b.
3. Load r = block b's word at offset l, at address baseB + (b << 8) + l.
   If r < count and back[r] = d, the digest has been seen: load
   u' = fwd[2r], v' = fwd[2r+1]. If (u',v') = (u_i,v_i), continue with
   the next sample (a repeated message is not an ordinary collision).
   Otherwise recompute H(u',v') and H(u_i,v_i) from fresh all-zero
   states, check full digest equality, output the two 64-byte messages
   and halt. On verification failure output failure and halt; this
   branch is unreachable under exact RAM semantics.
4. Otherwise insert: store count at block b offset l; back[count] = d;
   fwd[2count] = u_i; fwd[2count+1] = v_i; count = count + 1.

If the loop completes, output failure. There is one batch of n samples
and no restart or amplification.

Two invariants hold for arbitrary initial memory.

Invariant 1 (level 1). A write to T1[h] occurs only in the allocation
branch of a sample whose digest prefix is h, and it writes a fresh block
index with back1 updated to match. Before the first prefix-h sample, no
write to T1[h] ever occurred. Its load then yields some x0; if the
validation x0 < count1 and back1[x0] = h passed, back1[x0] would be a
genuinely written prefix equal to h, contradicting that no prefix-h sample
was inserted. So the first prefix-h sample allocates, establishing the
invariant; later prefix-h samples find the written value and never
overwrite it.

Invariant 2 (level 2). A write to block-b offset l occurs only in the
insert branch of a sample whose digest is d = 256*h(b) + l, because by
Invariant 1 the block reached through a validated T1[h] is the unique
block of prefix h. The first sample with digest d therefore finds, at its
slot, either a never-written word or a value failing validation: a passing
validation r < count with back[r] = d would mean a record with digest d
already exists, a contradiction. It inserts, and its slot contents persist:
any later sample with the same digest validates and takes the detection
branch without writing.

Consequently the algorithm succeeds exactly when the sample contains
distinct messages with equal target digests: the later sample of such a
pair validates against the first occurrence's record, the messages differ,
and recomputation confirms all 256 output bits. Detection is exact for
every fixed function H; there is no probing, no data-dependent chain, and
no distribution-dependent behavior anywhere in the search.

## 3. Unconditional success for this fixed function

The only randomness is the 2n independent uniform RAM words. H remains the
fixed function in section 1. For each of its N possible digest values y let

    p_y = |{m in D : H(m)=y}| / 2^512.

Some p_y may be zero, and no balance assumption is made. Independent uniform
messages produce independent outputs with this common distribution p,
because each output is a deterministic function of its respective input.
This fact asserts no independence among rounds or internal differences.

Here is the full finite-distribution bound. For q<=N let e_q(p) denote the
sum of products of probabilities over all q-element subsets of coordinates.
The probability of all q sampled outputs being distinct is q! e_q(p).
Hold all coordinates except a,b fixed, and keep a+b fixed. Then

    e_q(p) = a*b*e_(q-2)(rest) + (a+b)*e_(q-1)(rest) + e_q(rest),

where e_0=1 and impossible-size coefficients are zero.
All coefficients are nonnegative, so replacing a,b by their mean cannot
decrease e_q: their product increases at fixed sum.
To obtain a global maximum rigorously, e_q attains one on the compact
probability simplex. Among maximizers choose one minimizing sum p_i^2.
If two of its coordinates differ, averaging them does not decrease e_q
and strictly decreases the sum of squares, a contradiction.
Therefore the uniform vector maximizes e_q, including over distributions
with zero coordinates. No limiting repeated-averaging step is assumed.

Let E be the event that some two sampled digests agree. Apply this
inequality with q=n and then 1-x<=exp(-x) to each factor:

    Pr(not E) <= n! * binomial(N,n) / N^n
              = product_(j=0)^(n-1) (1-j/N)
              <= exp(-n*(n-1)/(2*N)).

Write L = n*(n-1)/(2*N). Because n >= 0.9943 * 2^128,

    L >= (0.9943 * 2^128) * (0.9943 * 2^128 - 1) / (2 * 2^256)
       = 0.9943 * (0.9943 - 2^{-128}) / 2
       = 0.9943^2 / 2 - 0.9943 * 2^{-129}.

Now 0.9943^2 = 9943^2 / 10^8 = 98863249 / 100000000, so
0.9943^2 / 2 = 98863249 / 200000000 = 0.494316245.
The subtracted term 0.9943 * 2^{-129} is positive and smaller than
2^{-128}, hence L > 0.494316244 > 0.4943.

Since L > 0.4943 one has exp(-L) < exp(-0.4943). The truncated
alternating series for exp(-x), stopped after the degree-6 term (a
positive contribution in the signed expansion), is an upper bound:

    exp(-x) <= 1 - x + x^2/2 - x^3/6 + x^4/24 - x^5/120 + x^6/720.

Substituting x = 0.4943 and evaluating the right-hand side with exact
decimal arithmetic gives a value strictly less than 0.6099992. Therefore

    Pr(not E) < 0.6099992,
    Pr(E) > 0.3900008.

(A tighter evaluation at the true lower threshold L > 0.494316244 yields
exp(-L) < 0.6099892 and Pr(E) > 0.3900108; the weaker 0.3900008 bound
already suffices below.)

Repeated inputs do not count as ordinary collisions. Let R be the event
that any two sampled messages are equal. Each particular pair agrees with
probability 2^-512; therefore the union bound gives

    Pr(R) <= binomial(n,2)/2^512 < n^2/2^513 < 2^{256}/2^{513} = 2^{-257},

using n < 2^128. On E without R an equal-digest pair necessarily has
distinct messages, and section 2 shows the search detects every such pair.
No independence between E and R is required for

    Pr(success) >= Pr(E)-Pr(R) > 0.3900008 - 2^{-257} > 0.39.

The JSON reports 0.39, the track minimum, at or below the proved bound.
This argument works for every fixed map D to N digests, including
unbalanced ones. It uses neither a random-oracle premise nor
balanced-output, pseudorandomness, experimental extrapolation or
differential independence. This is algorithmic success, not confidence in
the proof or an AI reviewer.

## 4. 256-bit RAM implementation and complete charged time

All actual scalar values fit in a word: n, h below 2^248, l below 256,
block indices and record indices below n, and every address below 2^256.
The proof cardinalities N and |D| and the large total-time bounds are not
machine registers. Only shifts and additions are used for addressing; no
multiplication is assumed. Block b is addressed as baseB + (b<<8); its
offset-l word adds l. Record r uses back at baseBack + r and fwd at
baseFwd + (r<<1). There are no unbounded counters, recursion stacks or
multiword addresses.

Under collision-frontier-v5 the charged primitive word operations are the
256-bit loads/stores, additions/subtractions, bitwise operations,
shifts/rotations, comparisons, conditional branches and independent uniform
random-word draws listed in the model, each costing 1/C = 1/1626 units.
Code and constants are charged to memory and their one-time loading to
time; the model's primitive list defines the per-instruction charged work,
and the envelope below overcounts the explicitly enumerated operations of
every path. Internals of the selected six-round permutation are not charged
as word operations: that work is exactly one selected-target unit per call.

### 4.1 Per-sample generation and hash construction

Charge only the RAM work that surrounds the selected permutation:

* two independent uniform random-word draws (2);
* lane extraction from u into A[0..3]: one AND and one store for A[0]
  (no shift), and for each of A[1],A[2],A[3] one shift, one AND and one
  store (11 total); likewise 11 for v into A[4..7] (22);
* fifteen zero stores for lanes A[9..15] and A[17..24] (15);
* two padding constant stores for A[8] and A[16] (2);
* two call/return branches for invoking the selected permutation as a
  subroutine (2);
* digest packing: four lane loads, three shifts and three ORs (10).

Explicit total: 2+22+15+2+2+10 = 53 primitive operations. No separate charge
is made for the permutation body itself.

### 4.2 Per-sample table path (worst case over adversarial memory)

The longest path on a single sample is: level-1 validation fails (so a fresh
prefix is allocated), level-2 validation fails (so the digest is inserted),
and the loop continues. Enumerating every charged primitive:

* split h,l: one shift and one AND (2);
* level-1 probe: one address add, one load, one comparison, one branch (4);
* level-1 failed validation: one address add, one load, one comparison,
  one branch (4);
* allocation: one register copy (charged as OR with 0), one increment,
  one address add and one store for back1, one store into the already
  computed T1 address (5);
* level-2 probe: one shift and two address adds for baseB+(b<<8)+l, one
  load, one comparison, one branch (6);
* level-2 failed validation: one address add, one load, one comparison,
  one branch (4);
* insert: one store into the block slot; one address add and one store for
  back; one shift and one address add for fwd base, one store of u, one
  address add and one store of v; one increment of count (9);
* loop control: one increment, one comparison, one branch (3).

Explicit total: 2+4+4+5+6+4+9+3 = 37. Paths that hit a known prefix skip
allocation and are strictly shorter. The detection path replaces the insert
block by two message-word loads, two equality comparisons and one branch,
then leaves the loop for a one-time verification; that replacement uses at
most 5 operations in place of 9, so it lies inside the same per-sample
envelope.

### 4.3 Envelope, batch cost and verification

Per-sample total: at most 53+37 = 90 primitive operations. The charged
envelope used below is 96 per sample (six operations of slack for loading
public base addresses and mask constants from the fixed workspace), hence
96n for the batch. The final verification and output emission uses two
selected permutations and fewer than 2^14 further word operations, charged
once.

The uniform program has the fixed loop bodies specified above. Its
elementary straight-line/control code needs fewer than 2^14 instructions.
Even if the selected primitive's code storage is included, six rounds of
25 lanes require fewer than this number: fixed lane coordinates eliminate
modulo/index computations, and each round uses fewer than 1024 elementary
instructions for the displayed XOR, rotation, chi, loads and stores.
All six rounds plus the generation, table and loop bodies remain below
2^14 instructions. Five-word encoding uses 81920 words.
Constants, counters, temporary words, output and working lanes together
use fewer than 4096 further words, totaling less than 2^17 words.
Reserve the larger 2^24-byte fixed area for all of them.
Loading this code/constants and clearing the fixed area costs at most
2^30 charged operations. These are uniform data, not searched advice.
No table, block or record array is zeroed; correctness rests on the
validation invariants of section 2, not on initial contents.

| Phase | Worst-case charged word operations |
| --- | ---: |
| Load fixed code/constants and initialize fixed workspace | 2^30 |
| Draw, construct, hash and search/insert every sample, envelope 96 each | 96n |
| Witness verification and output | 2^14 |

The table charges all samples, all failed validations and the final
verification regardless of success. There is no hidden restart cost.
These are worst-case bounds for one run, hence also bound expected time.
Total ordinary word operations:

    W <= 96n + 2^30 + 2^14
      < 96n + 2^31,

using 2^30 + 2^14 < 2^31. Since n < 0.9943 * 2^128 + 1,

    W < 96 * 0.9943 * 2^128 + 96 + 2^31
      = 95.4528 * 2^128 + 96 + 2^31.

The number of selected six-round permutations is

    H = n + 2 < 0.9943 * 2^128 + 3.

Under collision-frontier-v5 the total charged time is T = H + W/C with
C = 1626. Note that 96/1626 = 16/271 and

    96 * 0.9943 / 1626 = 95.4528 / 1626 = 0.058704059... < 0.05870406.

Also (96 + 2^31)/1626 < 2^31/1626 + 1 < 2^21 + 1, because
2^31/1626 < 2^31/2^{10} = 2^21. Therefore

    W/1626 < 0.05870406 * 2^128 + 2^21 + 1,

and

    T < 0.9943 * 2^128 + 3 + 0.05870406 * 2^128 + 2^21 + 1
      = 1.05300406 * 2^128 + 2^21 + 4
      < 1.05301 * 2^128,

because 2^21 + 4 < 2^22 < 0.000006 * 2^128. Finally compare 1.05301 with
2^0.08. Raising to the 25th power (since 0.08 = 2/25) gives

    1.05301^2  < 1.10884,
    1.05301^4  < 1.22953,
    1.05301^8  < 1.51175,
    1.05301^16 < 2.2854,
    1.05301^24 = 1.05301^16 * 1.05301^8 < 2.2854 * 1.51175 < 3.455,
    1.05301^25 < 3.455 * 1.05301 < 3.639 < 4 = 2^2,

so 1.05301 < 2^{2/25} = 2^0.08. Hence

    T < 2^0.08 * 2^128 = 2^128.08.

The organizer unit is named `target-compressions`: one selected six-round
sponge permutation costs one unit and each other listed primitive word
operation costs 1/1626 units. T is not merely the number of hashes.
Preprocessing is the fixed initialization only, already included in T:

    P <= 2^30 + 2^14 < 2^31.

No earlier search chooses messages, favorable coins, collisions, parameters
or advice. No failed trials or preparation steps are left outside T.

Relative to the prior 128.1 package: that package used n = 2^128 and a
112-operation envelope, giving T < 1.06889 * 2^128 < 2^128.1. The present
package uses the smaller birthday-minimal n and a 96-operation envelope
justified by the explicit 90-operation count above, giving
T < 1.05301 * 2^128 < 2^128.08.

## 5. Memory, addressing and interpretation of the claim

Word-addressed layout, all bases public constants:

| Region | Words | Address range |
| --- | ---: | --- |
| Fixed code/constants/workspace | < 2^24 | [0, 2^24) |
| back1 | n | [2^128, 2^128 + n) |
| back | n | [2^129, 2^129 + n) |
| fwd | 2n | [2^130, 2^130 + 2n) |
| Block arena, at most n blocks of 256 words | <= 256n < 2^136 | [2^136, 2^136 + 256n) |
| T1 | 2^248 | [2^256 - 2^248, 2^256) |

Each displayed range width is at least its region's word count, and the
regions are pairwise disjoint: the fixed area ends at 2^24 < 2^128;
back1 ends before 2^129; back ends before 2^130; fwd ends before
2^130 + 2^129 < 2^131 < 2^136; the block arena ends before
2^137 < 2^255 < 2^256 - 2^248 = 255 * 2^248, where T1 begins. No index
into one region can address another.
Every address is below 2^256 and fits in one word; addressing is by words,
and the byte totals below are the memory metric, not addresses.

    M <= 32 * (2^248 + 2^136 + 2n + n + n + 2^24)
      < 32 * 2^248 * (1 + 2^-110)
      < 2^254 bytes,

because 32*2^248 = 2^253 and the remaining regions total below 2^142
bytes (using n < 2^128). This is an extreme, physically meaningless bound
by design: the track scores only charged time, and this package deliberately
trades the unscored memory metric for the minimal charged work of exact
direct-addressed lookup. It is not constant memory or a statement of
physical practicality, and it stays within the 256-bit word-addressable
space of the model.

The JSON fields have these explicit units and meanings:

* `time_log2: 128.08` means T < 2^128.08 total charged operations.
* `memory_log2_bytes: 254` means M < 2^254 peak bytes, including code.
* `preprocessing_log2: 31` means P < 2^31 charged setup operations,
  already included in T, not an extra omitted phase.
* `success_probability: 0.39` is a proved one-batch lower bound; the
  proved value exceeds 0.3900008.
* `nonuniform_advice_log2_bytes: 0` bounds advice by 2^0 bytes.
  Actual nonuniform advice is zero bytes. The schema cannot encode log2(0),
  so the nonnegative value 0 is a conservative upper bound, not a hidden
  precomputed collision. Uniform program/constants are charged above.

Resource logarithms describe conservative upper bounds; success describes
a lower bound. The proposed scalar is 128.08. No scalar improvement or Pareto
dominance over the nominal reference 128 is claimed; the only comparison
asserted is against the prior 128.1 sparse-table package on this track.

## 6. Evidence, heuristic disclosures and limitations

All needed evidence is the self-contained analytic argument in sections
1 through 5. The heuristic list is empty: every material probability and
resource premise is discharged for the fixed target and stipulated RAM.
Fresh independent uniform random words are an explicit model primitive,
not an empirical assumption about a device or deterministic PRNG.
The sparse-validation invariants are proved for arbitrary initial memory,
so no initialization convention is assumed. No smaller-round experiment or
sibling package is needed for this proof. There are no toy-to-full-size
extrapolations or unexplained cryptanalytic premises, and no external link
must be fetched to assess the argument.

The certificate manifest is valid and empty. No computed collision or
certificate is claimed. No experiment is declared, and no candidate
program has been executed. Finite sampling would not establish the costs
or success of this infeasible run and is not used as evidence.
This is an analytic upper bound in the abstract model, not a measured
practical attack.

`ready` means complete and available for review. Qualification and score
emission require organizer review of this exact package.
Exploratory qualification is `plausible_not_refuted`; rigorous qualification
is `ai_rigor_qualified`. Neither is mathematical proof or human acceptance.
This candidate does not assert a review outcome, trusted score or successful
Yukon baseline import.
