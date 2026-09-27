# SHA3-256 prefix rounds 0 through 5: unconditional generic collision package

The scalar below is `time_log2` under `collision-frontier-v5` with selected-target
reference operation cost C = 1626. Memory remains a separately reported resource
bound.

Selected lane: exploratory. Target: `sha3-256-r6-prefix-v1`.
This finite classical algorithm has total charged time below 2^128.1,
peak memory below 2^254 bytes, and success probability above 0.39.
The proposed scalar is 128.1. It is a generic analytic construction
with infeasible resource use, not a claimed cryptanalytic advance.
The required `baseline_improved` identifier `sha3-256-r6-nominal-v2`
identifies the organizer's nominal reference only. That nominal 128 is not
an established attack, qualified baseline, or security bound; this package
does not claim to improve it.

## 1. Exact complete hash and legal messages

Let n = 2^128 and N = 2^256. The input family D is all 64-byte strings,
so |D| = 2^512. Every message has legal bit length 512 < 2^64.
Represent a message by two 256-bit words u,v and serialize it as
LE32(u) || LE32(v), where LE32 writes exactly 32 little-endian bytes,
including zero bytes. This is a bijection from pairs of words onto D.
N and |D| are mathematical cardinalities used only in the proof; the
algorithm never stores either of those out-of-word-range integers.

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
A[9..15] and A[17..24] to zero. Every lane is written exactly once, and the
result is precisely the padded rate block XORed into the all-zero state.

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

Here n*(n-1)/(2*N) = (2^256 - 2^128)/2^257 = 1/2 - 2^-129.
The truncated exponential series gives

    exp(1/2) > 1 + 1/2 + 1/8 + 1/48 + 1/384 = 633/384,

so exp(-1/2) < 384/633 < 0.6066352, because 633*0.6066352 = 384.0003 > 384.
Also exp(2^-129) < 1 + 2^-128 because exp(t) < 1 + 2t for 0 < t < 1/2.
Combining,

    Pr(not E) < 0.6066352 * (1 + 2^-128) < 0.6066353,
    Pr(E) > 0.3933647.

Repeated inputs do not count as ordinary collisions. Let R be the event
that any two sampled messages are equal. Each particular pair agrees with
probability 2^-512; therefore the union bound gives

    Pr(R) <= binomial(n,2)/2^512 < n^2/2^513 = 2^256/2^513 = 2^-257.

On E without R an equal-digest pair necessarily has distinct messages, and
section 2 shows the search detects every such pair. No independence between
E and R is required for

    Pr(success) >= Pr(E)-Pr(R) > 0.3933647 - 2^-257 > 0.3933.

The JSON reports 0.39, the track minimum, below the proved 0.3933.
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
every path.

Generation and hashing, per sample: two random-word draws; sixteen zero
stores for lanes 9..15 and 17..24; eight lane computations at one shift,
one AND and one store each; two padding constant stores; permutation call
bookkeeping; four output-lane loads, three shifts and three ORs. The
explicit count is at most 58 primitive operations.

Table work, per sample, worst path: one shift and one AND for h,l; one
address addition, one load, one comparison and one branch for the level-1
probe, plus one load, one comparison and one branch for validation; the
allocation path adds two stores, one increment and two address operations;
the level-2 probe uses one address addition, one load, one comparison, one
branch, one validation load, one comparison and one branch; the insert path
adds four stores, two address operations and one increment; loop control is
three operations. The worst path totals at most 33 primitive operations.
The detection path instead performs two message-word loads, two
comparisons and one branch before halting, within the same envelope.

Per-sample total: at most 91 primitive operations; the envelope is 112
per sample, hence 112n for the batch. The final verification and output
emission uses two selected permutations and fewer than 2^14 further
operations, charged once.

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
| Draw, hash and search/insert every sample, envelope 112 each | 112n |
| Witness verification and output | 2^14 |

The table charges all samples, all failed validations and the final
verification regardless of success. There is no hidden restart cost.
These are worst-case bounds for one run, hence also bound expected time.
Total ordinary word operations:

    W <= 112n + 2^30 + 2^14
      = 112*2^128 + 2^30 + 2^14
      < 112*2^128 + 2^31,

using 2^30 + 2^14 < 2^31.

The number of selected six-round permutations is

    H = n + 2,

one per sampled message plus the two final verification recomputations.
Under collision-frontier-v5 the total charged time is T = H + W/C with
C = 1626:

    W/1626 < (112*2^128)/1626 + 2^31/1626
           < 0.0688819*2^128 + 2^21,

because 112/1626 < 0.0688819 (equivalently 112 < 0.0688819*1626 = 112.002)
and 2^31/1626 < 2^31/2^10 = 2^21. Therefore

    T < 2^128 + 2 + 0.0688819*2^128 + 2^21
      = 1.0688819*2^128 + 2^21 + 2
      < 1.06889*2^128,

because 2^21 + 2 < 2^22 < 0.00001*2^128. Finally, the squaring chain
1.06889^2 = 1.142526, 1.06889^4 = 1.305366, 1.06889^5 = 1.395293 and
1.06889^10 = 1.946843 < 2 shows 1.06889 < 2^0.1, so

    T < 2^0.1 * 2^128 = 2^128.1.

The organizer unit is named `target-compressions`: one selected six-round
sponge permutation costs one unit and each other listed primitive word
operation costs 1/1626 units. T is not merely the number of hashes.
Preprocessing is the fixed initialization only, already included in T:

    P <= 2^30 + 2^14 < 2^31.

No earlier search chooses messages, favorable coins, collisions, parameters
or advice. No failed trials or preparation steps are left outside T.

## 5. Memory, addressing and interpretation of the claim

Word-addressed layout, all bases public constants:

| Region | Words | Address range |
| --- | ---: | --- |
| Fixed code/constants/workspace | < 2^24 | [0, 2^24) |
| back1 | n | [2^128, 2^129) |
| back | n | [2^129, 2^129 + 2^128) |
| fwd | 2n | [2^130, 2^130 + 2^129) |
| Block arena, at most n blocks of 256 words | 2^136 | [2^136, 2^137) |
| T1 | 2^248 | [2^256 - 2^248, 2^256) |

Each displayed range width equals its region's word count, and the
regions are pairwise disjoint: the fixed area ends at 2^24 < 2^128;
back1 ends at 2^129; back ends at 2^129 + 2^128 < 2^130; fwd ends at
2^130 + 2^129 < 2^131 < 2^136; the block arena ends at
2^137 < 2^255 < 2^256 - 2^248 = 255 * 2^248, where T1 begins. No index
into one region can address another.
Every address is below 2^256 and fits in one word; addressing is by words,
and the byte totals below are the memory metric, not addresses.

    M <= 32 * (2^248 + 2^136 + 2^129 + 2^128 + 2^128 + 2^24)
      < 32 * 2^248 * (1 + 2^-110)
      < 2^254 bytes,

because 32*2^248 = 2^253 and the remaining regions total below 2^142
bytes. This is an extreme, physically meaningless bound by design: the
track scores only charged time, and this package deliberately trades the
unscored memory metric for the minimal charged work of exact
direct-addressed lookup. It is not constant memory or a statement of
physical practicality, and it stays within the 256-bit word-addressable
space of the model.

The JSON fields have these explicit units and meanings:

* `time_log2: 128.1` means T < 2^128.1 total charged operations.
* `memory_log2_bytes: 254` means M < 2^254 peak bytes, including code.
* `preprocessing_log2: 31` means P < 2^31 charged setup operations,
  already included in T, not an extra omitted phase.
* `success_probability: 0.39` is a proved one-batch lower bound; the
  proved value exceeds 0.3933.
* `nonuniform_advice_log2_bytes: 0` bounds advice by 2^0 bytes.
  Actual nonuniform advice is zero bytes. The schema cannot encode log2(0),
  so the nonnegative value 0 is a conservative upper bound, not a hidden
  precomputed collision. Uniform program/constants are charged above.

Resource logarithms describe conservative upper bounds; success describes
a lower bound. The proposed scalar is 128.1. No scalar improvement or Pareto
dominance over an established attack is claimed.

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
